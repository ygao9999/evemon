use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};

use ferrisetw::parser::{Parser, Pointer};
use ferrisetw::provider::{kernel_providers, Provider};
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::KernelTrace;
use ferrisetw::EventRecord;

use sysinfo::{Pid, ProcessesToUpdate, System};

/// 事件环形缓冲最多保留多少条，防止长时间运行内存无限增长
pub const MAX_EVENTS: usize = 20_000;

/// FileObject -> 路径 关联表如果因为漏掉 Close 事件一直增长，超过这个阈值就整体清空重来
/// （粗暴但简单的安全阀，正经实现应该是 LRU）
const MAX_FILEOBJ_MAP: usize = 100_000;

#[derive(Clone, Debug)]
pub struct FileEvent {
    pub seq: u64,
    pub time_str: String,
    pub pid: u32,
    pub process_name: String,
    pub operation: String,
    pub path: String,
    /// 额外信息：读写的字节数/偏移量等，不是每种操作都有
    pub detail: String,
}

/// 实时事件日志：ETW 回调线程写入，GUI 线程读取快照。
pub struct EventLog {
    events: RwLock<VecDeque<FileEvent>>,
    seq: AtomicU64,
}

impl EventLog {
    pub fn new() -> Self {
        Self {
            events: RwLock::new(VecDeque::with_capacity(MAX_EVENTS)),
            seq: AtomicU64::new(0),
        }
    }

    fn push(&self, mut ev: FileEvent) {
        ev.seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let mut w = self.events.write();
        if w.len() >= MAX_EVENTS {
            w.pop_front();
        }
        w.push_back(ev);
    }

    pub fn len(&self) -> usize {
        self.events.read().len()
    }

    /// 拷贝一份当前快照给 UI 过滤用，避免长期持锁阻塞 ETW 回调线程写入。
    pub fn snapshot(&self) -> Vec<FileEvent> {
        self.events.read().iter().cloned().collect()
    }
}

/// FILETIME（自 1601-01-01 起的 100ns 间隔数）转成 HH:MM:SS.mmm 字符串
fn filetime_to_string(filetime: i64) -> String {
    const EPOCH_DIFF_100NS: i64 = 116_444_736_000_000_000; // 1601 -> 1970
    let unix_100ns = filetime - EPOCH_DIFF_100NS;
    let secs = unix_100ns.div_euclid(10_000_000);
    let nanos = (unix_100ns.rem_euclid(10_000_000) * 100) as u32;
    match chrono::DateTime::from_timestamp(secs, nanos) {
        Some(dt) => dt.format("%H:%M:%S%.3f").to_string(),
        None => "?".to_string(),
    }
}

fn resolve_process_name(proc_table: &Mutex<System>, pid: u32) -> String {
    proc_table
        .lock()
        .process(Pid::from_u32(pid))
        .map(|p| p.name().to_string_lossy().to_string())
        .unwrap_or_else(|| format!("pid:{pid}"))
}

/// 启动 ETW 内核 FileIo 追踪，捕获文件打开/读写/关闭/改名/删除等事件。
///
/// 背景（基于微软 FileIo 事件文档核实过字段名，不是凭印象猜的）：
/// - 单个 `EVENT_TRACE_FLAG_FILE_IO_INIT` (对应 ferrisetw 的 `FILE_INIT_IO_PROVIDER`)
///   就同时启用了 `FileIo_Create`（真正的打开事件）、`FileIo_ReadWrite`（读写）、
///   `FileIo_SimpleOp`（Cleanup/Close/Flush）、`FileIo_Info`（SetInfo/Delete/Rename/...）
///   这几类事件，不需要额外再挂一个 provider。
/// - **打开事件的文件名字段叫 `OpenPath`，不是 `FileName`**——`FileName` 字段属于另一个
///   叫 `FileIo_Name` 的类，只在 trace 启动那一刻用来枚举“已经打开的文件”，跟运行期间
///   持续产生的 Create 事件是两回事，很容易搞混。
/// - Read/Write/Close/Rename/Delete 这些事件本身**不带文件名**，只带一个 `FileObject`
///   指针，必须靠前面 Create 事件建立的 `FileObject -> 路径` 映射表去反查，这也是
///   Process Monitor 内部的做法。
///
/// 注意：
/// - 必须以管理员身份运行，否则启动 ETW 会话会报权限错误。
/// - 全系统同一时间只能有一个 "NT Kernel Logger" 会话，如果你机器上已经在跑
///   Process Monitor / xperf 之类工具，这里 start_and_process 可能会失败。
/// - FileObject -> 路径的映射是尽力而为的：如果文件在追踪启动前就已经打开了（没有
///   补做 rundown 枚举），或者 Close 事件丢失，对应的 Read/Write/Rename 就可能查不到
///   路径，界面上会显示 `<未知文件 fobj=0x..>`。
pub fn spawn_etw_capture(log: Arc<EventLog>) -> anyhow::Result<KernelTrace> {
    let proc_table = Arc::new(Mutex::new(System::new()));
    let fileobj_to_path: Arc<RwLock<HashMap<usize, String>>> =
        Arc::new(RwLock::new(HashMap::new()));

    // 独立线程周期性刷新进程表，用于把事件里的 pid 翻译成进程名。
    // 不在 ETW 回调里直接刷新，是因为回调线程要保持低延迟，不能被整表刷新阻塞。
    {
        let proc_table = proc_table.clone();
        std::thread::spawn(move || loop {
            proc_table
                .lock()
                .refresh_processes(ProcessesToUpdate::All, true);
            std::thread::sleep(std::time::Duration::from_secs(2));
        });
    }

    let callback = move |record: &EventRecord, schema_locator: &SchemaLocator| {
        let schema = match schema_locator.event_schema(record) {
            Ok(s) => s,
            Err(_) => return,
        };
        let parser = Parser::create(record, &schema);
        let opcode = schema.opcode_name();
        let pid = record.process_id();

        if opcode == "Create" {
            // FileIo_Create：真正的打开事件，字段名是 OpenPath 不是 FileName
            let path = match parser.try_parse::<String>("OpenPath") {
                Ok(p) if !p.is_empty() => p,
                _ => return,
            };
            if let Ok(fobj) = parser.try_parse::<Pointer>("FileObject") {
                let mut map = fileobj_to_path.write();
                if map.len() > MAX_FILEOBJ_MAP {
                    map.clear();
                }
                map.insert(*fobj, path.clone());
            }
            log.push(FileEvent {
                seq: 0,
                time_str: filetime_to_string(record.raw_timestamp()),
                pid,
                process_name: resolve_process_name(&proc_table, pid),
                operation: opcode,
                path,
                detail: String::new(),
            });
            return;
        }

        // 其余事件类型（Read/Write/Cleanup/Close/Flush/SetInfo/Delete/Rename/DirEnum/...）
        // 都只带 FileObject，需要反查
        let fobj = match parser.try_parse::<Pointer>("FileObject") {
            Ok(p) => *p,
            Err(_) => return,
        };

        let path = {
            let map = fileobj_to_path.read();
            map.get(&fobj)
                .cloned()
                .unwrap_or_else(|| format!("<未知文件 fobj=0x{fobj:x}>"))
        };

        // Close 之后这个 FileObject 就失效了，及时清理，避免映射表无限增长
        if opcode == "Close" {
            fileobj_to_path.write().remove(&fobj);
        }

        let detail = match (
            parser.try_parse::<u32>("IoSize"),
            parser.try_parse::<u64>("Offset"),
        ) {
            (Ok(size), Ok(offset)) => format!("size={size} offset={offset}"),
            (Ok(size), Err(_)) => format!("size={size}"),
            _ => String::new(),
        };

        log.push(FileEvent {
            seq: 0,
            time_str: filetime_to_string(record.raw_timestamp()),
            pid,
            process_name: resolve_process_name(&proc_table, pid),
            operation: opcode,
            path,
            detail,
        });
    };

    let provider = Provider::kernel(&kernel_providers::FILE_INIT_IO_PROVIDER)
        .add_callback(callback)
        .build();

    let trace = KernelTrace::new()
        .named("EveMonFileTrace".to_string())
        .enable(provider)
        .start_and_process()
        .map_err(|e| anyhow::anyhow!("启动 ETW 内核追踪失败: {e:?}（是否以管理员身份运行？）"))?;

    Ok(trace)
}
