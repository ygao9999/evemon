use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};

use ferrisetw::parser::{Parser, Pointer};
use ferrisetw::provider::{kernel_providers, Provider};
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::KernelTrace;
use ferrisetw::EventRecord;

use sysinfo::{Pid, ProcessesToUpdate, System};

use windows_sys::Win32::Storage::FileSystem::{GetLogicalDriveStringsW, QueryDosDeviceW};

use crate::store::{EventStore, FilterConfig, NewFileEvent};

/// FileObject -> 路径 关联表如果因为漏掉 Close 事件一直增长，超过这个阈值就整体清空重来
/// （粗暴但简单的安全阀，正经实现应该是 LRU）
const MAX_FILEOBJ_MAP: usize = 100_000;

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

/// 把 UTF-8 字符串编码成 0 结尾的 UTF-16，给 widestring 版本的 Win32 API 用。
fn to_wide_zstr(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 把 0 结尾的 UTF-16 buffer 解码成 String（在第一个 NUL 处截断）。
fn from_wide_zstr(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

/// 通过 GetLogicalDriveStringsW + QueryDosDeviceW 构建反向映射表：
///   "\Device\HarddiskVolume9" -> "C:"
///   "\Device\HarddiskVolume2" -> "D:"
/// 这样 ETW 给的 NT 内核路径 `\Device\HarddiskVolume9\Windows\System32`
/// 能翻译成用户能看懂的 `C:\Windows\System32`。
///
/// 失败时返回空表（不是 None），调用方按"翻译不了就保留原路径"处理。
fn build_device_to_drive_map() -> HashMap<String, String> {
    let mut map = HashMap::new();

    // GetLogicalDriveStringsW 返回形如 "C:\\\0D:\\\0E:\\\0\0" 的双 0 结尾串
    let mut buf = [0u16; 512];
    let len = unsafe { GetLogicalDriveStringsW(buf.len() as u32, buf.as_mut_ptr()) };
    if len == 0 || len as usize >= buf.len() {
        return map;
    }
    let drives_str = String::from_utf16_lossy(&buf[..len as usize]);

    // 每段形如 "C:\"；去掉尾部反斜杠得到 "C:"
    for drive in drives_str.split('\0').filter(|s| !s.is_empty()) {
        let drive_letter = drive.trim_end_matches('\\');
        if drive_letter.len() < 2 {
            continue;
        }
        let wide_drive = to_wide_zstr(drive_letter);
        let mut dev_buf = [0u16; 512];
        // QueryDosDeviceW("C:") 返回 "\Device\HarddiskVolume9\0"
        let dev_len = unsafe {
            QueryDosDeviceW(
                wide_drive.as_ptr(),
                dev_buf.as_mut_ptr(),
                dev_buf.len() as u32,
            )
        };
        if dev_len == 0 {
            continue;
        }
        let dev_path = from_wide_zstr(&dev_buf[..dev_len as usize]);
        if !dev_path.is_empty() {
            map.insert(dev_path, drive_letter.to_string());
        }
    }

    map
}

/// 用反向映射表把 NT 内核路径翻译成 Win32 路径。
///
/// 例如 map 里有 "\Device\HarddiskVolume9" -> "C:"，则
///   `\Device\HarddiskVolume9\Windows\System32\notepad.exe`
///   → `C:\Windows\System32\notepad.exe`
///
/// 关键：前缀匹配必须验证紧跟着的字符是 `\`（或字符串结束），否则
/// "\Device\HarddiskVolume1" 会误匹配 "\Device\HarddiskVolume10\foo"
/// 替换出 `C:0\foo` 这种垃圾。
///
/// 找不到匹配项时原样返回（例如网络重定向器路径 \Device\LanmanRedirector，
/// 或者映射表刷新滞后时插入的 U 盘等）。
fn translate_nt_path(nt_path: &str, map: &HashMap<String, String>) -> String {
    if nt_path.is_empty() || !nt_path.starts_with('\\') {
        return nt_path.to_string();
    }
    for (device, drive) in map {
        if let Some(rest) = nt_path.strip_prefix(device.as_str()) {
            if rest.is_empty() || rest.starts_with('\\') {
                return format!("{drive}{rest}");
            }
        }
    }
    nt_path.to_string()
}

/// 启动 ETW 内核 FileIo 追踪，捕获文件打开/读写/关闭/改名/删除等事件，写入 SQLite 内存库。
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
pub fn spawn_etw_capture(
    store: Arc<EventStore>,
    capture_filter: Arc<RwLock<FilterConfig>>,
) -> anyhow::Result<KernelTrace> {
    let proc_table = Arc::new(Mutex::new(System::new()));
    let fileobj_to_path: Arc<RwLock<HashMap<usize, String>>> =
        Arc::new(RwLock::new(HashMap::new()));

    // NT 设备路径 -> 盘符的反向映射表。ETW 给的 OpenPath 是
    // \Device\HarddiskVolume9\... 这种内核路径，需要翻译成 C:\... 才能看懂。
    // 启动时建一次表，之后后台线程每 60 秒刷一次（U 盘热插、网络盘挂载会让映射变化）。
    let device_to_drive: Arc<RwLock<HashMap<String, String>>> =
        Arc::new(RwLock::new(build_device_to_drive_map()));
    {
        let device_to_drive = device_to_drive.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
            let fresh = build_device_to_drive_map();
            *device_to_drive.write() = fresh;
        });
    }

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

        // 先解析出进程名，再做抓取层过滤——白/黑名单命中就直接 return，
        // 不走 FileObject 映射表更新也不写库，省内存也省 SQLite 写入压力。
        let process_name = resolve_process_name(&proc_table, pid);
        if !capture_filter.read().allows(&process_name) {
            return;
        }

        if opcode == "Create" {
            // FileIo_Create：真正的打开事件，字段名是 OpenPath 不是 FileName
            let raw_path = match parser.try_parse::<String>("OpenPath") {
                Ok(p) if !p.is_empty() => p,
                _ => return,
            };
            // 把 \Device\HarddiskVolume9\... 翻译成 C:\...
            let path = translate_nt_path(&raw_path, &device_to_drive.read());
            if let Ok(fobj) = parser.try_parse::<Pointer>("FileObject") {
                let mut map = fileobj_to_path.write();
                if map.len() > MAX_FILEOBJ_MAP {
                    map.clear();
                }
                // 注意：FileObject 映射表里也存翻译后的路径，这样后续 Read/Write/Close
                // 反查时拿到的就是 Win32 路径，不用每次都查 device_to_drive
                map.insert(*fobj, path.clone());
            }
            let ev = NewFileEvent {
                time_str: filetime_to_string(record.raw_timestamp()),
                pid,
                process_name,
                operation: opcode,
                path,
                detail: String::new(),
            };
            if let Err(e) = store.insert(&ev) {
                eprintln!("[etw] 写入事件失败: {e:?}");
            }
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

        let ev = NewFileEvent {
            time_str: filetime_to_string(record.raw_timestamp()),
            pid,
            process_name,
            operation: opcode,
            path,
            detail,
        };
        if let Err(e) = store.insert(&ev) {
            eprintln!("[etw] 写入事件失败: {e:?}");
        }
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
