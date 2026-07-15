use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use rusqlite::{backup::Backup, params, Connection};

/// 内存库里最多保留多少条事件（防止长时间运行内存无限增长）
pub const MAX_ROWS: i64 = 20_000;

/// 进程过滤配置——同时给 ETW 抓取层（决定哪些进程的事件入库）和 UI 显示层
/// （按进程名二次过滤）使用。匹配规则是 case-insensitive 子串包含：
/// "chrome" 会匹配 "chrome.exe"、"Chrome.exe" 但不会匹配 "chromium.exe"。
///
/// 两种模式可同时启用：白名单非空时进程必须命中白名单才放行；黑名单非空时命中
/// 黑名单的进程被剔除。两个都为空表示不过滤（默认行为，保持向后兼容）。
#[derive(Debug, Clone, Default)]
pub struct FilterConfig {
    /// 不为空时，仅记录进程名匹配任一关键字的进程产生的事件
    pub whitelist: Vec<String>,
    /// 进程名匹配任一关键字的事件一律丢弃
    pub blacklist: Vec<String>,
}

impl FilterConfig {
    pub fn is_empty(&self) -> bool {
        self.whitelist.is_empty() && self.blacklist.is_empty()
    }

    /// 判断给定进程名是否应该被记录/显示。
    /// 返回 false 表示该进程被过滤掉。
    pub fn allows(&self, process_name: &str) -> bool {
        if self.is_empty() {
            return true;
        }
        let pname = process_name.to_lowercase();
        if !self.whitelist.is_empty() {
            let hit = self
                .whitelist
                .iter()
                .any(|kw| !kw.trim().is_empty() && pname.contains(&kw.to_lowercase()));
            if !hit {
                return false;
            }
        }
        if !self.blacklist.is_empty() {
            let hit = self
                .blacklist
                .iter()
                .any(|kw| !kw.trim().is_empty() && pname.contains(&kw.to_lowercase()));
            if hit {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Clone)]
pub struct FileEvent {
    pub seq: i64,
    pub time_str: String,
    pub pid: u32,
    pub process_name: String,
    pub operation: String,
    pub path: String,
    pub detail: String,
}

/// 插入时不需要 seq（由 SQLite 自增），单独给一个结构体避免和查询返回的 FileEvent 混淆
pub struct NewFileEvent {
    pub time_str: String,
    pub pid: u32,
    pub process_name: String,
    pub operation: String,
    pub path: String,
    pub detail: String,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS file_events (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    time_str     TEXT NOT NULL,
    pid          INTEGER NOT NULL,
    process_name TEXT NOT NULL,
    operation    TEXT NOT NULL,
    path         TEXT NOT NULL,
    detail       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_file_events_path ON file_events(path);
";

/// 内存 SQLite（承担 ETW 回调的高频写入） + 后台线程定期用 SQLite 的
/// Online Backup API 把内存库整体同步到磁盘文件——这比每条事件都 fsync 一次快得多，
/// 也比自己攒 buffer 再批量 INSERT 可靠（备份是 SQLite 自己保证一致性的）。
pub struct EventStore {
    mem: Mutex<Connection>,
    disk_path: PathBuf,
}

impl EventStore {
    /// 打开（或新建）磁盘库：如果磁盘上已经有上次运行留下的历史数据，先整体拷回内存库，
    /// 这样重启后界面上还能看到之前的记录；然后启动后台定期落盘线程。
    pub fn open(disk_path: PathBuf, flush_interval: Duration) -> anyhow::Result<Arc<Self>> {
        let mut mem_conn = Connection::open_in_memory()?;
        mem_conn.execute_batch(SCHEMA)?;

        if disk_path.exists() {
            let disk_conn = Connection::open(&disk_path)?;
            // 反向操作：从磁盘 -> 内存
            let backup = Backup::new(&disk_conn, &mut mem_conn)?;
            backup.run_to_completion(100, Duration::from_millis(0), None)?;
        } else {
            // 磁盘文件不存在也要建好并写入 schema，保证第一次落盘时文件是有效的 SQLite 库
            let disk_conn = Connection::open(&disk_path)?;
            disk_conn.execute_batch(SCHEMA)?;
        }

        let store = Arc::new(Self {
            mem: Mutex::new(mem_conn),
            disk_path,
        });

        {
            let store = store.clone();
            std::thread::spawn(move || loop {
                std::thread::sleep(flush_interval);
                if let Err(e) = store.flush_to_disk() {
                    eprintln!("[EventStore] 落盘失败: {e:?}");
                }
            });
        }

        Ok(store)
    }

    pub fn insert(&self, ev: &NewFileEvent) -> anyhow::Result<()> {
        let conn = self.mem.lock();
        conn.execute(
            "INSERT INTO file_events (time_str, pid, process_name, operation, path, detail)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                ev.time_str,
                ev.pid,
                ev.process_name,
                ev.operation,
                ev.path,
                ev.detail
            ],
        )?;

        // 简单粗暴的裁剪：每次插入顺手删一次超出上限的老记录。
        // 在内存库里做这个非常快，量级到万级别没有可感知的开销。
        conn.execute(
            "DELETE FROM file_events WHERE seq <= (SELECT COALESCE(MAX(seq), 0) FROM file_events) - ?1",
            params![MAX_ROWS],
        )?;
        Ok(())
    }

    /// 最近 N 条，按时间倒序（最新的在最前面）
    pub fn recent(&self, limit: i64) -> anyhow::Result<Vec<FileEvent>> {
        let conn = self.mem.lock();
        let mut stmt = conn.prepare(
            "SELECT seq, time_str, pid, process_name, operation, path, detail
             FROM file_events ORDER BY seq DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], row_to_event)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// 按路径/进程名/操作类型做一次 SQL 层面的粗过滤（LIKE），缩小候选集之后
    /// 再交给上层用 fuzzy-matcher 做真正的相关性排序，避免每帧都把全部历史搬进 Rust 侧。
    pub fn search(&self, keyword: &str, limit: i64) -> anyhow::Result<Vec<FileEvent>> {
        let pattern = format!("%{}%", keyword.replace('%', "\\%").replace('_', "\\_"));
        let conn = self.mem.lock();
        let mut stmt = conn.prepare(
            "SELECT seq, time_str, pid, process_name, operation, path, detail
             FROM file_events
             WHERE path LIKE ?1 ESCAPE '\\'
                OR process_name LIKE ?1 ESCAPE '\\'
                OR operation LIKE ?1 ESCAPE '\\'
             ORDER BY seq DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![pattern, limit], row_to_event)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn count(&self) -> anyhow::Result<i64> {
        let conn = self.mem.lock();
        Ok(conn.query_row("SELECT COUNT(*) FROM file_events", [], |r| r.get(0))?)
    }

    /// 把内存库整体同步覆盖到磁盘文件。
    pub fn flush_to_disk(&self) -> anyhow::Result<()> {
        let mem_conn = self.mem.lock();
        let mut disk_conn = Connection::open(&self.disk_path)?;
        let backup = Backup::new(&mem_conn, &mut disk_conn)?;
        backup.run_to_completion(100, Duration::from_millis(5), None)?;
        Ok(())
    }
}

fn row_to_event(row: &rusqlite::Row) -> rusqlite::Result<FileEvent> {
    Ok(FileEvent {
        seq: row.get(0)?,
        time_str: row.get(1)?,
        pid: row.get(2)?,
        process_name: row.get(3)?,
        operation: row.get(4)?,
        path: row.get(5)?,
        detail: row.get(6)?,
    })
}
