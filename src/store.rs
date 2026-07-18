use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use rusqlite::{backup::Backup, params, Connection};

/// 内存库里最多保留多少条**唯一路径**（防止长时间运行内存无限增长）
pub const MAX_ROWS: i64 = 20_000;

/// schema 版本号——通过 PRAGMA user_version 持久化在 SQLite 库头里。
/// v0：旧 schema（无 UNIQUE 约束，path 重复插入）
/// v1：path UNIQUE + count + first_seen + last_activity 列
const SCHEMA_VERSION: i64 = 1;

/// 编译后的单个关键字匹配器。
///
/// 匹配规则：
/// - 关键字含 glob 元字符（`*` `?` `[` `{`）时，编译成 case-insensitive 的
///   [`globset::GlobMatcher`](globset) 对完整字符串做 glob 匹配。
///   - `D:\work_flow\**\*.java` 命中 `D:\work_flow\sub\foo.java`
///   - `chrome.*` 命中 `chrome.exe` 但不命中 `chrome` （glob 是完整匹配不是子串）
/// - 关键字不含 glob 元字符时，做 case-insensitive 子串包含匹配（向后兼容）：
///   - `chrome` 命中 `chrome.exe`、`chromium.exe`、`Chrome.EXE`
///   - `D:\work_flow` 命中 `D:\work_flow\foo\bar.java`
///
/// glob 编译失败的（语法错误）关键字会被跳过——不会命中任何字符串，等价于不存在。
#[derive(Clone)]
enum MatcherEntry {
    /// 已经 lower 过的子串关键字，待匹配的字符串也要 lower 后比较
    Substring(String),
    /// 编译好的 glob matcher，构造时已经设了 case_insensitive
    Glob(globset::GlobMatcher),
}

impl MatcherEntry {
    /// 把原始关键字字符串编译成 MatcherEntry。trim 后为空返回 None（调用方自己跳过）。
    fn compile(raw: &str) -> Option<Self> {
        let kw = raw.trim();
        if kw.is_empty() {
            return None;
        }
        if has_glob_meta(kw) {
            // case_insensitive 让 chrome.* 匹配 Chrome.EXE，和子串模式行为一致
            match globset::GlobBuilder::new(kw)
                .case_insensitive(true)
                .build()
            {
                Ok(glob) => Some(MatcherEntry::Glob(glob.compile_matcher())),
                Err(e) => {
                    eprintln!("[filter] glob 模式 {kw:?} 编译失败: {e}，已跳过");
                    None
                }
            }
        } else {
            Some(MatcherEntry::Substring(kw.to_lowercase()))
        }
    }

    fn matches(&self, value: &str) -> bool {
        match self {
            MatcherEntry::Substring(kw) => value.to_lowercase().contains(kw),
            // globset 的 matcher 已经 case_insensitive，直接喂原始 value
            MatcherEntry::Glob(m) => m.is_match(value),
        }
    }
}

/// 判断关键字是否含有 glob 元字符。`!` 只在 `[!...]` 里有意义，不单独算。
fn has_glob_meta(s: &str) -> bool {
    s.contains('*') || s.contains('?') || s.contains('[') || s.contains('{')
}

/// 一个完整的过滤器：白名单 + 黑名单，内部缓存了编译后的 matcher，避免每条 ETW 事件
/// 都重新编译 glob。`set_whitelist` / `set_blacklist` 在更新关键字的同时重建缓存。
///
/// 两个模式可同时启用：白名单非空时必须命中白名单才放行；黑名单非空时命中黑名单
/// 的被剔除。两个都空表示不过滤（默认行为）。
#[derive(Clone)]
pub struct FilterConfig {
    whitelist: Vec<String>,
    blacklist: Vec<String>,
    whitelist_matchers: Vec<MatcherEntry>,
    blacklist_matchers: Vec<MatcherEntry>,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            whitelist: Vec::new(),
            blacklist: Vec::new(),
            whitelist_matchers: Vec::new(),
            blacklist_matchers: Vec::new(),
        }
    }
}

impl std::fmt::Debug for FilterConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FilterConfig")
            .field("whitelist", &self.whitelist)
            .field("blacklist", &self.blacklist)
            .finish()
    }
}

impl FilterConfig {
    /// 从白名单 + 黑名单关键字列表构造，同时编译 matcher 缓存。
    pub fn new(whitelist: Vec<String>, blacklist: Vec<String>) -> Self {
        let whitelist_matchers = whitelist.iter().filter_map(|s| MatcherEntry::compile(s)).collect();
        let blacklist_matchers = blacklist.iter().filter_map(|s| MatcherEntry::compile(s)).collect();
        Self {
            whitelist,
            blacklist,
            whitelist_matchers,
            blacklist_matchers,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.whitelist.is_empty() && self.blacklist.is_empty()
    }

    /// 判断给定进程名是否应该被记录/显示。
    /// 返回 false 表示该进程被过滤掉。
    pub fn allows(&self, process_name: &str) -> bool {
        if self.is_empty() {
            return true;
        }
        if !self.whitelist_matchers.is_empty() {
            if !self.whitelist_matchers.iter().any(|m| m.matches(process_name)) {
                return false;
            }
        }
        if !self.blacklist_matchers.is_empty() {
            if self.blacklist_matchers.iter().any(|m| m.matches(process_name)) {
                return false;
            }
        }
        true
    }
}

/// 路径过滤配置——语义和 FilterConfig 完全对称，只是作用于 ETW 事件里的 path 字段。
///
/// 路径过滤在 NT 路径翻译完成之后才做，所以关键字写 Win32 路径就行
/// （`C:\Windows` 而不是 `\Device\HarddiskVolume9\Windows`）。
///
/// 支持两种匹配方式（每个关键字独立判断）：
/// - **子串匹配**（默认）：`D:\work_flow` 命中任何包含该子串的路径。case-insensitive。
/// - **glob 匹配**：关键字含 `*` `?` `[` `{` 之一时启用。例如：
///   - `D:\work_flow\**\*.java` 命中该目录下任意深度的 .java 文件
///   - `*.tmp` 命中任何以 .tmp 结尾的文件（注意 glob `*` 不跨路径分隔符，所以
///     `*.tmp` 只命中 `foo.tmp` 不命中 `dir\foo.tmp`；要跨目录用 `**\*.tmp`）
///   - `{*.log,*.bak}` 命中 .log 或 .bak
#[derive(Clone, Default)]
pub struct PathFilterConfig {
    whitelist: Vec<String>,
    blacklist: Vec<String>,
    whitelist_matchers: Vec<MatcherEntry>,
    blacklist_matchers: Vec<MatcherEntry>,
}

impl std::fmt::Debug for PathFilterConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PathFilterConfig")
            .field("whitelist", &self.whitelist)
            .field("blacklist", &self.blacklist)
            .finish()
    }
}

impl PathFilterConfig {
    pub fn new(whitelist: Vec<String>, blacklist: Vec<String>) -> Self {
        let whitelist_matchers = whitelist.iter().filter_map(|s| MatcherEntry::compile(s)).collect();
        let blacklist_matchers = blacklist.iter().filter_map(|s| MatcherEntry::compile(s)).collect();
        Self {
            whitelist,
            blacklist,
            whitelist_matchers,
            blacklist_matchers,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.whitelist.is_empty() && self.blacklist.is_empty()
    }

    /// 判断给定路径是否应该被记录/显示。
    /// 返回 false 表示该路径被过滤掉。
    pub fn allows(&self, path: &str) -> bool {
        if self.is_empty() {
            return true;
        }
        if !self.whitelist_matchers.is_empty() {
            if !self.whitelist_matchers.iter().any(|m| m.matches(path)) {
                return false;
            }
        }
        if !self.blacklist_matchers.is_empty() {
            if self.blacklist_matchers.iter().any(|m| m.matches(path)) {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct FileEvent {
    pub seq: i64,
    /// 最后一次活动对应的 last_activity 序号（单调递增，用于排序和裁剪）
    pub last_activity: i64,
    /// 最后一次看到该路径的时间字符串
    pub time_str: String,
    pub pid: u32,
    pub process_name: String,
    pub operation: String,
    pub path: String,
    pub detail: String,
    /// 该路径累计被命中的次数
    pub count: i64,
    /// 首次看到该路径的时间字符串
    pub first_seen: String,
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

/// schema 定义。和旧 schema 的关键差异：
/// - `path` 加 UNIQUE 约束——同一个路径在表里只允许一行
/// - 新增 `count` 列记录命中次数（首次插入 = 1，后续命中 +1）
/// - 新增 `first_seen` 列保留首次看到的时间（不被 ON CONFLICT 覆盖）
/// - 新增 `last_activity` 列——单调递增的活动序号，用于"最近活跃"排序和裁剪。
///   不能直接用 `seq`，因为 ON CONFLICT UPDATE 不会改 PRIMARY KEY AUTOINCREMENT。
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS file_events (
    seq           INTEGER PRIMARY KEY AUTOINCREMENT,
    last_activity INTEGER NOT NULL,
    time_str      TEXT NOT NULL,
    pid           INTEGER NOT NULL,
    process_name  TEXT NOT NULL,
    operation     TEXT NOT NULL,
    path          TEXT NOT NULL UNIQUE,
    detail        TEXT NOT NULL,
    count         INTEGER NOT NULL DEFAULT 1,
    first_seen    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_file_events_path ON file_events(path);
CREATE INDEX IF NOT EXISTS idx_file_events_last_activity ON file_events(last_activity);
";

/// 内存 SQLite（承担 ETW 回调的高频写入） + 后台线程定期用 SQLite 的
/// Online Backup API 把内存库整体同步到磁盘文件——这比每条事件都 fsync 一次快得多，
/// 也比自己攒 buffer 再批量 INSERT 可靠（备份是 SQLite 自己保证一致性的）。
///
/// 退出时必须调用 [`EventStore::shutdown`] 停止后台线程后再做最终 flush，否则
/// eframe 在 `on_exit` 之后立即调用 `std::process::exit(0)` 会强杀正在 flush
/// 的后台线程，导致磁盘文件损坏、重启后数据丢失。
pub struct EventStore {
    mem: Mutex<Connection>,
    disk_path: PathBuf,
    /// 单调递增的活动序号。每次 insert 调用 fetch_add(1)，作为 last_activity 写入。
    /// 启动时从 MAX(last_activity)+1 开始，保证跨重启的排序正确。
    activity_counter: AtomicI64,
    /// 后台落盘线程的关闭标志。设为 true 后线程在下一次循环检查时退出。
    shutdown: AtomicBool,
    /// 后台落盘线程的 JoinHandle。shutdown() 里 join 它以确保线程完全退出
    /// 后才做最终 flush，避免和 std::process::exit 竞争。
    flush_thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl EventStore {
    /// 打开（或新建）磁盘库：如果磁盘上已经有上次运行留下的历史数据，先整体拷回内存库，
    /// 这样重启后界面上还能看到之前的记录；然后启动后台定期落盘线程。
    ///
    /// schema 迁移：通过 PRAGMA user_version 检测旧库。旧版（v0）的表没有 UNIQUE(path)
    /// 约束、没有 count/first_seen/last_activity 列，里面已经累积了重复路径——这种库
    /// 直接 DROP TABLE 重建，旧数据丢弃（ETW 事件本来就是临时的，丢一次历史可接受）。
    /// 第一次落盘后磁盘库会被覆盖成新 schema + user_version=1，后续重启不再迁移。
    pub fn open(disk_path: PathBuf, flush_interval: Duration) -> anyhow::Result<Arc<Self>> {
        let mut mem_conn = Connection::open_in_memory()?;

        if disk_path.exists() {
            // 先把磁盘库整体拷回内存，mem_conn 现在带着磁盘库的 schema + user_version + 数据。
            // Backup::new 借走 mem_conn 的可变借用，必须放在独立作用域里，run_to_completion
            // 完成后 backup 被 drop、可变借用才释放，后面才能继续用 mem_conn 做迁移检查。
            {
                let disk_conn = Connection::open(&disk_path)?;
                disk_conn.busy_timeout(Duration::from_secs(5))?;
                let backup = Backup::new(&disk_conn, &mut mem_conn)?;
                backup.run_to_completion(100, Duration::from_millis(0), None)?;
                // backup + disk_conn 在这里 drop
            }

            let version: i64 =
                mem_conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
            if version < SCHEMA_VERSION {
                eprintln!(
                    "[EventStore] 旧 schema (user_version={version})，DROP TABLE 重建为 v{SCHEMA_VERSION}，旧数据丢弃"
                );
                mem_conn.execute("DROP TABLE IF EXISTS file_events", [])?;
                mem_conn.execute_batch(SCHEMA)?;
                mem_conn.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION}"))?;
            } else {
                // 已经是新 schema，CREATE TABLE IF NOT EXISTS 是 no-op，幂等
                mem_conn.execute_batch(SCHEMA)?;
            }
        } else {
            // 磁盘文件不存在：内存库建新 schema，磁盘也建一份保证第一次落盘时文件有效
            mem_conn.execute_batch(SCHEMA)?;
            mem_conn.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION}"))?;
            let disk_conn = Connection::open(&disk_path)?;
            disk_conn.busy_timeout(Duration::from_secs(5))?;
            disk_conn.execute_batch(SCHEMA)?;
            disk_conn.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION}"))?;
        }

        // activity_counter 从 MAX(last_activity)+1 起步，保证跨重启 last_activity 仍然单调
        let init_counter: i64 = mem_conn.query_row(
            "SELECT COALESCE(MAX(last_activity), 0) + 1 FROM file_events",
            [],
            |r| r.get(0),
        )?;

        let store = Arc::new(Self {
            mem: Mutex::new(mem_conn),
            disk_path: disk_path.clone(),
            activity_counter: AtomicI64::new(init_counter),
            shutdown: AtomicBool::new(false),
            flush_thread: Mutex::new(None),
        });

        if flush_interval > Duration::ZERO {
            let store_clone = store.clone();
            let handle = std::thread::spawn(move || loop {
                std::thread::sleep(flush_interval);
                // 先检查 shutdown 标志，设置了就立刻退出，不再做 flush
                if store_clone.shutdown.load(Ordering::Relaxed) {
                    break;
                }
                if let Err(e) = store_clone.flush_to_disk() {
                    store_clone.log_error(&format!("后台落盘失败: {e:?}"));
                }
            });
            *store.flush_thread.lock() = Some(handle);
        }

        Ok(store)
    }

    /// 停止后台落盘线程并等待其完全退出。
    ///
    /// 必须在 `on_exit` 里、最终 `flush_to_disk` 之前调用。否则 eframe 在
    /// `on_exit` 之后立即 `std::process::exit(0)`，会强杀正在 flush 的后台线程，
    /// 可能导致磁盘 SQLite 文件写了一半（页损坏），重启后加载不到数据。
    ///
    /// 调用此方法后后台线程保证已退出，后续的 `flush_to_disk` 不会和任何线程竞争。
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.flush_thread.lock().take() {
            // join 等待线程退出。线程可能正在 flush（持有 mem_conn 锁），
            // join 不会死锁——它只是等线程结束，不锁 mem_conn。
            if let Err(e) = handle.join() {
                self.log_error(&format!("后台落盘线程 join 失败: {e:?}"));
            }
        }
    }

    /// 把错误信息追加写入磁盘库同目录的 `.log` 文件。
    /// GUI 应用没有控制台，`eprintln!` 输出用户看不到，必须写文件才能诊断问题。
    fn log_error(&self, msg: &str) {
        let log_path = self.disk_path.with_extension("log");
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        let line = format!("[{timestamp}] {msg}\n");
        // 追加写入，失败就放弃（不能因为日志写不了就 panic）
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .and_then(|mut f| std::io::Write::write_all(&mut f, line.as_bytes()));
        // 同时也 eprintln，有控制台的情况下能看到
        eprintln!("[EventStore] {msg}");
    }

    /// 插入一条事件。同一个 path 在表里只允许一行——重复路径触发的 ON CONFLICT
    /// 会把 count + 1，并更新 last_activity / time_str / pid / process_name /
    /// operation / detail 到本次最新的值。first_seen 在首次插入时定下来，之后不变。
    ///
    /// 裁剪用 last_activity 而不是 seq：seq 在 ON CONFLICT UPDATE 时不会变化（PRIMARY
    /// KEY AUTOINCREMENT 不被 ON CONFLICT 改写），如果按 seq 裁剪会把"很早插入但
    /// 最近还在被访问"的热点路径误删。last_activity 是 Rust 侧用 AtomicI64 维护的
    /// 单调计数器，每次插入都 fetch_add，反映真实最近活跃度。
    pub fn insert(&self, ev: &NewFileEvent) -> anyhow::Result<()> {
        let activity = self.activity_counter.fetch_add(1, Ordering::Relaxed);
        let conn = self.mem.lock();
        conn.execute(
            "INSERT INTO file_events
                (last_activity, time_str, pid, process_name, operation, path, detail, count, first_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?2)
             ON CONFLICT(path) DO UPDATE SET
                last_activity = excluded.last_activity,
                time_str      = excluded.time_str,
                pid           = excluded.pid,
                process_name  = excluded.process_name,
                operation     = excluded.operation,
                detail        = excluded.detail,
                count         = file_events.count + 1",
            params![
                activity,
                ev.time_str,
                ev.pid,
                ev.process_name,
                ev.operation,
                ev.path,
                ev.detail
            ],
        )?;

        // 按行数裁剪：当唯一路径数超过 MAX_ROWS 时，只保留最近活跃的 MAX_ROWS 行。
        //
        // 旧实现按 last_activity 跨度裁剪（DELETE WHERE last_activity <= MAX-20000），
        // 但 last_activity 每次 insert 都 +1（含重复路径的 ON CONFLICT），高频 ETW
        // 事件下几分钟 activity_counter 就涨到 20000+，导致全表只有几百行时也大量
        // 删除"不活跃"路径——total_count 反常下降。改为按行数裁剪后，行数不超过
        // MAX_ROWS 就不会删任何东西。
        //
        // LIMIT -1 OFFSET ?1：跳过最近活跃的 MAX_ROWS 行，删除其余所有行。
        // 行数 <= MAX_ROWS 时 OFFSET 取不到行，DELETE 不删任何东西。
        conn.execute(
            "DELETE FROM file_events
             WHERE seq IN (
                 SELECT seq FROM file_events
                 ORDER BY last_activity DESC
                 LIMIT -1 OFFSET ?1
             )",
            params![MAX_ROWS],
        )?;
        Ok(())
    }

    /// 最近 N 条，按最后活跃时间倒序（最近被访问的路径在最前面）
    pub fn recent(&self, limit: i64) -> anyhow::Result<Vec<FileEvent>> {
        let conn = self.mem.lock();
        let mut stmt = conn.prepare(
            "SELECT seq, last_activity, time_str, pid, process_name, operation, path, detail, count, first_seen
             FROM file_events ORDER BY last_activity DESC LIMIT ?1",
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
            "SELECT seq, last_activity, time_str, pid, process_name, operation, path, detail, count, first_seen
             FROM file_events
             WHERE path LIKE ?1 ESCAPE '\\'
                OR process_name LIKE ?1 ESCAPE '\\'
                OR operation LIKE ?1 ESCAPE '\\'
             ORDER BY last_activity DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![pattern, limit], row_to_event)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn count(&self) -> anyhow::Result<i64> {
        let conn = self.mem.lock();
        Ok(conn.query_row("SELECT COUNT(*) FROM file_events", [], |r| r.get(0))?)
    }

    /// 把内存库整体同步覆盖到磁盘文件。
    ///
    /// 磁盘连接设置了 `busy_timeout(5000)`，遇到文件锁（杀毒软件扫描、另一进程
    /// 打开等）时会等待最多 5 秒而不是立即报 `SQLITE_BUSY` 错误。
    pub fn flush_to_disk(&self) -> anyhow::Result<()> {
        let mem_conn = self.mem.lock();
        let mut disk_conn = Connection::open(&self.disk_path)?;
        // 设置 busy_timeout：如果磁盘文件被其他进程/线程锁住（杀毒软件扫描、
        // SQLite 查看器等），等待最多 5 秒而不是立即失败。
        disk_conn.busy_timeout(Duration::from_secs(5))?;
        let backup = Backup::new(&mem_conn, &mut disk_conn)?;
        // sleep_ms 设为 0：我们已经在 mem_conn 锁的保护下，不需要让出给其他线程。
        // 原来的 5ms sleep 只是在分页之间让出 CPU，但持锁睡眠反而会阻塞 insert 更久。
        backup.run_to_completion(100, Duration::from_millis(0), None)?;
        // Rust 按逆序 drop：backup 先 drop（释放对 disk_conn 的借用），
        // 然后 disk_conn drop（SQLite 关闭连接并 flush 页缓存到磁盘），
        // 最后 mem_conn 的 MutexGuard drop（释放锁）。
        Ok(())
    }
}

fn row_to_event(row: &rusqlite::Row) -> rusqlite::Result<FileEvent> {
    Ok(FileEvent {
        seq: row.get(0)?,
        last_activity: row.get(1)?,
        time_str: row.get(2)?,
        pid: row.get(3)?,
        process_name: row.get(4)?,
        operation: row.get(5)?,
        path: row.get(6)?,
        detail: row.get(7)?,
        count: row.get(8)?,
        first_seen: row.get(9)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn make_event(path: &str) -> NewFileEvent {
        NewFileEvent {
            time_str: "2026-01-01 00:00:00".to_string(),
            pid: 1234,
            process_name: "test.exe".to_string(),
            operation: "open".to_string(),
            path: path.to_string(),
            detail: String::new(),
        }
    }

    fn test_db_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "evemon_test_{}_{}.sqlite3",
            std::process::id(),
            name
        ))
    }

    /// 基础复现测试：写入 → 落盘 → 重新打开 → 数据应该在。
    #[test]
    fn roundtrip_persist_and_reload() {
        let tmp = test_db_path("basic");
        let _ = std::fs::remove_file(&tmp);

        {
            let store = EventStore::open(tmp.clone(), Duration::ZERO).unwrap();
            store.insert(&make_event("C:\\foo\\bar.txt")).unwrap();
            store.insert(&make_event("C:\\foo\\baz.txt")).unwrap();
            assert_eq!(store.count().unwrap(), 2, "插入后应有 2 条");
            store.flush_to_disk().unwrap();
        }

        {
            let store = EventStore::open(tmp.clone(), Duration::ZERO).unwrap();
            assert_eq!(
                store.count().unwrap(),
                2,
                "重新打开后应该还能看到 2 条数据"
            );
        }

        let _ = std::fs::remove_file(&tmp);
    }

    /// 测试带后台线程的完整生命周期：open(有后台线程) → insert → shutdown → flush → reopen。
    /// 这模拟真实 App 的退出流程：on_exit 调 shutdown() 停后台线程，再 flush_to_disk。
    #[test]
    fn flush_with_background_thread_then_shutdown() {
        let tmp = test_db_path("bgthread");
        let _ = std::fs::remove_file(&tmp);

        {
            // 启动带后台落盘线程的 store（100ms 间隔）
            let store = EventStore::open(tmp.clone(), Duration::from_millis(100)).unwrap();
            store.insert(&make_event("C:\\alpha.txt")).unwrap();
            store.insert(&make_event("C:\\beta.txt")).unwrap();

            // 等后台线程至少跑一次 flush
            std::thread::sleep(Duration::from_millis(300));

            // 模拟 on_exit：先 shutdown 停后台线程，再最终 flush
            store.shutdown();
            store.flush_to_disk().unwrap();
        }

        {
            let store = EventStore::open(tmp.clone(), Duration::ZERO).unwrap();
            let count = store.count().unwrap();
            assert_eq!(count, 2, "带后台线程的 store 退出后数据应该在，但只有 {count}");
        }

        let _ = std::fs::remove_file(&tmp);
    }

    /// 测试多次 flush 到同一个文件（覆盖写）。
    /// 每次 flush 都用 Backup API 覆盖磁盘库，验证不会因目标非空而失败或损坏。
    #[test]
    fn multiple_flushes_to_same_file() {
        let tmp = test_db_path("multiflush");
        let _ = std::fs::remove_file(&tmp);

        {
            let store = EventStore::open(tmp.clone(), Duration::ZERO).unwrap();

            // 第一次 flush：2 条
            store.insert(&make_event("C:\\first.txt")).unwrap();
            store.insert(&make_event("C:\\second.txt")).unwrap();
            store.flush_to_disk().unwrap();

            // 第二次 flush：增加第 3 条，覆盖磁盘
            store.insert(&make_event("C:\\third.txt")).unwrap();
            store.flush_to_disk().unwrap();

            // 第三次 flush：更新 first.txt 的 count
            store.insert(&make_event("C:\\first.txt")).unwrap();
            store.flush_to_disk().unwrap();
        }

        {
            let store = EventStore::open(tmp.clone(), Duration::ZERO).unwrap();
            assert_eq!(store.count().unwrap(), 3, "应有 3 条唯一路径");
            let rows = store.recent(100).unwrap();
            let first = rows.iter().find(|e| e.path == "C:\\first.txt").unwrap();
            assert_eq!(first.count, 2, "first.txt 的 count 应该是 2（被 insert 了两次）");
        }

        let _ = std::fs::remove_file(&tmp);
    }

    /// 测试 shutdown 后再调用 flush_to_disk 不会出问题（模拟 on_exit 的完整流程）。
    #[test]
    fn shutdown_then_flush_is_safe() {
        let tmp = test_db_path("shutdown_flush");
        let _ = std::fs::remove_file(&tmp);

        {
            let store = EventStore::open(tmp.clone(), Duration::from_millis(50)).unwrap();
            store.insert(&make_event("C:\\data.txt")).unwrap();

            // 等后台线程 flush 一次
            std::thread::sleep(Duration::from_millis(150));

            // shutdown 后再 flush —— 不应该 panic 或死锁
            store.shutdown();
            store.flush_to_disk().unwrap();

            // 再次 shutdown 是 no-op（handle 已经 take 了）
            store.shutdown();
        }

        {
            let store = EventStore::open(tmp.clone(), Duration::ZERO).unwrap();
            assert_eq!(store.count().unwrap(), 1, "数据应该在");
        }

        let _ = std::fs::remove_file(&tmp);
    }

    /// 复现"total_count 反常下降"的 bug：少量唯一路径 + 高频重复访问。
    ///
    /// 旧裁剪逻辑按 last_activity 跨度删（DELETE WHERE last_activity <= MAX-20000），
    /// 但 last_activity 每次 insert 都 +1（含重复路径），高频事件下 activity_counter
    /// 很快超过 MAX_ROWS，导致全表才几十行时也把"不活跃"路径删掉。
    ///
    /// 修复后按行数裁剪：行数 <= MAX_ROWS 时一条都不删。
    #[test]
    fn count_does_not_decrease_with_high_freq_repeats() {
        let tmp = test_db_path("highfreq");
        let _ = std::fs::remove_file(&tmp);

        let store = EventStore::open(tmp.clone(), Duration::ZERO).unwrap();

        // 插入 5 个唯一路径
        let paths = ["C:\\a.txt", "C:\\b.txt", "C:\\c.txt", "C:\\d.txt", "C:\\e.txt"];
        for p in &paths {
            store.insert(&make_event(p)).unwrap();
        }
        assert_eq!(store.count().unwrap(), 5, "初始 5 条唯一路径");

        // 对 e.txt 高频重复插入，让 activity_counter 远超 MAX_ROWS(20000)
        // 旧逻辑此时会把 a/b/c/d（last_activity 很小）全部删掉
        for _ in 0..(MAX_ROWS + 10) {
            store.insert(&make_event("C:\\e.txt")).unwrap();
        }

        let count = store.count().unwrap();
        assert_eq!(
            count, 5,
            "高频重复插入后唯一路径数应仍为 5，但实际为 {count}（旧裁剪 bug 会导致路径被误删）"
        );

        // 验证最早插入的 a.txt 还在
        let rows = store.recent(100).unwrap();
        let still_has_a = rows.iter().any(|e| e.path == "C:\\a.txt");
        assert!(still_has_a, "a.txt 应该还在，不应被裁剪删掉");

        let _ = std::fs::remove_file(&tmp);
    }

    /// 测试超过 MAX_ROWS 时确实会裁剪到 MAX_ROWS 行（保留最近活跃的）。
    #[test]
    fn trims_to_max_rows_when_exceeded() {
        let tmp = test_db_path("trim");
        let _ = std::fs::remove_file(&tmp);

        let store = EventStore::open(tmp.clone(), Duration::ZERO).unwrap();

        // 插入 MAX_ROWS + 50 个唯一路径，按顺序插入
        // 最早插入的 50 个应该被裁剪掉（last_activity 最小）
        for i in 0..(MAX_ROWS + 50) {
            let path = format!("C:\\file_{i}.txt");
            store.insert(&make_event(&path)).unwrap();
        }

        let count = store.count().unwrap();
        assert_eq!(
            count, MAX_ROWS,
            "插入 {} 条唯一路径后应裁剪到 {} 条，实际 {count}",
            MAX_ROWS + 50,
            MAX_ROWS
        );

        // 最早的 50 个应该被删了，file_0 ~ file_49 不应存在
        let rows = store.recent(MAX_ROWS + 100).unwrap();
        let has_file_0 = rows.iter().any(|e| e.path == "C:\\file_0.txt");
        assert!(!has_file_0, "file_0.txt 应该已被裁剪删除");
        // file_50 及之后的应该还在
        let has_file_50 = rows.iter().any(|e| e.path == "C:\\file_50.txt");
        assert!(has_file_50, "file_50.txt 应该保留");

        let _ = std::fs::remove_file(&tmp);
    }
}
