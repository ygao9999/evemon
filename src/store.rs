use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, Ordering};
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
pub struct EventStore {
    mem: Mutex<Connection>,
    disk_path: PathBuf,
    /// 单调递增的活动序号。每次 insert 调用 fetch_add(1)，作为 last_activity 写入。
    /// 启动时从 MAX(last_activity)+1 开始，保证跨重启的排序正确。
    activity_counter: AtomicI64,
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
            disk_path,
            activity_counter: AtomicI64::new(init_counter),
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

        // 简单粗暴的裁剪：每次插入顺手删一次超出上限的老记录（按 last_activity 排）。
        // 在内存库里做这个非常快，量级到万级别没有可感知的开销。
        conn.execute(
            "DELETE FROM file_events
             WHERE last_activity <= (SELECT COALESCE(MAX(last_activity), 0) FROM file_events) - ?1",
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
