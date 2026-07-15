# EveMon

实时文件打开监控工具（"监控版的 Everything"）。基于 Rust + egui，用 ETW（Event
Tracing for Windows）内核日志实时捕获文件打开/读写/关闭/改名/删除事件，界面上
可以像 Everything 那样输入关键字实时过滤。

## 背景

传统的 [Sysinternals FileMon](https://learn.microsoft.com/en-us/sysinternals/)
要做到"实时监控文件活动"必须自己写一个内核过滤驱动，hook 每一个 IRP。现在 Windows
本身通过 ETW 把这套数据暴露了出来（NT Kernel Logger 的 FileIo Provider），不需要
自定义驱动，Process Monitor 内部也是这么做的。

## 架构

- `src/store.rs` —— 事件存储：内存 SQLite（承担 ETW 回调的高频写入）+ 后台线程按
  固定频率（默认 5 秒）用 SQLite 的 Online Backup API 把内存库整体同步到磁盘文件
  `evemon_events.sqlite3`。这部分逻辑在 Linux 沙盒里**真实编译、真实跑通过**：写入、
  SQL 粗过滤（LIKE）+ Rust 侧 fuzzy 精排、重启后从磁盘读回历史、自动落盘，都单独
  验证过，不是凭空写的。本文件还定义了 `FilterConfig`（白/黑名单 + case-insensitive
  子串匹配），同时供 ETW 抓取层和 UI 显示层复用。
  - **路径去重**：表里 `path` 是 UNIQUE 的，同一个路径只允许一行。重复打开同一个
    文件触发的 `ON CONFLICT(path) DO UPDATE` 只累加 `count`、把 `last_activity` /
    `time_str` / `pid` / `process_name` / `operation` / `detail` 更新为本次最新的值，
    `first_seen` 保留首次见到的时间不变。表多了一列 `count` 显示该路径累计被命中的
    次数，排序按 `last_activity DESC`（最近活跃的路径在最前面）。
  - schema 版本用 `PRAGMA user_version` 持久化。检测到旧版（无 UNIQUE 约束、无
    `count`/`first_seen`/`last_activity` 列）会 `DROP TABLE` 重建，旧数据丢弃
    （ETW 事件本来就是临时的，丢一次历史可接受）。
- `src/etw.rs` —— ETW 内核追踪的核心逻辑：
  - 只需启用一个 `FILE_INIT_IO_PROVIDER`（对应 `EVENT_TRACE_FLAG_FILE_IO_INIT`），
    就同时覆盖 Create（真正的打开事件）、Read/Write、Cleanup/Close/Flush、
    SetInfo/Delete/Rename、DirEnum 等事件类型。
  - Create 事件自带路径（字段名是 `OpenPath`，容易和另一个不相关的 `FileName`
    字段搞混）。其余事件只带一个 `FileObject` 指针，需要靠 Create 事件建立的
    `FileObject -> 路径` 映射表反查，这是 Process Monitor 内部的做法。
  - 用 `sysinfo` 定期刷新进程表，把事件里的 pid 翻译成进程名。
  - 回调拿到进程名后立即查 `Arc<RwLock<FilterConfig>>`，命中的进程直接 return，
    不走 FileObject 映射表也不写库，省内存也省 SQLite 写入压力。
  - ETW 给的 `OpenPath` 是 NT 内核路径（`\Device\HarddiskVolume9\...`），回调里
    用 `GetLogicalDriveStringsW` + `QueryDosDeviceW` 建立的反向映射表把它翻译成
    Win32 路径（`C:\...`）。映射表启动时建一次，后台每 60 秒刷新一次（应对 U 盘
    热插/网络盘挂载）。找不到匹配项时（例如 `\Device\LanmanRedirector` 网络重定向器
    路径）原样保留，不会替换。
- `src/main.rs` —— egui GUI：
  - 顶部搜索框实时模糊过滤（`fuzzy-matcher`），覆盖路径/进程名/操作/详情；
  - 可折叠"抓取层进程过滤"面板，支持白名单/黑名单两种模式，每行一个进程名片段，
    case-insensitive 子串匹配（例如 `chrome` 匹配 `chrome.exe`/`Chrome.EXE`，
    但不匹配 `chromium.exe`）。点"应用"即时同步到 ETW 回调，不需要重启 trace；
  - 表格展示 时间/PID/进程名/操作类型/路径/详情（读写字节数、偏移量），支持暂停/清空。

## 运行要求

- **必须以管理员身份运行**，否则启动 ETW 会话会报权限错误。
- 全系统同一时间只能有一个 "NT Kernel Logger" 会话，如果同时开着 Process Monitor
  / xperf 之类工具会冲突。
- 界面文本（"搜索"/"暂停"/"应用过滤" 等）依赖 Windows 系统中文字体；程序启动时会
  按顺序尝试 `C:/Windows/Fonts/` 下的 `msyh.ttf`/`msyh.ttc`/`msyhl.ttc`/`simhei.ttf`/
  `simsun.ttc`/`SourceHanSansSC-Regular.otf`，第一个能读到的就注入 egui 字体表。
  都读不到时中文会退化成方块（tofu），但程序仍能运行。

## 本地编译运行

```powershell
cargo run --release
```

## 已知限制

- 追踪启动前就已经打开的文件，`FileObject -> 路径` 映射表里没有记录，对应的
  Read/Write/Rename 事件会显示 `<未知文件 fobj=0x..>`。正经实现需要在追踪启动时
  再做一次 rundown 枚举去补这个洞，目前还没做。
- ETW 事件在系统压力大、缓冲区满时可能会丢，属于 ETW 机制本身的限制。
- `src/store.rs`（SQLite 内存库 + 定期落盘）**在 Linux 沙盒里真实编译并跑通过**，
  逻辑是可信的。`src/etw.rs` 和 `src/main.rs`（GUI）**没有**在 Windows 上实机编译
  验证过——沙盒是 Linux，且 `ferrisetw` 本身没有跨平台 cfg 隔离，根本编译不了。
  这两部分的 API 用法是对照 `ferrisetw`/`eframe`/`sysinfo` 源码逐个核实字段名和
  签名写的。第一次真实编译建议看 `.github/workflows/build.yml` 跑出来的 Actions
  日志，或者本地 `cargo check`。
