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

- `src/etw.rs` —— ETW 内核追踪的核心逻辑：
  - 只需启用一个 `FILE_INIT_IO_PROVIDER`（对应 `EVENT_TRACE_FLAG_FILE_IO_INIT`），
    就同时覆盖 Create（真正的打开事件）、Read/Write、Cleanup/Close/Flush、
    SetInfo/Delete/Rename、DirEnum 等事件类型。
  - Create 事件自带路径（字段名是 `OpenPath`，容易和另一个不相关的 `FileName`
    字段搞混）。其余事件只带一个 `FileObject` 指针，需要靠 Create 事件建立的
    `FileObject -> 路径` 映射表反查，这是 Process Monitor 内部的做法。
  - 用 `sysinfo` 定期刷新进程表，把事件里的 pid 翻译成进程名。
- `src/main.rs` —— egui GUI：顶部搜索框实时模糊过滤（`fuzzy-matcher`），表格展示
  时间/PID/进程名/操作类型/路径/详情（读写字节数、偏移量），支持暂停/清空。

## 运行要求

- **必须以管理员身份运行**，否则启动 ETW 会话会报权限错误。
- 全系统同一时间只能有一个 "NT Kernel Logger" 会话，如果同时开着 Process Monitor
  / xperf 之类工具会冲突。

## 本地编译运行

```powershell
cargo run --release
```

## 已知限制

- 追踪启动前就已经打开的文件，`FileObject -> 路径` 映射表里没有记录，对应的
  Read/Write/Rename 事件会显示 `<未知文件 fobj=0x..>`。正经实现需要在追踪启动时
  再做一次 rundown 枚举去补这个洞，目前还没做。
- ETW 事件在系统压力大、缓冲区满时可能会丢，属于 ETW 机制本身的限制。
- 这个仓库里的 GUI/ETW 代码没有在 Windows 上实机编译验证过（沙盒环境是 Linux，
  且 `ferrisetw` 本身没有跨平台 cfg 隔离，根本编译不了），所有 API 用法是对照
  `ferrisetw`/`sysinfo` 源码逐个核实字段名和签名写的。第一次真实编译建议看
  `.github/workflows/build.yml` 跑出来的 Actions 日志，或者本地 `cargo check`。
