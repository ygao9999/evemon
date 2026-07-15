mod config;
mod etw;
mod store;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use eframe::egui;
use fuzzy_matcher::skim::SkimMatcherV2;
use fuzzy_matcher::FuzzyMatcher;
use parking_lot::RwLock;

use config::{AppConfig, FilterModeDto};
use store::{EventStore, FileEvent, FilterConfig, PathFilterConfig};

const MAX_DISPLAY_ROWS: i64 = 5000;
/// 内存库同步到磁盘文件的频率——"以一定的频率写入硬盘"
const FLUSH_INTERVAL: Duration = Duration::from_secs(5);
const DISK_DB_FILENAME: &str = "evemon_events.sqlite3";
/// 过滤配置文件名。和 DISK_DB_FILENAME 同目录（程序当前工作目录）。
const CONFIG_FILENAME: &str = "evemon_config.json";

/// 抓取层过滤的模式：白名单只放行命中的进程，黑名单排除命中的进程。
/// 关闭 = 两个列表都清空，等价于不过滤。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilterMode {
    Off,
    Whitelist,
    Blacklist,
}

impl FilterMode {
    fn label(self) -> &'static str {
        match self {
            FilterMode::Off => "关闭",
            FilterMode::Whitelist => "白名单",
            FilterMode::Blacklist => "黑名单",
        }
    }
}

struct EveMonApp {
    store: Arc<EventStore>,
    _trace: ferrisetw::trace::KernelTrace, // 持有它，drop 就会停止 ETW 追踪
    query: String,
    matcher: SkimMatcherV2,
    paused: bool,
    frozen_rows: Vec<FileEvent>,
    total_count: i64,

    /// ETW 抓取层共享的进程过滤配置——回调里读这个决定是否入库
    capture_filter: Arc<RwLock<FilterConfig>>,
    /// UI 里编辑中的进程过滤模式（点"应用"才同步到 capture_filter）
    filter_mode: FilterMode,
    /// UI 里编辑中的进程过滤关键字文本（每行一个进程名片段）
    filter_text: String,
    /// 上一次"应用"后的进程过滤摘要，给状态栏显示用
    filter_summary: String,

    /// ETW 抓取层共享的路径过滤配置——回调里 NT 翻译后读这个决定是否入库
    path_filter: Arc<RwLock<PathFilterConfig>>,
    /// UI 里编辑中的路径过滤模式
    path_filter_mode: FilterMode,
    /// UI 里编辑中的路径过滤关键字文本（每行一个路径片段）
    path_filter_text: String,
    /// 上一次"应用"后的路径过滤摘要
    path_filter_summary: String,

    /// 配置文件路径，点"应用"时把进程 + 路径过滤都写回这个文件
    config_path: PathBuf,

    /// 当前选中的行索引（在 frozen_rows 里的下标）。None 表示没选中。
    /// 点表格行选中，Esc 取消选中。选中行高亮显示，底部详情面板显示完整路径。
    selected_row: Option<usize>,
}

impl EveMonApp {
    fn new() -> anyhow::Result<Self> {
        let disk_path = PathBuf::from(DISK_DB_FILENAME);
        let store = EventStore::open(disk_path, FLUSH_INTERVAL)?;

        // 启动时读取配置文件（不存在则默认全 off）。
        // 读到的过滤配置立即同步到 ETW 回调共享的 FilterConfig / PathFilterConfig，
        // 同时初始化 UI 里的编辑状态，保证启动后界面显示和实际生效的过滤一致。
        let config_path = PathBuf::from(CONFIG_FILENAME);
        let cfg = config::load(&config_path)?;
        let proc_filter = cfg.to_process_filter();
        let path_filter_cfg = cfg.to_path_filter();

        let capture_filter: Arc<RwLock<FilterConfig>> =
            Arc::new(RwLock::new(proc_filter.clone()));
        let path_filter: Arc<RwLock<PathFilterConfig>> =
            Arc::new(RwLock::new(path_filter_cfg.clone()));
        let trace = etw::spawn_etw_capture(
            store.clone(),
            capture_filter.clone(),
            path_filter.clone(),
        )?;

        // 把配置文件里的模式 + keywords 同步到 UI 编辑状态
        let (filter_mode, filter_text, filter_summary) = dto_to_ui_state(
            cfg.process_filter.mode,
            &cfg.process_filter.keywords,
        );
        let (path_filter_mode, path_filter_text, path_filter_summary) = dto_to_ui_state(
            cfg.path_filter.mode,
            &cfg.path_filter.keywords,
        );

        Ok(Self {
            store,
            _trace: trace,
            query: String::new(),
            matcher: SkimMatcherV2::default(),
            paused: false,
            frozen_rows: Vec::new(),
            total_count: 0,
            capture_filter,
            filter_mode,
            filter_text,
            filter_summary,
            path_filter,
            path_filter_mode,
            path_filter_text,
            path_filter_summary,
            config_path,
            selected_row: None,
        })
    }

    /// 把 UI 里编辑中的进程过滤设置同步到 ETW 回调共享的 FilterConfig，
    /// 同时把路径过滤也一起同步，最后把完整 AppConfig 写回文件。
    /// 空行和首尾空白会被忽略；模式为 Off 时清空两个列表。
    /// glob 模式的关键字（含 * ? [ {）会被 FilterConfig::new 编译成 GlobMatcher。
    fn apply_filters_and_save(&mut self) {
        // 进程过滤
        let proc_keywords: Vec<String> = self
            .filter_text
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        {
            let new_cfg = match self.filter_mode {
                FilterMode::Off => {
                    self.filter_summary = "未启用".to_string();
                    FilterConfig::default()
                }
                FilterMode::Whitelist => {
                    self.filter_summary = if proc_keywords.is_empty() {
                        "白名单(空) → 实际不过滤".to_string()
                    } else {
                        format!("白名单: {} 个关键字", proc_keywords.len())
                    };
                    FilterConfig::new(proc_keywords.clone(), Vec::new())
                }
                FilterMode::Blacklist => {
                    self.filter_summary = if proc_keywords.is_empty() {
                        "黑名单(空) → 实际不过滤".to_string()
                    } else {
                        format!("黑名单: {} 个关键字", proc_keywords.len())
                    };
                    FilterConfig::new(Vec::new(), proc_keywords.clone())
                }
            };
            *self.capture_filter.write() = new_cfg;
        }

        // 路径过滤
        let path_keywords: Vec<String> = self
            .path_filter_text
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        {
            let new_cfg = match self.path_filter_mode {
                FilterMode::Off => {
                    self.path_filter_summary = "未启用".to_string();
                    PathFilterConfig::default()
                }
                FilterMode::Whitelist => {
                    self.path_filter_summary = if path_keywords.is_empty() {
                        "白名单(空) → 实际不过滤".to_string()
                    } else {
                        format!("白名单: {} 个关键字", path_keywords.len())
                    };
                    PathFilterConfig::new(path_keywords.clone(), Vec::new())
                }
                FilterMode::Blacklist => {
                    self.path_filter_summary = if path_keywords.is_empty() {
                        "黑名单(空) → 实际不过滤".to_string()
                    } else {
                        format!("黑名单: {} 个关键字", path_keywords.len())
                    };
                    PathFilterConfig::new(Vec::new(), path_keywords.clone())
                }
            };
            *self.path_filter.write() = new_cfg;
        }

        // 持久化。save 失败不阻塞 UI，只打 stderr 提示用户。
        let app_cfg = AppConfig {
            process_filter: config::FilterConfigDto {
                mode: FilterModeDto::from(self.filter_mode),
                keywords: proc_keywords,
            },
            path_filter: config::FilterConfigDto {
                mode: FilterModeDto::from(self.path_filter_mode),
                keywords: path_keywords,
            },
        };
        if let Err(e) = config::save(&self.config_path, &app_cfg) {
            eprintln!("[config] 保存 {} 失败: {e}", self.config_path.display());
        }
    }

    /// 正常情况下每帧重新查一次库（内存 SQLite，量级到万条查询很快）；
    /// 暂停时冻结在暂停那一刻，方便仔细看某一条记录，不被持续写入的新事件打断。
    fn refresh(&mut self) {
        if self.paused {
            return;
        }
        self.total_count = self.store.count().unwrap_or(0);

        if self.query.is_empty() {
            self.frozen_rows = self.store.recent(MAX_DISPLAY_ROWS).unwrap_or_default();
        } else {
            // 先用 SQL LIKE 做一次粗过滤缩小候选集，再用 fuzzy-matcher 精排，
            // 兼顾"库里几万条也查得快"和"排序看起来跟 Everything 一样顺眼"。
            // hay 里带上 count，这样搜"47"这种数字也能命中被打开 47 次的路径。
            let candidates = self
                .store
                .search(&self.query, MAX_DISPLAY_ROWS)
                .unwrap_or_default();
            let mut scored: Vec<(i64, FileEvent)> = candidates
                .into_iter()
                .filter_map(|e| {
                    let hay = format!(
                        "{} {} {} {} {}",
                        e.path, e.process_name, e.operation, e.detail, e.count
                    );
                    self.matcher
                        .fuzzy_match(&hay, &self.query)
                        .map(|s| (s, e))
                })
                .collect();
            scored.sort_by(|a, b| b.0.cmp(&a.0));
            self.frozen_rows = scored.into_iter().map(|(_, e)| e).collect();
        }

        // 选中行索引可能因为行数变化而越界，越界就清空。
        // 不在这里按 path 重新定位——refresh 每帧都跑，按 path 找回代价太高，
        // 而且连续刷新里 frozen_rows 顺序通常是稳定的，简单清空更可预测。
        if let Some(idx) = self.selected_row {
            if idx >= self.frozen_rows.len() {
                self.selected_row = None;
            }
        }
    }
}

impl eframe::App for EveMonApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.request_repaint_after(Duration::from_millis(300));

        let mut query_changed = false;
        let mut filter_applied = false;

        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label("🔍");
                let response = ui.add(
                    egui::TextEdit::singleline(&mut self.query)
                        .desired_width(400.0)
                        .hint_text("按路径/进程名/操作类型过滤…"),
                );
                if response.changed() {
                    query_changed = true;
                }
                let pause_label = if self.paused { "▶ 继续" } else { "⏸ 暂停" };
                if ui.button(pause_label).clicked() {
                    self.paused = !self.paused;
                }
                if ui.button("💾 立即落盘").clicked() {
                    if let Err(e) = self.store.flush_to_disk() {
                        eprintln!("手动落盘失败: {e:?}");
                    }
                }
            });
            ui.add_space(4.0);
            ui.label(format!(
                "内存库共 {} 条唯一路径 · 每 {} 秒自动同步到磁盘文件 {}{}",
                self.total_count,
                FLUSH_INTERVAL.as_secs(),
                DISK_DB_FILENAME,
                if self.paused { " · 已暂停刷新" } else { "" }
            ));
            ui.add_space(6.0);
        });

        // 抓取层进程过滤面板（可折叠），收起时只占一行标题
        egui::TopBottomPanel::top("capture_filter").show(ctx, |ui| {
            egui::CollapsingHeader::new(format!("🖥  抓取层进程过滤 [{}]", self.filter_summary))
                .default_open(false)
                .show(ui, |ui| {
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label("模式:");
                        for mode in [FilterMode::Off, FilterMode::Whitelist, FilterMode::Blacklist] {
                            ui.radio_value(&mut self.filter_mode, mode, mode.label());
                        }
                    });
                    ui.add_space(2.0);
                    ui.label("每行一个进程名关键字。不含通配符时为 case-insensitive 子串匹配（chrome 命中 chrome.exe）；含 * ? [ { 时为 glob（chrome.* 命中 chrome.exe）:");
                    ui.add(
                        egui::TextEdit::multiline(&mut self.filter_text)
                            .desired_width(f32::INFINITY)
                            .desired_rows(4)
                            .code_editor(),
                    );
                });
        });

        // 路径过滤面板（可折叠）
        egui::TopBottomPanel::top("path_filter").show(ctx, |ui| {
            egui::CollapsingHeader::new(format!("📁  抓取层路径过滤 [{}]", self.path_filter_summary))
                .default_open(false)
                .show(ui, |ui| {
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label("模式:");
                        for mode in [FilterMode::Off, FilterMode::Whitelist, FilterMode::Blacklist] {
                            ui.radio_value(&mut self.path_filter_mode, mode, mode.label());
                        }
                    });
                    ui.add_space(2.0);
                    ui.label("每行一个路径关键字。不含通配符时为 case-insensitive 子串匹配（D:\\work_flow 命中 D:\\work_flow\\拦截activity\\...）；含 * ? [ { 时为 glob（D:\\work_flow\\**\\*.java 命中任意深度的 .java）:");
                    ui.add(
                        egui::TextEdit::multiline(&mut self.path_filter_text)
                            .desired_width(f32::INFINITY)
                            .desired_rows(4)
                            .code_editor(),
                    );
                });
        });

        // 应用按钮独占一个小面板，避免两个折叠面板各自点"应用"都要重复同步
        egui::TopBottomPanel::top("filter_actions").show(ctx, |ui| {
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                if ui.button("✓ 应用过滤并保存配置").clicked() {
                    self.apply_filters_and_save();
                    filter_applied = true;
                }
                if ui.button("清空进程过滤").clicked() {
                    self.filter_text.clear();
                    self.filter_mode = FilterMode::Off;
                    self.apply_filters_and_save();
                    filter_applied = true;
                }
                if ui.button("清空路径过滤").clicked() {
                    self.path_filter_text.clear();
                    self.path_filter_mode = FilterMode::Off;
                    self.apply_filters_and_save();
                    filter_applied = true;
                }
                ui.add_space(12.0);
                ui.label(format!(
                    "进程[{}] · 路径[{}] · 配置文件: {}",
                    self.filter_summary, self.path_filter_summary, CONFIG_FILENAME
                ));
            });
            ui.add_space(2.0);
        });

        // 不在暂停状态时，每帧都重新查询一次（下拉/输入变化，或者纯粹是新事件写入后自动刷新）
        if !self.paused {
            self.refresh();
        } else if query_changed || filter_applied {
            self.refresh();
        }

        // Esc 取消选中行
        if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            self.selected_row = None;
        }

        // 底部详情面板——显示选中行的完整路径和详情。路径在表格里可能被截断，
        // 这里用全宽 Label + wrap，保证看得到完整内容。没选中时显示提示。
        egui::TopBottomPanel::bottom("detail").show(ctx, |ui| {
            ui.add_space(4.0);
            if let Some(idx) = self.selected_row {
                if let Some(ev) = self.frozen_rows.get(idx) {
                    ui.horizontal(|ui| {
                        ui.strong("选中:");
                        ui.label(format!(
                            "#{} · {} · PID {} · {} · count {}",
                            idx + 1,
                            ev.time_str,
                            ev.pid,
                            ev.process_name,
                            ev.count
                        ));
                    });
                    ui.horizontal(|ui| {
                        ui.strong("路径:");
                        ui.add(
                            egui::Label::new(&ev.path)
                                .wrap(true)
                                .selectable(true),
                        );
                    });
                    if !ev.detail.is_empty() {
                        ui.horizontal(|ui| {
                            ui.strong("详情:");
                            ui.label(&ev.detail);
                        });
                    }
                    ui.horizontal(|ui| {
                        if ui.button("📋 复制路径").clicked() {
                            ui.output_mut(|o| o.copied_text = ev.path.clone().into());
                        }
                        if ui.button("取消选中 (Esc)").clicked() {
                            self.selected_row = None;
                        }
                    });
                } else {
                    ui.label("（选中行已不存在）");
                }
            } else {
                ui.label("点击表格任意一行查看完整路径 · Esc 取消选中");
            }
            ui.add_space(4.0);
        });

        // 表格主体。行选中逻辑：
        // - row.set_selected(idx == self.selected_row) 让选中行高亮
        // - row.response().clicked() 点击时记录到局部 clicked_row
        // - 表格渲染完后再赋值给 self.selected_row，避免和 frozen_rows 的不可变借用冲突
        let mut clicked_row: Option<usize> = None;
        let selected = self.selected_row;

        egui::CentralPanel::default().show(ctx, |ui| {
            let rows = &self.frozen_rows;
            egui_extras::TableBuilder::new(ui)
                .striped(true)
                .column(egui_extras::Column::auto().at_least(90.0))  // 最后访问时间
                .column(egui_extras::Column::auto().at_least(60.0))  // 次数
                .column(egui_extras::Column::auto().at_least(70.0))  // PID
                .column(egui_extras::Column::auto().at_least(140.0)) // 进程名
                .column(egui_extras::Column::auto().at_least(90.0))  // 操作
                .column(egui_extras::Column::remainder())            // 路径
                .column(egui_extras::Column::auto().at_least(140.0)) // 详情
                .header(20.0, |mut header| {
                    header.col(|ui| { ui.strong("最后访问"); });
                    header.col(|ui| { ui.strong("次数"); });
                    header.col(|ui| { ui.strong("PID"); });
                    header.col(|ui| { ui.strong("进程"); });
                    header.col(|ui| { ui.strong("操作"); });
                    header.col(|ui| { ui.strong("路径"); });
                    header.col(|ui| { ui.strong("详情"); });
                })
                .body(|body| {
                    body.rows(20.0, rows.len(), |mut row| {
                        let idx = row.index();
                        row.set_selected(selected == Some(idx));
                        let ev = &rows[idx];
                        row.col(|ui| { ui.label(&ev.time_str); });
                        row.col(|ui| { ui.label(ev.count.to_string()); });
                        row.col(|ui| { ui.label(ev.pid.to_string()); });
                        row.col(|ui| { ui.label(&ev.process_name); });
                        row.col(|ui| { ui.label(&ev.operation); });
                        row.col(|ui| {
                            ui.add(
                                egui::Label::new(&ev.path)
                                    .truncate(),
                            );
                        });
                        row.col(|ui| { ui.label(&ev.detail); });
                        let resp = row.response();
                        if resp.clicked() {
                            clicked_row = Some(idx);
                        }
                    });
                });
        });

        // 表格渲染完后再赋值。再点一下选中的行 = 取消选中。
        if let Some(idx) = clicked_row {
            if self.selected_row == Some(idx) {
                self.selected_row = None;
            } else {
                self.selected_row = Some(idx);
            }
        }
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1100.0, 650.0]),
        ..Default::default()
    };

    eframe::run_native(
        "EveMon - 实时文件打开监控",
        options,
        Box::new(move |cc| {
            // egui 默认字体 (Hack/Ubuntu) 不含 CJK 字形，所有中文会显示为方块 (tofu)。
            // 必须在创建 App 前注入一份中文字体到 FontDefinitions，否则界面里
            // "搜索"/"暂停"/"应用过滤" 等所有中文标签全部看不见。
            load_cjk_fonts(&cc.egui_ctx);
            let app = EveMonApp::new().expect(
                "启动失败：请确认以管理员身份运行 ETW 追踪，且当前目录可写（用于 SQLite 落盘文件 + 配置文件）",
            );
            Ok(Box::new(app))
        }),
    )
}

/// 把配置文件里读出的 FilterModeDto + keywords 转成 UI 用的编辑状态：
/// (FilterMode 枚举, 多行文本, 摘要)。多行文本是 keywords 用 \n 拼起来。
fn dto_to_ui_state(
    mode: FilterModeDto,
    keywords: &[String],
) -> (FilterMode, String, String) {
    let ui_mode = match mode {
        FilterModeDto::Off => FilterMode::Off,
        FilterModeDto::Whitelist => FilterMode::Whitelist,
        FilterModeDto::Blacklist => FilterMode::Blacklist,
    };
    let text = keywords.join("\n");
    let summary = match mode {
        FilterModeDto::Off => "未启用".to_string(),
        FilterModeDto::Whitelist => {
            if keywords.is_empty() {
                "白名单(空) → 实际不过滤".to_string()
            } else {
                format!("白名单: {} 个关键字", keywords.len())
            }
        }
        FilterModeDto::Blacklist => {
            if keywords.is_empty() {
                "黑名单(空) → 实际不过滤".to_string()
            } else {
                format!("黑名单: {} 个关键字", keywords.len())
            }
        }
    };
    (ui_mode, text, summary)
}

impl From<FilterMode> for FilterModeDto {
    fn from(m: FilterMode) -> Self {
        match m {
            FilterMode::Off => FilterModeDto::Off,
            FilterMode::Whitelist => FilterModeDto::Whitelist,
            FilterMode::Blacklist => FilterModeDto::Blacklist,
        }
    }
}

/// 把 Windows 系统自带的中文字体注入 egui 的 FontDefinitions。
///
/// 选 Proportional family 的第一个字体改为 CJK——这样英文继续走默认字体（Hack），
/// 但 fallback 到 CJK 字体，中文能正常显示。Monospace family 把 CJK 追加到末尾做
/// fallback，避免完全替换掉等宽字体。
///
/// 依次尝试候选列表里第一个能读到的字体文件；都读不到（理论上 Windows 上不可能）
/// 就打印一行 stderr 警告然后放弃，界面会退化成方块。
fn load_cjk_fonts(ctx: &egui::Context) {
    const CANDIDATES: &[&str] = &[
        // 微软雅黑（Windows 7+ 系统默认中文字体）
        "C:/Windows/Fonts/msyh.ttf",
        "C:/Windows/Fonts/msyh.ttc",
        // 微软雅黑 Light
        "C:/Windows/Fonts/msyhl.ttc",
        // 黑体（旧系统 fallback）
        "C:/Windows/Fonts/simhei.ttf",
        // 宋体（ttc 集合，ab_glyph 取第 0 个 face）
        "C:/Windows/Fonts/simsun.ttc",
        // 思源黑体（部分新版 Windows 自带）
        "C:/Windows/Fonts/SourceHanSansSC-Regular.otf",
    ];

    for path in CANDIDATES {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let mut fonts = egui::FontDefinitions::default();
        fonts.font_data.insert(
            "cjk".to_owned(),
            egui::FontData::from_owned(bytes),
        );
        if let Some(fam) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
            fam.insert(0, "cjk".to_owned());
        }
        if let Some(fam) = fonts.families.get_mut(&egui::FontFamily::Monospace) {
            fam.push("cjk".to_owned());
        }
        ctx.set_fonts(fonts);
        return;
    }
    eprintln!("[font] 未在 C:/Windows/Fonts/ 下找到任何 CJK 字体，中文将显示为方块");
}
