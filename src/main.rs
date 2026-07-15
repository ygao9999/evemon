mod etw;
mod store;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use eframe::egui;
use fuzzy_matcher::skim::SkimMatcherV2;
use fuzzy_matcher::FuzzyMatcher;
use parking_lot::RwLock;

use store::{EventStore, FileEvent, FilterConfig};

const MAX_DISPLAY_ROWS: i64 = 5000;
/// 内存库同步到磁盘文件的频率——"以一定的频率写入硬盘"
const FLUSH_INTERVAL: Duration = Duration::from_secs(5);
const DISK_DB_FILENAME: &str = "evemon_events.sqlite3";

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

    /// ETW 抓取层共享的过滤配置——回调里读这个决定是否入库
    capture_filter: Arc<RwLock<FilterConfig>>,
    /// UI 里编辑中的过滤模式（点"应用"才同步到 capture_filter）
    filter_mode: FilterMode,
    /// UI 里编辑中的关键字文本（每行一个进程名片段）
    filter_text: String,
    /// 上一次"应用"后的过滤摘要，给状态栏显示用
    filter_summary: String,
}

impl EveMonApp {
    fn new() -> anyhow::Result<Self> {
        let disk_path = PathBuf::from(DISK_DB_FILENAME);
        let store = EventStore::open(disk_path, FLUSH_INTERVAL)?;
        let capture_filter: Arc<RwLock<FilterConfig>> =
            Arc::new(RwLock::new(FilterConfig::default()));
        let trace = etw::spawn_etw_capture(store.clone(), capture_filter.clone())?;
        Ok(Self {
            store,
            _trace: trace,
            query: String::new(),
            matcher: SkimMatcherV2::default(),
            paused: false,
            frozen_rows: Vec::new(),
            total_count: 0,
            capture_filter,
            filter_mode: FilterMode::Off,
            filter_text: String::new(),
            filter_summary: "未启用".to_string(),
        })
    }

    /// 把 UI 里编辑中的过滤设置同步到 ETW 回调共享的 FilterConfig。
    /// 空行和首尾空白会被忽略；模式为 Off 时清空两个列表。
    fn apply_capture_filter(&mut self) {
        let keywords: Vec<String> = self
            .filter_text
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let mut cfg = self.capture_filter.write();
        cfg.whitelist.clear();
        cfg.blacklist.clear();
        match self.filter_mode {
            FilterMode::Off => {
                self.filter_summary = "未启用".to_string();
            }
            FilterMode::Whitelist => {
                cfg.whitelist = keywords.clone();
                self.filter_summary = if keywords.is_empty() {
                    "白名单(空) → 实际不过滤".to_string()
                } else {
                    format!("白名单: {} 个关键字", keywords.len())
                };
            }
            FilterMode::Blacklist => {
                cfg.blacklist = keywords.clone();
                self.filter_summary = if keywords.is_empty() {
                    "黑名单(空) → 实际不过滤".to_string()
                } else {
                    format!("黑名单: {} 个关键字", keywords.len())
                };
            }
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
            return;
        }

        // 先用 SQL LIKE 做一次粗过滤缩小候选集，再用 fuzzy-matcher 精排，
        // 兼顾"库里几万条也查得快"和"排序看起来跟 Everything 一样顺眼"。
        let candidates = self
            .store
            .search(&self.query, MAX_DISPLAY_ROWS)
            .unwrap_or_default();
        let mut scored: Vec<(i64, FileEvent)> = candidates
            .into_iter()
            .filter_map(|e| {
                let hay = format!("{} {} {} {}", e.path, e.process_name, e.operation, e.detail);
                self.matcher
                    .fuzzy_match(&hay, &self.query)
                    .map(|s| (s, e))
            })
            .collect();
        scored.sort_by(|a, b| b.0.cmp(&a.0));
        self.frozen_rows = scored.into_iter().map(|(_, e)| e).collect();
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
                "内存库共 {} 条事件 · 每 {} 秒自动同步到磁盘文件 {}{}",
                self.total_count,
                FLUSH_INTERVAL.as_secs(),
                DISK_DB_FILENAME,
                if self.paused { " · 已暂停刷新" } else { "" }
            ));
            ui.add_space(6.0);
        });

        // 抓取层过滤面板（可折叠），收起时只占一行标题
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
                    ui.label("每行一个进程名片段（case-insensitive 子串匹配，如 chrome 匹配 chrome.exe）:");
                    ui.add(
                        egui::TextEdit::multiline(&mut self.filter_text)
                            .desired_width(f32::INFINITY)
                            .desired_rows(4)
                            .code_editor(),
                    );
                    ui.add_space(2.0);
                    ui.horizontal(|ui| {
                        if ui.button("✓ 应用过滤").clicked() {
                            self.apply_capture_filter();
                            filter_applied = true;
                        }
                        if ui.button("清空").clicked() {
                            self.filter_text.clear();
                            self.filter_mode = FilterMode::Off;
                            self.apply_capture_filter();
                            filter_applied = true;
                        }
                        ui.add_space(8.0);
                        ui.label(format!("当前生效: {}", self.filter_summary));
                    });
                    ui.add_space(4.0);
                });
        });

        // 不在暂停状态时，每帧都重新查询一次（下拉/输入变化，或者纯粹是新事件写入后自动刷新）
        if !self.paused {
            self.refresh();
        } else if query_changed || filter_applied {
            self.refresh();
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            let rows = &self.frozen_rows;
            egui_extras::TableBuilder::new(ui)
                .striped(true)
                .column(egui_extras::Column::auto().at_least(90.0)) // 时间
                .column(egui_extras::Column::auto().at_least(70.0)) // PID
                .column(egui_extras::Column::auto().at_least(140.0)) // 进程名
                .column(egui_extras::Column::auto().at_least(90.0)) // 操作
                .column(egui_extras::Column::remainder()) // 路径
                .column(egui_extras::Column::auto().at_least(140.0)) // 详情
                .header(20.0, |mut header| {
                    header.col(|ui| {
                        ui.strong("时间");
                    });
                    header.col(|ui| {
                        ui.strong("PID");
                    });
                    header.col(|ui| {
                        ui.strong("进程");
                    });
                    header.col(|ui| {
                        ui.strong("操作");
                    });
                    header.col(|ui| {
                        ui.strong("路径");
                    });
                    header.col(|ui| {
                        ui.strong("详情");
                    });
                })
                .body(|body| {
                    body.rows(20.0, rows.len(), |mut row| {
                        let ev = &rows[row.index()];
                        row.col(|ui| {
                            ui.label(&ev.time_str);
                        });
                        row.col(|ui| {
                            ui.label(ev.pid.to_string());
                        });
                        row.col(|ui| {
                            ui.label(&ev.process_name);
                        });
                        row.col(|ui| {
                            ui.label(&ev.operation);
                        });
                        row.col(|ui| {
                            ui.label(&ev.path);
                        });
                        row.col(|ui| {
                            ui.label(&ev.detail);
                        });
                    });
                });
        });
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
                "启动失败：请确认以管理员身份运行 ETW 追踪，且当前目录可写（用于 SQLite 落盘文件）",
            );
            Ok(Box::new(app))
        }),
    )
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
