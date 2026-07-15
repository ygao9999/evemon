mod etw;
mod store;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use eframe::egui;
use fuzzy_matcher::skim::SkimMatcherV2;
use fuzzy_matcher::FuzzyMatcher;

use store::{EventStore, FileEvent};

const MAX_DISPLAY_ROWS: i64 = 5000;
/// 内存库同步到磁盘文件的频率——"以一定的频率写入硬盘"
const FLUSH_INTERVAL: Duration = Duration::from_secs(5);
const DISK_DB_FILENAME: &str = "evemon_events.sqlite3";

struct EveMonApp {
    store: Arc<EventStore>,
    _trace: ferrisetw::trace::KernelTrace, // 持有它，drop 就会停止 ETW 追踪
    query: String,
    matcher: SkimMatcherV2,
    paused: bool,
    frozen_rows: Vec<FileEvent>,
    total_count: i64,
}

impl EveMonApp {
    fn new() -> anyhow::Result<Self> {
        let disk_path = PathBuf::from(DISK_DB_FILENAME);
        let store = EventStore::open(disk_path, FLUSH_INTERVAL)?;
        let trace = etw::spawn_etw_capture(store.clone())?;
        Ok(Self {
            store,
            _trace: trace,
            query: String::new(),
            matcher: SkimMatcherV2::default(),
            paused: false,
            frozen_rows: Vec::new(),
            total_count: 0,
        })
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

        // 不在暂停状态时，每帧都重新查询一次（下拉/输入变化，或者纯粹是新事件写入后自动刷新）
        if !self.paused {
            self.refresh();
        } else if query_changed {
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
        Box::new(move |_cc| {
            let app = EveMonApp::new().expect(
                "启动失败：请确认以管理员身份运行 ETW 追踪，且当前目录可写（用于 SQLite 落盘文件）",
            );
            Ok(Box::new(app))
        }),
    )
}
