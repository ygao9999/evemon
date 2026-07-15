mod etw;

use std::sync::Arc;

use eframe::egui;
use fuzzy_matcher::skim::SkimMatcherV2;
use fuzzy_matcher::FuzzyMatcher;

use etw::{EventLog, FileEvent};

const MAX_DISPLAY_ROWS: usize = 5000;

struct EveMonApp {
    log: Arc<EventLog>,
    _trace: ferrisetw::trace::KernelTrace, // 持有它，drop 就会停止 ETW 追踪
    query: String,
    matcher: SkimMatcherV2,
    paused: bool,
    frozen_snapshot: Vec<FileEvent>,
}

impl EveMonApp {
    fn new() -> anyhow::Result<Self> {
        let log = Arc::new(EventLog::new());
        let trace = etw::spawn_etw_capture(log.clone())?;
        Ok(Self {
            log,
            _trace: trace,
            query: String::new(),
            matcher: SkimMatcherV2::default(),
            paused: false,
            frozen_snapshot: Vec::new(),
        })
    }

    /// 展示用的数据源：正常情况下每帧取一份最新快照（倒序，最新的在最上面）；
    /// 暂停时冻结在暂停那一刻的快照上，方便仔细看某一条记录，不被持续滚动的新事件打断。
    fn display_source(&mut self) -> &[FileEvent] {
        if !self.paused {
            self.frozen_snapshot = self.log.snapshot();
            self.frozen_snapshot.reverse();
        }
        &self.frozen_snapshot
    }
}

impl eframe::App for EveMonApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.request_repaint_after(std::time::Duration::from_millis(300));

        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label("🔍");
                ui.add(
                    egui::TextEdit::singleline(&mut self.query)
                        .desired_width(400.0)
                        .hint_text("按路径/进程名/操作类型过滤…"),
                );
                let pause_label = if self.paused { "▶ 继续" } else { "⏸ 暂停" };
                if ui.button(pause_label).clicked() {
                    self.paused = !self.paused;
                }
                if ui.button("🗑 清空").clicked() {
                    self.frozen_snapshot.clear();
                }
            });
            ui.add_space(4.0);
            ui.label(format!(
                "已捕获 {} 条文件打开事件{}",
                self.log.len(),
                if self.paused { " · 已暂停刷新" } else { "" }
            ));
            ui.add_space(6.0);
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            let query = self.query.clone();
            let matcher = &self.matcher;
            let source = self.display_source();

            let filtered: Vec<&FileEvent> = if query.is_empty() {
                source.iter().take(MAX_DISPLAY_ROWS).collect()
            } else {
                let mut scored: Vec<(i64, &FileEvent)> = source
                    .iter()
                    .filter_map(|e| {
                        let hay = format!(
                            "{} {} {} {}",
                            e.path, e.process_name, e.operation, e.detail
                        );
                        matcher.fuzzy_match(&hay, &query).map(|s| (s, e))
                    })
                    .collect();
                scored.sort_by(|a, b| b.0.cmp(&a.0));
                scored.truncate(MAX_DISPLAY_ROWS);
                scored.into_iter().map(|(_, e)| e).collect()
            };

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
                    body.rows(20.0, filtered.len(), |mut row| {
                        let ev = filtered[row.index()];
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
                "启动 ETW 追踪失败：请确认以管理员身份运行，且没有其他工具占用 NT Kernel Logger 会话",
            );
            Ok(Box::new(app))
        }),
    )
}
