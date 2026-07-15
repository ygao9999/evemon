//! 进程过滤 + 路径过滤的持久化配置。
//!
//! 配置文件是 JSON 格式，默认放在当前工作目录的 `evemon_config.json`。
//! 启动时 [`load`] 读取；UI 点"应用"时 [`save`] 写回。
//!
//! 文件结构示例：
//! ```json
//! {
//!   "process_filter": {
//!     "mode": "whitelist",
//!     "keywords": ["chrome", "firefox"]
//!   },
//!   "path_filter": {
//!     "mode": "off",
//!     "keywords": []
//!   }
//! }
//! ```
//!
//! 文件不存在 / 解析失败时返回默认值（两个 filter 都关闭，空关键字列表），
//! 不会 panic——这样首次运行或者用户手滑把文件改坏时程序还能起来。

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::store::{FilterConfig, PathFilterConfig};

/// 过滤模式——进程过滤和路径过滤共用。和 main.rs 里的 FilterMode 枚举一一对应，
/// 但这里用字符串而不是枚举，方便 serde_json 直接序列化为 "off"/"whitelist"/"blacklist"
/// 而不是 "Off"/"Whitelist"/"Blacklist"，文件可读性更好。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FilterModeDto {
    Off,
    Whitelist,
    Blacklist,
}

impl Default for FilterModeDto {
    fn default() -> Self {
        FilterModeDto::Off
    }
}

/// 一个过滤器的完整配置：模式 + 关键字列表。
/// 模式为 Off 时关键字列表被忽略；模式为 Whitelist 时 whitelist 生效，
/// Blacklist 时 blacklist 生效。简单起见只存一份 keywords，运行时按模式
/// 解释成 whitelist 或 blacklist。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FilterConfigDto {
    pub mode: FilterModeDto,
    pub keywords: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppConfig {
    pub process_filter: FilterConfigDto,
    pub path_filter: FilterConfigDto,
}

impl AppConfig {
    /// 把 DTO 转成 ETW 回调用的 FilterConfig。Off / 空 keywords 时返回空 config
    /// （等价于不过滤），避免回调里每次都查 mode。
    pub fn to_process_filter(&self) -> FilterConfig {
        let mut cfg = FilterConfig::default();
        match self.process_filter.mode {
            FilterModeDto::Off => {}
            FilterModeDto::Whitelist => {
                cfg.whitelist = trim_keywords(&self.process_filter.keywords);
            }
            FilterModeDto::Blacklist => {
                cfg.blacklist = trim_keywords(&self.process_filter.keywords);
            }
        }
        cfg
    }

    pub fn to_path_filter(&self) -> PathFilterConfig {
        let mut cfg = PathFilterConfig::default();
        match self.path_filter.mode {
            FilterModeDto::Off => {}
            FilterModeDto::Whitelist => {
                cfg.whitelist = trim_keywords(&self.path_filter.keywords);
            }
            FilterModeDto::Blacklist => {
                cfg.blacklist = trim_keywords(&self.path_filter.keywords);
            }
        }
        cfg
    }
}

/// 去掉每行首尾空白，丢掉空行，给 FilterConfig / PathFilterConfig 用
fn trim_keywords(raw: &[String]) -> Vec<String> {
    raw.iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// 从指定路径读取配置。文件不存在或解析失败时返回默认配置，并打印一行 stderr
/// 提示（用户能看到自己手滑改坏了 JSON）。其他 IO 错误（权限拒绝等）才往上抛。
pub fn load(path: &Path) -> anyhow::Result<AppConfig> {
    if !path.exists() {
        return Ok(AppConfig::default());
    }
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[config] 读取 {} 失败: {e}，使用默认配置", path.display());
            return Ok(AppConfig::default());
        }
    };
    match serde_json::from_str::<AppConfig>(&text) {
        Ok(cfg) => Ok(cfg),
        Err(e) => {
            eprintln!(
                "[config] 解析 {} 失败: {e}，使用默认配置（请检查 JSON 语法）",
                path.display()
            );
            Ok(AppConfig::default())
        }
    }
}

/// 把配置写回文件。用 `to_string_pretty` 输出带缩进的 JSON 方便用户编辑。
/// 写入是原子的——先写 `*.tmp` 再 rename，避免中途崩溃留下半截文件。
pub fn save(path: &Path, cfg: &AppConfig) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(cfg)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json + "\n")?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}
