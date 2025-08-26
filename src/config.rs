use std::env;
use std::time::Duration;

/// IP限流配置
#[derive(Clone, Debug)]
pub struct IPRateLimit {
    pub enabled: bool,         // 是否启用IP限流
    pub threshold: u64,        // 限流阈值（每秒数据包数）
    pub block_threshold: u64,  // 拒绝阈值（每秒数据包数）
    pub block_duration: Duration, // 拒绝持续时间
    pub check_interval: Duration, // 检查间隔
}

#[derive(Clone, Debug)]
pub struct Config {
    pub ws_bind: String,
    pub capture_mode: String,  // 抓包模式（"pcap"或"af_xdp"）
    pub capture_iface: String, // 抓包网卡（如"eth0"）
    pub ip_rate_limit: IPRateLimit, // IP限流配置
}

impl Default for IPRateLimit {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: 1000, // 默认每秒1000个包
            block_threshold: 5000, // 默认每秒5000个包触发拒绝
            block_duration: Duration::from_secs(60), // 默认拒绝60秒
            check_interval: Duration::from_secs(1), // 每秒检查一次
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ws_bind: "0.0.0.0:8080".to_string(),
            // 从环境变量获取模式，默认开发环境（pcap）
            capture_mode: env::var("CAPTURE_MODE").unwrap_or_else(|_| "pcap".to_string()),
            // 默认网卡（可通过环境变量覆盖）
            capture_iface: env::var("CAPTURE_IFACE").unwrap_or_else(|_| "eth0".to_string()),
            // IP限流配置
            ip_rate_limit: IPRateLimit::default(),
        }
    }
}
