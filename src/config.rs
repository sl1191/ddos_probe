use std::env;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use crate::network_utils;

/// IP限流配置
#[derive(Clone, Debug)]
pub struct IPRateLimit {
    pub enabled: bool,         // 是否启用IP限流
    pub threshold: u64,        // 限流阈值（每秒数据包数）
    pub block_threshold: u64,  // 拒绝阈值（每秒数据包数）
    pub block_duration: Duration, // 拒绝持续时间
    pub check_interval: Duration, // 检查间隔
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

/// 全局配置
/// 全局配置
#[derive(Clone, Debug)]
pub struct Config {
    pub ws_bind: String,           // WebSocket服务绑定地址
    pub capture_mode: String,      // 抓包模式（"pcap" 或 "af_xdp"）
    pub capture_iface: String,     // 抓包网卡（动态计算）
    pub capture_ports: Vec<u16>,   // 抓包网卡端口列表（新增字段）
    pub target_ip: IpAddr,         // 目标IP（用于动态选择抓包网卡）
    pub ip_rate_limit: IPRateLimit, // IP限流配置
}

impl Config {
    /// 动态加载配置
    pub fn load(target_ip: Option<IpAddr>) -> Self {
        let target_ip = target_ip.unwrap_or_else(|| {
            IpAddr::from_str("192.168.1.1").unwrap_or_else(|_| {
                panic!("无法解析默认目标IP，请检查配置");
            })
        });

        // 根据目标IP动态选择抓包网卡
        let capture_iface = network_utils::select_capture_iface(target_ip);

        Self {
            ws_bind: env::var("WS_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string()),
            capture_mode: env::var("CAPTURE_MODE").unwrap_or_else(|_| "pcap".to_string()),
            capture_iface,
            capture_ports: env::var("CAPTURE_PORTS")
                .map(|ports| ports.split(',').filter_map(|p| p.parse::<u16>().ok()).collect())
                .unwrap_or(vec![]), // 默认值为空列表（不限制端口）
            target_ip,
            ip_rate_limit: IPRateLimit::default(),
        }
    }
}

