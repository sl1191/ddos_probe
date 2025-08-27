use std::fs;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use serde::Deserialize; // 引入 Deserialize 特性
use crate::network_utils;

/// IP限流配置
#[derive(Clone, Debug, Deserialize)]
pub struct IPRateLimit {
    pub enabled: bool,         // 是否启用IP限流
    pub threshold: u64,        // 限流阈值（每秒数据包数）
    pub block_threshold: u64,  // 拒绝阈值（每秒数据包数）
    pub block_duration: u64,   // 拒绝持续时间（秒）
    pub check_interval: u64,   // 检查间隔（秒）
}

impl Default for IPRateLimit {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: 1000, // 默认每秒1000个包
            block_threshold: 5000, // 默认每秒5000个包触发拒绝
            block_duration: 60, // 默认拒绝60秒
            check_interval: 1, // 每秒检查一次
        }
    }
}

/// 全局配置
#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub ws_bind: String,           // WebSocket服务绑定地址
    pub capture_mode: String,      // 抓包模式（"pcap" 或 "af_xdp"）
    pub capture_iface: String,     // 抓包网卡（动态计算）
    pub capture_ports: Vec<u16>,   // 抓包网卡端口列表
    pub target_ip: String,         // 目标IP（用于动态选择抓包网卡）
    pub ip_rate_limit: IPRateLimit, // IP限流配置
}

impl Config {
    /// 从 config.toml 文件加载配置
    pub fn load() -> Self {
        // 读取配置文件内容
        let config_content = fs::read_to_string("./config.toml")
            .unwrap_or_else(|_| panic!("无法读取配置文件 config.toml，请检查文件是否存在"));

        // 解析 TOML 配置
        let mut config: Config = toml::from_str(&config_content)
            .unwrap_or_else(|e| panic!("解析配置文件失败: {}", e));

        // 如果 capture_iface 设置为 "auto"，根据目标IP动态选择网卡
        if config.capture_iface == "auto" {
            let target_ip = IpAddr::from_str(&config.target_ip).unwrap_or_else(|_| {
                panic!("无法解析目标IP: {}，请检查配置", config.target_ip)
            });
            config.capture_iface = network_utils::select_capture_iface(target_ip);
        }

        // 返回配置
        config
    }
}
