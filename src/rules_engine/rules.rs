use arc_swap::ArcSwap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::LazyLock; // 添加此导入

#[derive(Clone, Default)]
pub struct RuleSet {
    pub whitelist: Vec<String>, // CIDR/IP 简化占位
    pub blacklist: Vec<String>,
    pub deny_tcp_ports: Vec<(u16,u16)>,
    pub deny_udp_ports: Vec<(u16,u16)>,
}

impl RuleSet {
    pub fn is_white(&self, ip: &str) -> bool { self.whitelist.iter().any(|x| x==ip) }
    pub fn is_black(&self, ip: &str) -> bool { self.blacklist.iter().any(|x| x==ip) }
    pub fn deny_tcp(&self, port: u16) -> bool { self.deny_tcp_ports.iter().any(|(a,b)| port>=*a && port<=*b) }
    pub fn deny_udp(&self, port: u16) -> bool { self.deny_udp_ports.iter().any(|(a,b)| port>=*a && port<=*b) }
}

// 使用 LazyLock 进行惰性初始化
pub static RULESET: LazyLock<ArcSwap<RuleSet>> = LazyLock::new(|| {
    ArcSwap::from_pointee(RuleSet::default())
});
