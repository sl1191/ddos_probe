use arc_swap::ArcSwap;
use dashmap::DashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;

use rangemap::RangeMap;

/// 规则集合，存储IP和端口访问控制规则
#[derive(Clone, Default)]
pub struct RuleSet {
    /// IP白名单集合，包含允许访问的IP地址
    pub whitelist_v4: DashMap<u32, ()>, // IPv4 白名单
    pub whitelist_v6: DashMap<u128, ()>, // IPv6 白名单

    /// IP黑名单集合，包含禁止访问的IP地址
    pub blacklist_v4: DashMap<u32, ()>, // IPv4 黑名单
    pub blacklist_v6: DashMap<u128, ()>, // IPv6 黑名单

    /// TCP端口范围黑名单，使用RangeMap实现高效的范围查询和管理
    pub deny_tcp_ports: RangeMap<u16, bool>,
    /// UDP端口范围黑名单，使用RangeMap实现高效的范围查询和管理
    pub deny_udp_ports: RangeMap<u16, bool>,
}

impl RuleSet {
    /// 创建一个新的空规则集
    pub fn new() -> Self {
        Self {
            whitelist_v4: DashMap::with_capacity(1000),
            whitelist_v6: DashMap::with_capacity(100),
            blacklist_v4: DashMap::with_capacity(1000),
            blacklist_v6: DashMap::with_capacity(100),
            deny_tcp_ports: RangeMap::new(),
            deny_udp_ports: RangeMap::new(),
        }
    }

    /// 检查指定IP是否在白名单中
    pub fn is_white(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.whitelist_v4.contains_key(&u32::from(v4)),
            IpAddr::V6(v6) => self.whitelist_v6.contains_key(&ipv6_to_u128(v6)),
        }
    }

    /// 检查指定IP是否在黑名单中
    pub fn is_black(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.blacklist_v4.contains_key(&u32::from(v4)),
            IpAddr::V6(v6) => self.blacklist_v6.contains_key(&ipv6_to_u128(v6)),
        }
    }

    /// 向白名单添加IP地址
pub fn add_white(&self, ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => self.whitelist_v4.insert(u32::from(v4), ()).is_none(),
        IpAddr::V6(v6) => self.whitelist_v6.insert(ipv6_to_u128(v6), ()).is_none(),
    }
}


   /// 从白名单移除IP地址
pub fn remove_white(&self, ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => self.whitelist_v4.remove(&u32::from(v4)).is_some(),
        IpAddr::V6(v6) => self.whitelist_v6.remove(&ipv6_to_u128(v6)).is_some(),
    }
}


  /// 向黑名单添加IP地址
pub fn add_black(&self, ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => self.blacklist_v4.insert(u32::from(v4), ()).is_none(),
        IpAddr::V6(v6) => self.blacklist_v6.insert(ipv6_to_u128(v6), ()).is_none(),
    }
}


   /// 从黑名单移除IP地址
pub fn remove_black(&self, ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => self.blacklist_v4.remove(&u32::from(v4)).is_some(),
        IpAddr::V6(v6) => self.blacklist_v6.remove(&ipv6_to_u128(v6)).is_some(),
    }
}


    /// 检查指定端口是否在TCP黑名单范围内
    pub fn deny_tcp(&self, port: u16) -> bool {
        self.deny_tcp_ports.contains_key(&port)
    }

    /// 检查指定端口是否在UDP黑名单范围内
    pub fn deny_udp(&self, port: u16) -> bool {
        self.deny_udp_ports.contains_key(&port)
    }

    /// 添加TCP端口范围到黑名单
    pub fn add_deny_tcp_port_range(&mut self, start_port: u16, end_port: u16) {
        self.deny_tcp_ports.insert(start_port..(end_port + 1), true);
    }

    /// 添加UDP端口范围到黑名单
    pub fn add_deny_udp_port_range(&mut self, start_port: u16, end_port: u16) {
        self.deny_udp_ports.insert(start_port..(end_port + 1), true);
    }

    /// 从黑名单中移除TCP端口范围
    pub fn remove_deny_tcp_port_range(&mut self, start_port: u16, end_port: u16) {
        self.deny_tcp_ports.remove(start_port..(end_port + 1));
    }

    /// 从黑名单中移除UDP端口范围
    pub fn remove_deny_udp_port_range(&mut self, start_port: u16, end_port: u16) {
        self.deny_udp_ports.remove(start_port..(end_port + 1));
    }
}

/// 全局规则集实例，使用ArcSwap实现线程安全的规则更新
pub static RULESET: LazyLock<ArcSwap<RuleSet>> = LazyLock::new(|| {
    ArcSwap::from_pointee(RuleSet::new())
});
/// 将 IPv6 地址转换为 u128
fn ipv6_to_u128(ip: Ipv6Addr) -> u128 {
    let segments = ip.segments();
    ((segments[0] as u128) << 112)
        | ((segments[1] as u128) << 96)
        | ((segments[2] as u128) << 80)
        | ((segments[3] as u128) << 64)
        | ((segments[4] as u128) << 48)
        | ((segments[5] as u128) << 32)
        | ((segments[6] as u128) << 16)
        | (segments[7] as u128)
}