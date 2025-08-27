
use dashmap::DashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// 进程启动时间：用于相对毫秒时间戳，避免把 `Instant` 放到每个桶里
static START: OnceLock<Instant> = OnceLock::new();

#[inline]
fn now_ms() -> u64 {
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// 紧凑令牌桶
#[derive(Clone, Copy)]
struct Bucket {
    capacity: u32,
    tokens: u32,
    rate_per_sec: u32,
    last_ms: u64,
}

impl Bucket {
    #[inline]
    fn new(capacity: u32, rate_per_sec: u32) -> Self {
        Self { capacity, tokens: capacity, rate_per_sec, last_ms: now_ms() }
    }
    
    #[inline]
    fn refill(&mut self) {
        let now = now_ms();
        let dt = now.saturating_sub(self.last_ms);
        if dt == 0 { return; }
        let add = (self.rate_per_sec as u64).saturating_mul(dt) / 1000;
        if add > 0 {
            let v = (self.tokens as u64).saturating_add(add);
            self.tokens = v.min(self.capacity as u64) as u32;
            self.last_ms = now;
        }
    }
    
    #[inline]
    fn try_consume(&mut self, n: u32) -> bool {
        self.refill();
        if self.tokens >= n { self.tokens -= n; true } else { false }
    }
}

/// IPv4+IPv6 限流器（DashMap 分片并发）
pub struct IPRateLimiter {
    v4: DashMap<u32, Bucket>,
    v6: DashMap<u128, Bucket>,
    default_capacity: u64,  // 保持与原有接口兼容
    default_rate: u64,      // 保持与原有接口兼容
    inactive_timeout_ms: u64,
    cleanup_interval: u64,  // 保持与原有接口兼容
}

impl IPRateLimiter {
    /// 创建新的IP限流管理器
    pub fn new(default_capacity: u64, default_rate: u64) -> Self {
        Self {
            v4: DashMap::with_capacity(10000),  // 预分配容量，可根据实际情况调整
            v6: DashMap::with_capacity(1000),   // 预分配容量，可根据实际情况调整
            default_capacity,
            default_rate,
            inactive_timeout_ms: 300_000, // 5分钟
            cleanup_interval: 60000,      // 1分钟
        }
    }
    
    /// 检查IP是否可以通过限流
    pub async fn check(&self, ip: &str, tokens: u64) -> bool {
        // 解析IP字符串为IpAddr
        if let Some(ip_addr) = ip_str_to_addr(ip) {
            // 转换u64为u32，因为我们的Bucket只支持u32
            let tokens_u32 = tokens.min(u32::MAX as u64) as u32;
            // 将default_capacity和default_rate从u64转换为u32
            let capacity = self.default_capacity.min(u32::MAX as u64) as u32;
            let rate = self.default_rate.min(u32::MAX as u64) as u32;
            
            self.check_with_params(ip_addr, tokens_u32, capacity, rate)
        } else {
            false // 无效的IP地址，拒绝
        }
    }
    
    /// 设置特定IP的限流参数
    pub async fn set_ip_limit(&self, ip: &str, capacity: u64, rate: u64) {
        if let Some(ip_addr) = ip_str_to_addr(ip) {
            let capacity_u32 = capacity.min(u32::MAX as u64) as u32;
            let rate_u32 = rate.min(u32::MAX as u64) as u32;
            
            match ip_addr {
                IpAddr::V4(v4) => self.v4.insert(u32::from(v4), Bucket::new(capacity_u32, rate_u32)),
                IpAddr::V6(v6) => self.v6.insert(ipv6_to_u128(v6), Bucket::new(capacity_u32, rate_u32)),
            };
        }
    }
    
    /// 移除特定IP的限流
    pub async fn remove_ip_limit(&self, ip: &str) {
        if let Some(ip_addr) = ip_str_to_addr(ip) {
            match ip_addr {
                IpAddr::V4(v4) => { self.v4.remove(&u32::from(v4)); },
                IpAddr::V6(v6) => { self.v6.remove(&ipv6_to_u128(v6)); },
            }
        }
    }
    
    /// 清理过期的令牌桶
    pub async fn cleanup(&self) {
        let now = now_ms();
        self.v4.retain(|_, b| now.saturating_sub(b.last_ms) < self.inactive_timeout_ms);
        self.v6.retain(|_, b| now.saturating_sub(b.last_ms) < self.inactive_timeout_ms);
    }
    
    // 内部方法：根据IP类型和参数检查
    #[inline]
    fn check_with_params(&self, ip: IpAddr, tokens: u32, capacity: u32, rate: u32) -> bool {
        match ip {
            IpAddr::V4(v4) => self.check_v4(u32::from(v4), tokens, capacity, rate),
            IpAddr::V6(v6) => self.check_v6(ipv6_to_u128(v6), tokens, capacity, rate),
        }
    }
    
    // IPv4 检查
    #[inline]
    fn check_v4(&self, ip_u32: u32, tokens: u32, capacity: u32, rate: u32) -> bool {
        use dashmap::mapref::entry::Entry;
        match self.v4.entry(ip_u32) {
            Entry::Occupied(mut e) => e.get_mut().try_consume(tokens),
            Entry::Vacant(v) => {
                let mut b = Bucket::new(capacity, rate);
                let ok = b.try_consume(tokens);
                v.insert(b);
                ok
            }
        }
    }
    
    // IPv6 检查
    #[inline]
    fn check_v6(&self, ip_u128: u128, tokens: u32, capacity: u32, rate: u32) -> bool {
        use dashmap::mapref::entry::Entry;
        match self.v6.entry(ip_u128) {
            Entry::Occupied(mut e) => e.get_mut().try_consume(tokens),
            Entry::Vacant(v) => {
                let mut b = Bucket::new(capacity, rate);
                let ok = b.try_consume(tokens);
                v.insert(b);
                ok
            }
        }
    }
}

// 小工具：IPv6 <-> u128，String 解析
#[inline]
pub fn ipv6_to_u128(ip: Ipv6Addr) -> u128 {
    let s = ip.segments();
    ((s[0] as u128) << 112)
        | ((s[1] as u128) << 96)
        | ((s[2] as u128) << 80)
        | ((s[3] as u128) << 64)
        | ((s[4] as u128) << 48)
        | ((s[5] as u128) << 32)
        | ((s[6] as u128) << 16)
        | (s[7] as u128)
}

#[inline]
pub fn ip_str_to_addr(s: &str) -> Option<IpAddr> {
    s.parse().ok()
}
