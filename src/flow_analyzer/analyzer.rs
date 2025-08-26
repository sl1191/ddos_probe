
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use crate::packet_capture::parser::FiveTuple;

/// IP流量统计信息
#[derive(Debug)]
pub struct IPStats {
    pub packet_count: u64,       // 数据包数量
    pub byte_count: u64,         // 字节数
    pub last_update: Instant,    // 最后更新时间
    pub is_blocked: bool,        // 是否被拒绝
    pub block_expiry: Option<Instant>, // 拒绝到期时间
}

impl Default for IPStats {
    fn default() -> Self {
        Self {
            packet_count: 0,
            byte_count: 0,
            last_update: Instant::now(),
            is_blocked: false,
            block_expiry: None,
        }
    }
}

/// 流量分析器，负责统计和分析网络流量
pub struct Analyzer {
    // IP地址到流量统计的映射，使用RwLock保证线程安全
    pub ip_stats: Arc<RwLock<HashMap<String, IPStats>>>,
    // 清理间隔（毫秒）
    pub cleanup_interval: u64,
    // 非活动超时时间（毫秒）
    pub inactive_timeout: u64,
}

impl Analyzer {
    /// 创建新的流量分析器
    pub fn new() -> Self {
        Self {
            ip_stats: Arc::new(RwLock::new(HashMap::new())),
            cleanup_interval: 60000, // 默认每分钟清理一次
            inactive_timeout: 300000, // 默认5分钟无活动后清理
        }
    }
    
    /// 更新IP流量统计
    pub async fn update(&self, ft: &FiveTuple, packet_size: u64) {
        let now = Instant::now();
        
        // 使用写锁更新统计信息
        let mut stats = self.ip_stats.write().await;
        
        // 获取或创建IP统计信息
        let ip_stat = stats.entry(ft.src_ip.clone()).or_insert_with(|| IPStats::default());
        ip_stat.packet_count += 1;
        ip_stat.byte_count += packet_size;
        ip_stat.last_update = now;
        
        // 如果IP已被拒绝但拒绝期已过，解除拒绝
        if let Some(expiry) = ip_stat.block_expiry {
            if now > expiry {
                ip_stat.is_blocked = false;
                ip_stat.block_expiry = None;
            }
        }
    }
    
    /// 获取IP的当前流量（每秒数据包数）
    pub async fn get_ip_packet_rate(&self, ip: &str) -> Option<u64> {
        let now = Instant::now();
        let stats = self.ip_stats.read().await;
        
        if let Some(stat) = stats.get(ip) {
            let duration = now.duration_since(stat.last_update);
            let seconds = duration.as_secs_f64().max(1.0); // 至少算1秒
            Some((stat.packet_count as f64 / seconds) as u64)
        } else {
            None
        }
    }
    
    /// 检查IP是否被拒绝
    pub async fn is_ip_blocked(&self, ip: &str) -> bool {
        let stats = self.ip_stats.read().await;
        if let Some(stat) = stats.get(ip) {
            stat.is_blocked
        } else {
            false
        }
    }
    
    /// 拒绝指定IP
    pub async fn block_ip(&self, ip: &str, duration: Duration) {
        let now = Instant::now();
        let mut stats = self.ip_stats.write().await;
        
        let ip_stat = stats.entry(ip.to_string()).or_insert_with(|| IPStats::default());
        ip_stat.is_blocked = true;
        ip_stat.block_expiry = Some(now + duration);
        ip_stat.last_update = now;
    }
    
    /// 清理过期的IP统计信息
    pub async fn cleanup(&self) {
        let now = Instant::now();
        let mut stats = self.ip_stats.write().await;
        
        // 移除长时间无活动的IP统计
        stats.retain(|_, stat| {
            let inactive_time = now.duration_since(stat.last_update).as_millis();
            inactive_time < self.inactive_timeout.into()
        });
    }
}
