
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// 令牌桶算法实现
pub struct TokenBucket {
    pub capacity: u64,    // 桶容量
    pub tokens: u64,      // 当前令牌数
    pub rate_per_sec: u64, // 每秒生成的令牌数
    pub last_refill: Instant, // 上次填充时间
}

impl TokenBucket {
    /// 创建新的令牌桶
    pub fn new(capacity: u64, rate_per_sec: u64) -> Self {
        Self { 
            capacity, 
            tokens: capacity, 
            rate_per_sec, 
            last_refill: Instant::now()
        } 
    }
    
    /// 尝试消耗指定数量的令牌
    pub fn try_consume(&mut self, n: u64) -> bool {
        // 先更新令牌数量
        self.refill();
        
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }
    
    /// 填充令牌
    pub fn refill(&mut self) {
        let now = Instant::now();
        let duration = now.duration_since(self.last_refill);
        let seconds = duration.as_secs_f64();
        
        // 计算应该添加的令牌数
        let tokens_to_add = (seconds * self.rate_per_sec as f64) as u64;
        
        if tokens_to_add > 0 {
            self.tokens = self.tokens.saturating_add(tokens_to_add).min(self.capacity);
            self.last_refill = now;
        }
    }
}

/// IP限流管理器
pub struct IPRateLimiter {
    // IP地址到令牌桶的映射
    buckets: Arc<RwLock<HashMap<String, TokenBucket>>>,
    // 默认桶容量
    default_capacity: u64,
    // 默认每秒生成的令牌数
    default_rate: u64,
    // 清理间隔
    cleanup_interval: u64,
    // 非活动超时时间
    inactive_timeout: u64,
}

impl IPRateLimiter {
    /// 创建新的IP限流管理器
    pub fn new(default_capacity: u64, default_rate: u64) -> Self {
        Self {
            buckets: Arc::new(RwLock::new(HashMap::new())),
            default_capacity,
            default_rate,
            cleanup_interval: 60000, // 默认每分钟清理一次
            inactive_timeout: 300000, // 默认5分钟无活动后清理
        }
    }
    
    /// 检查IP是否可以通过限流
    pub async fn check(&self, ip: &str, tokens: u64) -> bool {
        let mut buckets = self.buckets.write().await;
        
        // 获取或创建IP的令牌桶
        let bucket = buckets.entry(ip.to_string())
            .or_insert_with(|| TokenBucket::new(self.default_capacity, self.default_rate));
        
        bucket.try_consume(tokens)
    }
    
    /// 设置特定IP的限流参数
    pub async fn set_ip_limit(&self, ip: &str, capacity: u64, rate: u64) {
        let mut buckets = self.buckets.write().await;
        buckets.insert(ip.to_string(), TokenBucket::new(capacity, rate));
    }
    
    /// 移除特定IP的限流
    pub async fn remove_ip_limit(&self, ip: &str) {
        let mut buckets = self.buckets.write().await;
        buckets.remove(ip);
    }
    
    /// 清理过期的令牌桶
    pub async fn cleanup(&self) {
        let now = Instant::now();
        let mut buckets = self.buckets.write().await;
        
        buckets.retain(|_, bucket| {
            let inactive_time = now.duration_since(bucket.last_refill).as_millis();
            inactive_time < self.inactive_timeout.into()
        });
    }
}
