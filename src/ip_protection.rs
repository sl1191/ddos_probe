use std::sync::Arc;
use std::time::Duration;
use tokio::task;
use tracing::{debug, info, warn};
use crate::config::Config;
use crate::flow_analyzer::{analyzer::Analyzer, metrics::Metrics};
use crate::packet_capture::parser::FiveTuple;
use crate::rules_engine::limiter::IPRateLimiter;

/// IP保护操作结果
pub enum IPProtectionResult {
    Allow,     // 允许通过
    Limit,     // 限流（允许但计数）
    Block,     // 拒绝（直接丢弃）
    Error(String), // 处理错误
}

/// IP保护服务，整合限流和拒绝功能
pub struct IPProtectionService {
    analyzer: Arc<Analyzer>,
    rate_limiter: Arc<IPRateLimiter>,
    metrics: Arc<Metrics>,
    config: Config,
}

impl IPProtectionService {
    /// 创建新的IP保护服务
    pub fn new(config: Config, metrics: Arc<Metrics>) -> Self {
        let analyzer = Arc::new(Analyzer::new());
        let rate_limiter = Arc::new(IPRateLimiter::new(
            config.ip_rate_limit.threshold,
            config.ip_rate_limit.block_threshold,
        ));

        Self {
            analyzer,
            rate_limiter,
            metrics,
            config,
        }
    }

    /// 启动IP保护服务
    pub async fn start(self: Arc<Self>) {
        let check_interval = Duration::from_secs(self.config.ip_rate_limit.check_interval);

        // 启动定期清理任务
        let cleanup_service = self.clone();
        task::spawn(async move {
            let mut interval = tokio::time::interval(check_interval);
            loop {
                interval.tick().await;
                cleanup_service.cleanup().await;
            }
        });

        // 启动流量检查任务
        let check_service = self.clone();
        task::spawn(async move {
            let mut interval = tokio::time::interval(check_interval);
            loop {
                interval.tick().await;
                check_service.check_ip_traffic().await;
            }
        });

        info!(
            "IP保护服务已启动，限流阈值: {} PPS，拒绝阈值: {} PPS",
            self.config.ip_rate_limit.threshold,
            self.config.ip_rate_limit.block_threshold
        );
    }

    /// 定期清理过期的IP统计信息
    async fn cleanup(&self) {
        self.analyzer.cleanup().await;
        self.rate_limiter.cleanup().await;
    }

    /// 处理单个IP的数据包
    pub async fn handle_packet(&self, ft: &FiveTuple, packet_size: u64) -> IPProtectionResult {
        // 如果IP限流未启用，直接允许通过
        if !self.config.ip_rate_limit.enabled {
            return IPProtectionResult::Allow;
        }

        // 检查IP是否被拒绝
        if self.analyzer.is_ip_blocked(&ft.src_ip).await {
            self.metrics.dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            debug!("拒绝来自被阻止IP的数据包: {}", ft.src_ip);
            return IPProtectionResult::Block;
        }

        // 更新IP流量统计
        self.analyzer.update(ft, packet_size).await;

        // 检查是否超过限流阈值
        match self.rate_limiter.check(&ft.src_ip, 1).await {
            true => IPProtectionResult::Allow,
            false => {
                self.metrics.dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                debug!("IP流量超过限流阈值: {}", ft.src_ip);
                IPProtectionResult::Limit
            }
        }
    }

    /// 定期检查IP流量，识别可能的攻击行为
    async fn check_ip_traffic(&self) {
        let now = std::time::Instant::now();

        for entry in self.analyzer.ip_stats.iter() {
            let ip = entry.key(); // 获取 IP 地址
            let stat = entry.value(); // 获取对应的统计信息

            // 计算每秒数据包数
            let duration = now.duration_since(stat.last_update);
            let seconds = duration.as_secs_f64().max(1.0);
            let pps = (stat.packet_count as f64 / seconds) as u64;

            // 如果超过拒绝阈值且未被阻止，执行阻止操作
            if pps >= self.config.ip_rate_limit.block_threshold && !stat.is_blocked {
                warn!(
                    "检测到异常流量，IP: {}, PPS: {}，已超出拒绝阈值: {}",
                    ip,
                    pps,
                    self.config.ip_rate_limit.block_threshold
                );

                let analyzer = self.analyzer.clone();
                let ip_clone = ip.to_string();
                let block_duration = Duration::from_secs(self.config.ip_rate_limit.block_duration);

                tokio::task::spawn(async move {
                    analyzer.block_ip(&ip_clone, block_duration).await;
                    info!("已阻止异常IP: {}，持续时间: {:?}", ip_clone, block_duration);
                });
            }
        }
    }

    /// 手动阻止指定IP
    pub async fn manually_block_ip(&self, ip: &str, duration: Duration) {
        self.analyzer.block_ip(ip, duration).await;
        info!("手动阻止IP: {}，持续时间: {:?}", ip, duration);
    }

    /// 手动解除IP阻止
    pub async fn unblock_ip(&self, ip: &str) {
        if let Some(mut stat) = self.analyzer.ip_stats.get_mut(ip) {
            stat.is_blocked = false;
            stat.block_expiry = None;
            info!("已解除IP阻止: {}", ip);
        }
    }

    /// 设置特定IP的限流阈值
    pub async fn set_ip_threshold(&self, ip: &str, threshold: u64) {
        self.rate_limiter.set_ip_limit(ip, threshold, threshold).await;
        info!("已设置IP: {}的限流阈值: {}", ip, threshold);
    }
}

/// IP保护策略枚举
#[derive(Clone, Copy, Debug)]
pub enum ProtectionPolicy {
    Strict,     // 严格模式：快速响应异常流量
    Balanced,   // 平衡模式：兼顾安全性和可用性
    Permissive, // 宽松模式：优先保证可用性
}

impl ProtectionPolicy {
    /// 根据策略获取推荐的限流配置
    pub fn get_recommended_config(&self) -> (u64, u64, Duration) {
        match self {
            ProtectionPolicy::Strict => (500, 2000, Duration::from_secs(300)),  // 严格：低阈值，长阻止时间
            ProtectionPolicy::Balanced => (1000, 5000, Duration::from_secs(60)), // 平衡：中等阈值，中等阻止时间
            ProtectionPolicy::Permissive => (5000, 20000, Duration::from_secs(30)), // 宽松：高阈值，短阻止时间
        }
    }
}
