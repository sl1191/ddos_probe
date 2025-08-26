use std::io;
use std::sync::Arc;
use tokio::task;
use tracing::{debug, error, info, warn};
use crate::flow_analyzer::metrics::Metrics;
use crate::ip_protection::{IPProtectionService, IPProtectionResult};
use crate::packet_capture::parser::FiveTuple;
use crate::mitigation::{forwarder, dropper};

/// 数据包处理器，用于在捕获过程中应用IP保护策略
pub struct PacketProcessor {
    ip_protection: Arc<IPProtectionService>,
}

impl PacketProcessor {
    /// 创建新的数据包处理器
    pub fn new(ip_protection: Arc<IPProtectionService>) -> Self {
        Self {
            ip_protection,
        }
    }
    
    /// 处理单个数据包
    pub async fn process_packet(&self, five_tuple: Option<&FiveTuple>, data: &[u8], metrics: &Metrics) -> bool {
        // 如果能解析五元组，应用IP保护策略
        if let Some(ft) = five_tuple {
            match self.ip_protection.handle_packet(ft, data.len() as u64).await {
                IPProtectionResult::Allow => {
                    // 数据包被允许通过，更新指标
                    metrics.increment_pps();
                    metrics.increment_bps(data.len() as u64 * 8);
                    
                    // 转发数据包
                    forwarder::forward_packet(data);
                    return true;
                },
                IPProtectionResult::Block => {
                    // 数据包被阻止，更新丢弃指标
                    metrics.increment_dropped();
                    
                    // 记录被阻止的IP
                    debug!("阻止来自IP: {}的数据包", ft.src_ip);
                    
                    // 丢弃数据包
                    dropper::drop_packet(data);
                    return false;
                },
                IPProtectionResult::Limit => {
                    // 数据包被限流，更新指标并允许通过
                    metrics.increment_pps();
                    metrics.increment_bps(data.len() as u64 * 8);
                    
                    // 转发受限流的数据包
                    forwarder::forward_packet(data);
                    return true;
                },
                IPProtectionResult::Error(err) => {
                    // 处理错误情况
                    error!("处理数据包时出错: {}", err);
                    // 默认允许通过
                    metrics.increment_pps();
                    metrics.increment_bps(data.len() as u64 * 8);
                    forwarder::forward_packet(data);
                    return true;
                }
            }
        } else {
            // 无法解析的数据包，默认允许通过
            metrics.increment_pps();
            metrics.increment_bps(data.len() as u64 * 8);
            forwarder::forward_packet(data);
            return true;
        }
    }
    
    /// 启动IP保护服务的后台任务
    pub fn start_background_tasks(&self) {
        // IP保护服务已经在main函数中启动
        // 这里可以添加额外的任务（如果需要）
    }
}