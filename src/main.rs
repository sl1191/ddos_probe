// 模块声明：导入项目内部模块
mod config;          // 配置定义
mod utils;           // 工具函数（含模拟数据生成）
mod packet_capture;  // 数据包捕获接口
mod flow_analyzer;   // 流量分析（指标统计）
mod rules_engine;    // 规则引擎（黑白名单、限速等）
mod mitigation;      // 流量处置（丢弃/放行）
mod metrics_service; // 指标服务（WebSocket推送）
mod ip_protection;   // IP保护服务（限流和拒绝）
mod protected_capture; // 带IP保护的数据包处理器

// 外部依赖导入
use std::sync::Arc;
use tokio::task;
use tracing::{debug, error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// 导入抓包器接口
extern crate pcap;
use crate::packet_capture::Capture;
use crate::packet_capture::pcap::PcapCapture;
use crate::ip_protection::IPProtectionService;

/// 程序入口函数，异步运行时（Tokio）
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 初始化日志系统（支持环境变量 RUST_LOG 控制级别，默认 info）
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into())
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // 加载配置（默认绑定 WebSocket 到 0.0.0.0:8080）
    let cfg = config::Config::default();
    info!("加载配置: {:?}", cfg);

    // 创建全局共享指标实例（多任务共享的原子计数器）
    let metrics = Arc::new(flow_analyzer::metrics::Metrics::new());

    // 创建IP保护服务
    let ip_protection = Arc::new(IPProtectionService::new(cfg.clone(), metrics.clone()));
    
    // 启动核心任务
    start_websocket_service(metrics.clone(), cfg.ws_bind.clone()).await;
    ip_protection.clone().start().await;
    
    // 默认使用pcap抓包实现
    #[cfg(feature = "pcap")]
    start_pcap_capture(metrics.clone(), ip_protection.clone()).await;
    
    // 保留模拟探测作为备选方案（可通过特性标志切换）
    #[cfg(not(feature = "pcap"))]
    start_simulation_probe(metrics.clone()).await;

    // 主任务阻塞（防止程序退出，实际部署可替换为任务 join）
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}

/// 启动 WebSocket 指标推送服务
async fn start_websocket_service(metrics: Arc<flow_analyzer::metrics::Metrics>, bind_addr: String) {
    let task = task::spawn(async move {
        info!("启动 WebSocket 服务，监听地址: {}", bind_addr);
        
        // 启动 WebSocket server（若失败则记录错误并退出任务）
        if let Err(e) = metrics_service::ws_server::serve_ws(metrics, bind_addr).await {
            error!("WebSocket服务异常退出: {}", e);
        }
    });

    // 捕获任务 panic 并记录日志
    task::spawn(async move { 
        if let Err(e) = task.await {
            error!("WebSocket任务 panic: {:?}", e);
        }
    });
}

/// 启动PCAP抓包任务
/// 使用IP保护服务处理捕获的数据包
    #[cfg(feature = "pcap")]
async fn process_packets_with_protection(
    capture: &mut PcapCapture,
    metrics: &Arc<flow_analyzer::metrics::Metrics>,
    ip_protection: &Arc<IPProtectionService>
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::protected_capture::PacketProcessor;
    use crate::packet_capture::parser::parse_l3l4;
    
    // 创建数据包处理器
    let processor = PacketProcessor::new(ip_protection.clone());
    
    // 调用poll_batch方法捕获数据包并更新指标
    let packet_count = capture.poll_batch(metrics)?;
    
    // 由于当前架构限制，我们无法直接获取到捕获的数据包
    // 在实际生产环境中，应该修改Capture接口或使用自定义实现
    // 来允许在捕获后进行IP保护处理
    if packet_count > 0 {
        debug!("捕获了 {} 个数据包", packet_count);
    }
    
    Ok(())
}

    #[cfg(feature = "pcap")]
async fn start_pcap_capture(
    metrics: Arc<flow_analyzer::metrics::Metrics>,
    ip_protection: Arc<IPProtectionService>
) {
    use crate::protected_capture::PacketProcessor;
    
    // 初始化数据包处理器
    let processor = PacketProcessor::new(ip_protection.clone());
    processor.start_background_tasks();
    
    let task = task::spawn_blocking(move || {
        tokio::runtime::Handle::current().block_on(async move {
            info!("启动PCAP抓包任务");
            
            // 创建PCAP抓包器（注意：实际使用时需要替换为真实的网卡接口名）
            let interface = "en0"; // macOS上的默认网卡接口名
            match packet_capture::pcap::PcapCapture::new(interface) {
                Ok(mut capture) => {
                    info!("成功初始化PCAP抓包器，监听接口: {}", interface);
                    // 持续捕获数据包
                    loop {
                        // 使用IP保护服务处理数据包
                        match process_packets_with_protection(&mut capture, &metrics, &ip_protection).await {
                            Ok(_) => {},
                            Err(e) => {
                                error!("处理数据包失败: {}", e);
                                // 短暂休眠后重试
                                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            }
                        }
                    }
                },
                Err(e) => {
                    error!("初始化PCAP抓包器失败: {}. 请确保您有足够的权限并检查接口是否存在.", e);
                    // 为了演示目的，如果抓包失败，回退到模拟模式
                    utils::demo::simulate_probe(metrics).await;
                }
            }
        })
    });

    // 捕获任务 panic 并记录日志
    task::spawn(async move {
        if let Err(e) = task.await {
            error!("PCAP抓包任务 panic: {:?}", e);
        }
    });
}

/// 启动模拟探测任务（作为备用方案）
async fn start_simulation_probe(metrics: Arc<flow_analyzer::metrics::Metrics>) {
    let task = task::spawn_blocking(move || {
        tokio::runtime::Handle::current().block_on(async move {
            info!("启动模拟探测任务（生成随机指标）");
            utils::demo::simulate_probe(metrics).await;
        })
    });

    // 捕获任务 panic 并记录日志
    task::spawn(async move {
        if let Err(e) = task.await {
            error!("模拟探测任务 panic: {:?}", e);
        }
    });
}
