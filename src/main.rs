mod config;
mod utils;
mod packet_capture;
mod flow_analyzer;
mod rules_engine;
mod mitigation;
mod metrics_service;
mod ip_protection;
mod protected_capture;
mod network_utils;

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::task;
use tracing::{debug, error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// 导入抓包器接口
extern crate pcap;
use crate::packet_capture::Capture;
use crate::packet_capture::pcap::PcapCapture;
use crate::ip_protection::IPProtectionService;

/// 程序入口函数（异步运行时：Tokio）
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. 初始化日志系统
    init_logging();

    // 2. 加载配置并初始化全局状态
    let cfg = config::Config::load(None);
    info!("加载配置: {:?}", cfg);

    let capture_iface = select_capture_interface(&cfg.target_ip);
    let metrics = Arc::new(flow_analyzer::metrics::Metrics::new());
    let ip_protection = Arc::new(IPProtectionService::new(cfg.clone(), metrics.clone()));

    // 3. 启动核心服务
    start_core_services(metrics.clone(), ip_protection.clone(), &cfg).await;

    // 4. 根据配置启动抓包任务
    match cfg.capture_mode.as_str() {
        "pcap" => start_pcap_capture(metrics, ip_protection, &capture_iface).await,
        _ => panic!("不支持的抓包模式: {}", cfg.capture_mode),
    }

    // 主任务阻塞，防止程序退出
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}

/// 初始化日志系统
fn init_logging() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();
}

/// 根据目标 IP 动态选择抓包网卡
fn select_capture_interface(target_ip: &IpAddr) -> String {
    let target_ip = IpAddr::from_str(&target_ip.to_string()).unwrap_or_else(|_| {
        panic!("无法解析目标IP，请检查配置");
    });
    network_utils::select_capture_iface(target_ip)
}

/// 启动核心服务（WebSocket 指标推送 + IP保护服务）
async fn start_core_services(
    metrics: Arc<flow_analyzer::metrics::Metrics>,
    ip_protection: Arc<IPProtectionService>,
    cfg: &config::Config,
) {
    // 启动 WebSocket 指标推送服务
    start_websocket_service(metrics.clone(), cfg.ws_bind.clone()).await;

    // 启动 IP 保护服务
    ip_protection.clone().start().await;
}

/// 启动 WebSocket 指标推送服务
async fn start_websocket_service(metrics: Arc<flow_analyzer::metrics::Metrics>, bind_addr: String) {
    let task = task::spawn(async move {
        info!("启动 WebSocket 服务，监听地址: {}", bind_addr);

        if let Err(e) = metrics_service::ws_server::serve_ws(metrics, bind_addr).await {
            error!("WebSocket服务异常退出: {}", e);
        }
    });

    task::spawn(async move {
        if let Err(e) = task.await {
            error!("WebSocket任务 panic: {:?}", e);
        }
    });
}

/// 启动 PCAP 抓包任务
async fn start_pcap_capture(
    metrics: Arc<flow_analyzer::metrics::Metrics>,
    ip_protection: Arc<IPProtectionService>,
    capture_iface: &str,
) {
    use crate::protected_capture::PacketProcessor;

    // 初始化数据包处理器
    let processor = PacketProcessor::new(ip_protection.clone());
    processor.start_background_tasks();

    // 克隆 capture_iface 为拥有所有权的 String
    let capture_iface_owned = capture_iface.to_string();

    let task = task::spawn_blocking(move || {
        tokio::runtime::Handle::current().block_on(async move {
            info!("启动PCAP抓包任务");

            match PcapCapture::new(&capture_iface_owned, &[]) {
                Ok(mut capture) => {
                    info!("成功初始化PCAP抓包器，监听接口: {}", capture_iface_owned);
                    loop {
                        match process_packets_with_protection(&mut capture, &metrics, &ip_protection).await {
                            Ok(_) => {}
                            Err(e) => {
                                error!("处理数据包失败: {}", e);
                                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            }
                        }
                    }
                }
                Err(e) => {
                    error!(
                        "初始化PCAP抓包器失败: {}. 请确保您有足够的权限并检查接口是否存在.",
                        e
                    );
                    utils::demo::simulate_probe(metrics).await;
                }
            }
        })
    });

    task::spawn(async move {
        if let Err(e) = task.await {
            error!("PCAP抓包任务 panic: {:?}", e);
        }
    });
}

/// 处理数据包并应用IP保护策略
async fn process_packets_with_protection(
    capture: &mut PcapCapture,
    metrics: &Arc<flow_analyzer::metrics::Metrics>,
    ip_protection: &Arc<IPProtectionService>,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::protected_capture::PacketProcessor;
    use crate::packet_capture::parser::parse_l3l4;

    // 创建数据包处理器
    let processor = PacketProcessor::new(ip_protection.clone());

    // 调用 poll_batch 方法捕获数据包并更新指标
    let packet_count = capture.poll_batch(metrics)?;

    if packet_count > 0 {
        debug!("捕获了 {} 个数据包", packet_count);
    }

    Ok(())
}
