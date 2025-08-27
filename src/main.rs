mod config; // 配置管理模块
mod utils;  // 工具函数模块

// 抓包相关模块
mod packet_capture;
mod flow_analyzer;    // 流量分析模块
mod rules_engine;     // 规则引擎模块
mod mitigation;       // 缓解措施模块
mod metrics_service;  // 指标服务模块
mod ip_protection;    // IP保护模块
mod protected_capture;// 数据包处理模块
mod network_utils;    // 网络工具模块

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::task;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// 导入抓包器接口
use crate::packet_capture::Capture;
use crate::packet_capture::pcap::PcapCapture;
use crate::ip_protection::IPProtectionService;

/// 程序入口函数（异步运行时：Tokio）
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 初始化日志系统
    init_logging();

    // 加载配置并初始化全局状态
    let cfg = load_and_validate_config()?;
    info!("加载配置: {:?}", cfg);

    // 解析目标 IP 和选择抓包网卡
    let target_ip = parse_target_ip(&cfg.target_ip)?;
    let capture_iface = select_capture_interface(&target_ip)?;

    // 初始化全局服务
    let metrics = Arc::new(flow_analyzer::metrics::Metrics::new());
    let ip_protection = Arc::new(IPProtectionService::new(cfg.clone(), metrics.clone()));

    // 启动核心服务
    start_core_services(metrics.clone(), ip_protection.clone(), &cfg).await;

    // 根据配置启动抓包任务
    match cfg.capture_mode.as_str() {
        "pcap" => start_pcap_capture_task(metrics, ip_protection, &capture_iface, &cfg.capture_ports).await?,
        _ => return Err(anyhow::anyhow!("不支持的抓包模式: {}", cfg.capture_mode)),
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

/// 加载并验证配置文件
fn load_and_validate_config() -> anyhow::Result<config::Config> {
    let cfg = config::Config::load();
    if cfg.capture_ports.is_empty() {
        warn!("未配置任何抓包端口，可能会影响抓包任务的正常运行");
    }
    Ok(cfg)
}

/// 解析目标 IP 地址
fn parse_target_ip(target_ip: &str) -> anyhow::Result<IpAddr> {
    IpAddr::from_str(target_ip)
        .map_err(|_| anyhow::anyhow!("无法解析目标IP: {}，请检查配置", target_ip))
}

/// 根据目标 IP 动态选择抓包网卡
fn select_capture_interface(target_ip: &IpAddr) -> anyhow::Result<String> {
    let iface = network_utils::select_capture_iface(*target_ip);
    if iface.is_empty() {
        Err(anyhow::anyhow!("未能找到合适的抓包网卡，请检查网络配置"))
    } else {
        info!("选择抓包网卡: {}", iface);
        Ok(iface)
    }
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
    ip_protection.start().await;
}

/// 启动 WebSocket 指标推送服务
async fn start_websocket_service(metrics: Arc<flow_analyzer::metrics::Metrics>, bind_addr: String) {
    task::spawn(async move {
        info!("启动 WebSocket 服务，监听地址: {}", bind_addr);
        if let Err(e) = metrics_service::ws_server::serve_ws(metrics, bind_addr).await {
            error!("WebSocket服务异常退出: {}", e);
        }
    });
}

/// 启动 PCAP 抓包任务
async fn start_pcap_capture_task(
    metrics: Arc<flow_analyzer::metrics::Metrics>,
    ip_protection: Arc<IPProtectionService>,
    capture_iface: &str,
    capture_ports: &[u16],
) -> anyhow::Result<()> {
    // 克隆捕获端口列表和网卡名称
    let capture_ports_owned = capture_ports.to_vec();
    let capture_iface_owned = capture_iface.to_string();

    // 启动抓包任务
    task::spawn_blocking(move || {
        tokio::runtime::Handle::current().block_on(async move {
            info!("启动PCAP抓包任务");

            match PcapCapture::new(&capture_iface_owned, &capture_ports_owned) {
                Ok(mut capture) => {
                    info!(
                        "成功初始化PCAP抓包器，监听接口: {}，捕获端口: {:?}",
                        capture_iface_owned, capture_ports_owned
                    );
                    loop {
                        match process_packets_with_protection(&mut capture, &metrics, &ip_protection, &capture_ports_owned).await {
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

    Ok(())
}

/// 处理数据包并应用IP保护策略
async fn process_packets_with_protection(
    capture: &mut PcapCapture,
    metrics: &Arc<flow_analyzer::metrics::Metrics>,
    ip_protection: &Arc<IPProtectionService>,
    capture_ports_owned: &Vec<u16>,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::protected_capture::PacketProcessor;
    use crate::packet_capture::parser::parse_l3l4;

    // 创建数据包处理器
    let processor = PacketProcessor::new(ip_protection.clone());
    // 调用 poll_batch 方法捕获数据包并更新指标
    let packet_count = capture.poll_batch(metrics, capture_ports_owned)?;

    if packet_count > 0 {
        debug!("捕获了 {} 个数据包", packet_count);
    }

    Ok(())
}
