pub mod parser; // 导出L3/L4解析模块（五元组提取）

use std::io;
use crate::flow_analyzer::metrics::Metrics;

/// 抓包器统一接口（多实现适配：开发用pcap/生产用AF_XDP/测试用Dummy）
pub trait Capture {
    /// 创建抓包器实例
    fn new(iface: &str, capture_ports: &[u16]) -> io::Result<Self>
    where
        Self: Sized;

    /// 批量捕获数据包并更新指标
    fn poll_batch(&mut self, metrics: &Metrics) -> io::Result<usize>;
}

// ===== 开发环境：pcap抓包实现（需启用"pcap"特性）=====
#[cfg(feature = "pcap")]
pub mod pcap {
    use super::*;
    use ::pcap::{Capture, Error};

    /// pcap抓包器（基于libpcap/npcap内核驱动，跨平台兼容）
    /// 适合开发调试，支持Linux/macOS/Windows，性能满足中小流量场景（<1Gbps）
    pub struct PcapCapture {
        driver: ::pcap::Capture<::pcap::Active>, // 使用具体的实现类型
    }

    impl super::Capture for PcapCapture {
        /** 创建pcap抓包器（支持端口过滤） */
        fn new(iface: &str, capture_ports: &[u16]) -> io::Result<Self> {
            let mut capture = ::pcap::Capture::from_device(iface)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("pcap设备初始化失败: {}", e)))?
                .promisc(true)       // 混杂模式
                .snaplen(1500)       // 捕获长度限制
                .timeout(1000)       // 超时时间
                .open()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("打开设备失败: {}", e)))?
                .setnonblock()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("设置非阻塞模式失败: {}", e)))?;

            // 如果指定了端口，则添加BPF过滤器
            if !capture_ports.is_empty() {
                let filter = capture_ports
                    .iter()
                    .map(|port| format!("port {}", port))
                    .collect::<Vec<_>>()
                    .join(" or ");

                // 调用 set_filter 方法时，确保 capture 是可变引用
                capture
                    .set_filter(&filter)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("设置BPF过滤器失败: {}", e)))?;
            }
            }

            Ok(Self { driver: capture })
        }

        /** 批量捕获数据包并更新指标（单次最多100个包） */
        fn poll_batch(&mut self, metrics: &Metrics) -> io::Result<usize> {
            let mut count = 0;
            for _ in 0..100 {
                match self.driver.next_packet() {
                    Ok(packet) => {
                        count += 1;
                        metrics.pps.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        metrics.bps.fetch_add(packet.len() as u64 * 8, std::sync::atomic::Ordering::Relaxed);

                        // 解析L3/L4信息并更新QPS指标
                        if let Some(tuple) = parser::parse_l3l4(&packet.data) {
                            if tuple.proto == "TCP" && (tuple.dst_port == 80 || tuple.dst_port == 443) {
                                metrics.qps.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    }
                    Err(Error::NoMorePackets) => break,
                    Err(e) => return Err(io::Error::new(io::ErrorKind::Other, format!("pcap捕获错误: {}", e))),
                }
            }
            Ok(count)
        }
    }
}

// ===== 生产环境：AF_XDP抓包实现（需启用"af_xdp"特性）=====
#[cfg(feature = "af_xdp")]
pub mod af_xdp {
    use super::*;
    use afxdp::socket::{Socket, Config};

    /// AF_XDP抓包器（基于Linux内核零拷贝技术，需内核5.4+）
    /// 适合生产环境高吞吐场景（10Gbps+），通过共享内存（UMEM）避免内核态/用户态数据拷贝
    pub struct AfXdpCapture {
        socket: Socket,             // AF_XDP用户态socket
        buffer: Vec<u8>,            // 接收缓冲区（MTU=1500字节）
    }

    impl Capture for AfXdpCapture {
        /** 创建AF_XDP抓包器（默认配置：4MB共享内存+队列0） */
        fn new(iface: &str, _capture_ports: &[u16]) -> io::Result<Self> {
            let config = Config::new()
                .ifname(iface)                // 绑定目标网卡
                .queue_id(0)                  // 接收队列ID
                .umem_size(32 * 1024 * 1024); // 32MB共享内存

            let socket = Socket::new(&config)?;
            Ok(Self {
                socket,
                buffer: vec![0; 1500],
            })
        }

        /** 批量捕获数据包（零拷贝模式） */
        fn poll_batch(&mut self, metrics: &Metrics) -> io::Result<usize> {
            let mut count = 0;
            loop {
                match self.socket.recv(&mut self.buffer) {
                    Ok(packet) => {
                        count += 1;
                        metrics.pps.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        metrics.bps.fetch_add(packet.len() as u64 * 8, std::sync::atomic::Ordering::Relaxed);

                        // 解析L3/L4信息并更新QPS指标
                        if let Some(tuple) = parser::parse_l3l4(&self.buffer[..packet.len()]) {
                            if tuple.proto == "TCP" && (tuple.dst_port == 80 || tuple.dst_port == 443) {
                                metrics.qps.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                        self.socket.release_rx_buffer(packet.desc())?;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }
            Ok(count)
        }
    }
}

// ===== 活跃抓包器类型别名（互斥条件，避免重复定义）=====
#[cfg(feature = "pcap")]
pub type ActiveCapture = pcap::PcapCapture; // 开发环境：pcap实现（优先）

#[cfg(all(feature = "af_xdp", not(feature = "pcap")))]
pub type ActiveCapture = af_xdp::AfXdpCapture; // 生产环境：AF_XDP实现

#[cfg(not(any(feature = "pcap", feature = "af_xdp")))]
compile_error!("必须启用 'pcap' 或 'af_xdp' 特性之一");
