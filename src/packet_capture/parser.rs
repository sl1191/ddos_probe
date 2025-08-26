use std::net::{Ipv4Addr, Ipv6Addr};
use etherparse::SlicedPacket;

/// 网络五元组（L3-L4协议标识）
/// 用于唯一标识一个网络流（源IP:端口 -> 目的IP:端口 + 协议）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FiveTuple {
    pub src_ip: String,    // 源IP地址（IPv4/IPv6字符串）
    pub dst_ip: String,    // 目的IP地址
    pub src_port: u16,     // 源端口（TCP/UDP）
    pub dst_port: u16,     // 目的端口
    pub proto: &'static str,  // 传输层协议（"TCP"/"UDP"）
}

/// 从以太网帧中解析L3（网络层）和L4（传输层）信息，提取五元组
/// - 输入：原始以太网帧字节流（包含L2头部）
/// - 返回：成功时返回`Some(FiveTuple)`，失败时返回`None`（不支持的协议/格式错误）
pub fn parse_l3l4(frame: &[u8]) -> Option<FiveTuple> {
    // 辅助函数：构建五元组（减少IPv4/IPv6重复代码）
    fn build_five_tuple(
        src_ip: String,
        dst_ip: String,
        src_port: u16,
        dst_port: u16,
        proto: &'static str
    ) -> FiveTuple {
        FiveTuple { src_ip, dst_ip, src_port, dst_port, proto }
    }

    // 1. 解析以太网帧（L2层），失败则返回None（非以太网帧或截断）
    let pkt = SlicedPacket::from_ethernet(frame).ok()?;

    // 2. 匹配网络层（L3）和传输层（L4）协议（仅支持IPv4/IPv6 + TCP/UDP）
    match (pkt.net, pkt.transport) {
        // ===== IPv4 + TCP/UDP =====
        (Some(etherparse::NetSlice::Ipv4(ipv4)), Some(transport)) => {
            let ip_header = ipv4.header();  // IPv4头部（含源/目的IP）
            // 修复：调用source()和destination()方法（而非访问字段）
            let src_ip = Ipv4Addr::from(ip_header.source()).to_string();
            let dst_ip = Ipv4Addr::from(ip_header.destination()).to_string();

            match transport {
                etherparse::TransportSlice::Tcp(tcp) => Some(build_five_tuple(
                    src_ip, dst_ip, tcp.source_port(), tcp.destination_port(), "TCP"
                )),
                etherparse::TransportSlice::Udp(udp) => Some(build_five_tuple(
                    src_ip, dst_ip, udp.source_port(), udp.destination_port(), "UDP"
                )),
                _ => None,  // ⽀持的传输层协议（如ICMP/IGMP）
            }
        }

        // ===== IPv6 + TCP/UDP =====
        (Some(etherparse::NetSlice::Ipv6(ipv6)), Some(transport)) => {
            let ip_header = ipv6.header();  // IPv6头部（含源/目的IP）
            let src_ip = Ipv6Addr::from(ip_header.source()).to_string();
            let dst_ip = Ipv6Addr::from(ip_header.destination()).to_string();

            match transport {
                etherparse::TransportSlice::Tcp(tcp) => Some(build_five_tuple(
                    src_ip, dst_ip, tcp.source_port(), tcp.destination_port(), "TCP"
                )),
                etherparse::TransportSlice::Udp(udp) => Some(build_five_tuple(
                    src_ip, dst_ip, udp.source_port(), udp.destination_port(), "UDP"
                )),
                _ => None,  // ⽀持的传输层协议
            }
        }

        // ===== 不支持的网络层/传输层组合 =====
        _ => None,  // 如：ARP帧、IPv4无传输层、IPv6+ICMPv6等
    }

}
