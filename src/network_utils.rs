use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use pcap::Device;
use tracing::{error, info, warn};

/// 网络接口信息
#[derive(Debug)]
pub struct InterfaceInfo {
    pub name: String,         // 接口名称（如"eth0"）
    pub ips: Vec<IpAddr>,     // 接口绑定的IP地址列表
}

/// 扫描系统中的所有网络接口
/// 扫描系统中的所有网络接口
pub fn scan_interfaces() -> HashMap<String, InterfaceInfo> {
    let mut interfaces = HashMap::new();

    // 使用 pcap::Device::list() 获取网络接口列表
    if let Ok(devices) = Device::list() {
        for device in devices {
            let ips: Vec<IpAddr> = device
                .addresses
                .iter()
                .filter_map(|addr| Some(addr.addr))
                .collect();

            if !ips.is_empty() {
                interfaces.insert(
                    device.name.clone(),
                    InterfaceInfo {
                        name: device.name,
                        ips,
                    },
                );
            }
        }
    }

    interfaces
}



/// 根据目标IP选择合适的网卡
pub fn select_interface(target_ip: IpAddr, interfaces: &HashMap<String, InterfaceInfo>) -> Option<String> {
    for (name, info) in interfaces {

        for ip in &info.ips {
            if is_in_same_subnet(target_ip, *ip) {
                warn!("选择网卡: {:?}", name);
                return Some(name.clone());
            }
        }
    }
    None // 如果没有找到匹配的网卡，返回None
}

/// 根据目标IP自动选择抓包网卡
pub fn select_capture_iface(target_ip: IpAddr) -> String {
    let interfaces = scan_interfaces(); // 扫描所有网络接口
    if let Some(iface_name) = select_interface(target_ip, &interfaces) {
        iface_name
    } else {
        "eth0".to_string() // 默认网卡名称
    }
}

/// 判断两个IP地址是否在同一子网内
fn is_in_same_subnet(ip1: IpAddr, ip2: IpAddr) -> bool {
    match (ip1, ip2) {
        (IpAddr::V4(ip1), IpAddr::V4(ip2)) => {
            let subnet_mask = Ipv4Addr::new(255, 255, 255, 0); // 假设子网掩码为255.255.255.0
            let subnet1 = Ipv4Addr::from(u32::from(ip1) & u32::from(subnet_mask));
            let subnet2 = Ipv4Addr::from(u32::from(ip2) & u32::from(subnet_mask));
            subnet1 == subnet2
        }
        _ => false, // 当前仅支持IPv4
    }
}
