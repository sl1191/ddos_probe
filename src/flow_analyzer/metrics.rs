// 导入原子操作和线程同步相关模块
use std::sync::atomic::{AtomicU64, Ordering};  // AtomicU64: 线程安全的无锁64位计数器；Ordering: 原子操作内存顺序
use std::sync::Arc;  // Arc: 原子引用计数，支持多线程共享所有权

/// 全局指标收集器，通过原子操作实现多线程安全计数
/// 用于实时统计网络流量指标（PPS/QPS/BPS/丢包数）
#[derive(Clone)]  // 自动派生Clone trait，支持浅拷贝（Arc本身是引用计数，拷贝成本低）
pub struct Metrics {
    /// 每秒数据包数 (Packets Per Second)
    pub pps: Arc<AtomicU64>,
    /// 每秒查询数 (Queries Per Second，业务层概念，此处简化为数据包相关统计)
    pub qps: Arc<AtomicU64>,
    /// 每秒字节数 (Bytes Per Second)
    pub bps: Arc<AtomicU64>,
    /// 丢包数 (累计丢弃的数据包数量)
    pub dropped: Arc<AtomicU64>,
}

impl Metrics {
    /// 创建新的指标收集器实例，初始化所有计数器为0
    pub fn new() -> Self {
        Self {
            pps: Arc::new(AtomicU64::new(0)),
            qps: Arc::new(AtomicU64::new(0)),
            bps: Arc::new(AtomicU64::new(0)),
            dropped: Arc::new(AtomicU64::new(0)),
        }
    }

    /// 获取当前指标快照（原子读取所有计数器值）
    /// 返回元组：(pps, qps, bps, dropped)
    pub fn snapshot(&self) -> (u64, u64, u64, u64) {
        (
            self.pps.load(Ordering::Relaxed),  // Relaxed: 非严格内存顺序，适用于对时序一致性要求低的场景（如统计指标）
            self.qps.load(Ordering::Relaxed),
            self.bps.load(Ordering::Relaxed),
            self.dropped.load(Ordering::Relaxed),
        )
    }

    /// 增加每秒数据包数计数
    pub fn increment_pps(&self) {
        self.pps.fetch_add(1, Ordering::Relaxed);
    }

    /// 增加每秒字节数计数
    pub fn increment_bps(&self, bytes: u64) {
        self.bps.fetch_add(bytes, Ordering::Relaxed);
    }

    /// 增加丢包数计数
    pub fn increment_dropped(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}
