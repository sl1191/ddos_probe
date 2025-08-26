
use std::time::{SystemTime, UNIX_EPOCH};
pub fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()
}

pub mod demo {
    use std::sync::Arc;
    use tokio::time::{interval, Duration};
    use rand::{Rng, thread_rng};
    use crate::flow_analyzer::metrics::Metrics;

    // 模拟探测任务：生成随机指标数据（用于测试前端展示）
pub async fn simulate_probe(metrics: Arc<Metrics>) {
    let mut tick = interval(Duration::from_millis(100));  // 定时器：每100ms更新一次指标
    let mut rng = thread_rng();  // 线程本地随机数生成器
    loop {
        tick.tick().await;  // 等待下一个周期

        // 生成随机指标值（模拟真实场景下的流量波动）
        let pps = rng.random_range(50_000..120_000);  // 数据包每秒：5万~12万
        let qps = rng.random_range(500..2_000);       // 查询每秒：500~2000
        let bps = pps as u64 * 64 * 8;             // 字节每秒：假设包大小64字节（64B*8bit/B=512bit/包）
        let drop = rng.random_range(0..1_000);        // 丢包数：0~1000

        // 更新指标（原子存储，Relaxed内存顺序：性能优先，非严格时序）
        metrics.pps.store(pps as u64, std::sync::atomic::Ordering::Relaxed);
        metrics.qps.store(qps as u64, std::sync::atomic::Ordering::Relaxed);
        metrics.bps.store(bps as u64, std::sync::atomic::Ordering::Relaxed);
        metrics.dropped.store(drop as u64, std::sync::atomic::Ordering::Relaxed);
    }
}

}
