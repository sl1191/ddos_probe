
use serde::Serialize;

#[derive(Serialize)]
pub struct MetricsDto {
    pub pps: u64,
    pub qps: u64,
    pub bps: u64,
    pub dropped: u64,
}
