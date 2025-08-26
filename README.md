场景
命令
说明
开发调试
cargo run（默认启用 pcap 特性）
使用 pcap 抓包，跨平台兼容
生产部署
cargo run --features af_xdp
启用 AF_XDP 零拷贝抓包
构建优化
cargo build --release --features af_xdp
生产环境编译（含优化）
*注：optional = true 表示依赖仅在显式启用特性时才会被包含。