// Axum Web框架核心组件：状态提取、路由、WebSocket支持
use axum::{extract::State, response::IntoResponse, routing::get, Router};
use axum::extract::ws::{WebSocketUpgrade, WebSocket, Message, Utf8Bytes};  // WebSocket升级和消息类型
use serde_json::json;  // JSON序列化工具（生成指标数据）
use std::sync::Arc;
use tokio::time::{interval, Duration};  // 定时器：周期性推送指标
use crate::flow_analyzer::metrics::Metrics;  // 导入指标结构体
use tokio::net::TcpListener;  // TCP监听器（Axum服务绑定）
use anyhow::Result;

/// WebSocket服务状态：包装共享的Metrics实例
#[derive(Clone)]  // 支持Clone，便于Axum状态传递
pub struct AppState {
    pub metrics: Arc<Metrics>,  // 共享指标实例（Arc确保多线程安全）
}

/// WebSocket连接处理入口：升级HTTP连接为WebSocket
pub async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| client_ws(socket, state))  // 升级成功后调用client_ws处理客户端连接
}

/// 客户端WebSocket连接逻辑：周期性推送指标数据
async fn client_ws(mut socket: WebSocket, state: AppState) {
    let mut ticker = interval(Duration::from_millis(500));  // 定时器：每500ms推送一次指标
    loop {
        ticker.tick().await;  // 等待下一个周期
        
        // 读取当前指标快照（原子操作，无锁）
        let (pps, qps, bps, dropped) = state.metrics.snapshot();
        
        // 构造JSON数据：包含pps/qps/bps/dropped字段
        let data = json!({ "pps": pps, "qps": qps, "bps": bps, "dropped": dropped });
        
        // 发送消息：若发送失败（如客户端断开），退出循环
        if socket.send(Message::Text(Utf8Bytes::from(data.to_string()))).await.is_err() {
            break;
        }
    }
}

/// 启动WebSocket服务：绑定地址并启动Axum路由
pub async fn serve_ws(metrics: Arc<Metrics>, bind: String) -> anyhow::Result<()> {
    // 创建Axum路由：GET /ws -> ws_handler
    let app = Router::new()
        .route("/ws", get(ws_handler))  // 注册WebSocket路由
        .with_state(AppState { metrics });  // 注入共享状态（Metrics）

    tracing::info!("metrics ws listening on {}", bind);  // 日志：服务启动信息
    
    // 绑定地址并启动服务
    let listener = TcpListener::bind(&bind).await?;  // 绑定TCP端口
    axum::serve(listener, app.into_make_service())  // 启动Axum服务
        .await?;
    Ok(())
}
