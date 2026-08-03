//! Shared harness for the Phase-7 HTTP boundary tests: spins the real axum
//! server on an ephemeral loopback port, drives it over real HTTP (reqwest),
//! and shuts it down cleanly so a port-leak is observable.

use std::net::SocketAddr;

use ciss::server::App;
use tokio::sync::oneshot;

/// A running test server bound to an ephemeral port, driven over real HTTP.
pub struct TestServer {
    /// The bound loopback address (ephemeral port).
    pub addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl TestServer {
    /// Bind `127.0.0.1:0`, serve `app`'s router with graceful shutdown, return
    /// a handle. `app` is dropped after the router is built — the router holds
    /// its own `Arc` clones of the shared state, so the server stays live.
    pub async fn spawn(app: App) -> Self {
        let router = app.router();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local_addr");
        let (tx, rx) = oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = rx.await;
                })
                .await
                .expect("serve");
        });
        Self {
            addr,
            shutdown: Some(tx),
            handle: Some(handle),
        }
    }

    /// A full URL for `path` against this server.
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    /// Signal graceful shutdown and wait for the server task to finish, so a
    /// caller can then assert the port was released.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}
