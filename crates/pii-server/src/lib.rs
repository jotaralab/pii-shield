//! `pii-server` library: HTTP/JSON + MCP Streamable HTTP server for
//! pii-shield. The `main.rs` binary wires these modules together.

pub mod api;
pub mod config;
pub mod mcp;
pub mod metrics;
pub mod state;
