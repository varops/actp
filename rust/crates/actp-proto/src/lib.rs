//! The ACTP wire format (`docs/wire.md`): the `actp.v1` envelope, the
//! sequencing, acks, heartbeats and replay that let a link survive dropped
//! sockets, the HTTP message shapes, and JSON-RPC peeking that leaves ACP
//! messages untouched. Byte-for-byte compatible with the Go implementation.

pub mod api;
pub mod conn;
pub mod e2e;
pub mod endpoint;
pub mod frame;
pub mod gojson;
pub mod jsonrpc;
pub mod relay;
pub mod wsio;

pub use conn::{FrameConn, Incoming, Outgoing};
pub use endpoint::{Deliver, Endpoint, Options, ServeEnd, deliver_fn};
pub use frame::{Frame, RemoteError};
