//! `actp serve` as a library: runs ACP agents on this machine and serves them
//! to actp bridges (docs/design.md). Token auth, per-token agent, folder and
//! link limits, agents started in allowed folders, links that survive dropped
//! connections, the rewrites of design 3.3 and the management endpoints.
//!
//! The core ([`Server`]) does not listen on anything itself:
//! - [`http::serve`] serves it over HTTP/WebSocket from any [`http::Acceptor`]
//!   (TCP and TLS listeners, or [`relay::RelayAcceptor`], which dials out to a
//!   relay and serves the callers it routes here);
//! - [`Server::check_agent`] and [`Server::open_link`] open links for any
//!   transport that can carry `actp.v1` frames as a [`actp_proto::FrameConn`].
//!
//! Who a token belongs to is decided by an [`auth::Authenticator`], so other
//! token formats can be added without touching the rest.

pub mod agentproc;
pub mod audit;
pub mod auth;
pub mod config;
pub mod continuity;
mod fsutil;
pub mod http;
mod leftovers;
mod link;
pub mod modes;
pub mod org;
mod probe;
pub mod relay;
pub mod rewrite;
mod server;

pub use link::{STATE_ATTACHED, STATE_DETACHED, STATE_ENDED, STATE_UNATTENDED, TOMBSTONE_FOR};
pub use server::{AgentState, LinkInfo, LinkRequest, Options, PendingLink, Rejection, Server};
