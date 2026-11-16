//! A message-level connection that carries `actp.v1` frames.
//!
//! The endpoint does not know about TCP, TLS, HTTP or WebSocket handshakes: it
//! is handed a [`FrameConn`], a sink and a stream of WebSocket-style messages.
//! Today that is a WebSocket accepted by a listening server or dialed by the
//! bridge; a relay that multiplexes sessions over one outbound connection can
//! hand the same endpoint its own `FrameConn` without any other change.

use std::io;
use std::pin::Pin;

use std::task::{Context, Poll};

use futures_util::stream::SplitSink;
use futures_util::{Sink, Stream, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::{self, Message};

/// A message received from the peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Incoming {
    Text(String),
    /// Binary frames are ignored by the wire format, but count as traffic.
    Binary,
    /// The peer closed the socket, with its close code if it sent one.
    Close(Option<u16>),
}

/// A message sent to the peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outgoing {
    Text(String),
    Close(u16, String),
}

pub type FrameSink = Pin<Box<dyn Sink<Outgoing, Error = io::Error> + Send>>;
pub type FrameStream = Pin<Box<dyn Stream<Item = io::Result<Incoming>> + Send>>;

/// One socket's worth of frames: a sink and a stream.
pub struct FrameConn {
    pub sink: FrameSink,
    pub stream: FrameStream,
}

impl FrameConn {
    pub fn new(sink: FrameSink, stream: FrameStream) -> Self {
        FrameConn { sink, stream }
    }

    /// Adapts a tokio-tungstenite WebSocket.
    pub fn from_websocket<S>(ws: WebSocketStream<S>) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (sink, stream) = ws.split();
        let sink = WsSink(sink);
        let stream = stream.filter_map(|item| async move {
            match item {
                Ok(Message::Text(t)) => Some(Ok(Incoming::Text(t.as_str().to_string()))),
                Ok(Message::Binary(_)) => Some(Ok(Incoming::Binary)),
                Ok(Message::Close(frame)) => {
                    Some(Ok(Incoming::Close(frame.map(|f| u16::from(f.code)))))
                }
                Ok(Message::Ping(_)) | Ok(Message::Pong(_)) | Ok(Message::Frame(_)) => None,
                Err(e) => Some(Err(to_io(e))),
            }
        });
        FrameConn {
            sink: Box::pin(sink),
            stream: Box::pin(stream),
        }
    }
}

/// Maps [`Outgoing`] to WebSocket messages. Unlike `sink_map_err`, it can be
/// polled again after an error (it reports the error again).
struct WsSink<S>(SplitSink<WebSocketStream<S>, Message>);

impl<S: AsyncRead + AsyncWrite + Unpin> Sink<Outgoing> for WsSink<S> {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_ready(cx).map_err(to_io)
    }

    fn start_send(mut self: Pin<&mut Self>, out: Outgoing) -> io::Result<()> {
        let m = match out {
            Outgoing::Text(t) => Message::text(t),
            Outgoing::Close(code, reason) => Message::Close(Some(CloseFrame {
                code: CloseCode::from(code),
                reason: reason.into(),
            })),
        };
        Pin::new(&mut self.0).start_send(m).map_err(to_io)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx).map_err(to_io)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_close(cx).map_err(to_io)
    }
}

fn to_io(e: tungstenite::Error) -> io::Error {
    match e {
        tungstenite::Error::Io(e) => e,
        other => io::Error::other(other.to_string()),
    }
}

/// WebSocket settings both sides use: frames up to 16 MB, no compression.
pub fn websocket_config() -> tungstenite::protocol::WebSocketConfig {
    tungstenite::protocol::WebSocketConfig::default()
        .max_message_size(Some(crate::frame::MAX_FRAME))
        .max_frame_size(Some(crate::frame::MAX_FRAME))
}
