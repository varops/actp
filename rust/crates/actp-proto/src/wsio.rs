//! A byte stream carried in the binary messages of a WebSocket.
//!
//! The relay (docs/relay.md) pipes a caller's whole HTTP connection to a
//! machine through one WebSocket that the machine dialed out to the relay.
//! [`WsIo`] turns that WebSocket back into an [`AsyncRead`] + [`AsyncWrite`]
//! byte stream at both ends, so the machine can serve it with the ordinary
//! HTTP server and the relay can copy bytes between it and the caller.
//!
//! Each write becomes one binary message of at most [`MAX_CHUNK`] bytes. A
//! close message, or the end of the socket, reads as end of file. A text
//! message is a protocol error.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes};
use futures_util::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::{self, Message};

/// Largest binary message one write sends.
pub const MAX_CHUNK: usize = 64 << 10;

/// A WebSocket as a byte stream.
pub struct WsIo<S> {
    ws: WebSocketStream<S>,
    buf: Bytes,
    eof: bool,
}

impl<S> WsIo<S> {
    pub fn new(ws: WebSocketStream<S>) -> Self {
        WsIo {
            ws,
            buf: Bytes::new(),
            eof: false,
        }
    }
}

fn to_io(e: tungstenite::Error) -> io::Error {
    match e {
        tungstenite::Error::Io(e) => e,
        tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed => {
            io::Error::from(io::ErrorKind::BrokenPipe)
        }
        other => io::Error::other(other.to_string()),
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.buf.is_empty() {
                let n = self.buf.len().min(out.remaining());
                out.put_slice(&self.buf[..n]);
                self.buf.advance(n);
                return Poll::Ready(Ok(()));
            }
            if self.eof {
                return Poll::Ready(Ok(()));
            }
            match ready!(Pin::new(&mut self.ws).poll_next(cx)) {
                Some(Ok(Message::Binary(b))) => self.buf = b,
                Some(Ok(Message::Close(_))) | None => self.eof = true,
                Some(Ok(Message::Text(_))) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "text message on a relayed byte stream",
                    )));
                }
                Some(Ok(_)) => {} // ping, pong: tungstenite answers pings itself
                Some(Err(tungstenite::Error::ConnectionClosed)) => self.eof = true,
                Some(Err(e)) => return Poll::Ready(Err(to_io(e))),
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(Pin::new(&mut self.ws).poll_ready(cx)).map_err(to_io)?;
        let n = buf.len().min(MAX_CHUNK);
        Pin::new(&mut self.ws)
            .start_send(Message::Binary(Bytes::copy_from_slice(&buf[..n])))
            .map_err(to_io)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.ws).poll_flush(cx).map_err(to_io)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match ready!(Pin::new(&mut self.ws).poll_close(cx)) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed) => {
                Poll::Ready(Ok(()))
            }
            Err(e) => Poll::Ready(Err(to_io(e))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::tungstenite::protocol::Role;

    #[tokio::test]
    async fn carries_bytes_both_ways_and_ends_with_eof() {
        let (a, b) = tokio::io::duplex(1 << 20);
        let wa = WebSocketStream::from_raw_socket(a, Role::Client, None).await;
        let wb = WebSocketStream::from_raw_socket(b, Role::Server, None).await;
        let (mut a, mut b) = (WsIo::new(wa), WsIo::new(wb));
        let big: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
        let sent = big.clone();
        let writer = tokio::spawn(async move {
            a.write_all(&sent).await.unwrap();
            a.flush().await.unwrap();
            let mut back = [0u8; 5];
            a.read_exact(&mut back).await.unwrap();
            assert_eq!(&back, b"hello");
            a.shutdown().await.unwrap();
        });
        let mut got = vec![0u8; big.len()];
        b.read_exact(&mut got).await.unwrap();
        assert_eq!(got, big);
        b.write_all(b"hello").await.unwrap();
        b.flush().await.unwrap();
        let mut rest = Vec::new();
        b.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
        writer.await.unwrap();
    }
}
