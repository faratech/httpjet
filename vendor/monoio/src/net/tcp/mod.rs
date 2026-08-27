#![allow(unreachable_pub)]
//! TCP related.

mod listener;
mod split;
mod stream;
mod tfo;

pub use listener::TcpListener;
pub use split::{TcpOwnedReadHalf, TcpOwnedWriteHalf};
pub use stream::{TcpConnectOpts, TcpStream};
#[cfg(all(target_os = "linux", feature = "iouring"))]
pub use stream::RecvMultiStream;

#[cfg(feature = "poll-io")]
pub mod stream_poll;
