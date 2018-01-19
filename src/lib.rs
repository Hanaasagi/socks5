#![crate_type = "lib"]
#![crate_name = "socks5"]

#[macro_use]
extern crate tokio_core;
extern crate tokio_io;
extern crate futures;
extern crate trust_dns;
#[macro_use]
extern crate log;

pub mod server;
pub mod transfer;
pub mod dns;

pub use self::server::run as run_server;
