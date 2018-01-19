extern crate clap;
extern crate socks5;
extern crate pretty_env_logger;

use clap::{Arg, App};
use socks5::run_server;
use std::net::SocketAddr;

fn main() {
    pretty_env_logger::init();

    let matches = App::new("socks5 server")
        .version("0.1")
        .author("Hanaasagi <ambiguous404@gmail.com>")
        .about("socks5 server implementation")
        .arg(Arg::with_name("HOST")
             .short("h")
             .long("host")
             .takes_value(true)
             .help(""))
        .arg(Arg::with_name("PORT")
             .short("p")
             .long("port")
             .takes_value(true)
             .help(""))
        .arg(Arg::with_name("CONFIG")
             .short("c")
             .long("config")
             .takes_value(true)
             .help(""))
        .get_matches();

    let host = matches.value_of("HOST").unwrap_or("127.0.0.1");
    let port = matches.value_of("PORT").unwrap_or("1080");

    let addr = format!("{}:{}", host, port).parse::<SocketAddr>().unwrap();
    let dns = "8.8.8.8:53".parse::<SocketAddr>().unwrap();

    run_server(addr, dns);
}
