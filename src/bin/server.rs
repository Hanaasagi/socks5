extern crate clap;
extern crate socks5;

use clap::{Arg, App};
use socks5::run_server;
use std::net::SocketAddr;

fn main() {
    let matches = App::new("socks5 server")
        .version("0.1")
        .author("Hanaasagi <ambiguous404@gmail.com>")
        .about("socks5 server implementation")
        .arg(Arg::with_name("HOST")
             .short("h")
             .long("host")
             .help("")
             .takes_value(true))
        .arg(Arg::with_name("PORT")
             .short("p")
             .long("port")
             .help(""))
        .arg(Arg::with_name("CONFIG")
             .short("c")
             .long("config")
             .takes_value(true)
             .help(""))
        .get_matches();

    let config = matches.value_of("CONFIG").unwrap_or("default.conf");
    let host = matches.value_of("HOST").unwrap_or("127.0.0.1");
    let port = matches.value_of("PORT").unwrap_or("1080");

    let addr = format!("{}:{}", host, port).parse::<SocketAddr>().unwrap();

    let dns = "8.8.8.8:53".parse::<SocketAddr>().unwrap();

    run_server(addr, dns);
}
