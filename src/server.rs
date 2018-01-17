extern crate futures;
extern crate tokio_core;
extern crate tokio_io;
extern crate trust_dns;
extern crate pretty_env_logger;
extern crate log;

use std::cell::RefCell;
use std::io;
use std::net::{SocketAddr, Ipv4Addr, SocketAddrV4};
use std::rc::Rc;
use std::str;
use std::time::Duration;

use futures::future;
use futures::{Future, Stream};
use tokio_io::io::{read_exact, write_all, Window};
use tokio_core::net::{TcpStream, TcpListener};
use tokio_core::reactor::{Core, Handle, Timeout};
use trust_dns::client::ClientFuture;
use trust_dns::rr::Name;
use trust_dns::udp::UdpClientStream;

use transfer::Transfer;
use dns::DNSClient;

#[allow(dead_code)]
mod v4 {
    pub const VERSION: u8 = 4;

    pub const CMD_CONNECT: u8 = 1;
    pub const CMD_BIND: u8 = 2;
}

#[allow(dead_code)]
mod v5 {
    pub const VERSION: u8 = 5;

    pub const METH_NO_AUTH: u8 = 0;
    pub const METH_GSSAPI: u8 = 1;
    pub const METH_USER_PASS: u8 = 2;

    pub const CMD_CONNECT: u8 = 1;
    pub const CMD_BIND: u8 = 2;
    pub const CMD_UDP_ASSOCIATE: u8 = 3;

    pub const ATYP_IPV4: u8 = 1;
    pub const ATYP_IPV6: u8 = 4;
    pub const ATYP_DOMAIN: u8 = 3;
}

pub fn run(addr: SocketAddr, dns: SocketAddr) {

    let buffer = Rc::new(RefCell::new(vec![0; 64 * 1024]));
    let mut lp = Core::new().unwrap();
    let handle = lp.handle();

    let (stream, sender) = UdpClientStream::new(dns, handle.clone());
    let client = ClientFuture::new(stream, sender, handle.clone(), None);
    let listener = TcpListener::bind(&addr, &handle).unwrap();

    println!("Listening for socks5 proxy connections on {}", addr);

    let clients = listener.incoming().map(move |(socket, addr)| {
        (Client {
            buffer: buffer.clone(),
            dns: DNSClient::new(client.clone()),
            handle: handle.clone(),
        }.serve(socket), addr)
    });
    let handle = lp.handle();
    let server = clients.for_each(|(client, addr)| {
        handle.spawn(client.then(move |res| {
            match res {
                Ok((a, b)) => {
                    debug!("proxied {}/{} bytes for {}", a, b, addr)
                }
                Err(e) => error!("error for {}: {}", addr, e),
            }
            future::ok(())
        }));
        Ok(())
    });

    lp.run(server).unwrap();
}

struct Client {
    buffer: Rc<RefCell<Vec<u8>>>,
    dns: DNSClient,
    handle: Handle,
}

impl Client {

    fn serve(self, conn: TcpStream)
              -> Box<Future<Item=(u64, u64), Error=io::Error>> {
        Box::new(read_exact(conn, [0u8]).and_then(|(conn, buf)| {
            match buf[0] {
                v5::VERSION => self.serve_v5(conn),
                v4::VERSION => self.serve_v4(conn),
                _ => Box::new(future::err(other("unknown version")))
            }
        }))
    }

    fn serve_v4(self, _conn: TcpStream)
                -> Box<Future<Item=(u64, u64), Error=io::Error>> {
        Box::new(future::err(other("unimplemented")))
    }

    fn serve_v5(self, conn: TcpStream)
                -> Box<Future<Item=(u64, u64), Error=io::Error>> {
        let num_methods = read_exact(conn, [0u8]);

        let authenticated = num_methods.and_then(|(conn, buf)| {
            read_exact(conn, vec![0u8; buf[0] as usize])
        }).and_then(|(conn, buf)| {
            if buf.contains(&v5::METH_NO_AUTH) {
                Ok(conn)
            } else {
                Err(other("no supported method given"))
            }
        });

        let part1 = authenticated.and_then(|conn| {
            write_all(conn, [v5::VERSION, v5::METH_NO_AUTH])
        });

        let ack = part1.and_then(|(conn, _)| {
            read_exact(conn, [0u8]).and_then(|(conn, buf)| {
                match buf[0] {
                    v5::VERSION => Ok(conn),
                    _ => Err(other("didn't confirm with v5 version")),
                }
            })
        });

        let command = ack.and_then(|conn| {
            read_exact(conn, [0u8]).and_then(|(conn, buf)| {
                match buf[0] {
                    v5::CMD_CONNECT => Ok(conn),
                    _ => Err(other("unsupported command")),
                }
            })
        });

        let mut dns = self.dns.clone();
        let resv = command.and_then(|c| read_exact(c, [0u8]).map(|c| c.0));
        let atyp = resv.and_then(|c| read_exact(c, [0u8]));
        let addr = mybox(atyp.and_then(move |(c, buf)| {
            match buf[0] {
                v5::ATYP_IPV4 => {
                    mybox(read_exact(c, [0u8; 6]).map(|(c, buf)| {
                        let addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                        let port = ((buf[4] as u16) << 8) | (buf[5] as u16);
                        let addr = SocketAddrV4::new(addr, port);
                        (c, SocketAddr::V4(addr))
                    }))
                },
                v5::ATYP_DOMAIN => {
                    mybox(read_exact(c, [0u8]).and_then(|(conn, buf)| {
                        read_exact(conn, vec![0u8; buf[0] as usize + 2])
                    }).and_then(move |(conn, buf)| {
                        // The last two bytes of the buffer are the port, and the other parts of it
                        // are the hostname.
                        let pos = buf.len() - 2;
                        let hostname = &buf[..pos];
                        let hostname = match str::from_utf8(hostname).map_err(|_e| {
                            other("hostname buffer provided was not valid utf-8")
                        }) {
                            Ok(v) => v,
                            Err(e) => return mybox(future::err(e)),
                        };

                        let port = ((buf[pos] as u16) << 8) | (buf[pos + 1] as u16);

                        if let Ok(ip) = hostname.parse() {
                            return mybox(future::ok((conn, SocketAddr::new(ip, port))))
                        }

                        let name = match Name::parse(hostname, Some(&Name::root())).map_err(|e| {
                            io::Error::new(io::ErrorKind::Other, e.to_string())
                        }) {
                            Ok(v) => v,
                            Err(e) => return mybox(future::err(e)),
                        };

                        let ipv4 = dns.lookup(name, port);
                        mybox(ipv4.map(|addr| (conn, addr)))
                        //let (name, port) = match name_port(&buf) {
                            //Ok(UrlHost::Name(name, port)) => (name, port),
                            //Ok(UrlHost::Addr(addr)) => {
                                //return mybox(future::ok((conn, addr)))
                            //}
                            //Err(e) => return mybox(future::err(e)),
                        //};

                    }))
                },
                n => {
                    let msg = format!("unknown ATYP received: {}", n);
                    mybox(future::err(other(&msg)))
                },
            }
        }));
    }
}

fn mybox<F: Future + 'static>(f: F) -> Box<Future<Item=F::Item, Error=F::Error>> {
    Box::new(f)
}


fn other(desc: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, desc)
}
