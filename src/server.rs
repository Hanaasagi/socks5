extern crate futures;
extern crate tokio_core;
extern crate tokio_io;
extern crate trust_dns;
extern crate pretty_env_logger;
extern crate log;

use std::cell::RefCell;
use std::io;
use std::net::{SocketAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
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
                        info!("proxy {}", addr);
                        (c, SocketAddr::V4(addr))
                    }))
                },
                v5::ATYP_IPV6 => {
                    mybox(read_exact(c, [0u8; 18]).map(|(conn, buf)| {
                        let mut ip_bytes = vec![0u16; 8];
                        for i in 0..8 {
                            ip_bytes[i] = ((buf[2*i] as u16) << 8) | (buf[2*i+1] as u16);
                        }
                        let addr = Ipv6Addr::new(ip_bytes[0], ip_bytes[1],
                                                 ip_bytes[2], ip_bytes[3],
                                                 ip_bytes[4], ip_bytes[5],
                                                 ip_bytes[6], ip_bytes[7]);
                        let port = ((buf[16] as u16) << 8) | (buf[17] as u16);
                        let addr = SocketAddrV6::new(addr, port, 0, 0);
                        info!("proxy {}", addr);
                        (conn, SocketAddr::V6(addr))
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
                            let addr = SocketAddr::new(ip, port);
                            info!("proxy {}", addr);
                            return mybox(future::ok((conn, addr)))
                        }

                        let name = match Name::parse(hostname, Some(&Name::root())).map_err(|e| {
                            io::Error::new(io::ErrorKind::Other, e.to_string())
                        }) {
                            Ok(v) => v,
                            Err(e) => return mybox(future::err(e)),
                        };
                        info!("proxy {}:{}", name, port);
                        let ipv4 = dns.lookup(name, port);
                        mybox(ipv4.map(|addr| (conn, addr)))
                    }))
                },
                n => {
                    let msg = format!("unknown ATYP received: {}", n);
                    mybox(future::err(other(&msg)))
                },
            }
        }));


        let handle = self.handle.clone();
        let connected = mybox(addr.and_then(move |(c, addr)| {
            TcpStream::connect(&addr, &handle).then(move |c2| Ok((c, c2, addr)))
        }));

        let handshake_finish = mybox(connected.and_then(|(c1, c2, addr)| {
            // response buffer
            let mut resp = [0u8; 32];

            // protocal version
            resp[0] = 5;

            // rep field
            resp[1] = match c2 {
                Ok(..) => 0,
                Err(ref e) if e.kind() == io::ErrorKind::ConnectionRefused => 5,
                Err(..) => 1,
            };

            // rsv field
            resp[2] = 0;

            let addr = match c2.as_ref().map(|r| r.local_addr()) {
                Ok(Ok(addr)) => addr,
                Ok(Err(..)) |
                Err(..) => addr,
            };

            let pos = match addr {
                SocketAddr::V4(ref a) => {
                    resp[3] = 1;
                    resp[4..8].copy_from_slice(&a.ip().octets()[..]);
                    8
                }
                SocketAddr::V6(ref a) => {
                    resp[3] = 4;
                    let mut pos = 4;
                    for &segment in a.ip().segments().iter() {
                        resp[pos] = (segment >> 8) as u8;
                        resp[pos + 1] = segment as u8;
                        pos += 2;
                    }
                    pos
                }
            };
            resp[pos] = (addr.port() >> 8) as u8;
            resp[pos + 1] = addr.port() as u8;

            // Slice our 32-byte `resp` buffer to the actual size, as it's
            // variable depending on what address we just encoding. Once that's
            // done, write out the whole buffer to our client.
            //
            // The returned type of the future here will be `(TcpStream,
            // TcpStream)` representing the client half and the proxy half of
            // the connection.
            let mut w = Window::new(resp);
            w.set_end(pos + 2);
            write_all(c1, w).and_then(|(c1, _)| {
                c2.map(|c2| (c1, c2))
            })
        }));

        let timeout = Timeout::new(Duration::new(10, 0), &self.handle).unwrap();
        let pair = mybox(handshake_finish.map(Ok).select(timeout.map(Err)).then(|res| {
            match res {
                Ok((Ok(pair), _timeout)) => Ok(pair),
                Ok((Err(()), _handshake)) => {
                    Err(other("timeout during handshake"))
                },
                Err((e, _other)) => Err(e),
            }
        }));

        // shuttle data back and for between the two connections.
        // data is read from c1 and written to c2
        let buffer = self.buffer.clone();
        mybox(pair.and_then(|(c1, c2)| {
            let c1 = Rc::new(c1);
            let c2 = Rc::new(c2);

            let half1 = Transfer::new(c1.clone(), c2.clone(), buffer.clone());
            let half2 = Transfer::new(c2, c1, buffer);
            half1.join(half2)
        }))
    }
}

fn mybox<F: Future + 'static>(f: F) -> Box<Future<Item=F::Item, Error=F::Error>> {
    Box::new(f)
}

fn other(desc: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, desc)
}
