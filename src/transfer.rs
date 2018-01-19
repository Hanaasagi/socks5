extern crate tokio_core;
extern crate futures;

use std::rc::Rc;
use std::cell::RefCell;
use std::io::{self, Read, Write};
use std::net::Shutdown;

use futures::{Poll, Future, Async};
use tokio_core::net::{TcpStream};

pub struct Transfer {
    reader: Rc<TcpStream>,
    writer: Rc<TcpStream>,
    buf: Rc<RefCell<Vec<u8>>>,
    amt: u64,
}

impl Transfer {
    pub fn new(reader: Rc<TcpStream>, writer: Rc<TcpStream>,
           buffer: Rc<RefCell<Vec<u8>>>) -> Transfer {
        Transfer {
            reader: reader,
            writer: writer,
            buf: buffer,
            amt: 0,
        }
    }
}

impl Future for Transfer {

    type Item = u64;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<u64, io::Error> {
        let mut buffer = self.buf.borrow_mut();

        loop {
            let read_ready  = self.reader.poll_read().is_ready();
            let write_ready = self.writer.poll_write().is_ready();

            if !(read_ready && write_ready) {
                return Ok(Async::NotReady)
            }

            let n = try_nb!((&*self.reader).read(&mut buffer));
            if n == 0 {
                try!(self.writer.shutdown(Shutdown::Write));
                return Ok(self.amt.into())
            }
            self.amt += n as u64;

            let _m = (&*self.writer).write(&buffer[..n])?;
            assert_eq!(n, _m);
        }
    }
}
