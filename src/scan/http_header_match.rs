//! HTTP scan to match by response headers

use std::fmt::Write;
use std::net::Ipv4Addr;
use std::rc::Rc;

use bstr::ByteSlice;
use io_uring::{
    cqueue, opcode, squeue,
    types::{Fd, Timespec},
    Probe,
};
use nix::{
    errno::Errno,
    libc,
    sys::socket::{socket, AddressFamily, SockFlag, SockType, SockaddrLike},
    unistd,
};

use crate::config::{CommandLineOptions, HttpHeaderMatchScanOptions};
use crate::ring::{BufferDirection, BufferInfo, EntryInfo, RingAllocator};
use crate::scan::{check_op_supported, PushError, RawFd, Scan, SockaddrIn};

pub struct ScanHttpHeaderMatch {
    opts: HttpHeaderMatchScanOptions,
    tx_buf_size: Option<usize>,
}

/// Describes what scan step does an entry do
#[derive(Debug)]
enum EntryStep {
    Connect = 0,
    ConnectTimeout,
    Send,
    SendTimeout,
    Recv,
    RecvTimeout,
    Close,
}

impl From<u8> for EntryStep {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Connect,
            1 => Self::ConnectTimeout,
            2 => Self::Send,
            3 => Self::SendTimeout,
            4 => Self::Recv,
            5 => Self::RecvTimeout,
            6 => Self::Close,
            _ => unreachable!(),
        }
    }
}

impl ScanHttpHeaderMatch {
    /// Parse response headers and log match
    fn handle_response(&self, addr: &SockaddrIn, buf: &[u8]) {
        // The parsing here never copies data from the response buffer
        // We also usr bstr to operate directly on &[u8] instead of &str which would require valid UTF-8
        // See https://www.rfc-editor.org/rfc/rfc2616.html#section-4.2
        let mut match_count = 0;
        for line in buf.lines() {
            if line.is_empty() {
                // double crlf, end of headers, bail out
                break;
            }
            if let Some((hdr_key, hdr_value)) = Self::parse_header_line(line) {
                for rule in self
                    .opts
                    .response_header_regexs
                    .iter()
                    .filter(|r| r.key.as_bytes() == hdr_key)
                {
                    if rule.val_regex.is_match(hdr_value) {
                        match_count += 1;
                    }
                }
            }
        }
        if match_count == self.opts.response_header_regexs.len() {
            println!("{}", Ipv4Addr::from(addr.ip()));
        }
    }

    pub fn new(opts: &HttpHeaderMatchScanOptions) -> Self {
        Self {
            opts: opts.to_owned(),
            tx_buf_size: None,
        }
    }

    fn parse_header_line(line: &[u8]) -> Option<(&[u8], &[u8])> {
        if let Some((key, value)) = line.split_once_str(":") {
            let key = key.trim_ascii_end();
            let value = value.trim_ascii_start();
            Some((key, value))
        } else {
            None
        }
    }

    fn format_request(&self, addr: &SockaddrIn) -> String {
        let mut s = if let Some(size_hint) = self.tx_buf_size {
            String::with_capacity(size_hint)
        } else {
            String::new()
        };
        write!(
            &mut s,
            "GET {} HTTP/1.1\r\nHost: {}\r\n",
            self.opts.relative_url, addr,
        )
        .unwrap();
        for hdr in &self.opts.request_headers {
            write!(&mut s, "{}: {}\r\n", hdr.key, hdr.val).unwrap();
        }
        write!(&mut s, "\r\n").unwrap();
        s
    }
}

impl Scan for ScanHttpHeaderMatch {
    fn check_supported(&self, probe: &Probe) {
        check_op_supported(probe, opcode::Connect::CODE, "connect");
        check_op_supported(probe, opcode::LinkTimeout::CODE, "link timeout");
        check_op_supported(probe, opcode::WriteFixed::CODE, "write fixed");
        check_op_supported(probe, opcode::ReadFixed::CODE, "read fixed");
        check_op_supported(probe, opcode::Close::CODE, "close");
    }

    fn max_tx_size(&mut self) -> Option<usize> {
        let sz = self
            .format_request(&SockaddrIn::new(255, 255, 255, 255, u16::MAX))
            .len();
        self.tx_buf_size = Some(sz);
        Some(sz)
    }

    fn ops_per_ip(&self) -> usize {
        7
    }

    fn process_completed_entry(
        &self,
        cq_entry: &cqueue::Entry,
        entry_info: &EntryInfo,
        ring_allocator: &RingAllocator,
    ) -> bool {
        let step = EntryStep::from(entry_info.step);
        let errno = Errno::from_i32(-cq_entry.result());
        log::debug!(
            "op #{} ({:?} {}) returned {} ({:?})",
            cq_entry.user_data(),
            step,
            entry_info.ip,
            cq_entry.result(),
            errno
        );
        if let Some(buf) = entry_info.buf.as_ref() {
            log::debug!(
                "buf: {:?}",
                String::from_utf8_lossy(ring_allocator.get_buf(buf.idx))
            );
        }
        match step {
            EntryStep::Recv => {
                if cq_entry.result() > 0 {
                    self.handle_response(
                        &entry_info.ip,
                        ring_allocator.get_buf(entry_info.buf.as_ref().unwrap().idx),
                    );
                }
                false
            }
            EntryStep::Close => {
                // TODO push to a channel to do this in another thread instead
                if cq_entry.result() == -libc::ECANCELED {
                    // if a previous entry errored and the socket close was canceled, do it now to avoid fd leak
                    unistd::close(entry_info.fd).unwrap();
                }
                true
            }
            _ => false,
        }
    }

    fn push_scan_ops(
        &mut self,
        sckt: RawFd,
        addr: &SockaddrIn,
        squeue: &mut io_uring::squeue::SubmissionQueue,
        allocator: &mut RingAllocator,
        cl_opts: &CommandLineOptions,
    ) -> Result<usize, PushError> {
        let addr = Rc::new(addr.to_owned());

        let entry_connect_idx = allocator
            .alloc_entry(EntryInfo {
                ip: Rc::clone(&addr),
                step: EntryStep::Connect as u8,
                buf: None,
                fd: sckt,
            })
            .unwrap();
        let op_connect = opcode::Connect::new(Fd(sckt), addr.as_ptr(), addr.len())
            .build()
            .flags(squeue::Flags::IO_LINK)
            .user_data(entry_connect_idx);

        let entry_connect_timeout_idx = allocator
            .alloc_entry(EntryInfo {
                ip: Rc::clone(&addr),
                step: EntryStep::ConnectTimeout as u8,
                buf: None,
                fd: sckt,
            })
            .unwrap();
        let op_connect_timeout =
            opcode::LinkTimeout::new(&Timespec::new().sec(cl_opts.timeout_connect_secs))
                .build()
                .flags(squeue::Flags::IO_LINK)
                .user_data(entry_connect_timeout_idx);

        let req = self.format_request(&addr);
        let tx_buffer = allocator.alloc_buf(BufferDirection::TX, Some(req.as_bytes()));
        let op_send_idx = allocator
            .alloc_entry(EntryInfo {
                ip: Rc::clone(&addr),
                step: EntryStep::Send as u8,
                buf: Some(BufferInfo {
                    idx: tx_buffer.idx,
                    direction: BufferDirection::TX,
                }),
                fd: sckt,
            })
            .unwrap();
        let op_send = opcode::WriteFixed::new(
            Fd(sckt),
            tx_buffer.iov.iov_base.cast::<u8>(),
            tx_buffer.iov.iov_len as u32,
            tx_buffer.idx as u16,
        )
        .build()
        .flags(squeue::Flags::IO_LINK)
        .user_data(op_send_idx);

        let entry_send_timeout_idx = allocator
            .alloc_entry(EntryInfo {
                ip: Rc::clone(&addr),
                step: EntryStep::SendTimeout as u8,
                buf: None,
                fd: sckt,
            })
            .unwrap();
        let op_send_timeout =
            opcode::LinkTimeout::new(&Timespec::new().sec(cl_opts.timeout_write_secs))
                .build()
                .flags(squeue::Flags::IO_LINK)
                .user_data(entry_send_timeout_idx);

        let rx_buffer = allocator.alloc_buf(BufferDirection::RX, None);
        let op_recv_idx = allocator
            .alloc_entry(EntryInfo {
                ip: Rc::clone(&addr),
                step: EntryStep::Recv as u8,
                buf: Some(BufferInfo {
                    idx: rx_buffer.idx,
                    direction: BufferDirection::RX,
                }),
                fd: sckt,
            })
            .unwrap();
        let op_recv = opcode::ReadFixed::new(
            Fd(sckt),
            rx_buffer.iov.iov_base.cast::<u8>(),
            rx_buffer.iov.iov_len as u32,
            rx_buffer.idx as u16,
        )
        .build()
        .flags(squeue::Flags::IO_LINK)
        .user_data(op_recv_idx);

        let entry_recv_timeout_idx = allocator
            .alloc_entry(EntryInfo {
                ip: Rc::clone(&addr),
                step: EntryStep::RecvTimeout as u8,
                buf: None,
                fd: sckt,
            })
            .unwrap();
        let op_recv_timeout =
            opcode::LinkTimeout::new(&Timespec::new().sec(cl_opts.timeout_read_secs))
                .build()
                .flags(squeue::Flags::IO_LINK)
                .user_data(entry_recv_timeout_idx);

        let entry_close_idx = allocator
            .alloc_entry(EntryInfo {
                ip: Rc::clone(&addr),
                step: EntryStep::Close as u8,
                buf: None,
                fd: sckt,
            })
            .unwrap();
        let op_close = opcode::Close::new(Fd(sckt))
            .build()
            .user_data(entry_close_idx);

        let ops = [
            op_connect,
            op_connect_timeout,
            op_send,
            op_send_timeout,
            op_recv,
            op_recv_timeout,
            op_close,
        ];
        unsafe {
            squeue.push_multiple(&ops).expect("Failed to push ops");
        }
        Ok(ops.len())
    }

    fn socket(&self) -> RawFd {
        socket(
            AddressFamily::Inet,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .expect("Failed to create TCP socket")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_header_line() {
        assert_eq!(ScanHttpHeaderMatch::parse_header_line("200 OK"), None);
        assert_eq!(
            ScanHttpHeaderMatch::parse_header_line("Server: srv 1.2.3"),
            Some(("Server", "srv 1.2.3"))
        );
        assert_eq!(
            ScanHttpHeaderMatch::parse_header_line(" Server: srv 1.2.3"),
            Some((" Server", "srv 1.2.3"))
        );
        assert_eq!(
            ScanHttpHeaderMatch::parse_header_line("Server:   srv 1.2.3"),
            Some(("Server", "srv 1.2.3"))
        );
        assert_eq!(
            ScanHttpHeaderMatch::parse_header_line("Server: srv 1.2.3  "),
            Some(("Server", "srv 1.2.3  "))
        );
        assert_eq!(
            ScanHttpHeaderMatch::parse_header_line("Server:: srv 1.2.3"),
            Some(("Server", ": srv 1.2.3"))
        );
    }
}
