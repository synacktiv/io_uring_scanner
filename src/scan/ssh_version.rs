//! SSH scan to grab server version

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

use crate::config::{CommandLineOptions, SshVersionScanOptions};
use crate::ring::{BufferDirection, BufferInfo, EntryInfo, RingAllocator};
use crate::scan::{check_op_supported, PushError, RawFd, Scan, SockaddrIn};

pub struct ScanSshVersion {
    opts: SshVersionScanOptions,
}

/// Describes what scan step does an entry do
#[derive(Debug)]
enum EntryStep {
    Connect = 0,
    ConnectTimeout,
    Recv,
    RecvTimeout,
    Close,
}

impl From<u8> for EntryStep {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Connect,
            1 => Self::ConnectTimeout,
            2 => Self::Recv,
            3 => Self::RecvTimeout,
            4 => Self::Close,
            _ => unreachable!(),
        }
    }
}

impl ScanSshVersion {
    /// Parse response and log match
    fn handle_response(&self, addr: &SockaddrIn, buf: &[u8]) {
        if self.opts.regex.as_ref().map_or(true, |r| r.is_match(buf)) {
            println!("{} {:?}", Ipv4Addr::from(addr.ip()), buf.as_bstr());
        }
    }

    pub fn new(opts: &SshVersionScanOptions) -> Self {
        Self {
            opts: opts.to_owned(),
        }
    }
}

impl Scan for ScanSshVersion {
    fn check_supported(&self, probe: &Probe) {
        check_op_supported(probe, opcode::Connect::CODE, "connect");
        check_op_supported(probe, opcode::LinkTimeout::CODE, "link timeout");
        check_op_supported(probe, opcode::ReadFixed::CODE, "read fixed");
        check_op_supported(probe, opcode::Close::CODE, "close");
    }

    fn max_tx_size(&mut self) -> Option<usize> {
        None
    }

    fn ops_per_ip(&self) -> usize {
        5
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
                let ret = cq_entry.result();
                if ret > 0 {
                    let buf = ring_allocator.get_buf(entry_info.buf.as_ref().unwrap().idx);
                    self.handle_response(&entry_info.ip, &buf[..ret as usize]);
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
