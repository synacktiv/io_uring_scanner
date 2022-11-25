//! SSH scan to grab server version

use std::rc::Rc;

use io_uring::{cqueue, opcode, squeue, types::Fd, Probe};
use nix::{
    errno::Errno,
    libc,
    sys::socket::{socket, AddressFamily, SockFlag, SockType, SockaddrLike},
    unistd,
};

use crate::ring::{EntryInfo, RingAllocator};
use crate::scan::{check_op_supported, PushError, RawFd, Scan, SockaddrIn, Timeouts};

pub struct ScanTcpConnect {}

/// Describes what scan step does an entry do
#[derive(Debug)]
enum EntryStep {
    Connect = 0,
    ConnectTimeout,
    Close,
}

impl From<u8> for EntryStep {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Connect,
            1 => Self::ConnectTimeout,
            2 => Self::Close,
            _ => unreachable!(),
        }
    }
}

impl ScanTcpConnect {
    pub fn new() -> Self {
        Self {}
    }
}

impl Scan for ScanTcpConnect {
    fn check_supported(&self, probe: &Probe) {
        check_op_supported(probe, opcode::Connect::CODE, "connect");
        check_op_supported(probe, opcode::LinkTimeout::CODE, "link timeout");
        check_op_supported(probe, opcode::Close::CODE, "close");
    }

    fn max_tx_size(&mut self) -> Option<usize> {
        None
    }

    fn ops_per_ip(&self) -> usize {
        3
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
            EntryStep::Connect => {
                let ret = cq_entry.result();
                if ret == 0 {
                    println!("{}", &entry_info.ip);
                }
                false
            }
            EntryStep::Close => {
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
        timeouts: &Timeouts,
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
        let op_connect_timeout = opcode::LinkTimeout::new(&timeouts.connect)
            .build()
            .flags(squeue::Flags::IO_LINK)
            .user_data(entry_connect_timeout_idx);

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

        let ops = [op_connect, op_connect_timeout, op_close];
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
