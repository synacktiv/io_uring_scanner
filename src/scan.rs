//! Scan type specific logic

use std::os::unix::io::RawFd;

use io_uring::{
    cqueue,
    squeue::{PushError, SubmissionQueue},
    types::Timespec,
    Probe,
};
use nix::sys::socket::SockaddrIn;

use crate::ring::{EntryInfo, RingAllocator};

pub mod http_header_match;
pub mod ssh_version;

pub struct Timeouts {
    pub connect: Timespec,
    pub read: Timespec,
    pub write: Timespec,
}

/// Network scan
pub trait Scan {
    /// Check if this scan is supported by the kernel io_uring code, panics if it does not
    fn check_supported(&self, probe: &Probe);

    /// Maximum byte count we need to send (used to pre allocate buffers)
    fn max_tx_size(&mut self) -> Option<usize>;

    /// Number of io_uring ops we need to scan a single IP
    fn ops_per_ip(&self) -> usize;

    /// Process a completed entry, returns true if this is the last one for an IP
    fn process_completed_entry(
        &self,
        cq_entry: &cqueue::Entry,
        entry_info: &EntryInfo,
        ring_allocator: &RingAllocator,
    ) -> bool;

    /// Push ring ops to scan peer IP
    fn push_scan_ops(
        &mut self,
        sckt: RawFd,
        ip: &SockaddrIn,
        squeue: &mut SubmissionQueue,
        allocator: &mut RingAllocator,
        timeouts: &Timeouts,
    ) -> Result<usize, PushError>;

    /// Create a socket for this scan
    fn socket(&self) -> RawFd;
}

fn check_op_supported(probe: &Probe, opcode: u8, name: &str) {
    assert!(
        probe.is_supported(opcode),
        "This kernel does not support io_uring op code {} ({:?})",
        name,
        opcode
    );
}

pub fn can_push(squeue: &SubmissionQueue, scan: &dyn Scan, allocator: &RingAllocator) -> bool {
    let ops_per_ip = scan.ops_per_ip();
    allocator.has_free_entry_count(ops_per_ip) && (squeue.capacity() - squeue.len() >= ops_per_ip)
}
