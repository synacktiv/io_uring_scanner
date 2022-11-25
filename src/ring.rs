//! Tracks ring entries & buffer state

use std::ffi::c_void;
use std::os::unix::io::RawFd;
use std::rc::Rc;

use io_uring::Submitter;
pub use nix::libc::iovec;
use nix::sys::socket::SockaddrIn;

pub type EntryIdx = u64;

#[derive(Clone)]
pub struct EntryInfo {
    pub ip: Rc<SockaddrIn>,
    pub step: u8,
    pub buf: Option<BufferInfo>,
    pub fd: RawFd,
}

pub type BufferIdx = usize;

pub struct Buffer {
    pub idx: BufferIdx,
    pub iov: iovec,
}

#[derive(Clone)]
pub struct BufferInfo {
    pub idx: BufferIdx,
    pub direction: BufferDirection,
}

#[derive(Clone, Debug)]
pub enum BufferDirection {
    RX,
    TX,
}

pub struct RingAllocator {
    buffers: Vec<Vec<u8>>,
    rx_buf_size: usize,
    tx_buf_size: Option<usize>,
    entries: Vec<Option<EntryInfo>>,
    free_entry_idx: Vec<EntryIdx>,
    free_rx_buf_idx: Vec<BufferIdx>,
    free_tx_buf_idx: Vec<BufferIdx>,
}

impl RingAllocator {
    pub fn new(
        ring_size: usize,
        rx_buf_size: usize,
        tx_buf_size: Option<usize>,
        submitter: &Submitter,
    ) -> Self {
        let mut buffers = Vec::with_capacity(ring_size * 2);
        buffers.append(&mut vec![vec![0; rx_buf_size]; ring_size]);
        if let Some(tx_buf_size) = tx_buf_size {
            buffers.append(&mut vec![vec![0; tx_buf_size]; ring_size]);
        }
        let iovs: Vec<iovec> = buffers
            .iter_mut()
            .enumerate()
            .map(|(i, b)| iovec {
                iov_base: b.as_mut_ptr() as *mut c_void,
                iov_len: if i < ring_size {
                    rx_buf_size
                } else if let Some(tx_buf_size) = tx_buf_size {
                    tx_buf_size
                } else {
                    unreachable!()
                },
            })
            .collect();
        submitter
            .register_buffers(&iovs)
            .expect("Failed to register buffers");

        Self {
            buffers,
            rx_buf_size,
            tx_buf_size,
            entries: vec![None; ring_size],
            free_entry_idx: (0..ring_size as EntryIdx).collect(),
            free_rx_buf_idx: (0..ring_size).collect(),
            free_tx_buf_idx: (ring_size..ring_size * 2).collect(),
        }
    }

    pub fn get_entry(&self, idx: EntryIdx) -> &EntryInfo {
        self.entries[idx as usize]
            .as_ref()
            .expect("Unallocated entry")
    }

    pub fn has_free_entry_count(&self, count: usize) -> bool {
        self.free_entry_idx.len() >= count
    }

    pub fn allocated_entry_count(&self) -> usize {
        self.entries.capacity() - self.free_entry_idx.len()
    }

    pub fn free_entry(&mut self, idx: EntryIdx) {
        if let Some(buf) = &self.entries[idx as usize].as_ref().unwrap().buf {
            let buf = buf.clone();
            self.free_buf(&buf.direction, buf.idx);
        }
        log::trace!("Freeing entry #{idx}");
        self.free_entry_idx.push(idx);
        self.entries[idx as usize] = None;
    }

    pub fn alloc_entry(&mut self, info: EntryInfo) -> Option<EntryIdx> {
        match self.free_entry_idx.pop() {
            Some(idx) => {
                log::trace!("Allocating entry #{idx}");
                debug_assert!(self.entries[idx as usize].is_none());
                self.entries[idx as usize] = Some(info);
                Some(idx)
            }
            None => {
                log::trace!("No free entry");
                None
            }
        }
    }

    pub fn get_buf(&self, idx: BufferIdx) -> &Vec<u8> {
        &self.buffers[idx]
    }

    pub fn free_buf(&mut self, direction: &BufferDirection, idx: BufferIdx) {
        log::trace!("Freeing {direction:?} buf #{idx}");
        match direction {
            BufferDirection::RX => &mut self.free_rx_buf_idx,
            BufferDirection::TX => &mut self.free_tx_buf_idx,
        }
        .push(idx)
    }

    pub fn alloc_buf(&mut self, direction: BufferDirection, init_val: Option<&[u8]>) -> Buffer {
        let idx = match direction {
            BufferDirection::RX => &mut self.free_rx_buf_idx,
            BufferDirection::TX => &mut self.free_tx_buf_idx,
        }
        .pop()
        .expect("No free buffers");

        let iov = iovec {
            iov_base: self.buffers[idx].as_mut_ptr().cast::<c_void>(),
            iov_len: match direction {
                BufferDirection::RX => self.rx_buf_size,
                BufferDirection::TX => self.tx_buf_size.expect("TX buffer size was not set"),
            },
        };

        log::trace!("Allocating {direction:?} buf #{idx}: {iov:?}");

        if let Some(init_val) = init_val {
            self.buffers[idx][..init_val.len()].copy_from_slice(init_val);
        }

        Buffer { idx, iov }
    }
}
