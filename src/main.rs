#![feature(byte_slice_trim_ascii)]

// TODO clippy pedantic + deny unwrap

use std::cmp::min;
use std::io;
use std::net::SocketAddrV4;
use std::os::fd::AsRawFd;

use indicatif::{ProgressBar, ProgressStyle};
use io_uring::{IoUring, Probe};
use iprange::IpRange;
use nix::sys::{resource, socket::SockaddrIn};
use structopt::StructOpt;

use scan::http_header_match::ScanHttpHeaderMatch;
use scan::ssh_version::ScanSshVersion;
use scan::{can_push, Scan};

mod config;
mod ring;
mod scan;

fn main() -> io::Result<()> {
    // Init logger
    simple_logger::SimpleLogger::new()
        .init()
        .expect("Failed to init logger");

    // Parse command line args
    let cl_opts = config::CommandLineOptions::from_args();
    log::trace!("{:?}", cl_opts);

    // Bump limit of open files
    let (soft_limit, hard_limit) = resource::getrlimit(resource::Resource::RLIMIT_NOFILE).unwrap();
    resource::setrlimit(resource::Resource::RLIMIT_NOFILE, hard_limit, hard_limit).unwrap();
    log::info!("Bumped RLIMIT_NOFILE from {soft_limit} to {hard_limit}");

    // TODO tweak via builder
    let mut iorings = IoUring::new(cl_opts.ring_size as u32)?;

    let mut scan: Box<dyn Scan> = match &cl_opts.scan_opts {
        config::ScanOptions::HttpHeaderMatch(scan_opts) => {
            Box::new(ScanHttpHeaderMatch::new(scan_opts))
        }
        config::ScanOptions::SshVersion(scan_opts) => Box::new(ScanSshVersion::new(scan_opts)),
    };

    // Probe
    let mut probe = Probe::new();
    iorings.submitter().register_probe(&mut probe)?;
    scan.check_supported(&probe);

    // Init map to track ring state
    let mut ring_allocator = ring::RingAllocator::new(
        cl_opts.ring_size,
        cl_opts.max_read_size,
        scan.max_tx_size(),
        &iorings.submitter(),
    );

    let ip_ranges = cl_opts.ip_subnets.iter().copied().collect::<IpRange<_>>();
    let total_ip_count: usize = ip_ranges.iter().map(|r| r.hosts().count()).sum();
    let mut ip_iter = ip_ranges.iter().flat_map(|r| r.hosts());

    let progress = ProgressBar::new(total_ip_count as u64);
    progress.set_style(
        ProgressStyle::default_bar()
            .template("Scanning IPs {msg} {wide_bar} {pos}/{len} ({per_sec}) ETA {eta}")
            .unwrap(),
    );

    loop {
        let mut wait = false;
        if can_push(&iorings.submission(), &*scan, &ring_allocator) {
            if let Some(ip_addr) = ip_iter.next() {
                let addr = SockaddrIn::from(SocketAddrV4::new(ip_addr, cl_opts.port));
                let sckt = scan.socket();
                log::trace!("New socket: {}", sckt);

                scan.push_scan_ops(
                    sckt.as_raw_fd(),
                    &addr,
                    &mut iorings.submission(),
                    &mut ring_allocator,
                    &cl_opts,
                )
                .expect("Failed to push ring ops");
                iorings.submission().sync();
            } else if ring_allocator.allocated_entry_count() == 0 {
                break;
            } else {
                wait = true;
            };
        } else {
            wait = true;
        }
        if wait {
            iorings.submit_and_wait(min(
                cl_opts.ring_batch_size,
                total_ip_count - progress.length().unwrap() as usize,
            ))?;
        } else {
            iorings.submit()?;
        }
        for ce in iorings.completion() {
            let entry = ring_allocator.get_entry(ce.user_data());
            if scan.process_completed_entry(&ce, entry, &ring_allocator) {
                progress.inc(1);
            }
            ring_allocator.free_entry(ce.user_data());
        }
        iorings.completion().sync();
    }
    progress.finish();

    Ok(())
}