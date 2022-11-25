#![feature(byte_slice_trim_ascii)]

use std::cmp::min;
use std::fmt::Write;
use std::io;
use std::net::SocketAddrV4;
use std::os::fd::AsRawFd;
use std::time::Duration;

use indicatif::{HumanDuration, ProgressBar, ProgressState, ProgressStyle};
use io_uring::types::Timespec;
use io_uring::{IoUring, Probe};
use iprange::IpRange;
use nix::sys::{resource, socket::SockaddrIn};
use structopt::StructOpt;

use scan::http_header_match::ScanHttpHeaderMatch;
use scan::ssh_version::ScanSshVersion;
use scan::tcp_connect::ScanTcpConnect;
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
        config::ScanOptions::TcpConnect(_) => Box::new(ScanTcpConnect::new()),
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
            .template(
                "Scanning IPs {msg} {wide_bar} {pos}/{len} ({smoothed_per_sec}) ETA {smoothed_eta}",
            )
            .unwrap()
            .with_key(
                "smoothed_eta",
                |s: &ProgressState, w: &mut dyn Write| match (s.pos(), s.len()) {
                    (pos, Some(len)) => write!(
                        w,
                        "{:#}",
                        HumanDuration(Duration::from_millis(
                            (s.elapsed().as_millis() * (len as u128 - pos as u128) / (pos as u128))
                                as u64
                        ))
                    )
                    .unwrap(),
                    _ => write!(w, "-").unwrap(),
                },
            )
            .with_key(
                "smoothed_per_sec",
                |s: &ProgressState, w: &mut dyn Write| match (s.pos(), s.elapsed().as_millis()) {
                    (pos, elapsed_ms) if elapsed_ms > 0 => {
                        write!(w, "{:.2}/s", pos as f64 * 1000_f64 / elapsed_ms as f64).unwrap()
                    }
                    _ => write!(w, "-").unwrap(),
                },
            ),
    );

    // Build timeouts for direct use by io_uring
    let timeouts = scan::Timeouts {
        connect: Timespec::new().sec(cl_opts.timeout_connect_secs),
        read: Timespec::new().sec(cl_opts.timeout_read_secs),
        write: Timespec::new().sec(cl_opts.timeout_write_secs),
    };

    let mut done = false;
    while !done {
        while can_push(&iorings.submission(), &*scan, &ring_allocator) {
            if let Some(ip_addr) = ip_iter.next() {
                let addr = SockaddrIn::from(SocketAddrV4::new(ip_addr, cl_opts.port));
                let sckt = scan.socket();
                log::trace!("New socket: {}", sckt);

                scan.push_scan_ops(
                    sckt.as_raw_fd(),
                    &addr,
                    &mut iorings.submission(),
                    &mut ring_allocator,
                    &timeouts,
                )
                .expect("Failed to push ring ops");
            } else if ring_allocator.allocated_entry_count() == 0 {
                done = true;
                break;
            } else {
                break;
            }
        }

        let completed_count = iorings.completion().len();
        log::trace!("Completed count before wait: {completed_count}");
        iorings.submit_and_wait(min(
            cl_opts.ring_batch_size,
            ring_allocator.allocated_entry_count() - completed_count,
        ))?;
        log::trace!("Completed count after wait: {}", iorings.completion().len());

        for ce in iorings.completion() {
            let entry = ring_allocator.get_entry(ce.user_data());
            if scan.process_completed_entry(&ce, entry, &ring_allocator) {
                progress.inc(1);
            }
            ring_allocator.free_entry(ce.user_data());
        }
    }
    progress.finish();

    Ok(())
}
