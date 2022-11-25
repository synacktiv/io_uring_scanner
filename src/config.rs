//! Command line option handling

use std::str::FromStr;

use ipnet::Ipv4Net;

/// Command line options
#[derive(Debug, structopt::StructOpt)]
#[structopt(version=env!("CARGO_PKG_VERSION"), about="io_uring based network scanner.", long_about=r#"
Examples:
  - Look for Nginx servers on 192.168.0.1/24:
    io_uring_scanner 80 192.168.0.1/24 http-header-match --resp-header-regex 'Server: ^nginx'
  - Look for OpenSSH 8.4 servers on 10.0.0.1/16:
    io_uring_scanner 22 10.0.0.1/16 ssh-version '^SSH-2\.0-OpenSSH_8\.4'
"#)]
pub struct CommandLineOptions {
    /// TCP port to scan
    pub port: u16,

    /// IPv4 subnets to scan
    pub ip_subnets: Vec<Ipv4Net>,

    /// Maximum count of preallocated sockets
    #[structopt(long = "max-prealloc-sockets", default_value = "16")]
    pub prealloc_socket_count: usize,

    /// io_uring submition/completion ring size, depending on the scan type 5-10 entries may be needed per IP
    #[structopt(long, default_value = "1024")]
    pub ring_size: usize,

    /// Number of ring entries to process at once
    #[structopt(long, default_value = "32")]
    pub ring_batch_size: usize,

    /// Socket connect timeout
    #[structopt(long = "connect-timeout-sec", default_value = "5")]
    pub timeout_connect_secs: u64,

    /// Socket read/recv timeout
    #[structopt(long = "read-timeout-sec", default_value = "2")]
    pub timeout_read_secs: u64,

    /// Socket write/send timeout
    #[structopt(long = "write-timeout-sec", default_value = "2")]
    pub timeout_write_secs: u64,

    /// Maximum byte count to read from socket
    #[structopt(long, default_value = "768")]
    pub max_read_size: usize,

    /// Scan specific options
    #[structopt(subcommand)]
    pub scan_opts: ScanOptions,
}

/// Scan specific options
#[derive(Debug, structopt::StructOpt)]
pub enum ScanOptions {
    HttpHeaderMatch(HttpHeaderMatchScanOptions),
    SshVersion(SshVersionScanOptions),
}

const HTTP_VERBS: [&str; 8] = [
    "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE",
];

/// HTTP header match scan options
#[derive(Debug, Clone, structopt::StructOpt)]
pub struct HttpHeaderMatchScanOptions {
    #[structopt(long = "req-verb", default_value = "GET", possible_values(&HTTP_VERBS))]
    pub request_verb: String,

    #[structopt(long = "req-uri", default_value = "/")]
    pub request_uri: String,

    // #[structopt(long = "req-data")]
    // pub request_data: Option<bstr::BString>,
    #[structopt(
        long = "req-header",
        help = "HTTP header to set in request, in 'key: value' form"
    )]
    pub request_headers: Vec<RequestHttpHeader>,

    #[structopt(
        long = "resp-header-regex",
        help = "Regex to match for in response header in 'key: regex' form. Multiple rules will match response if all rules do match."
    )]
    pub response_header_regexs: Vec<ResponseHttpHeaderRegex>,
}

#[derive(Debug, Clone)]
pub struct RequestHttpHeader {
    pub key: String,
    pub val: String,
}

impl FromStr for RequestHttpHeader {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<_> = s.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid request header format: {:?}", s));
        }

        let key = parts[0].to_string();
        let val = parts[1].trim_start().to_string();

        Ok(Self { key, val })
    }
}

#[derive(Debug, Clone, structopt::StructOpt)]
pub struct ResponseHttpHeaderRegex {
    pub key: String,
    pub val_regex: regex::bytes::Regex,
}

impl FromStr for ResponseHttpHeaderRegex {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<_> = s.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid response header regex format: {:?}", s));
        }

        let key = parts[0].to_string();
        let val_regex_str = parts[1].trim_start();
        let val_regex = regex::bytes::Regex::new(val_regex_str)
            .map_err(|e| format!("Invalid regex {:?}: {}", val_regex_str, e))?;

        Ok(Self { key, val_regex })
    }
}

/// SSH version scan options
#[derive(Debug, Clone, structopt::StructOpt)]
pub struct SshVersionScanOptions {
    /// Regex to match on version string
    pub regex: Option<regex::bytes::Regex>,
}
