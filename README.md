# io_uring scanner

`io_uring` based network scanner written in Rust.

Supports 3 scan modes:

* TCP connect
* SSH version match (regular expression matching)
* HTTP header match (regular expression matching on reponse header)

## Build from source

You need a Rust build environment for example from [rustup](https://rustup.rs/).

```
cargo build --release
# binary is built as target/release/io_uring_scanner
```

## Usage

Run `io_uring_scanner -h` for detailed command line usage help with examples.

## License

[GPLv3](https://www.gnu.org/licenses/gpl-3.0.html)
