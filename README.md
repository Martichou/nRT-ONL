# n-rt-onl

**TLDR**: Operating system support:

| Operating System | userspace | ebpf |
|---|---|---|
| Windows | yes | no |
| macOS | yes | no |
| Linux | yes | yes |

Features:
- default: eBPF on Linux and userspace on macOS/Windows
- userspace: userspace on all OSes

# Linux (default - ebpf, userspace available)

The Linux version use eBPF with TC in order to perform the analysis on the TX/RX packets.

### Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

### Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

### Build Userspace

```bash
cargo build
```

### Run

```bash
export RUST_LOG=info
cargo xtask run
```

### Use the library

You can check the [example](examples/nrt_test/). You'll need to download the ebpf program
and place it somewhere accessible for the user running the binary.

# macOS and Windows (only userspace)

The macOS and Windows version use pnet's datalink::channel.

### Prerequisites

1. None, just Rust

### Run

```bash
export RUST_LOG=info
cargo run
```

### Use the library

Same as for the Linux (they share the same API), but you don't need to
specify the eBPF program path.