# n-rt-onl-ebpf

# Linux

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

# macOS and Windows

