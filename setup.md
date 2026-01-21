# Setup Steps and Requirements

## Prerequisites

- Linux Kernel 20.04+
- Kernel Capabilities (CAP_BPF, CAP_PERFMON, CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_SYSLOG, CAP_IPC_LOCK)
- Go 1.22
- Clang compiler
- Access to /sys/kernel/btf/vmlinux

```bash
sudo apt update
sudo apt install -y \
    git make gcc pkg-config \
    clang llvm libelf-dev zlib1g-dev
```


## Build

```bash

# Build ebpf exporter
make build

# Build BPF objects
make -C examples clean build

# Run exporter with example config
sudo ./ebpf_exporter --config.dir=examples --config.names=accept-latency

# Check metrics
curl -s localhost:9435/metrics | grep -E 'accept_latency_seconds|tcp_syn_backlog|ebpf_exporter'

```
