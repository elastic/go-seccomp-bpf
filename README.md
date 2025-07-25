# go-seccomp-bpf

[![Go Report
Card](https://goreportcard.com/badge/github.com/elastic/go-seccomp-bpf)](https://goreportcard.com/report/github.com/elastic/go-seccomp-bpf)
[![Contributors](https://img.shields.io/github/contributors/elastic/go-seccomp-bpf.svg)](https://github.com/elastic/go-seccomp-bpf/graphs/contributors)
[![GitHub release](https://img.shields.io/github/release/elastic/go-seccomp-bpf.svg?label=changelog)](https://github.com/elastic/go-seccomp-bpf/releases/latest)
[![Go Documentation](http://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)][godocs]

[godocs]:   http://godoc.org/github.com/elastic/go-seccomp-bpf

go-seccomp-bpf is a library for Go (golang) for loading a system call filter on
Linux 3.17 and later by taking advantage of secure computing mode, also known as
seccomp. Seccomp restricts the system calls that a process can invoke.

The kernel exposes a large number of system calls that are not used by most
processes. By installing a seccomp filter, you can limit the total kernel
surface exposed to a process (principle of least privilege). This minimizes
the impact of unknown vulnerabilities that might be found in the process.

The filter is expressed as a Berkeley Packet Filter (BPF) program. The BPF
program is generated based on a filter policy created by you.

###### Requirements

- Requires Linux 3.17 because it uses the `seccomp` syscall in order to take
  advantage of the `SECCOMP_FILTER_FLAG_TSYNC` flag to sync the filter to all
  threads.

###### Features

- Pure Go and does not have a libseccomp dependency.
- Filters are customizable and can be written as an allowlist or blocklist.
- Supports system call argument filtering.
- Uses `SECCOMP_FILTER_FLAG_TSYNC` to sync the filter to all threads created by
  the Go runtime.
- Invokes `prctl(PR_SET_NO_NEW_PRIVS, 1)` to set the threads `no_new_privs` bit
  which is generally required before loading a seccomp filter.
- [seccomp-profiler](./cmd/seccomp-profiler) tool for automatically generating
  a allowlist policy based on the system calls that a binary uses.

###### Limitations

- System call tables are only implemented for 386, amd64, arm and arm64.
  (More system call table generation code should be added to
  [arch/mk_syscalls_linux.go](./arch/mk_syscalls_linux.go).)

###### Examples

- [GoDoc Package Example](https://godoc.org/github.com/elastic/go-seccomp-bpf#example-package)
- `sandbox` example in [cmd/sandbox](./cmd/sandbox).
 
###### Updating syscalls for new Linux releases

This package contains a list of syscall numbers that are generated from the
Linux sources. Update the git tag [here](https://github.com/elastic/go-seccomp-bpf/blob/b57d796185ac9f05fc0483554da79c4bbaedcc97/arch/mk_syscalls_linux.go)
and then run this command to generate the code.

```shell
docker run -it --rm -v `pwd`:/go-seccomp-bpf -w /go-seccomp-bpf/arch golang:1.23.0 go generate
```

###### Projects Using elastic/go-seccomp-bpf

Please open a PR to submit your project.

- [elastic/beats](https://www.github.com/elastic/beats)
