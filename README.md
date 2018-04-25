# go-seccomp-bpf

[![Build Status](http://img.shields.io/travis/elastic/go-seccomp-bpf.svg?style=flat-square)][travis]
[![Go Documentation](http://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)][godocs]

[travis]:   http://travis-ci.org/elastic/go-seccomp-bpf
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

- Requires Linux 3.17 because it uses `SECCOMP_FILTER_FLAG_TSYNC` in order to
  sync the filter to all threads created by the Go runtime.

###### Features

- Pure Go and does not have a libseccomp dependency.
- Filters are customizable and can be written a whitelist or blacklist.

###### Limitations

- System call argument filtering is not implemented. (Pull requests are
  welcomed.)

###### Example

See the `sandbox` example in [cmd/sandbox](./cmd/sandbox).

###### Projects using elastic/go-seccomp-bpf

- [elastic/beats](https://www.github.com/elastic/beats)
