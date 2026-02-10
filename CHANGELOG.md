# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

- Update syscall table based on linux v6.16. [52](https://github.com/elastic/go-seccomp-bpf/pull/52)
- Update syscall table based on linux v6.17. [55](https://github.com/elastic/go-seccomp-bpf/pull/55)
- Update syscall table based on linux v6.18. [57](https://github.com/elastic/go-seccomp-bpf/pull/57)
- Update syscall table based on linux v6.19. [58](https://github.com/elastic/go-seccomp-bpf/pull/58)

### Deprecated

### Removed

### Fixed

### Security

## [1.6.0] - 2025-06-20

### Changed

- Updated syscall table based on Linux v6.15. [#47](https://github.com/elastic/go-seccomp-bpf/pull/47)
- Update Go module version 1.23.0. [#50](https://github.com/elastic/go-seccomp-bpf/pull/50)

### Fixed

- Fixed a control flow bug in the filter when multiple syscall groups are defined. [#40](https://github.com/elastic/go-seccomp-bpf/issues/40)

## [1.5.0] - 2024-11-06

### Changed

- Updated syscall tables based on Linux v6.11. [#36](https://github.com/elastic/go-seccomp-bpf/pull/36)

## [1.4.0] - 2023-11-21

### Added

- Added system call argument filtering. [#28](https://github.com/elastic/go-seccomp-bpf/pull/28)

### Changed

- Updated syscall tables for Linux v6.6 to add cachestat, fchmodat2, map_shadow_stack. [#27](https://github.com/elastic/go-seccomp-bpf/pull/27) [#30](https://github.com/elastic/go-seccomp-bpf/pull/30)

## [1.3.0] - 2022-11-27

### Changed

- Updated go.mod to require Go 1.18. [#20](https://github.com/elastic/go-seccomp-bpf/pull/20)
- Updated syscall tables for Linux v6.0. [#19](https://github.com/elastic/go-seccomp-bpf/pull/19)

## [1.2.0] - 2021-09-15

### Added

- Added support for arm64. [#15](https://github.com/elastic/go-seccomp-bpf/pull/15)

### Changed

- Updated syscall tables for Linux v5.14. [#16](https://github.com/elastic/go-seccomp-bpf/pull/16)

## [1.1.0] - 2019-04-10

### Added
- Added go.mod file. [#10](https://github.com/elastic/go-seccomp-bpf/pull/10)
- Added new syscalls to be in sync with Linux v5.0. [#11](https://github.com/elastic/go-seccomp-bpf/pull/11)

### Fixed
- Fixed integer overflow in BPF conditional jumps when using long lists of
  syscalls (>256). [#9](https://github.com/elastic/go-seccomp-bpf/pull/9)

## [1.0.0] - 2018-05-17

### Added
- Initial release.

[Unreleased]: https://github.com/elastic/go-seccomp-bpf/compare/v1.6.0...HEAD
[1.6.0]: https://github.com/elastic/go-seccomp-bpf/releases/v1.6.0
[1.5.0]: https://github.com/elastic/go-seccomp-bpf/releases/v1.5.0
[1.4.0]: https://github.com/elastic/go-seccomp-bpf/releases/v1.4.0
[1.3.0]: https://github.com/elastic/go-seccomp-bpf/releases/v1.3.0
[1.2.0]: https://github.com/elastic/go-seccomp-bpf/releases/v1.2.0
[1.1.0]: https://github.com/elastic/go-seccomp-bpf/releases/v1.1.0
[1.0.0]: https://github.com/elastic/go-seccomp-bpf/releases/v1.0.0
