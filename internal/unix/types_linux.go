//go:build linux
// +build linux

package unix

import (
	linux "golang.org/x/sys/unix"
)

const PR_SET_NO_NEW_PRIVS = linux.PR_SET_NO_NEW_PRIVS

const (
	SECCOMP_SET_MODE_STRICT = linux.SECCOMP_SET_MODE_STRICT
	SECCOMP_SET_MODE_FILTER = linux.SECCOMP_SET_MODE_FILTER
)

const (
	SECCOMP_RET_KILL_THREAD  = linux.SECCOMP_RET_KILL_THREAD
	SECCOMP_RET_KILL_PROCESS = linux.SECCOMP_RET_KILL_PROCESS
	SECCOMP_RET_TRAP         = linux.SECCOMP_RET_TRAP
	SECCOMP_RET_ERRNO        = linux.SECCOMP_RET_ERRNO
	SECCOMP_RET_TRACE        = linux.SECCOMP_RET_TRACE
	SECCOMP_RET_LOG          = linux.SECCOMP_RET_LOG
	SECCOMP_RET_ALLOW        = linux.SECCOMP_RET_ALLOW
)

const (
	EPERM  = linux.EPERM
	ENOSYS = linux.ENOSYS
)

const (
	SECCOMP_FILTER_FLAG_TSYNC = linux.SECCOMP_FILTER_FLAG_TSYNC
	SECCOMP_FILTER_FLAG_LOG   = linux.SECCOMP_FILTER_FLAG_LOG
)
