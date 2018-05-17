// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

// +build ignore

package seccomp

// #include <errno.h>
// #include <linux/filter.h>
// #include <linux/seccomp.h>
// #include <sys/prctl.h>
// #include <stdlib.h>
import "C"

// prSetNoNewPrivs defines the prctl flag to set the calling thread's
// no_new_privs bit.
const prSetNoNewPrivs = C.PR_SET_NO_NEW_PRIVS

// Valid operations for seccomp syscall.
// https://github.com/torvalds/linux/blob/v4.16/include/uapi/linux/seccomp.h#L14-L17
const (
	// Seccomp filter mode where only system calls that the calling thread is
	// permitted to make are read(2), write(2), _exit(2) (but not
	// exit_group(2)), and sigreturn(2). Flags must be 0.
	seccompSetModeStrict = C.SECCOMP_SET_MODE_STRICT

	// Seccomp filter mode where a BPF filter defines what system calls are
	// allowed.
	seccompSetModeFilter = C.SECCOMP_SET_MODE_FILTER
)

// The arch field is not unique for all calling conventions.  The x86-64
// ABI and the x32 ABI both use AUDIT_ARCH_X86_64 as arch, and they run
// on the same processors.  Instead, the mask __X32_SYSCALL_BIT is used
// on the system call number to tell the two ABIs apart.
// https://github.com/torvalds/linux/blob/v4.16/arch/x86/include/uapi/asm/unistd.h#L6
const x32SyscallMask = 0x40000000

// List of actions.
// https://github.com/torvalds/linux/blob/v4.16/include/uapi/linux/seccomp.h#L32-L39
const (
	ActionKillThread  Action = C.SECCOMP_RET_KILL_THREAD  // Kill the calling thread.
	ActionKillProcess Action = C.SECCOMP_RET_KILL_PROCESS // Kill the process (since kernel 4.14).
	ActionTrap        Action = C.SECCOMP_RET_TRAP         // Disallow and force a SIGSYS signal.
	ActionErrno       Action = C.SECCOMP_RET_ERRNO        // Disallow and return an errno.
	ActionTrace       Action = C.SECCOMP_RET_TRACE        // Pass to a tracer or disallow.
	ActionLog         Action = C.SECCOMP_RET_LOG          // Allow after logging.
	ActionAllow       Action = C.SECCOMP_RET_ALLOW        // Allow.
)

const (
	errnoEPERM  = C.EPERM
	errnoENOSYS = C.ENOSYS
)

// List of SECCOMP_SET_MODE_FILTER values.
// https://github.com/torvalds/linux/blob/v4.16/include/uapi/linux/seccomp.h#L19-L21
const (
	// When adding a new filter, synchronize all other threads of the calling
	// process to the same seccomp filter tree. Since Linux 3.17.
	FilterFlagTSync FilterFlag = C.SECCOMP_FILTER_FLAG_TSYNC

	// All filter return actions except SECCOMP_RET_ALLOW should be logged.
	// Since Linux 4.14.
	FilterFlagLog FilterFlag = C.SECCOMP_FILTER_FLAG_LOG
)
