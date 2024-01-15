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
	SECCOMP_RET_USER_NOTIF   = linux.SECCOMP_RET_USER_NOTIF
)

const (
	EPERM  = linux.EPERM
	ENOSYS = linux.ENOSYS
)

const (
	SECCOMP_FILTER_FLAG_TSYNC = linux.SECCOMP_FILTER_FLAG_TSYNC
	SECCOMP_FILTER_FLAG_LOG   = linux.SECCOMP_FILTER_FLAG_LOG
)
