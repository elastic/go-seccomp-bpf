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

//go:build !linux
// +build !linux

package unix

const PR_SET_NO_NEW_PRIVS = 0x26

const (
	SECCOMP_SET_MODE_STRICT = 0x0
	SECCOMP_SET_MODE_FILTER = 0x1
)

const (
	SECCOMP_RET_KILL_THREAD  = 0x0
	SECCOMP_RET_KILL_PROCESS = 0x80000000
	SECCOMP_RET_TRAP         = 0x30000
	SECCOMP_RET_ERRNO        = 0x50000
	SECCOMP_RET_TRACE        = 0x7ff00000
	SECCOMP_RET_LOG          = 0x7ffc0000
	SECCOMP_RET_ALLOW        = 0x7fff0000
	SECCOMP_RET_USER_NOTIF   = 0x7fc00000
)

const (
	EPERM  = 0x1
	ENOSYS = 0x26
)

const (
	SECCOMP_FILTER_FLAG_TSYNC = 0x1
	SECCOMP_FILTER_FLAG_LOG   = 0x2
)
