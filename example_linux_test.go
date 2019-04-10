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

// +build linux
// +build 386 arm amd64

package seccomp_test

import (
	"fmt"

	seccomp "github.com/elastic/go-seccomp-bpf"
)

func Example() {
	// Create a filter.
	filter := seccomp.Filter{
		NoNewPrivs: true,
		Flag:       seccomp.FilterFlagTSync,
		Policy: seccomp.Policy{
			DefaultAction: seccomp.ActionAllow,
			Syscalls: []seccomp.SyscallGroup{
				{
					Action: seccomp.ActionErrno,
					Names: []string{
						"fork",
						"vfork",
						"execve",
						"execveat",
					},
				},
			},
		},
	}

	// Load it. This will set no_new_privs before loading.
	if err := seccomp.LoadFilter(filter); err != nil {
		fmt.Println("failed to load filter: ", err)
		return
	}
}
