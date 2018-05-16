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

package seccomp

import (
	"net"
	"os"
	"os/exec"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"

	"github.com/elastic/go-seccomp-bpf/arch"
)

func TestLoadFilter(t *testing.T) {
	if !Supported() {
		t.Skip("seccomp not supported by kernel")
	}

	var policy Policy

	switch runtime.GOARCH {
	default:
		t.Skip("arch not implemented")
	case "arm":
		policy = Policy{
			DefaultAction: ActionAllow,
			Syscalls: []SyscallGroup{
				{
					Action: ActionErrno,
					Names: []string{
						"bind",
						"listen",
						"execve",
					},
				},
			},
		}
	case "386":
		policy = Policy{
			DefaultAction: ActionAllow,
			Syscalls: []SyscallGroup{
				{
					Action: ActionErrno,
					Names: []string{
						"bind",
						"listen",
						"execve",
						"socketcall",
					},
				},
			},
		}
	case "amd64":
		policy = Policy{
			DefaultAction: ActionAllow,
			Syscalls: []SyscallGroup{
				{
					arch:   arch.X86_64,
					Action: ActionErrno,
					Names: []string{
						"bind",
						"listen",
						"execve",
					},
				},
			},
		}
	}

	if *dump {
		policy.Dump(os.Stdout)
	}

	filter := Filter{
		NoNewPrivs: true,
		Flag:       FilterFlagTSync,
		Policy:     policy,
	}

	err := LoadFilter(filter)
	if err != nil {
		t.Fatal(err)
	}

	// Perform restricted syscalls.
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		assert.Contains(t, err.Error(), unix.EPERM.Error())
	} else {
		l.Close()
		t.Error("expected to receive an EPERM error when listening on socket")
	}

	_, err = exec.Command("ls", "-la").Output()
	if err != nil {
		assert.Contains(t, err.Error(), unix.EPERM.Error())
	} else {
		t.Error("expected to receive an EPERM error when exec'ing")
	}
}
