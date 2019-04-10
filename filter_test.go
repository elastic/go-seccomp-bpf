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

package seccomp

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"sort"
	"testing"

	"golang.org/x/net/bpf"

	"github.com/elastic/go-seccomp-bpf/arch"
)

var dump = flag.Bool("dump", false, "dump seccomp filter instructions to stdout")

// The simulator expects big-endian, but seccomp_data uses native endian.
// As a workaround send in big endian data.
// https://github.com/golang/go/issues/20556
// https://github.com/torvalds/linux/blob/v4.16/kernel/seccomp.c#L73-L74
var simulatorEndian = binary.BigEndian

type SeccompData struct {
	NR                 int32
	Arch               uint32
	InstructionPointer uint64
	Args               [6]uint64
}

type SeccompTest struct {
	Data SeccompData
	Rtn  Action
}

func simulateSyscalls(t testing.TB, policy *Policy, tests []SeccompTest) {
	t.Helper()

	filter, err := policy.Assemble()
	if err != nil {
		t.Fatal(err)
	}

	vm, err := bpf.NewVM(filter)
	if err != nil {
		t.Fatal(err)
	}

	for n, tc := range tests {
		buf := new(bytes.Buffer)
		if err := binary.Write(buf, simulatorEndian, tc.Data); err != nil {
			t.Fatal(err)
		}

		rtn, err := vm.Run(buf.Bytes())
		if err != nil {
			t.Fatal(err)
		}

		if Action(rtn) != tc.Rtn {
			t.Errorf("Expected %v, but got %v for test case %v with seccomp_data=%#v",
				tc.Rtn, rtn, n+1, tc.Data)
		}
	}
}

func TestPolicyAssembleBlacklist(t *testing.T) {
	policy := &Policy{
		arch:          arch.X86_64,
		DefaultAction: ActionAllow,
		Syscalls: []SyscallGroup{
			{
				Names:  []string{"execve", "fork"},
				Action: ActionKillThread,
			},
		},
	}

	if *dump {
		policy.Dump(os.Stdout)
	}

	simulateSyscalls(t, policy, []SeccompTest{
		{
			SeccompData{NR: 59, Arch: uint32(arch.X86_64.ID)},
			ActionKillThread,
		},
		{
			SeccompData{NR: 57, Arch: uint32(arch.X86_64.ID)},
			ActionKillThread,
		},
		{
			SeccompData{NR: 4, Arch: uint32(arch.X86_64.ID)},
			ActionAllow,
		},
		{
			SeccompData{NR: 4, Arch: uint32(arch.ARM.ID)},
			ActionAllow,
		},
		{
			// Attempts to bypass the filter by using X32 syscalls on X86_64
			// are met with ENOSYS.
			SeccompData{NR: int32(arch.X32.SyscallNames["execve"] + arch.X32.SeccompMask), Arch: uint32(arch.X86_64.ID)},
			ActionErrno | Action(errnoENOSYS),
		},
	})
}

func TestPolicyAssembleWhitelist(t *testing.T) {
	policy := &Policy{
		arch:          arch.X86_64,
		DefaultAction: ActionKillProcess,
		Syscalls: []SyscallGroup{
			{
				Names:  []string{"execve", "fork"},
				Action: ActionAllow,
			},
			{
				Names:  []string{"clone", "listen"},
				Action: ActionAllow,
			},
		},
	}

	if *dump {
		policy.Dump(os.Stdout)
	}

	simulateSyscalls(t, policy, []SeccompTest{
		{
			SeccompData{NR: 59, Arch: uint32(arch.X86_64.ID)},
			ActionAllow,
		},
		{
			SeccompData{NR: 4, Arch: uint32(arch.X86_64.ID)},
			ActionKillProcess,
		},
		{
			SeccompData{NR: 4, Arch: uint32(arch.ARM.ID)},
			ActionKillProcess,
		},
	})
}

func TestPolicyAssembleLongList(t *testing.T) {
	// Sort syscall numbers to make manual review of filters with -dump easier.
	syscallNumbers := make([]int, 0, len(arch.X86_64.SyscallNumbers))
	for nr := range arch.X86_64.SyscallNumbers {
		syscallNumbers = append(syscallNumbers, nr)
	}
	sort.Ints(syscallNumbers)

	for i := 1; i <= len(syscallNumbers); i++ {
		filterSize := i

		t.Run(fmt.Sprintf("size=%d", filterSize), func(t *testing.T) {
			var syscallNames []string
			var tests []SeccompTest

			for _, nr := range syscallNumbers[:filterSize] {
				name := arch.X86_64.SyscallNumbers[nr]

				var action Action
				if name != "exit" {
					syscallNames = append(syscallNames, name)
					action = ActionAllow
				} else {
					action = ActionKillProcess
				}

				tests = append(tests, SeccompTest{
					SeccompData{NR: int32(nr), Arch: uint32(arch.X86_64.ID)},
					action,
				})

				// Incorrect arch should always kill process.
				tests = append(tests, SeccompTest{
					SeccompData{NR: int32(nr), Arch: uint32(arch.ARM.ID)},
					ActionKillProcess,
				})
			}

			policy := &Policy{
				arch:          arch.X86_64,
				DefaultAction: ActionKillProcess,
				Syscalls: []SyscallGroup{
					{
						Names:  syscallNames,
						Action: ActionAllow,
					},
				},
			}

			if *dump {
				policy.Dump(os.Stdout)
			}

			simulateSyscalls(t, policy, tests)
		})
	}
}

func TestPolicyAssembleDefault(t *testing.T) {
	policy := Policy{
		DefaultAction: ActionAllow,
		Syscalls: []SyscallGroup{
			{
				Action: ActionErrno,
				Names: []string{
					"execve",
					"fork",
					"vfork",
					"execveat",
				},
			},
		},
	}

	for _, arch := range []*arch.Info{arch.ARM, arch.I386, arch.X86_64} {
		policy.arch = arch
		_, err := policy.Assemble()
		if err != nil {
			t.Errorf("failed to assemble default policy on %v: %v", arch.Name, err)
		}
	}
}
