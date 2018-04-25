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

package arch

// #include <linux/audit.h>
import "C"

import (
	"strconv"
)

// The arch field is not unique for all calling conventions.  The x86-64
// ABI and the x32 ABI both use AUDIT_ARCH_X86_64 as arch, and they run
// on the same processors.  Instead, the mask __X32_SYSCALL_BIT is used
// on the system call number to tell the two ABIs apart.
// https://github.com/torvalds/linux/blob/v4.16/arch/x86/include/uapi/asm/unistd.h#L6
const x32SyscallMask = 0x40000000

// AuditArch represents a machine architecture (i.e. arm, ppc, x86_64).
type AuditArch uint32

// List of architectures constants used by then kernel.
const (
	auditArchAARCH64     AuditArch = C.AUDIT_ARCH_AARCH64
	auditArchARM         AuditArch = C.AUDIT_ARCH_ARM
	auditArchARMEB       AuditArch = C.AUDIT_ARCH_ARMEB
	auditArchCRIS        AuditArch = C.AUDIT_ARCH_CRIS
	auditArchFRV         AuditArch = C.AUDIT_ARCH_FRV
	auditArchI386        AuditArch = C.AUDIT_ARCH_I386
	auditArchIA64        AuditArch = C.AUDIT_ARCH_IA64
	auditArchM32R        AuditArch = C.AUDIT_ARCH_M32R
	auditArchM68K        AuditArch = C.AUDIT_ARCH_M68K
	auditArchMIPS        AuditArch = C.AUDIT_ARCH_MIPS
	auditArchMIPS64      AuditArch = C.AUDIT_ARCH_MIPS64
	auditArchMIPS64N32   AuditArch = C.AUDIT_ARCH_MIPS64N32
	auditArchMIPSEL      AuditArch = C.AUDIT_ARCH_MIPSEL
	auditArchMIPSEL64    AuditArch = C.AUDIT_ARCH_MIPSEL64
	auditArchMIPSEL64N32 AuditArch = C.AUDIT_ARCH_MIPSEL64N32
	auditArchPARISC      AuditArch = C.AUDIT_ARCH_PARISC
	auditArchPARISC64    AuditArch = C.AUDIT_ARCH_PARISC64
	auditArchPPC         AuditArch = C.AUDIT_ARCH_PPC
	auditArchPPC64       AuditArch = C.AUDIT_ARCH_PPC64
	auditArchPPC64LE     AuditArch = C.AUDIT_ARCH_PPC64LE
	auditArchS390        AuditArch = C.AUDIT_ARCH_S390
	auditArchS390X       AuditArch = C.AUDIT_ARCH_S390X
	auditArchSH          AuditArch = C.AUDIT_ARCH_SH
	auditArchSH64        AuditArch = C.AUDIT_ARCH_SH64
	auditArchSHEL        AuditArch = C.AUDIT_ARCH_SHEL
	auditArchSHEL64      AuditArch = C.AUDIT_ARCH_SHEL64
	auditArchSPARC       AuditArch = C.AUDIT_ARCH_SPARC
	auditArchSPARC64     AuditArch = C.AUDIT_ARCH_SPARC64
	auditArchX86_64      AuditArch = C.AUDIT_ARCH_X86_64
)

var auditArchNames = map[AuditArch]string{
	auditArchAARCH64:     "aarch64",
	auditArchARM:         "arm",
	auditArchARMEB:       "armeb",
	auditArchCRIS:        "cris",
	auditArchFRV:         "frv",
	auditArchI386:        "i386",
	auditArchIA64:        "ia64",
	auditArchM32R:        "m32r",
	auditArchM68K:        "m68k",
	auditArchMIPS:        "mips",
	auditArchMIPS64:      "mips64",
	auditArchMIPS64N32:   "mips64n32",
	auditArchMIPSEL:      "mipsel",
	auditArchMIPSEL64:    "mipsel64",
	auditArchMIPSEL64N32: "mipsel64n32",
	auditArchPARISC:      "parisc",
	auditArchPARISC64:    "parisc64",
	auditArchPPC:         "ppc",
	auditArchPPC64:       "ppc64",
	auditArchPPC64LE:     "ppc64le",
	auditArchS390:        "s390",
	auditArchS390X:       "s390x",
	auditArchSH:          "sh",
	auditArchSH64:        "sh64",
	auditArchSHEL:        "shel",
	auditArchSHEL64:      "shel64",
	auditArchSPARC:       "sparc",
	auditArchSPARC64:     "sparc64",
	auditArchX86_64:      "x86_64",
}

// String returns a string representation of the architecture.
func (a AuditArch) String() string {
	name, found := auditArchNames[a]
	if found {
		return name
	}

	return "unknown[" + strconv.Itoa(int(a)) + "]"
}
