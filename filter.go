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
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/net/bpf"

	"github.com/elastic/go-seccomp-bpf/arch"
)

const (
	syscallNumOffset = 0
	archOffset       = 4
)

// FilterFlag is a flag that is passed to the seccomp. Multiple flags can be
// OR'ed together.
type FilterFlag uint32

var filterFlagNames = map[FilterFlag]string{
	FilterFlagTSync: "tsync",
	FilterFlagLog:   "log",
}

// String returns a string representation of the FilterFlag.
func (f FilterFlag) String() string {
	if name, found := filterFlagNames[f]; found {
		return name
	}

	var list []string
	for flag, name := range filterFlagNames {
		if f&flag != 0 {
			f ^= flag
			list = append(list, name)
		}
	}
	if f != 0 {
		list = append(list, "unknown")
	}
	return strings.Join(list, "|")
}

// MarshalText marshals the value to text.
func (f FilterFlag) MarshalText() ([]byte, error) {
	return []byte(f.String()), nil
}

// Action specifies what to do when a syscall matches during filter evaluation.
type Action uint32

var actionNames = map[Action]string{
	ActionKillThread:  "kill_thread",
	ActionKillProcess: "kill_process",
	ActionTrap:        "trap",
	ActionErrno:       "errno",
	ActionTrace:       "trace",
	ActionLog:         "log",
	ActionAllow:       "allow",
}

// Unpack sets the Action value based on the string.
func (a *Action) Unpack(s string) error {
	s = strings.ToLower(s)
	for action, name := range actionNames {
		if name == s {
			*a = action
			return nil
		}
	}
	return fmt.Errorf("invalid action: %v", s)
}

// String returns a string representation of the Action.
func (a Action) String() string {
	name, found := actionNames[a]
	if found {
		return name
	}
	return "unknown"
}

// MarshalText marshals the value to text.
func (a Action) MarshalText() ([]byte, error) {
	return []byte(a.String()), nil
}

// Filter contains all the parameters necessary to install a Linux seccomp
// filter for the process.
type Filter struct {
	NoNewPrivs bool       `config:"no_new_privs" json:"no_new_privs"` // Set the process's no new privs bit.
	Flag       FilterFlag `config:"flag"         json:"flag"`         // Flag to pass to the seccomp call.
	Policy     Policy     `config:"policy"       json:"policy"`       // Policy that will be assembled into a BPF filter.
}

// Policy defines the BPF seccomp filter.
type Policy struct {
	DefaultAction Action         `config:"default_action" json:"default_action" yaml:"default_action"` // Action when no syscalls match.
	Syscalls      []SyscallGroup `config:"syscalls"       json:"syscalls"       yaml:"syscalls"`       // Groups of syscalls and actions.

	arch *arch.Info
}

// SyscallGroup is a logical block within a Policy that contains a set of
// syscalls to match against and an action to take.
type SyscallGroup struct {
	Names              []string             `config:"names"  json:"names"  yaml:"names"`                              // List of syscall names (all must exist).
	NamesWithCondtions []NameWithConditions `config:"names_with_args" json:"names_with_args"  yaml:"names_with_args"` // List of syscall with argument filters
	Action             Action               `config:"action" validate:"required" json:"action" yaml:"action"`         // Action to take upon a match.

	arch *arch.Info
}

// ArgumentConditions consist of a list of up to six conditions for the six arguments.
type ArgumentConditions []Condition

func (a ArgumentConditions) Validate() []string {
	var problems []string
	for _, condition := range a {
		if condition.Argument < 0 || condition.Argument > 5 {
			problems = append(problems, fmt.Sprintf("argument must be between 0 and 5 (inclusive), but is %v", condition.Argument))
		}
	}
	return problems
}

type NameWithConditions struct {
	Name       string             `config:"name" validate:"required" json:"name"  yaml:"name"`
	Conditions ArgumentConditions `config:"arguments" validate:"required" json:"arguments"  yaml:"arguments"`
}

type Condition struct {
	Argument  uint32    `config:"argument" default:"0" json:"position"  yaml:"position"`
	Operation Operation `config:"operation" validate:"required" json:"operation"  yaml:"operation"`
	Value     uint64    `config:"value" default:"0" json:"value"  yaml:"value"`
}

type Operation string

const (
	Equal          Operation = "Equal"
	NotEqual       Operation = "NotEqual"
	GreaterThan    Operation = "GreaterThan"
	LessThan       Operation = "LessThan"
	GreaterOrEqual Operation = "GreaterOrEqual"
	LessOrEqual    Operation = "LessOrEqual"
	BitsSet        Operation = "BitsSet"
	BitsNotSet     Operation = "BitsNotSet"
)

var Operations = []Operation{Equal, NotEqual, GreaterThan, LessThan, GreaterOrEqual, LessOrEqual, BitsSet, BitsNotSet}

// Unpack sets the Operation value based on the string.
func (o *Operation) Unpack(s string) error {
	s = strings.ToLower(s)
	for _, name := range Operations {
		if strings.ToLower(string(name)) == s {
			*o = name
			return nil
		}
	}

	return fmt.Errorf("invalid operation: %v", s)
}

// Validate validates that the configuration has both a default action and a
// set of syscalls.
func (p *Policy) Validate() error {
	if _, found := actionNames[p.DefaultAction]; !found {
		return fmt.Errorf("invalid default_action value %d", p.DefaultAction)
	}

	if len(p.Syscalls) == 0 {
		return errors.New("syscalls must not be empty")
	}

	return nil
}

// Assemble assembles the policy into a list of BPF instructions. If the policy
// contains any unknown syscalls or invalid actions an error will be returned.
func (p *Policy) Assemble() ([]bpf.Instruction, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}

	// Ensure arch has been set for the policy.
	if p.arch == nil {
		arch, err := arch.GetInfo("")
		if err != nil {
			return nil, err
		}
		p.arch = arch
	}

	// Build the syscall filter.
	prog := NewProgram()
	for _, group := range p.Syscalls {
		if group.arch == nil {
			group.arch = p.arch
		}

		err := group.Assemble(&prog)
		if err != nil {
			return nil, err
		}

	}
	prog.Ret(p.DefaultAction)

	instructions, err := prog.Assemble()
	if err != nil {
		return nil, err
	}

	// Filter out x32 to prevent bypassing blacklists by using the 32-bit ABI.
	var x32Filter []bpf.Instruction
	if p.arch.ID == arch.X86_64.ID {
		x32Filter = []bpf.Instruction{
			bpf.JumpIf{Cond: bpf.JumpGreaterOrEqual, Val: uint32(arch.X32.SeccompMask), SkipFalse: 1},
			bpf.RetConstant{Val: uint32(ActionErrno) | uint32(errnoENOSYS)},
		}
	}

	program := make([]bpf.Instruction, 0, len(x32Filter)+len(instructions)+5)

	program = append(program, bpf.LoadAbsolute{Off: archOffset, Size: sizeOfUint32})

	// If the loaded arch ID is not equal p.arch.ID, jump to the final Ret instruction.
	jumpN := len(x32Filter) + len(instructions)
	if jumpN <= 255 {
		program = append(program, bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: uint32(p.arch.ID), SkipTrue: uint8(jumpN)})
	} else {
		// JumpIf cannot handle long jumps, so we switch to two instructions for this case.
		program = append(program, bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(p.arch.ID), SkipTrue: 1})
		program = append(program, bpf.Jump{Skip: uint32(jumpN)})
	}

	program = append(program, bpf.LoadAbsolute{Off: syscallNumOffset, Size: sizeOfUint32})
	program = append(program, x32Filter...)
	program = append(program, instructions...)
	return program, nil
}

// Dump writes a textual represenation of the BPF instructions to out.
func (p *Policy) Dump(out io.Writer) error {
	assembled, err := p.Assemble()
	if err != nil {
		return err
	}

	for n, instruction := range assembled {
		fmt.Fprintf(out, "%d: %v\n", n, instruction)
	}
	return nil
}

// SyscallWithConditions consists of a syscall number and optional conditions.
//
// The conditions are applied to the arguments of the syscall.
// So, conditions consist of a list of up to six argument conditions.
// This filter matches if all argument conditions match for any Conditions.
type SyscallWithConditions struct {
	Num        uint32
	Conditions []ArgumentConditions
}

// getSyscall searches the syscall in the list.
// Do not use a map to keep the ordering, as specified by the user.
func getSyscall(syscalls []SyscallWithConditions, syscall uint32) *SyscallWithConditions {
	for i := range syscalls {
		// Use the reference directely from the slice rather than the iteration variable from range,
		// as the iteration variable in a range loop is a copy and cannot be modified.
		s := &syscalls[i]
		if s.Num == syscall {
			return s
		}
	}
	return nil
}

// toSyscallsWithConditions transforms a syscall group to syscalls with conditions.
func (g *SyscallGroup) toSyscallsWithConditions() ([]SyscallWithConditions, error) {
	var (
		syscalls []SyscallWithConditions
		problems []string
	)
	for _, name := range g.Names {
		if num, found := g.arch.SyscallNames[name]; found {
			syscall := uint32(num | g.arch.SeccompMask)
			if getSyscall(syscalls, syscall) == nil {
				syscalls = append(syscalls, SyscallWithConditions{Num: syscall})
			} else {
				problems = append(problems, fmt.Sprintf("found duplicate syscall %v", name))
			}
		} else {
			problems = append(problems, fmt.Sprintf("found unknown syscalls for arch %v: %v", g.arch.Name, name))
		}
	}

	for _, nc := range g.NamesWithCondtions {
		if num, found := g.arch.SyscallNames[nc.Name]; found {
			syscall := uint32(num | g.arch.SeccompMask)
			check := getSyscall(syscalls, syscall)

			invalidArguments := nc.Conditions.Validate()
			if len(invalidArguments) > 0 {
				problems = append(problems, invalidArguments...)
				continue
			}
			if check == nil {
				conditions := []ArgumentConditions{nc.Conditions}
				syscalls = append(syscalls, SyscallWithConditions{Num: syscall, Conditions: conditions})
			} else {
				if len(check.Conditions) == 0 {
					// Unconditional check found.
					problems = append(problems, fmt.Sprintf("found conditional and unconditional check: %v", nc.Name))
				} else {
					check.Conditions = append(check.Conditions, nc.Conditions)
				}
			}
		} else {
			problems = append(problems, fmt.Sprintf("found unknown syscalls for arch %v: %v", g.arch.Name, nc.Name))
		}
	}

	if len(problems) > 0 {
		return nil, fmt.Errorf(strings.Join(problems, "\n"))
	}

	return syscalls, nil
}

func (g *SyscallGroup) Assemble(p *Program) error {
	// Skip empty syscall groups.
	if len(g.Names)+len(g.NamesWithCondtions) == 0 {
		return nil
	}

	// Transform and validate the syscalls
	syscalls, err := g.toSyscallsWithConditions()
	if err != nil {
		return err
	}

	// Create labels for control flow.
	actionLabel := p.NewLabel()    // Jump here when a syscall in this group matches.
	nextGroupLabel := p.NewLabel() // Jump here to continue to the next syscall group.

	// Process each syscall in the group
	for i, syscall := range syscalls {
		moreSyscalls := i < len(syscalls)-1

		// Assemble instructions for this syscall
		// If this syscall matches, we jump to the action
		// If this syscall doesn't match, we either:
		// - Check the next syscall in this group (if there are more)
		// - Or jump to the next group if this was the last syscall
		syscall.Assemble(p, moreSyscalls, actionLabel, nextGroupLabel)
	}

	// When a syscall matches, execute this group's action.
	p.SetLabel(actionLabel)
	p.Ret(g.Action)

	// Control continues here for the next group when no syscalls match.
	p.SetLabel(nextGroupLabel)
	return nil
}

func (s SyscallWithConditions) Assemble(p *Program, moreSyscalls bool, action, end Label) {
	// Simple case: No conditions to check
	if len(s.Conditions) == 0 {
		if moreSyscalls {
			p.JmpIfTrue(bpf.JumpEqual, s.Num, action)
		} else {
			p.JmpIf(bpf.JumpEqual, s.Num, action, end)
		}
		return
	}

	// Complex case: Need to compare syscall number and check conditions
	nextSyscall := nextLabel(p, moreSyscalls, end)
	p.JmpIfTrue(bpf.JumpNotEqual, s.Num, nextSyscall)

	// Process each set of conditions (multiple condition sets are OR'd together)
	for j, conditions := range s.Conditions {
		moreConditions := j < len(s.Conditions)-1
		nextCondition := nextLabel(p, moreConditions, nextSyscall)

		// All conditions in a set must match (AND logic)
		for i, c := range conditions {
			moreArguments := i < len(conditions)-1
			nextArgument := nextLabel(p, moreArguments, action)

			// Handle 64-bit comparisons using 32-bit BPF operations
			hiValue := uint32(c.Value >> 32)
			loValue := uint32(c.Value)

			// Load high bits of the argument
			p.LdHi(c.Argument)

			switch c.Operation {
			case Equal:
				// Arg_hi == Val_hi && Arg_lo == Val_lo
				p.JmpIfTrue(bpf.JumpNotEqual, hiValue, nextCondition)
				p.LdLo(c.Argument)
				p.JmpIf(bpf.JumpEqual, loValue, nextArgument, nextCondition)

			case NotEqual:
				// Arg_hi != Val_hi || Arg_lo != Val_lo
				p.JmpIfTrue(bpf.JumpNotEqual, hiValue, nextArgument)
				p.LdLo(c.Argument)
				p.JmpIf(bpf.JumpNotEqual, loValue, nextArgument, nextCondition)

			case GreaterThan:
				// Arg_hi > Val_hi || (Arg_hi == Val_hi && Arg_lo > Val_lo)
				p.JmpIfTrue(bpf.JumpGreaterThan, hiValue, nextArgument)
				p.JmpIfTrue(bpf.JumpNotEqual, hiValue, nextCondition)
				p.LdLo(c.Argument)
				p.JmpIf(bpf.JumpGreaterThan, loValue, nextArgument, nextCondition)

			case GreaterOrEqual:
				// Arg_hi > Val_hi || (Arg_hi == Val_hi && Arg_lo >= Val_lo)
				p.JmpIfTrue(bpf.JumpGreaterThan, hiValue, nextArgument)
				p.JmpIfTrue(bpf.JumpNotEqual, hiValue, nextCondition)
				p.LdLo(c.Argument)
				p.JmpIf(bpf.JumpGreaterOrEqual, loValue, nextArgument, nextCondition)

			case LessThan:
				// Arg_hi < Val_hi || (Arg_hi == Val_hi && Arg_lo < Val_lo)
				p.JmpIfTrue(bpf.JumpLessThan, hiValue, nextArgument)
				p.JmpIfTrue(bpf.JumpNotEqual, hiValue, nextCondition)
				p.LdLo(c.Argument)
				p.JmpIf(bpf.JumpLessThan, loValue, nextArgument, nextCondition)

			case LessOrEqual:
				// Arg_hi < Val_hi || (Arg_hi == Val_hi && Arg_lo <= Val_lo)
				p.JmpIfTrue(bpf.JumpLessThan, hiValue, nextArgument)
				p.JmpIfTrue(bpf.JumpNotEqual, hiValue, nextCondition)
				p.LdLo(c.Argument)
				p.JmpIf(bpf.JumpLessOrEqual, loValue, nextArgument, nextCondition)

			case BitsSet:
				// (Arg_hi & Val_hi != 0) || (Arg_lo & Val_lo != 0)
				p.JmpIfTrue(bpf.JumpBitsSet, hiValue, nextArgument)
				p.LdLo(c.Argument)
				p.JmpIf(bpf.JumpBitsSet, loValue, nextArgument, nextCondition)

			case BitsNotSet:
				// (Arg_hi & Val_hi == 0) && (Arg_lo & Val_lo == 0)
				p.JmpIfTrue(bpf.JumpBitsSet, hiValue, nextCondition)
				p.LdLo(c.Argument)
				p.JmpIf(bpf.JumpBitsNotSet, loValue, nextArgument, nextCondition)
			}

			if moreArguments {
				p.SetLabel(nextArgument)
			}
		}

		if moreConditions {
			p.SetLabel(nextCondition)
		}
	}

	if moreSyscalls {
		p.SetLabel(nextSyscall)
	}
}

// nextLabel returns a new label if more is true. Otherwise, it returns end.
func nextLabel(p *Program, more bool, end Label) Label {
	if more {
		return p.NewLabel()
	}
	return end
}
