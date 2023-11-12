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
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/net/bpf"
)

const (
	argumentOffset = 16
)

var nativeEndian binary.ByteOrder

func init() {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		nativeEndian = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		nativeEndian = binary.BigEndian
	default:
		panic("Could not determine native endianness.")
	}
}

// Label marks a jump destination in the instruction list of the Program.
type Label int

// Index is the concrete index of an instruction in the instruction list.
type Index int

// Jump jumps conditionally to the true or the false label.
// The concrete condition is not relevant to resolve the jumps.
type Jump struct {
	index      Index
	trueLabel  Label
	falseLabel Label
}

// The Program consists of a list of bpf.Instructions.
// Conditional jumps can point to different labels in the program and must be resolved by calling ResolveJumps.
//
// NewLabel creates a new label that can be used as jump destination.
//
// SetLabel must be used to specify the concrete instruction.
// Only forward jumps are supported; this means a label must not be used after setting it.
type Program struct {
	instructions []bpf.Instruction
	jumps        []Jump
	labels       map[Label][]Index
	nextLabel    Label
}

// NewProgram returns an initialized empty program.
func NewProgram() Program {
	return Program{
		labels:       make(map[Label][]Index),
		nextLabel:    Label(1),
	}
}

// JmpIfTrue inserts a conditional jump.
// If the condition is true, it jumps to the given label.
// If it is false, the program flow continues with the next instruction.
func (p *Program) JmpIfTrue(cond bpf.JumpTest, val uint32, trueLabel Label) {
	nextInst := p.NewLabel()
	p.JmpIf(cond, val, trueLabel, nextInst)
	p.SetLabel(nextInst)
}

// JmpIf inserts a conditional jump.
// If the condition is true, it jumps to the true label.
// If it is false, it jumps to the false label.
func (p *Program) JmpIf(cond bpf.JumpTest, val uint32, trueLabel Label, falseLabel Label) {
	p.jumps = append(p.jumps, Jump{index: p.currentIndex(), trueLabel: trueLabel, falseLabel: falseLabel})

	inst := bpf.JumpIf{Cond: cond, Val: val}
	p.instructions = append(p.instructions, inst)
}

// SetLabel sets the label to the latest instruction.
func (p *Program) SetLabel(label Label) {
	index := p.currentIndex()
	p.labels[label] = append(p.labels[label], index)
}

// Ret inserts a return instruction.
func (p *Program) Ret(action Action) {
	if action == ActionErrno {
		action |= Action(errnoEPERM)
	}
	p.instructions = append(p.instructions, bpf.RetConstant{Val: uint32(action)})
}

// LdHi inserts an instruction to load the most significant 32-bit of the 64-bit argument.
func (p *Program) LdHi(arg int) {
	offset := uint32(argumentOffset + 8*arg)
	if nativeEndian == binary.LittleEndian {
		offset += 4
	}
	p.instructions = append(p.instructions, bpf.LoadAbsolute{Off: offset, Size: 4})
}

// LdLo inserts an instruction to load the least significant 32-bit of the 64-bit argument.
func (p *Program) LdLo(arg int) {
	offset := uint32(argumentOffset + 8*arg)
	if nativeEndian == binary.BigEndian {
		offset += 4
	}
	p.instructions = append(p.instructions, bpf.LoadAbsolute{Off: offset, Size: 4})
}

// NewLabel creates a new label. It must be used with SetLabel.
func (p *Program) NewLabel() Label {
	p.nextLabel++
	return p.nextLabel
}

// Assemble resolves all jump destinations to concrete instructions using the labels.
// This method takes care of long jumps and resolves them by using early returns or unconditional long jumps.
func (p *Program) Assemble() ([]bpf.Instruction, error) {
	for _, jump := range p.jumps {
		jumpInst := p.instructions[jump.index].(bpf.JumpIf)

		skip, err := p.resolveLabel(jump, jump.trueLabel)
		if err != nil {
			return nil, err
		}
		jumpInst.SkipTrue = uint8(skip)

		skip, err = p.resolveLabel(jump, jump.falseLabel)
		if err != nil {
			return nil, err
		}
		jumpInst.SkipFalse = uint8(skip)

		if jumpInst.SkipTrue == 0 && jumpInst.SkipFalse == 0 {
			return nil, fmt.Errorf("useless jump found")
		}

		p.instructions[jump.index] = jumpInst
	}

	return p.instructions, nil
}

// resolveLabel resolves the label to a short jump.
func (p *Program) resolveLabel(jump Jump, label Label) (int, error) {
	dest := p.labels[label]
	skipN := p.computeSkipN(jump, label)

	for skipN < 0 {
		dest = dest[1:]
		if len(dest) == 0 {
			return 0, fmt.Errorf("backward jumps are not supported")
		}
		p.labels[label] = dest
		skipN = p.computeSkipN(jump, label)
	}

	if skipN > 255 {
		insertAfter := findInsertAfter(p.jumps, jump)

		// If the jump destination is a return instruction, copy it and add an early return,
		// if not, insert a long jump.
		jumpDest := p.instructions[dest[0]]
		if _, ok := jumpDest.(bpf.RetConstant); !ok {
			jumpDest = bpf.Jump{Skip: uint32(skipN - int(insertAfter.index))}
		}

		insertIndex := p.insertAfter(insertAfter.index, jumpDest)
		p.labels[label] = append([]Index{insertIndex}, dest...)
		skipN = p.computeSkipN(jump, label)
	}
	return skipN, nil
}

// Inserts the instruction after the instruction indicated by index.
func (p *Program) insertAfter(index Index, inst bpf.Instruction) Index {
	jumpInst := p.instructions[index].(bpf.JumpIf)
	p.instructions[index] = jumpInst

	index++
	p.instructions = append(p.instructions[:index+1], p.instructions[index:]...)
	p.instructions[index] = inst
	p.updateIndices(index)
	return index
}

// After inserting a new instruction into the instruction list, the indices are wrong.
// This method updates all indices after the instruction point.
func (p *Program) updateIndices(after Index) {
	for i := range p.jumps {
		if p.jumps[i].index >= after {
			p.jumps[i].index++
		}
	}

	for _, v := range p.labels {
		for i := range v {
			if v[i] >= after {
				v[i]++
			}
		}
	}
}

// Computes the number of instructions to skip by resolving the label.
// It might be that the jump is a long jump.
func (p *Program) computeSkipN(jump Jump, label Label) int {
	dest := p.labels[label]
	return int(dest[0]-jump.index) - 1
}

// To insert a new instruction into the instruction list, the furthest jump instruction within
// a short jump is searched.
// It is necessary to search a jump instruction to jump over the new inserted instruction
// and do not disturb the program flow.
func findInsertAfter(jumps []Jump, currentJump Jump) Jump {
	insertAfter := currentJump
	maxIndex := currentJump.index + 255
	for _, jump := range jumps {
		if jump.index < maxIndex {
			insertAfter = jump
		}
	}
	return insertAfter
}

// Calculate the index of the current instruction.
func (p *Program) currentIndex() Index {
	return Index(len(p.instructions))
}
