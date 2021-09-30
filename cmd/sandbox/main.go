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

package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"

	"github.com/elastic/go-ucfg/yaml"

	seccomp "github.com/elastic/go-seccomp-bpf"
)

var (
	policyFile string
	noNewPrivs bool
)

func main() {
	flag.StringVar(&policyFile, "policy", "seccomp.yml", "seccomp policy file")
	flag.BoolVar(&noNewPrivs, "no-new-privs", true, "set no new privs bit")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "You must specify a command and args to execute.\n")
		os.Exit(1)
	}

	// Load policy from file.
	policy, err := parsePolicy()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Create a filter based on config.
	filter := seccomp.Filter{
		NoNewPrivs: noNewPrivs,
		Flag:       seccomp.FilterFlagTSync,
		Policy:     *policy,
	}

	// Load the BPF filter using the seccomp system call.
	if err = seccomp.LoadFilter(filter); err != nil {
		fmt.Fprintf(os.Stderr, "error loading filter: %v\n", err)
		os.Exit(1)
	}

	// Execute the specified command (requires execve).
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err = cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func parsePolicy() (*seccomp.Policy, error) {
	conf, err := yaml.NewConfigWithFile(policyFile)
	if err != nil {
		return nil, err
	}

	type Config struct {
		Seccomp seccomp.Policy
	}

	var config Config
	if err = conf.Unpack(&config); err != nil {
		return nil, err
	}

	return &config.Seccomp, nil
}
