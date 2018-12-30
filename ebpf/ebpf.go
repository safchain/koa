/*
 * Copyright (C) 2018 Sylvain Afchain
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

package ebpf

import (
	"bytes"
	"debug/elf"
	"fmt"
	"runtime"
	"strings"

	ebpelf "github.com/iovisor/gobpf/elf"

	ebpf "github.com/safchain/koa/ebpf/module"
)

// #cgo CFLAGS: -Iinclude
// #include <stdint.h>
// #include "io.h"
import "C"

// LoadModule load the ebpf module for the given asset name
func LoadModule(asset string) (*ebpelf.Module, error) {
	data, err := ebpf.Asset(asset)
	if err != nil {
		return nil, fmt.Errorf("Unable to find eBPF ebpelf binary in bindata")
	}

	reader := bytes.NewReader(data)

	module := ebpelf.NewModuleFromReader(reader)

	// load to test if everything is ok
	err = module.Load(nil)
	if err != nil {
		// split to skip to kernel stack trace
		errs := strings.Split(err.Error(), ":")

		return nil, fmt.Errorf("Unable to load eBPF ebpelf binary (host %s) from bindata: %+v", runtime.GOARCH, errs)
	}

	return module, nil
}

// EnableKProbes enable the given probes
func EnableKProbes(module *ebpelf.Module, probes []string) error {
	for _, probe := range probes {
		if err := module.EnableKprobe(probe, 10); err != nil {
			return fmt.Errorf("Unable to enable kprobe %s: %s", probe, err)
		}
	}

	return nil
}

func EnableUProbe(module *ebpelf.Module, probe string, fnc string, path string) error {
	file, err := elf.Open(path)
	if err != nil {
		return err
	}

	var bAddr uint64
	for _, prog := range file.Progs {
		if prog.Type == elf.PT_LOAD && (prog.Flags&elf.PF_X) > 0 {
			bAddr = prog.Vaddr
		}
	}

	symbols, err := file.Symbols()
	if err != nil {
		return err
	}

	var offset uint64
	for _, symbol := range symbols {
		if symbol.Name == fnc {
			offset = symbol.Value
			break
		}
	}

	if offset < bAddr {
		return fmt.Errorf("Wrong symbol offset: %s", fnc)
	}
	offset -= bAddr

	for uprobe := range module.IterUprobes() {
		if uprobe.Name == probe {
			fmt.Printf(">>>>>>>>>>>>>>>>: %s %d\n", path, offset)
			if err := ebpelf.AttachUprobe(uprobe, path, offset); err != nil {
				return err
			}
			return nil
		}
	}

	return fmt.Errorf("probe not found: %s", probe)
}
