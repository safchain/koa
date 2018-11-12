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
	"fmt"
	"runtime"
	"strings"

	"github.com/iovisor/gobpf/elf"

	ebpf "github.com/safchain/koa/ebpf/module"
)

// #cgo CFLAGS: -Iinclude
// #include <stdint.h>
// #include "io.h"
import "C"

// LoadModule load the ebpf module for the given asset name
func LoadModule(asset string) (*elf.Module, error) {
	data, err := ebpf.Asset(asset)
	if err != nil {
		return nil, fmt.Errorf("Unable to find eBPF elf binary in bindata")
	}

	reader := bytes.NewReader(data)

	module := elf.NewModuleFromReader(reader)

	// load to test if everything is ok
	err = module.Load(nil)
	if err != nil {
		// split to skip to kernel stack trace
		errs := strings.Split(err.Error(), ":")

		return nil, fmt.Errorf("Unable to load eBPF elf binary (host %s) from bindata: %+v", runtime.GOARCH, errs)
	}

	return module, nil
}

// EnableKProbes enable the given probes
func EnableKProbes(module *elf.Module, probes []string) error {
	for _, probe := range probes {
		if err := module.EnableKprobe(probe, 10); err != nil {
			return err
		}
	}

	return nil
}
