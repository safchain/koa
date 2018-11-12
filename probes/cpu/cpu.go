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

package cpu

import (
	"context"
	"errors"
	"time"
	"unsafe"

	"github.com/iovisor/gobpf/elf"
	"github.com/safchain/koa/ebpf"
	"github.com/safchain/koa/probes"
	"github.com/safchain/koa/sender"
)

// #cgo CFLAGS: -I../../ebpf/include
// #include <stdint.h>
// #include "cpu.h"
import "C"

type CPUEntry struct {
	PID         int64
	ProcessName string
	Nanoseconds int64
	Timestamp   time.Time
}

type Probe struct {
	module *elf.Module
	sender sender.Sender
	opts   probes.Opts
}

const (
	probeAsset = "cpu.o"
)

var (
	kprobes = []string{
		"kprobe/finish_task_switch",
	}
)

func (p *Probe) run(ctx context.Context) {
	cmap := p.module.Map("value_map")

	ticker := time.NewTicker(p.opts.Rate)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var key, nextKey C.uint32_t
			var value C.struct_value_t

			for {
				found, _ := p.module.LookupNextElement(cmap, unsafe.Pointer(&key), unsafe.Pointer(&nextKey), unsafe.Pointer(&value))
				if !found {
					break
				}
				key = nextKey

				entry := &CPUEntry{
					PID:         int64(key),
					ProcessName: C.GoString(&value.name[0]),
					Nanoseconds: int64(value.ns),
					Timestamp:   time.Now().UTC(),
				}
				p.sender.Send(entry)
			}
		}
	}
}

func (p *Probe) Start(ctx context.Context) {
	go p.run(ctx)
}

func New(sender sender.Sender, opts probes.Opts) (*Probe, error) {
	module, err := ebpf.LoadModule(probeAsset)
	if err != nil {
		return nil, err
	}

	if err = ebpf.EnableKProbes(module, kprobes); err != nil {
		return nil, err
	}

	cmap := module.Map("value_map")
	if cmap == nil {
		return nil, errors.New("value_map map not found")
	}

	return &Probe{
		module: module,
		sender: sender,
		opts:   opts,
	}, nil
}
