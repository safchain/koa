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

package fnc

import (
	"context"
	"debug/elf"
	"errors"
	fmt "fmt"
	"sync"
	"time"
	"unsafe"

	ebpelf "github.com/iovisor/gobpf/elf"

	"github.com/safchain/koa/api/types"
	"github.com/safchain/koa/ebpf"
	"github.com/safchain/koa/probes"
	"github.com/safchain/koa/sender"
)

// #cgo CFLAGS: -I../../ebpf/include
// #include <stdint.h>
// #include "fnc.h"
import "C"

type Probe struct {
	sync.RWMutex
	module   *ebpelf.Module
	sender   sender.Sender
	opts     probes.Opts
	runID    int64
	tag      string
	wg       sync.WaitGroup
	funcName map[uint64]string
}

const (
	Type       = "fnc"
	probeAsset = "fnc.o"
)

var (
	uprobes = []string{
		"uprobe/entry",
		"uretprobe/return",
	}
)

func (p *Probe) SetTag(tag string) {
	p.Lock()
	p.tag = tag
	p.Unlock()
}

func (p *Probe) SetRunID(runID int64) {
	p.Lock()
	p.runID = runID
	p.Unlock()
}

func (p *Probe) AddPID(pid int64) error {
	path := fmt.Sprintf("/proc/%d/exe", pid)

	file, err := elf.Open(path)
	if err != nil {
		return err
	}

	symbols, err := file.Symbols()
	if err != nil {
		return err
	}

	// extract functions
	var fncs []string
	for _, symbol := range symbols {
		if elf.ST_TYPE(symbol.Info) == elf.STT_FUNC {
			// map offset to name
			p.Lock()
			p.funcName[symbol.Value] = symbol.Name
			p.Unlock()

			fncs = append(fncs, symbol.Name)
		}
	}

	for _, probe := range uprobes {
		for _, fnc := range fncs {
			// TODO: check errors. Ignoring for now
			ebpf.EnableUProbe(p.module, probe, fnc, path)
		}
	}

	return nil
}

func (p *Probe) read(cmap *ebpelf.Map) {
	var key, nextKey C.struct_key_t
	var value C.struct_value_t

	for {
		found, _ := p.module.LookupNextElement(cmap, unsafe.Pointer(&key), unsafe.Pointer(&nextKey), unsafe.Pointer(&value))
		if !found {
			break
		}
		key = nextKey

		p.RLock()
		funcName := p.funcName[uint64(key.ip)]
		p.RUnlock()

		p.RLock()
		entry := &types.ProcFncEntry{
			Header: &types.ProcEntryHeader{
				Type:        Type,
				PID:         int64(key.pid),
				ProcessName: C.GoString(&value.name[0]),

				Timestamp: time.Now().UTC().Unix(),
				RunID:     p.runID,
				Tag:       p.tag,
			},
			FuncName: funcName,
			Calls:    int64(value.calls),
		}
		p.RUnlock()

		p.sender.Send(entry)
	}
}

func (p *Probe) run(ctx context.Context) {
	p.wg.Add(1)
	defer p.wg.Done()

	cmap := p.module.Map("value_map")
	p.read(cmap)

	ticker := time.NewTicker(p.opts.Rate)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			p.read(cmap)
			return
		case <-ticker.C:
			p.read(cmap)
		}
	}
}

func (p *Probe) Start(ctx context.Context) {
	go p.run(ctx)
}

func (p *Probe) Wait() {
	p.wg.Wait()
}

func New(sender sender.Sender, opts probes.Opts) (*Probe, error) {
	module, err := ebpf.LoadModule(probeAsset)
	if err != nil {
		return nil, err
	}

	cmap := module.Map("value_map")
	if cmap == nil {
		return nil, errors.New("value_map map not found")
	}

	return &Probe{
		module:   module,
		sender:   sender,
		opts:     opts,
		funcName: make(map[uint64]string),
	}, nil
}
