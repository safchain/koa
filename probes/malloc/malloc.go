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

package malloc

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/iovisor/gobpf/elf"
	"github.com/safchain/koa/ebpf"
	"github.com/safchain/koa/probes"
	"github.com/safchain/koa/sender"
)

// #cgo CFLAGS: -I../../ebpf/include
// #include <stdint.h>
// #include "malloc.h"
import "C"

type Probe struct {
	sync.RWMutex
	module *elf.Module
	sender sender.Sender
	opts   probes.Opts
	runID  int64
	tag    string
	wg     sync.WaitGroup
}

const (
	Type       = "malloc"
	probeAsset = "malloc.o"
)

var (
	uprobes = map[string]string{
		"uprobe/malloc": "/lib64/libc.so.6",
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

func (p *Probe) read(cmap *elf.Map) {
	var key, nextKey C.uint32_t
	var value C.struct_value_t

	for {
		found, _ := p.module.LookupNextElement(cmap, unsafe.Pointer(&key), unsafe.Pointer(&nextKey), unsafe.Pointer(&value))
		if !found {
			break
		}
		key = nextKey

		p.RLock()
		entry := &MallocEntry{
			Type:        Type,
			PID:         int64(key),
			ProcessName: C.GoString(&value.name[0]),
			Bytes:       int64(value.bytes),
			Timestamp:   time.Now().UTC().Unix(),
			RunID:       p.runID,
			Tag:         p.tag,
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

	for probe, path := range uprobes {
		fnc := strings.TrimPrefix(probe, "uprobe/")

		if err := ebpf.EnableUProbe(module, probe, fnc, path); err != nil {
			return nil, err
		}
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
