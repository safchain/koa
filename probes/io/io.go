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

package io

import (
	"context"
	"errors"
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
// #include "io.h"
import "C"

type Probe struct {
	sync.RWMutex
	module *elf.Module
	sender sender.Sender
	opts   probes.Opts
	runID  int64
	tag    string
}

const (
	Type       = "io"
	probeAsset = "io.o"
)

var (
	kprobes = []string{
		"kprobe/blk_account_io_start",
		"kprobe/blk_start_request",
		"kprobe/blk_mq_start_request",
		"kprobe/blk_account_io_completion",
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

func (p *Probe) run(ctx context.Context) {
	cmap := p.module.Map("value_map")

	ticker := time.NewTicker(p.opts.Rate)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var key, nextKey C.struct_key_t
			var value C.struct_value_t

			for {
				found, _ := p.module.LookupNextElement(cmap, unsafe.Pointer(&key), unsafe.Pointer(&nextKey), unsafe.Pointer(&value))
				if !found {
					break
				}
				key = nextKey

				pid := int64(key.pid)
				if !p.opts.ContainsPID(pid) {
					continue
				}

				p.RLock()
				entry := &IOEntry{
					Type:        Type,
					PID:         pid,
					ProcessName: C.GoString(&key.name[0]),
					Device:      "",
					Flag:        int64(key.rwflag),
					IO:          int64(value.io),
					Bytes:       int64(value.bytes),
					Timestamp:   time.Now().UTC().Unix(),
					RunID:       p.runID,
					Tag:         p.tag,
				}
				p.RUnlock()

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
