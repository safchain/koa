/*
 * Copyright (C) 2019 Sylvain Afchain
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

package collector

import (
	"log"

	"github.com/safchain/koa/api"
	"github.com/safchain/koa/collector/storage"
	"golang.org/x/net/context"
)

type Collector struct {
	storage storage.Storage
}

func (c *Collector) SendProcEntry(ctx context.Context, in *api.ProcEntryMessage) (*api.Void, error) {
	log.Printf("Receive message %+v\n", in)

	if in.VFSEntry != nil {
		c.storage.Store(in.VFSEntry)
	}
	if in.FncEntry != nil {
		c.storage.Store(in.FncEntry)
	}
	if in.IOEntry != nil {
		c.storage.Store(in.IOEntry)
	}
	if in.MallocEntry != nil {
		c.storage.Store(in.MallocEntry)
	}
	if in.CPUEntry != nil {
		c.storage.Store(in.CPUEntry)
	}

	return &api.Void{}, nil
}

func NewCollector(storage storage.Storage) *Collector {
	return &Collector{
		storage: storage,
	}
}
