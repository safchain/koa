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

package sender

import (
	"context"
	"errors"

	"github.com/safchain/koa/api"
	"github.com/safchain/koa/api/types"
	"google.golang.org/grpc"
)

type Collector struct {
	client api.CollectorClient
}

func (s *Collector) Send(entry types.ProcEntry) error {
	var msg api.ProcEntryMessage

	switch entry.(type) {
	case *types.ProcCPUEntry:
		msg.CPUEntry = entry.(*types.ProcCPUEntry)
	case *types.ProcFncEntry:
		msg.FncEntry = entry.(*types.ProcFncEntry)
	case *types.ProcIOEntry:
		msg.IOEntry = entry.(*types.ProcIOEntry)
	case *types.ProcMallocEntry:
		msg.MallocEntry = entry.(*types.ProcMallocEntry)
	case *types.ProcVFSEntry:
		msg.VFSEntry = entry.(*types.ProcVFSEntry)
	default:
		return errors.New("entry record type unknown")
	}

	if _, err := s.client.SendProcEntry(context.Background(), &msg); err != nil {
		return err
	}

	return nil
}

func NewCollector() (*Collector, error) {
	conn, err := grpc.Dial(":7777", grpc.WithInsecure())
	if err != nil {
		return nil, err
	}

	c := api.NewCollectorClient(conn)

	return &Collector{
		client: c,
	}, nil
}
