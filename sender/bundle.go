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

package sender

import (
	"github.com/safchain/koa/api/types"
	"github.com/safchain/koa/probes"
)

type Bundle struct {
	senders []Sender
	filters *probes.Filters
}

func (b *Bundle) Send(entry types.ProcEntry) error {
	if b.filters.IsMatching(entry) {
		return nil
	}

	for _, sender := range b.senders {
		sender.Send(entry)
	}

	return nil
}

func NewBundle(filters *probes.Filters, senders ...Sender) *Bundle {
	return &Bundle{
		senders: senders,
		filters: filters,
	}
}
