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

package probes

import "sync"

type Filters struct {
	sync.RWMutex
	PIDs []int64
}

func (f *Filters) ContainsPID(pid int64) bool {
	f.RLock()
	defer f.RUnlock()

	if len(f.PIDs) == 0 {
		return true
	}

	for _, p := range f.PIDs {
		if p == pid {
			return true
		}
	}

	return false
}

func (f *Filters) AddPIDs(pid ...int64) {
	f.Lock()
	f.PIDs = append(f.PIDs, pid...)
	f.Unlock()
}
