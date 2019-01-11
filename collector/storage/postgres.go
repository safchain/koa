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

package storage

import (
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/safchain/koa/api/types"
)

type Postgres struct {
	db *gorm.DB
}

func (p *Postgres) Store(entry types.ProcEntry) error {
	p.db.Create(entry)

	return nil
}

func NewPostgres(structs ...interface{}) (*Postgres, error) {
	db, err := gorm.Open("postgres", "host=127.0.0.1 port=5432 user=postgres dbname=postgres password=mysecretpassword sslmode=disable")
	if err != nil {
		return nil, err
	}

	for _, s := range structs {
		db.AutoMigrate(s)
	}

	return &Postgres{
		db: db,
	}, nil
}
