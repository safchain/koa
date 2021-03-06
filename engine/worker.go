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

package engine

import (
	"io/ioutil"

	yaml "gopkg.in/yaml.v2"
)

type Worker struct {
	Host        string
	Port        int
	Username    string
	AuthOptions AuthOptions `yaml:"auth_options"`
}

func (w *Worker) Parse(path string) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	if err := yaml.Unmarshal(data, w); err != nil {
		return nil
	}

	return nil
}

func (w *Worker) Get() error {
	return nil
}
