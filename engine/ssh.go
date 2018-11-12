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
	"fmt"
	"io/ioutil"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	DEFAULT_TIMEOUT = 3 // TODO use the jobDef
)

type AuthType string

const (
	PasswordType  AuthType = "password"
	PublicKeyType          = "public_key"
)

type AuthOptions struct {
	Type      AuthType
	Password  string
	PublicKey string `yaml:"public_key"`
}

type SSH struct {
	Host        string
	Port        int
	Username    string
	AuthOptions AuthOptions

	client *ssh.Client
}

func (s *SSH) readPublicKeyFile(file string) (ssh.AuthMethod, error) {
	buffer, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		return nil, err
	}
	return ssh.PublicKeys(key), nil
}

func (s *SSH) Connect() error {
	var auth []ssh.AuthMethod
	switch s.AuthOptions.Type {
	case PasswordType:
		auth = []ssh.AuthMethod{ssh.Password(s.AuthOptions.Password)}
	case PublicKeyType:
		key, err := s.readPublicKeyFile(s.AuthOptions.PublicKey)
		if err != nil {
			return err
		}
		auth = []ssh.AuthMethod{key}
	}

	cfg := &ssh.ClientConfig{
		User: s.Username,
		Auth: auth,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
		Timeout: time.Second * DEFAULT_TIMEOUT,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", s.Host, s.Port), cfg)
	if err != nil {
		return err
	}

	s.client = client

	return nil
}

func (s *SSH) RunCmd(cmd string) error {
	session, err := s.client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	out, err := session.CombinedOutput(cmd)
	if err != nil {
		fmt.Println("!!", err)
	}
	fmt.Println(string(out))

	return nil
}

func (s *SSH) Close() {
	s.client.Close()
}

func NewSSH(host string, port int, username string, authOptions AuthOptions) *SSH {
	return &SSH{
		Host:        host,
		Port:        port,
		Username:    username,
		AuthOptions: authOptions,
	}
}
