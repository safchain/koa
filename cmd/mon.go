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

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/safchain/koa/probes"
	"github.com/safchain/koa/probes/cpu"
	"github.com/safchain/koa/probes/io"
	"github.com/safchain/koa/sender"
	"github.com/spf13/cobra"
)

func exit(err error) {
	fmt.Fprintf(os.Stderr, "Unable to create io probe: %s\n", err)
	os.Exit(1)
}

var rootCmd = &cobra.Command{
	Use:   "mon",
	Short: "Monitoring tools...",
	Long:  `Monitoring tools...`,
	Run: func(cmd *cobra.Command, args []string) {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)

		stdout := &sender.Stdout{}

		ctx, cancel := context.WithCancel(context.Background())

		opts := probes.Opts{
			Rate: 2 * time.Second,
		}

		io, err := io.New(stdout, opts)
		if err != nil {
			exit(err)
		}
		io.Start(ctx)

		cpu, err := cpu.New(stdout, opts)
		if err != nil {
			exit(err)
		}
		cpu.Start(ctx)

		<-c
		cancel()
	},
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
