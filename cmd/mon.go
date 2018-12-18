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
	"strconv"
	"time"

	"github.com/safchain/koa/probes"
	"github.com/safchain/koa/probes/cpu"
	"github.com/safchain/koa/probes/io"
	"github.com/safchain/koa/probes/malloc"
	"github.com/safchain/koa/sender"
	"github.com/spf13/cobra"
)

var (
	pids []string
)

type ProbeID int

const (
	IOProbe ProbeID = iota + 1
	CPUProbe
	MallocProbe
)

func exit(err error) {
	fmt.Fprintf(os.Stderr, "Unable to create probe: %s\n", err)
	os.Exit(1)
}

func NewProbe(id ProbeID, sender sender.Sender, opts probes.Opts) (probes.Probe, error) {
	switch id {
	case IOProbe:
		return io.New(sender, opts)
	case CPUProbe:
		return cpu.New(sender, opts)
	case MallocProbe:
		return malloc.New(sender, opts)
	}

	return nil, nil
}

func int64PIDs() []int64 {
	var p []int64

	for _, s := range pids {
		i, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			exit(fmt.Errorf("PID %s not valid", s))
		}
		p = append(p, i)
	}

	return p
}

var rootCmd = &cobra.Command{
	Use:   "mon",
	Short: "Monitoring tools...",
	Long:  `Monitoring tools...`,
	Run: func(cmd *cobra.Command, args []string) {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)

		stdout := &sender.Stdout{}
		sql, err := sender.NewPostgres(&io.IOEntry{}, &cpu.CPUEntry{}, &malloc.MallocEntry{})
		if err != nil {
			exit(err)
		}
		bundle := sender.NewBundle(stdout, sql)

		ctx, cancel := context.WithCancel(context.Background())

		opts := probes.Opts{
			Rate: 2 * time.Second,
			PIDs: int64PIDs(),
		}

		var all []probes.Probe
		for _, id := range []ProbeID{CPUProbe, IOProbe, MallocProbe} {
			probe, err := NewProbe(id, bundle, opts)
			if err != nil {
				exit(err)
			}
			probe.SetRunID(int64(os.Getpid()))
			probe.SetTag("standard")

			all = append(all, probe)
		}

		for _, probe := range all {
			probe.Start(ctx)
		}

		<-c
		cancel()
	},
}

func main() {
	rootCmd.PersistentFlags().StringArrayVarP(&pids, "pid", "p", []string{}, "capture specified pid")
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
