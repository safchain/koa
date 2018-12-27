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
	"os/exec"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/safchain/koa/probes"
	"github.com/safchain/koa/probes/cpu"
	"github.com/safchain/koa/probes/io"
	"github.com/safchain/koa/probes/malloc"
	"github.com/safchain/koa/sender"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
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
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func NewProbe(id ProbeID, sender sender.Sender, opts probes.Opts, filters *probes.Filters) (probes.Probe, error) {
	switch id {
	case IOProbe:
		return io.New(sender, opts, filters)
	case CPUProbe:
		return cpu.New(sender, opts, filters)
	case MallocProbe:
		return malloc.New(sender, opts, filters)
	}

	return nil, nil
}

func int64PIDs() []int64 {
	var p []int64

	for _, s := range pids {
		pid, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			exit(fmt.Errorf("PID %s not valid: %s", s, err))
		}

		if _, err = os.FindProcess(int(pid)); err != nil {
			exit(fmt.Errorf("PID %s not valid: %s", s, err))
		}

		p = append(p, pid)
	}

	return p
}

func monitor(ctx context.Context, opts probes.Opts, filters *probes.Filters, wg *sync.WaitGroup) {
	defer wg.Done()

	stderr := &sender.Stderr{}
	/*sql, err := sender.NewPostgres(&io.IOEntry{}, &cpu.CPUEntry{}, &malloc.MallocEntry{})
	if err != nil {
		exit(err)
	}*/
	bundle := sender.NewBundle(stderr)

	const tag = "standard"
	var tagNum int

	var all []probes.Probe
	for _, id := range []ProbeID{CPUProbe, IOProbe, MallocProbe} {
		probe, err := NewProbe(id, bundle, opts, filters)
		if err != nil {
			exit(err)
		}
		probe.SetRunID(int64(os.Getpid()))
		probe.SetTag(fmt.Sprintf("%s/%d", tag, tagNum))

		all = append(all, probe)
	}

	for _, probe := range all {
		probe.Start(ctx)
	}

	usr1 := make(chan os.Signal, 1)
	signal.Notify(usr1, syscall.SIGUSR1)

LOOP:
	for {
		select {
		case <-ctx.Done():
			break LOOP
		case <-usr1:
			tagNum++
			for _, probe := range all {
				probe.SetTag(fmt.Sprintf("%s/%d", tag, tagNum))
			}
		}
	}

	for _, probe := range all {
		probe.Wait()
	}
}

var rootCmd = &cobra.Command{
	Use:   "mon",
	Short: "Monitoring tools...",
	Long:  `Monitoring tools...`,
	Run: func(cmd *cobra.Command, args []string) {
		opts := probes.Opts{
			Rate: 2 * time.Second,
		}

		filters := &probes.Filters{}
		filters.AddPIDs(int64PIDs()...)

		ctx, cancel := context.WithCancel(context.Background())

		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, os.Interrupt)

		child := make(chan os.Signal, 1)
		signal.Notify(child, unix.SIGCHLD)

		var wg sync.WaitGroup

		wg.Add(1)
		go monitor(ctx, opts, filters, &wg)

		if len(args) > 0 {
			name := args[0]

			path, err := exec.LookPath(name)
			if err != nil {
				exit(err)
			}

			cmd := exec.Command(path, args[1:]...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr

			if err = cmd.Start(); err != nil {
				exit(err)
			}

			filters.AddPIDs(int64(cmd.Process.Pid))
		}

	LOOP:
		for {
			select {
			case <-interrupt:
				cancel()
				break LOOP
			case <-child:
				var status unix.WaitStatus
				_, err := unix.Wait4(-1, &status, unix.WNOHANG, nil)
				if err != nil {
					exit(err)
				}

				if len(pids) == 0 {
					cancel()
					break LOOP
				}
			}
		}
		wg.Wait()
	},
}

func main() {
	rootCmd.PersistentFlags().StringArrayVarP(&pids, "pid", "p", []string{}, "capture specified pid")
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
