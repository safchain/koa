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
	"github.com/safchain/koa/probes/fnc"
	"github.com/safchain/koa/probes/io"
	"github.com/safchain/koa/probes/malloc"
	"github.com/safchain/koa/probes/vfs"
	"github.com/safchain/koa/sender"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

var (
	pidArgs        []string
	allProbesArg   bool
	cpuProbeArg    bool
	mallocProbeArg bool
	ioProbeArg     bool
	vfsProbeArg    bool
	fncProbeArg    bool
)

type Monitor struct {
	sync.RWMutex
	Sender sender.Sender
	Opts   probes.Opts
	probes map[string]probes.Probe
	wg     sync.WaitGroup
}

func exit(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func (m *Monitor) AddProbe(typ string) error {
	var probe probes.Probe
	var err error

	switch typ {
	case io.Type:
		probe, err = io.New(m.Sender, m.Opts)
	case cpu.Type:
		probe, err = cpu.New(m.Sender, m.Opts)
	case malloc.Type:
		probe, err = malloc.New(m.Sender, m.Opts)
	case vfs.Type:
		probe, err = vfs.New(m.Sender, m.Opts)
	case fnc.Type:
		probe, err = fnc.New(m.Sender, m.Opts)
	}

	if err != nil {
		return err
	}

	probe.SetRunID(int64(os.Getpid()))
	probe.SetTag("default")

	m.Lock()
	m.probes[typ] = probe
	m.Unlock()

	return nil
}

func (m *Monitor) Run(ctx context.Context) error {
	m.wg.Add(1)
	defer m.wg.Done()

	m.RLock()
	for _, probe := range m.probes {
		probe.Start(ctx)
	}
	m.RUnlock()

	usr1 := make(chan os.Signal, 1)
	signal.Notify(usr1, syscall.SIGUSR1)

	var tag int
LOOP:
	for {
		select {
		case <-ctx.Done():
			break LOOP
		case <-usr1:
			tag++

			m.RLock()
			for _, probe := range m.probes {
				probe.SetTag(fmt.Sprintf("usr1/%d", tag))
			}
			m.RUnlock()
		}
	}

	m.RLock()
	for _, probe := range m.probes {
		probe.Wait()
	}
	m.RUnlock()

	return nil
}

func (m *Monitor) Start(ctx context.Context) {
	go func() {
		if err := m.Run(ctx); err != nil {
			exit(err)
		}
	}()
}

func (m *Monitor) Probe(typ string) probes.Probe {
	m.RLock()
	p := m.probes[typ]
	m.RUnlock()

	return p
}

func (m *Monitor) Wait() {
	m.wg.Wait()
}

func PIDs() []int64 {
	var p []int64

	for _, s := range pidArgs {
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

func enabledProbeTypes() []string {
	var types []string
	if cpuProbeArg || allProbesArg {
		types = append(types, cpu.Type)
	}
	if mallocProbeArg || allProbesArg {
		types = append(types, malloc.Type)
	}
	if ioProbeArg || allProbesArg {
		types = append(types, io.Type)
	}
	if vfsProbeArg || allProbesArg {
		types = append(types, vfs.Type)
	}
	if fncProbeArg || allProbesArg {
		types = append(types, fnc.Type)
	}

	return types
}

var rootCmd = &cobra.Command{
	Use:   "mon",
	Short: "Monitoring tools...",
	Long:  `Monitoring tools...`,
	Run: func(cmd *cobra.Command, args []string) {
		filters := &probes.Filters{}

		if len(pidArgs) > 0 || len(args) > 0 {
			filters.Flags |= probes.PIDFilter
		}

		pids := PIDs()
		if len(pids) > 0 {
			filters.AddPIDs(pids...)
		}

		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, os.Interrupt)

		child := make(chan os.Signal, 1)
		signal.Notify(child, unix.SIGCHLD)

		cc, err := sender.NewCollector()
		if err != nil {
			exit(err)
		}

		monitor := &Monitor{
			Opts: probes.Opts{
				Rate: 2 * time.Second,
			},
			Sender: sender.NewBundle(filters,
				&sender.Stderr{},
				cc,
			),
			probes: make(map[string]probes.Probe),
		}

		for _, typ := range enabledProbeTypes() {
			if err := monitor.AddProbe(typ); err != nil {
				exit(err)
			}
		}

		ctx, cancel := context.WithCancel(context.Background())
		monitor.Start(ctx)

		// function latency specific
		fncProbe := monitor.Probe(fnc.Type)
		if fncProbe != nil {
			for _, pid := range pids {
				fncProbe.(*fnc.Probe).AddPID(pid)
			}
		}

		// wait just a bit to ensure that the probes are started
		time.Sleep(time.Second)

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

			pid := int64(cmd.Process.Pid)

			filters.AddPIDs(pid)

			if fncProbe != nil {
				fncProbe.(*fnc.Probe).AddPID(pid)
			}
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

				if len(pidArgs) == 0 {
					cancel()
					break LOOP
				}
			}
		}
		monitor.Wait()
	},
}

func main() {
	rootCmd.PersistentFlags().StringArrayVarP(&pidArgs, "pid", "p", []string{}, "capture specified pid")

	rootCmd.PersistentFlags().BoolVarP(&allProbesArg, "all", "a", false, "enable all probes")
	rootCmd.PersistentFlags().BoolVarP(&cpuProbeArg, "cpu", "c", false, "enable cpu probe")
	rootCmd.PersistentFlags().BoolVarP(&ioProbeArg, "io", "i", false, "enable io probe")
	rootCmd.PersistentFlags().BoolVarP(&mallocProbeArg, "malloc", "m", false, "enable malloc probe")
	rootCmd.PersistentFlags().BoolVarP(&vfsProbeArg, "vfs", "v", false, "enable vfs probe")
	rootCmd.PersistentFlags().BoolVarP(&fncProbeArg, "fnc", "f", false, "enable function probe")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
