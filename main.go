package main

import (
	"github.com/safchain/koa/engine"
)

func main() {
	mon, err := engine.NewMonitor()
	if err != nil {
		engine.Logger.Errorf("Unable to load bpf program: %s", err)
	}
	_ = mon

	var worker engine.Worker

	if err := worker.Parse("worker.yaml"); err != nil {
		engine.Logger.Errorf("Unable to parse worker definition: %s", err)
	}

	var jobdef engine.JobDef

	if err := jobdef.Parse("job.yaml"); err != nil {
		engine.Logger.Errorf("Unable to parse job definition: %s", err)
	}

	job := engine.NewJob(worker, jobdef)
	job.Start()
}
