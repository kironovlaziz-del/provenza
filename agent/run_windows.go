package main

import (
	"log"

	"golang.org/x/sys/windows/svc"

	"shadow-ai-agent/service"
)

// runPlatform: started by the Service Control Manager, the agent talks the
// service protocol (start, stop, shutdown); from a console it just runs.
func runPlatform(configPath string) {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		runUntilSignal(configPath)
		return
	}
	if err := svc.Run(service.WinServiceName, &winService{configPath: configPath}); err != nil {
		log.Fatalf("[Service] %v", err)
	}
}

type winService struct{ configPath string }

func (w *winService) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		runAgent(w.configPath, stop)
	}()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case <-done: // the agent ended on its own (a configuration error)
			return false, 1
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				close(stop)
				<-done
				return false, 0
			}
		}
	}
}
