package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"shadow-ai-agent/collectors"
	"shadow-ai-agent/collectors/discovery"
	"shadow-ai-agent/config"
	"shadow-ai-agent/reporters"
)

func main() {
	configPath := flag.String("config", "config.json", "Path to agent configuration file")
	flag.Parse()

	log.Println("==================================================")
	log.Println(" Starting Shadow AI Endpoint Agent                ")
	log.Println("==================================================")

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to initialize config: %v", err)
	}

	log.Printf("[Init] Agent ID: %s", cfg.AgentID)
	log.Printf("[Init] Central API URL: %s", cfg.APIURL)

	reporter := reporters.NewReporter(cfg)
	go reporter.Start()

	stopChan := make(chan struct{})

	// Initialize Collectors
	procCollector := collectors.NewProcessCollector(cfg, reporter)
	go procCollector.RunPeriodic(stopChan)

	netCollector := collectors.NewNetworkCollector(cfg, reporter)
	go netCollector.RunPeriodic(stopChan)

	fileCollector := collectors.NewFileCollector(cfg, reporter)
	go fileCollector.RunPeriodic(stopChan)

	if cfg.DiscoveryEnabled {
		log.Println("[Init] Network discovery enabled")
		discoveryCollector := discovery.NewCollector(cfg)
		go discoveryCollector.RunPeriodic(stopChan)
	} else {
		log.Println("[Init] Network discovery disabled (set discovery_enabled=true to enable)")
	}

	go heartbeat(cfg, reporter, stopChan)

	log.Println("[Init] All background collectors initialized successfully.")

	// Handle graceful shutdown on OS signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	<-sigChan
	log.Println("[Shutdown] Signal received, shutting down gracefully...")
	close(stopChan)
	reporter.Stop()
	log.Println("[Shutdown] Agent stopped cleanly.")
}

// heartbeat: the agent is alive - its device is listed (Discovery -> Devices)
// even when nothing AI-related runs on it.
func heartbeat(cfg *config.AgentConfig, rep *reporters.Reporter, stop <-chan struct{}) {
	t := time.NewTicker(time.Duration(cfg.HeartbeatSec) * time.Second)
	defer t.Stop()
	for {
		rep.Submit(reporters.TelemetryEvent{EventType: "agent_heartbeat", ActionTaken: "monitored",
			UserID: os.Getenv("USER")})
		select {
		case <-stop:
			return
		case <-t.C:
		}
	}
}
