// provenza-agent: the Provenza endpoint agent for Linux, Windows and macOS.
//
//	provenza-agent install --server https://provenza.example.com --key KEY
//	provenza-agent status
//	provenza-agent uninstall [--purge]
//	provenza-agent run -config config.json      (what the service runs)
//	provenza-agent version
//
// "provenza-agent -config config.json" without a command is "run", as in
// earlier versions.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"shadow-ai-agent/collectors"
	"shadow-ai-agent/collectors/discovery"
	"shadow-ai-agent/config"
	"shadow-ai-agent/reporters"
	"shadow-ai-agent/service"
)

const usage = `Provenza endpoint agent %s (%s/%s)

Commands:
  install    install as a service and start it (as root / administrator)
               --server URL   your Provenza, https://provenza.example.com
               --key KEY      the Ingestion Source key ("-": read it from stdin)
               --agent-id ID  the name this machine is listed under (default: host name)
               --discovery    also discover network services (DNS, gateway, mDNS)
             run again to upgrade; the configuration is kept unless --server is given
  status     the service, the server and the queue of undelivered events
  uninstall  stop and remove the service (--purge: also the configuration and the key)
  run        run in the foreground: -config FILE [-log FILE]
  version    print the version
`

func main() {
	args := os.Args[1:]
	cmd := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "run":
		cmdRun(args)
	case "install":
		cmdInstall(args)
	case "uninstall":
		fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
		purge := fs.Bool("purge", false, "also remove the configuration, the key and the queue")
		_ = fs.Parse(args)
		exitOn(service.Uninstall(*purge, os.Stdout))
	case "status":
		exitOn(service.Status(os.Stdout))
	case "version", "--version":
		fmt.Printf("provenza-agent %s %s/%s\n", reporters.AgentVersion, runtime.GOOS, runtime.GOARCH)
	case "help", "-h", "--help":
		fmt.Printf(usage, reporters.AgentVersion, runtime.GOOS, runtime.GOARCH)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		fmt.Fprintf(os.Stderr, usage, reporters.AgentVersion, runtime.GOOS, runtime.GOARCH)
		os.Exit(2)
	}
}

func exitOn(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func cmdInstall(args []string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	var o service.Options
	fs.StringVar(&o.Server, "server", "", "your Provenza, https://provenza.example.com")
	fs.StringVar(&o.Key, "key", "", `the Ingestion Source key ("-": read it from stdin)`)
	fs.StringVar(&o.AgentID, "agent-id", "", "the name this machine is listed under")
	fs.BoolVar(&o.Discovery, "discovery", false, "also discover network services")
	_ = fs.Parse(args)
	if o.Key == "-" {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && err != io.EOF {
			exitOn(err)
		}
		o.Key = strings.TrimSpace(line)
	}
	exitOn(service.Install(o, os.Stdout))
}

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", "config.json", "Path to agent configuration file")
	logPath := fs.String("log", "", "write the log to this file (rotated at 10 MB) instead of stderr")
	_ = fs.Parse(args)
	if *logPath != "" {
		if f, err := openLog(*logPath, 10<<20); err == nil {
			log.SetOutput(f)
		} else {
			log.Printf("cannot open the log %s: %v", *logPath, err)
		}
	}
	runPlatform(*configPath)
}

// runUntilSignal runs the agent until Ctrl-C or SIGTERM.
func runUntilSignal(configPath string) {
	stop := make(chan struct{})
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("[Shutdown] Signal received, shutting down gracefully...")
		close(stop)
	}()
	runAgent(configPath, stop)
}

// runAgent starts the collectors and blocks until stop is closed.
func runAgent(configPath string, stop chan struct{}) {
	log.Printf("Starting Provenza endpoint agent %s (%s/%s)", reporters.AgentVersion, runtime.GOOS, runtime.GOARCH)

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to initialize config: %v", err)
	}
	if cfg.IngestionKey == "" {
		log.Printf("[Init] No ingestion key configured: the server will reject events until one is set")
	}

	log.Printf("[Init] Agent ID: %s", cfg.AgentID)
	log.Printf("[Init] Central API URL: %s", cfg.APIURL)

	reporter := reporters.NewReporter(cfg)
	go reporter.Start()

	procCollector := collectors.NewProcessCollector(cfg, reporter)
	go procCollector.RunPeriodic(stop)

	netCollector := collectors.NewNetworkCollector(cfg, reporter)
	go netCollector.RunPeriodic(stop)

	fileCollector := collectors.NewFileCollector(cfg, reporter)
	go fileCollector.RunPeriodic(stop)

	if cfg.DiscoveryEnabled {
		log.Println("[Init] Network discovery enabled")
		discoveryCollector := discovery.NewCollector(cfg)
		go discoveryCollector.RunPeriodic(stop)
	} else {
		log.Println("[Init] Network discovery disabled (set discovery_enabled=true to enable)")
	}

	go heartbeat(cfg, reporter, stop)

	log.Println("[Init] All background collectors initialized successfully.")

	<-stop
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
			UserID: collectors.AgentUser()})
		select {
		case <-stop:
			return
		case <-t.C:
		}
	}
}
