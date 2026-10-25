package collectors

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"shadow-ai-agent/config"
	"shadow-ai-agent/reporters"
)

// TargetModelExtensions lists model weight file formats.
var TargetModelExtensions = []string{
	".gguf",
	".safetensors",
	".bin",
	".onnx",
	".pt",
}

// FileCollector scans configured directories for AI model weights.
type FileCollector struct {
	cfg       *config.AgentConfig
	reporter  *reporters.Reporter
	seenFiles map[string]int64
	mu        sync.Mutex
}

// NewFileCollector creates a file scanner.
func NewFileCollector(cfg *config.AgentConfig, rep *reporters.Reporter) *FileCollector {
	return &FileCollector{
		cfg:       cfg,
		reporter:  rep,
		seenFiles: make(map[string]int64),
	}
}

// ScanOnce traverses directories looking for downloaded models.
func (c *FileCollector) ScanOnce() {
	currentUser := os.Getenv("USER")

	for _, rootPath := range c.cfg.SearchRoots() {
		if _, err := os.Stat(rootPath); os.IsNotExist(err) {
			continue
		}

		_ = filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil
			}

			// Models are usually > 10MB
			if info.Size() < 10*1024*1024 {
				return nil
			}

			ext := strings.ToLower(filepath.Ext(path))
			isModel := false
			for _, targetExt := range TargetModelExtensions {
				if ext == targetExt {
					isModel = true
					break
				}
			}

			if isModel {
				c.mu.Lock()
				lastSize, seen := c.seenFiles[path]
				c.seenFiles[path] = info.Size()
				c.mu.Unlock()

				if !seen || lastSize != info.Size() {
					log.Printf("[FileCollector] Discovered local model file: %s (%d MB)", path, info.Size()/(1024*1024))
					c.reporter.Submit(reporters.TelemetryEvent{
						EventType:   "local_model_found",
						AgentID:     c.cfg.AgentID,
						Domain:      "local_filesystem",
						UserID:      currentUser,
						RiskScore:   0.5,
						ActionTaken: "monitored",
						Payload: map[string]interface{}{
							"file_path": path,
							"file_name": filepath.Base(path),
							"extension": ext,
							"size_mb":   info.Size() / (1024 * 1024),
						},
					})
				}
			}
			return nil
		})
	}
}

// RunPeriodic runs the file collector periodically (every 5 minutes by default).
func (c *FileCollector) RunPeriodic(stopChan <-chan struct{}) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	c.ScanOnce()
	for {
		select {
		case <-stopChan:
			return
		case <-ticker.C:
			c.ScanOnce()
		}
	}
}
