package reporters

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// diskQueue keeps batches the server has not accepted yet, one JSON file
// per batch, so they survive a network outage and a restart of the agent
// or the machine. Files are named by time, so the oldest is sent first; the
// queue is bounded by size and drops its oldest batches when full.
type diskQueue struct {
	dir      string
	maxBytes int64
	mu       sync.Mutex
	seq      uint64
}

const queueSuffix = ".batch.json"

func openQueue(stateDir string, maxMB int) (*diskQueue, error) {
	dir := filepath.Join(stateDir, "queue")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &diskQueue{dir: dir, maxBytes: int64(maxMB) << 20}, nil
}

// push stores one batch; the write is atomic (temporary file, then rename).
func (q *diskQueue) push(data []byte) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.seq++
	name := fmt.Sprintf("%020d-%06d%s", time.Now().UnixNano(), q.seq%1000000, queueSuffix)
	tmp, err := os.CreateTemp(q.dir, ".tmp-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(q.dir, name)); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	q.trimLocked()
	return nil
}

type queued struct {
	name string
	size int64
}

func (q *diskQueue) listLocked() []queued {
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return nil
	}
	var out []queued
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), queueSuffix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, queued{name: e.Name(), size: info.Size()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// trimLocked drops the oldest batches while the queue is over its size.
func (q *diskQueue) trimLocked() {
	items := q.listLocked()
	var total int64
	for _, it := range items {
		total += it.size
	}
	for i := 0; total > q.maxBytes && i < len(items)-1; i++ { // keep the newest
		if os.Remove(filepath.Join(q.dir, items[i].name)) == nil {
			total -= items[i].size
			droppedLog(items[i].name)
		}
	}
}

// oldest returns the oldest batch, or ok=false when the queue is empty.
func (q *diskQueue) oldest() (name string, data []byte, ok bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, it := range q.listLocked() {
		data, err := os.ReadFile(filepath.Join(q.dir, it.name))
		if err != nil {
			continue
		}
		return it.name, data, true
	}
	return "", nil, false
}

func (q *diskQueue) remove(name string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	os.Remove(filepath.Join(q.dir, name))
}

func (q *diskQueue) len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.listLocked())
}
