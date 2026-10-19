// Copyright 2026 The Transparency Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hammer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/transparency-dev/formats/log"
	"k8s.io/klog/v2"
)

// ServerConfig configures the drip-feed HTTP server.
type ServerConfig struct {
	ListenAddr    string
	StorageDir    string
	DripRate      float64       // Checkpoints per second released to clients (0 = immediate)
	BurstSize     int           // Number of checkpoints released per burst (default: 1)
	BurstInterval time.Duration // Interval between bursts (0 = steady drip)
	InitialPause  time.Duration // Initial pause duration before drip-feeding begins
}

// DefaultServerConfig returns default server settings.
func DefaultServerConfig(storageDir string) ServerConfig {
	return ServerConfig{
		ListenAddr:    ":8085",
		StorageDir:    storageDir,
		DripRate:      2.0,
		BurstSize:     1,
		BurstInterval: 0,
		InitialPause:  0,
	}
}

// DripServer hosts local POSIX log tiles and drip-feeds checkpoints to vindexd.
type DripServer struct {
	cfg         ServerConfig
	queue       *CheckpointQueue
	httpServer  *http.Server
	listener    net.Listener
	mu          sync.RWMutex
	publishedCP []byte
	publishedSz uint64
	dripCount   uint64
}

// NewDripServer creates a new DripServer instance.
func NewDripServer(cfg ServerConfig, queue *CheckpointQueue) *DripServer {
	if cfg.BurstSize <= 0 {
		cfg.BurstSize = 1
	}
	if queue == nil {
		queue = NewCheckpointQueue()
	}

	return &DripServer{
		cfg:   cfg,
		queue: queue,
	}
}

// RegisterRoutes sets up HTTP handlers on the given ServeMux.
func (s *DripServer) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/checkpoint", s.HandleCheckpoint)
	mux.HandleFunc("/checkpoint_direct", s.HandleDirectCheckpoint)

	// File server for tiles, entry bundles, etc.
	fileServer := http.FileServer(http.Dir(s.cfg.StorageDir))
	mux.Handle("/", fileServer)
}

// HandleCheckpoint serves the current drip-fed checkpoint.
func (s *DripServer) HandleCheckpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	cp := s.publishedCP
	s.mu.RUnlock()

	if len(cp) == 0 {
		http.Error(w, "checkpoint not ready", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(cp)
}

// HandleDirectCheckpoint serves the latest checkpoint in the queue without waiting for the drip schedule.
func (s *DripServer) HandleDirectCheckpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cp, ok := s.queue.PeekLatest()
	if !ok {
		s.mu.RLock()
		cp = s.publishedCP
		s.mu.RUnlock()
	}

	if len(cp) == 0 {
		http.Error(w, "no checkpoint available", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(cp)
}

// SetPublishedCheckpoint manually sets the active drip-fed checkpoint.
func (s *DripServer) SetPublishedCheckpoint(rawCP []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.publishedCP = rawCP
	s.dripCount++
}

// GetPublishedCheckpoint returns the currently published checkpoint bytes.
func (s *DripServer) GetPublishedCheckpoint() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.publishedCP
}

// URL returns the base URL of the running server.
func (s *DripServer) URL() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.listener == nil {
		return fmt.Sprintf("http://%s", s.cfg.ListenAddr)
	}
	return fmt.Sprintf("http://%s", s.listener.Addr().String())
}

// Start binds to the listening port and starts background drip scheduling.
func (s *DripServer) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	s.RegisterRoutes(mux)

	listener, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.cfg.ListenAddr, err)
	}

	s.mu.Lock()
	s.listener = listener
	s.httpServer = &http.Server{
		Handler: mux,
	}
	s.mu.Unlock()

	go func() {
		if err := s.httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			klog.Errorf("DripServer HTTP error: %v", err)
		}
	}()

	go s.runDripScheduler(ctx)

	klog.Infof("DripServer listening on %s (storage: %s)", listener.Addr().String(), s.cfg.StorageDir)
	return nil
}

func (s *DripServer) runDripScheduler(ctx context.Context) {
	if s.cfg.InitialPause > 0 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.cfg.InitialPause):
		}
	}

	// Burst mode
	if s.cfg.BurstInterval > 0 && s.cfg.BurstSize > 1 {
		ticker := time.NewTicker(s.cfg.BurstInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				burst := s.queue.DequeueBurst(s.cfg.BurstSize)
				if len(burst) > 0 {
					latest := burst[len(burst)-1]
					s.updatePublished(latest)
					klog.V(2).Infof("DripServer released burst of %d checkpoints", len(burst))
				}
			}
		}
	}

	// Steady drip mode
	var interval time.Duration
	if s.cfg.DripRate > 0 {
		interval = time.Duration(float64(time.Second) / s.cfg.DripRate)
	} else {
		interval = 5 * time.Millisecond // Fast immediate polling
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if cp, ok := s.queue.Dequeue(); ok {
				s.updatePublished(cp)
			}
		}
	}
}

func (s *DripServer) updatePublished(rawCP []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.publishedCP = rawCP
	s.dripCount++

	if parsed, err := publisherParseCP(rawCP); err == nil {
		s.publishedSz = parsed.Size
	}
}

func publisherParseCP(rawCP []byte) (*log.Checkpoint, error) {
	// Extract origin and size from standard 3-line checkpoint header
	lines := splitLines(rawCP)
	if len(lines) < 3 {
		return nil, errors.New("malformed checkpoint")
	}
	var size uint64
	if _, err := fmt.Sscanf(string(lines[1]), "%d", &size); err != nil {
		return nil, err
	}
	return &log.Checkpoint{
		Origin: string(lines[0]),
		Size:   size,
	}, nil
}

func splitLines(b []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			lines = append(lines, b[start:i])
			start = i + 1
		}
	}
	if start < len(b) {
		lines = append(lines, b[start:])
	}
	return lines
}

// Close gracefully stops the HTTP server.
func (s *DripServer) Close(ctx context.Context) error {
	s.mu.Lock()
	srv := s.httpServer
	s.mu.Unlock()

	if srv != nil {
		return srv.Shutdown(ctx)
	}
	return nil
}
