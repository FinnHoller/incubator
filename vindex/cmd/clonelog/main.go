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

// clonelog mirrors a tlog-tiles log to local disk with high concurrency.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/transparency-dev/tessera/api/layout"
	"golang.org/x/sync/errgroup"
	"k8s.io/klog/v2"
)

var (
	logURL             = flag.String("log_url", "https://bootstrap-mtca-shard3.cloudflareresearch.com/", "Base URL of the remote tlog-tiles log")
	outDir             = flag.String("out_dir", "", "Local directory to store mirrored log tiles (required)")
	numWorkers         = flag.Int("workers", 64, "Number of concurrent download workers")
	maxRetries         = flag.Int("max_retries", 10, "Maximum retry attempts per tile on transient network/server errors")
	progressInterval   = flag.Duration("progress_interval", 5*time.Second, "Interval for logging periodic progress")
	tileLevel          = flag.Int("tile_level", -1, "Tile level to clone (0..63 for tree tiles, -1 for entry bundles)")
	useLocalCheckpoint = flag.Bool("use_local_checkpoint", false, "Use existing local checkpoint file to determine tree size without overwriting it")
	logType            = flag.String("log_type", "auto", "Log layout type: 'auto', 'tessera', or 'static-ct'")
)

type cloneStats struct {
	downloadedTiles atomic.Uint64
	skippedTiles    atomic.Uint64
	downloadedBytes atomic.Uint64
	downloadedCerts atomic.Uint64
	skippedCerts    atomic.Uint64
}

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		klog.Exitf("clonelog failed: %v", err)
	}
}

func run(ctx context.Context) error {
	if *outDir == "" {
		return errors.New("--out_dir must be specified")
	}
	if *numWorkers <= 0 {
		return errors.New("--workers must be > 0")
	}

	baseURL, err := url.Parse(*logURL)
	if err != nil {
		return fmt.Errorf("invalid log_url %q: %w", *logURL, err)
	}
	if !strings.HasSuffix(baseURL.Path, "/") {
		baseURL.Path += "/"
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return fmt.Errorf("failed to create out_dir %q: %w", *outDir, err)
	}

	// High concurrency HTTP client with connection pooling
	transport := &http.Transport{
		MaxIdleConns:        *numWorkers * 4,
		MaxIdleConnsPerHost: *numWorkers * 2,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
	}

	var treeSize uint64
	if *useLocalCheckpoint {
		cpPath := filepath.Join(*outDir, "checkpoint")
		cpBytes, err := os.ReadFile(cpPath)
		if err != nil {
			return fmt.Errorf("failed to read local checkpoint %q: %w", cpPath, err)
		}
		treeSize, err = parseCheckpointTreeSize(cpBytes)
		if err != nil {
			return fmt.Errorf("failed to parse local checkpoint: %w", err)
		}
		klog.Infof("Using local checkpoint: treeSize = %d (checkpoint size: %d bytes)", treeSize, len(cpBytes))
	} else {
		klog.Infof("Fetching checkpoint from %s ...", baseURL.String())
		checkpointBytes, ts, err := fetchAndSaveCheckpoint(ctx, httpClient, baseURL, *outDir, *maxRetries)
		if err != nil {
			return fmt.Errorf("failed to fetch checkpoint: %w", err)
		}
		treeSize = ts
		klog.Infof("Fetched checkpoint successfully: treeSize = %d (checkpoint size: %d bytes)", treeSize, len(checkpointBytes))
	}

	numBundles := uint64(0)
	if treeSize > 0 {
		if *tileLevel >= 0 {
			shift := uint(uint64(*tileLevel)+1) * 8
			tileWidth := uint64(1) << shift
			numBundles = (treeSize + tileWidth - 1) / tileWidth
		} else {
			bundleWidth := uint64(layout.EntryBundleWidth)
			if bundleWidth == 0 {
				bundleWidth = 256
			}
			numBundles = (treeSize + bundleWidth - 1) / bundleWidth
		}
	}
	if *tileLevel >= 0 {
		klog.Infof("Starting clone of %d level-%d tree tiles to %s across %d workers", numBundles, *tileLevel, *outDir, *numWorkers)
	} else {
		klog.Infof("Starting clone of %d entry bundles (%d total certs) to %s across %d workers", numBundles, treeSize, *outDir, *numWorkers)
	}

	var stats cloneStats
	startTime := time.Now()

	// Progress monitor goroutine
	stopProgress := make(chan struct{})
	var wgProgress sync.WaitGroup
	wgProgress.Add(1)
	go func() {
		defer wgProgress.Done()
		ticker := time.NewTicker(*progressInterval)
		defer ticker.Stop()

		var lastBytes uint64
		var lastCerts uint64
		lastTime := startTime

		for {
			select {
			case <-stopProgress:
				return
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				dlTiles := stats.downloadedTiles.Load()
				skTiles := stats.skippedTiles.Load()
				totalProcessed := dlTiles + skTiles
				dlBytes := stats.downloadedBytes.Load()
				dlCerts := stats.downloadedCerts.Load()

				deltaSec := now.Sub(lastTime).Seconds()
				if deltaSec <= 0 {
					deltaSec = 1.0
				}
				deltaBytes := dlBytes - lastBytes
				deltaCerts := dlCerts - lastCerts

				rateMB := float64(deltaBytes) / (1024 * 1024 * deltaSec)
				rateCerts := float64(deltaCerts) / deltaSec

				pct := 0.0
				if numBundles > 0 {
					pct = float64(totalProcessed) / float64(numBundles) * 100.0
				}

				totalMB := float64(dlBytes) / (1024 * 1024)
				if *tileLevel >= 0 {
					rateTiles := float64(deltaCerts) / deltaSec
					klog.Infof("[Progress %5.1f%%] %d/%d tiles (%d downloaded, %d skipped) | %.1f MB | Rate: %.2f MB/s, %.0f tiles/s | Elapsed: %s",
						pct, totalProcessed, numBundles, dlTiles, skTiles, totalMB, rateMB, rateTiles, time.Since(startTime).Truncate(time.Second))
				} else {
					klog.Infof("[Progress %5.1f%%] %d/%d tiles (%d downloaded, %d skipped) | %d certs (%.1f MB) | Rate: %.2f MB/s, %.0f certs/s | Elapsed: %s",
						pct, totalProcessed, numBundles, dlTiles, skTiles, dlCerts, totalMB, rateMB, rateCerts, time.Since(startTime).Truncate(time.Second))
				}

				lastBytes = dlBytes
				lastCerts = dlCerts
				lastTime = now
			}
		}
	}()

	// Worker pool with errgroup
	g, gCtx := errgroup.WithContext(ctx)
	jobs := make(chan uint64, *numWorkers*4)

	// Feed bundle indices
	g.Go(func() error {
		defer close(jobs)
		for bIdx := uint64(0); bIdx < numBundles; bIdx++ {
			select {
			case <-gCtx.Done():
				return gCtx.Err()
			case jobs <- bIdx:
			}
		}
		return nil
	})

	// Spawn workers
	for w := 0; w < *numWorkers; w++ {
		g.Go(func() error {
			for bIdx := range jobs {
				if err := downloadBundle(gCtx, httpClient, baseURL, *outDir, bIdx, treeSize, *maxRetries, &stats); err != nil {
					return fmt.Errorf("failed on bundle %d: %w", bIdx, err)
				}
			}
			return nil
		})
	}

	workErr := g.Wait()
	close(stopProgress)
	wgProgress.Wait()

	elapsed := time.Since(startTime)
	dlTiles := stats.downloadedTiles.Load()
	skTiles := stats.skippedTiles.Load()
	dlBytes := stats.downloadedBytes.Load()
	dlCerts := stats.downloadedCerts.Load()
	totalMB := float64(dlBytes) / (1024 * 1024)

	if workErr != nil {
		return workErr
	}

	avgRateMB := 0.0
	avgRateCerts := 0.0
	if elapsed.Seconds() > 0 {
		avgRateMB = totalMB / elapsed.Seconds()
		avgRateCerts = float64(dlCerts) / elapsed.Seconds()
	}

	klog.Infof("Clone completed successfully in %s! Total: %d tiles (%d downloaded, %d skipped), %d certs, %.2f MB (Avg: %.2f MB/s, %.0f certs/s)",
		elapsed.Truncate(time.Second), dlTiles+skTiles, dlTiles, skTiles, dlCerts, totalMB, avgRateMB, avgRateCerts)

	return nil
}

func fetchAndSaveCheckpoint(ctx context.Context, client *http.Client, baseURL *url.URL, outDir string, retries int) ([]byte, uint64, error) {
	cpURL := baseURL.JoinPath("checkpoint").String()
	var rawData []byte
	var lastErr error

	for attempt := 0; attempt < retries; attempt++ {
		if ctx.Err() != nil {
			return nil, 0, ctx.Err()
		}
		if attempt > 0 {
			backoff := time.Duration(100*(1<<attempt))*time.Millisecond + time.Duration(rand.Intn(100))*time.Millisecond
			if backoff > 5*time.Second {
				backoff = 5 * time.Second
			}
			select {
			case <-ctx.Done():
				return nil, 0, ctx.Err()
			case <-time.After(backoff):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, cpURL, nil)
		if err != nil {
			return nil, 0, err
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("unexpected HTTP status %s from %s", resp.Status, cpURL)
			continue
		}
		rawData, err = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		break
	}

	if rawData == nil {
		return nil, 0, fmt.Errorf("failed to fetch checkpoint after %d attempts: %w", retries, lastErr)
	}

	treeSize, err := parseCheckpointTreeSize(rawData)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to parse checkpoint: %w", err)
	}

	destPath := filepath.Join(outDir, "checkpoint")
	tempPath := destPath + ".tmp"
	if err := os.WriteFile(tempPath, rawData, 0o644); err != nil {
		return nil, 0, fmt.Errorf("failed to write checkpoint to %s: %w", tempPath, err)
	}
	if err := os.Rename(tempPath, destPath); err != nil {
		return nil, 0, fmt.Errorf("failed to rename %s to %s: %w", tempPath, destPath, err)
	}

	return rawData, treeSize, nil
}

func parseCheckpointTreeSize(raw []byte) (uint64, error) {
	lines := strings.Split(string(bytes.TrimRight(raw, "\n")), "\n")
	if len(lines) < 2 {
		return 0, fmt.Errorf("checkpoint has %d lines, want at least 2", len(lines))
	}
	size, err := strconv.ParseUint(strings.TrimSpace(lines[1]), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid tree size %q: %w", lines[1], err)
	}
	return size, nil
}

func bundleCertsCount(bIdx, treeSize uint64) uint64 {
	bundleWidth := uint64(layout.EntryBundleWidth)
	if bundleWidth == 0 {
		bundleWidth = 256
	}
	start := bIdx * bundleWidth
	if start >= treeSize {
		return 0
	}
	end := start + bundleWidth
	if end > treeSize {
		return treeSize - start
	}
	return bundleWidth
}

func downloadBundle(ctx context.Context, client *http.Client, baseURL *url.URL, outDir string, bIdx, treeSize uint64, retries int, stats *cloneStats) error {
	var p uint8
	var relPath, fullRelPath string
	certsInBundle := uint64(1)

	isStaticCT := false
	switch strings.ToLower(*logType) {
	case "static-ct", "ct":
		isStaticCT = true
	case "auto":
		if strings.Contains(baseURL.Host, "certificate.transparency") || strings.Contains(baseURL.Path, "static-ct") {
			isStaticCT = true
		}
	}

	if *tileLevel >= 0 {
		lvl := uint64(*tileLevel)
		p = layout.PartialTileSize(lvl, bIdx, treeSize)
		relPath = layout.TilePath(lvl, bIdx, p)
		fullRelPath = layout.TilePath(lvl, bIdx, 0)
	} else if isStaticCT {
		p = layout.PartialTileSize(0, bIdx, treeSize)
		tileRel := layout.TilePath(0, bIdx, p)
		relPath = fmt.Sprintf("tile/data/%s", tileRel[7:])
		fullRel := layout.TilePath(0, bIdx, 0)
		fullRelPath = fmt.Sprintf("tile/data/%s", fullRel[7:])
		certsInBundle = bundleCertsCount(bIdx, treeSize)
	} else {
		p = layout.PartialTileSize(0, bIdx, treeSize)
		relPath = layout.EntriesPath(bIdx, p)
		fullRelPath = layout.EntriesPath(bIdx, 0)
		certsInBundle = bundleCertsCount(bIdx, treeSize)
	}
	destPath := filepath.Join(outDir, relPath)

	// Check if already downloaded on restart
	if info, err := os.Stat(destPath); err == nil && info.Size() > 0 {
		stats.skippedTiles.Add(1)
		stats.skippedCerts.Add(certsInBundle)
		return nil
	}
	if p != 0 {
		fullPath := filepath.Join(outDir, fullRelPath)
		if info, err := os.Stat(fullPath); err == nil && info.Size() > 0 {
			stats.skippedTiles.Add(1)
			stats.skippedCerts.Add(certsInBundle)
			return nil
		}
	}

	tileURL := baseURL.JoinPath(relPath).String()
	tempPath := destPath + ".tmp"

	var lastErr error
	for attempt := 0; attempt < retries; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if attempt > 0 {
			backoff := time.Duration(100*(1<<attempt))*time.Millisecond + time.Duration(rand.Intn(100))*time.Millisecond
			if backoff > 10*time.Second {
				backoff = 10 * time.Second
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, tileURL, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		// Fallback for partial tiles if server converted them to full tiles
		if resp.StatusCode == http.StatusNotFound && p != 0 {
			_ = resp.Body.Close()
			fullURL := baseURL.JoinPath(fullRelPath).String()
			fullReq, fullErr := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
			if fullErr == nil {
				if fullResp, fullErr := client.Do(fullReq); fullErr == nil {
					if fullResp.StatusCode == http.StatusOK {
						data, readErr := io.ReadAll(fullResp.Body)
						_ = fullResp.Body.Close()
						if readErr == nil {
							fullDestPath := filepath.Join(outDir, fullRelPath)
							_ = os.MkdirAll(filepath.Dir(fullDestPath), 0o755)
							_ = os.WriteFile(fullDestPath+".tmp", data, 0o644)
							_ = os.Rename(fullDestPath+".tmp", fullDestPath)

							_ = os.MkdirAll(filepath.Dir(destPath), 0o755)
							_ = os.WriteFile(tempPath, data, 0o644)
							_ = os.Rename(tempPath, destPath)

							stats.downloadedTiles.Add(1)
							stats.downloadedBytes.Add(uint64(len(data)))
							stats.downloadedCerts.Add(certsInBundle)
							return nil
						}
					} else {
						_ = fullResp.Body.Close()
					}
				}
			}
			lastErr = fmt.Errorf("HTTP %s for %s and full tile fallback failed", resp.Status, tileURL)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %s for %s", resp.Status, tileURL)
			continue
		}

		data, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}

		dir := filepath.Dir(destPath)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("failed to create directory %q: %w", dir, err)
		}
		if err := os.WriteFile(tempPath, data, 0o644); err != nil {
			return fmt.Errorf("failed to write temp tile %q: %w", tempPath, err)
		}
		if err := os.Rename(tempPath, destPath); err != nil {
			return fmt.Errorf("failed to atomically rename %q to %q: %w", tempPath, destPath, err)
		}

		stats.downloadedTiles.Add(1)
		stats.downloadedBytes.Add(uint64(len(data)))
		stats.downloadedCerts.Add(certsInBundle)
		return nil
	}

	return fmt.Errorf("failed to download %s after %d attempts: %w", tileURL, retries, lastErr)
}
