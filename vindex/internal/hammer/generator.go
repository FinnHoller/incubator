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

// Package hammer provides synthetic load generation and verification tools for VIndex.
package hammer

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"sync"
)

// Distribution defines the key selection distribution.
type Distribution string

const (
	DistZipf    Distribution = "zipf"
	DistPareto  Distribution = "pareto"
	DistUniform Distribution = "uniform"
)

// LeafFormat defines the raw payload formatting for synthetic leaves.
type LeafFormat string

const (
	FormatRaw   LeafFormat = "raw"   // Leaf is the raw key bytes (identity mapping)
	FormatSumDB LeafFormat = "sumdb" // Leaf is structured: "<key> v1.<ver>.0 h1:<hash>\n"
	FormatCT    LeafFormat = "ct"    // Leaf is line-delimited subdomains: "sub-1.domain-<id>.com\n..."
)

// GeneratorConfig configures the synthetic leaf generator.
type GeneratorConfig struct {
	Distribution Distribution
	NumKeys      uint64
	ZipfS        float64 // Skew parameter for Zipf (s > 1.0, e.g. 1.2)
	ZipfV        float64 // Scale parameter for Zipf (v >= 1.0, e.g. 1.0)
	Seed         int64
	LeafFormat   LeafFormat
	CTMinDomains int
	CTMaxDomains int
}

// DefaultGeneratorConfig returns a production-like default generator configuration.
func DefaultGeneratorConfig() GeneratorConfig {
	return GeneratorConfig{
		Distribution: DistZipf,
		NumKeys:      10000,
		ZipfS:        1.2,
		ZipfV:        1.0,
		Seed:         42,
		LeafFormat:   FormatRaw,
		CTMinDomains: 1,
		CTMaxDomains: 50,
	}
}

// LeafEntry represents a generated leaf with its key and key hash.
type LeafEntry struct {
	LeafData []byte
	Key      string
	KeyHash  [sha256.Size]byte
	Version  uint64
}

// Generator generates synthetic leaves with configurable key distributions.
type Generator struct {
	mu          sync.Mutex
	cfg         GeneratorConfig
	rng         *rand.Rand
	zipf        *rand.Zipf
	versionMap  map[uint64]uint64
	totalLeaves uint64
}

// NewGenerator creates a new Generator instance.
func NewGenerator(cfg GeneratorConfig) *Generator {
	if cfg.NumKeys == 0 {
		cfg.NumKeys = 10000
	}
	if cfg.ZipfS <= 1.0 {
		cfg.ZipfS = 1.2
	}
	if cfg.ZipfV < 1.0 {
		cfg.ZipfV = 1.0
	}
	if cfg.Seed == 0 {
		cfg.Seed = 42
	}
	if cfg.LeafFormat == "" {
		cfg.LeafFormat = FormatRaw
	}
	if cfg.CTMinDomains <= 0 {
		cfg.CTMinDomains = 1
	}
	if cfg.CTMaxDomains <= 0 {
		cfg.CTMaxDomains = 50
	}
	if cfg.CTMaxDomains < cfg.CTMinDomains {
		cfg.CTMaxDomains = cfg.CTMinDomains
	}

	src := rand.NewSource(cfg.Seed)
	rng := rand.New(src)

	var zipf *rand.Zipf
	if cfg.Distribution == DistZipf || cfg.Distribution == DistPareto {
		zipf = rand.NewZipf(rng, cfg.ZipfS, cfg.ZipfV, cfg.NumKeys-1)
	}

	return &Generator{
		cfg:        cfg,
		rng:        rng,
		zipf:       zipf,
		versionMap: make(map[uint64]uint64),
	}
}

func (g *Generator) keyForIDLocked(id uint64) string {
	if g.cfg.LeafFormat == FormatCT {
		return fmt.Sprintf("domain-%d.com", id)
	}
	return KeyForID(id)
}

func (g *Generator) keyHashForIDLocked(id uint64) [sha256.Size]byte {
	return sha256.Sum256([]byte(g.keyForIDLocked(id)))
}

// NextLeaf generates the next sequential leaf entry according to the configured distribution.
func (g *Generator) NextLeaf() LeafEntry {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.totalLeaves++

	if g.cfg.LeafFormat == FormatCT {
		count := g.cfg.CTMinDomains
		if g.cfg.CTMaxDomains > g.cfg.CTMinDomains {
			count = g.cfg.CTMinDomains + g.rng.Intn(g.cfg.CTMaxDomains-g.cfg.CTMinDomains+1)
		}

		var domainIDs []uint64
		seen := make(map[uint64]bool)
		for i := 0; i < count; i++ {
			id := g.sampleKeyIDLocked()
			if !seen[id] {
				seen[id] = true
				domainIDs = append(domainIDs, id)
			}
		}

		if len(domainIDs) == 0 {
			id := g.sampleKeyIDLocked()
			domainIDs = append(domainIDs, id)
		}

		for _, id := range domainIDs {
			g.versionMap[id]++
		}

		var buf strings.Builder
		for i, id := range domainIDs {
			fmt.Fprintf(&buf, "sub-%d.domain-%d.com\n", i+1, id)
		}

		primaryID := domainIDs[0]
		keyStr := g.keyForIDLocked(primaryID)
		keyHash := g.keyHashForIDLocked(primaryID)
		ver := g.versionMap[primaryID]

		return LeafEntry{
			LeafData: []byte(buf.String()),
			Key:      keyStr,
			KeyHash:  keyHash,
			Version:  ver,
		}
	}

	keyID := g.sampleKeyIDLocked()
	ver := g.versionMap[keyID] + 1
	g.versionMap[keyID] = ver

	keyStr := g.keyForIDLocked(keyID)
	keyHash := g.keyHashForIDLocked(keyID)

	var leafData []byte
	if g.cfg.LeafFormat == FormatSumDB {
		h := sha256.Sum256([]byte(fmt.Sprintf("%s@v1.%d.0", keyStr, ver)))
		leafData = []byte(fmt.Sprintf("%s v1.%d.0 h1:%s\n", keyStr, ver, hex.EncodeToString(h[:16])))
	} else {
		// Raw format: raw key string
		leafData = []byte(keyStr)
	}

	return LeafEntry{
		LeafData: leafData,
		Key:      keyStr,
		KeyHash:  keyHash,
		Version:  ver,
	}
}

// SampleExistingKey samples a key from the existing key distribution for reading.
func (g *Generator) SampleExistingKey() (string, [sha256.Size]byte) {
	g.mu.Lock()
	defer g.mu.Unlock()

	keyID := g.sampleKeyIDLocked()
	return g.keyForIDLocked(keyID), g.keyHashForIDLocked(keyID)
}

// SampleHotKey samples from the top 1% hottest keys in the working set.
func (g *Generator) SampleHotKey() (string, [sha256.Size]byte) {
	g.mu.Lock()
	defer g.mu.Unlock()

	hotCount := g.cfg.NumKeys / 100
	if hotCount == 0 {
		hotCount = 1
	}
	keyID := uint64(g.rng.Int63n(int64(hotCount)))
	return g.keyForIDLocked(keyID), g.keyHashForIDLocked(keyID)
}

// SampleLongTailKey samples from the bottom 50% rarest keys.
func (g *Generator) SampleLongTailKey() (string, [sha256.Size]byte) {
	g.mu.Lock()
	defer g.mu.Unlock()

	half := g.cfg.NumKeys / 2
	keyID := half + uint64(g.rng.Int63n(int64(g.cfg.NumKeys-half)))
	return g.keyForIDLocked(keyID), g.keyHashForIDLocked(keyID)
}

// SampleNonInclusionKey returns a key that is guaranteed to not exist in the log.
func (g *Generator) SampleNonInclusionKey() (string, [sha256.Size]byte) {
	g.mu.Lock()
	defer g.mu.Unlock()

	id := g.cfg.NumKeys + uint64(g.rng.Int63n(1000000)) + 1
	if g.cfg.LeafFormat == FormatCT {
		keyStr := fmt.Sprintf("nonexistent-domain-%d.com", id)
		return keyStr, sha256.Sum256([]byte(keyStr))
	}
	keyStr := fmt.Sprintf("nonexistent/pkg-%d", id)
	return keyStr, sha256.Sum256([]byte(keyStr))
}

func (g *Generator) sampleKeyIDLocked() uint64 {
	switch g.cfg.Distribution {
	case DistUniform:
		return uint64(g.rng.Int63n(int64(g.cfg.NumKeys)))
	case DistPareto:
		// Pareto distribution via inverse transform sampling or Zipf
		if g.zipf != nil {
			return g.zipf.Uint64()
		}
		return uint64(g.rng.Int63n(int64(g.cfg.NumKeys)))
	case DistZipf:
		fallthrough
	default:
		if g.zipf != nil {
			return g.zipf.Uint64()
		}
		return uint64(g.rng.Int63n(int64(g.cfg.NumKeys)))
	}
}

// KeyForID returns the deterministic string key name for a given key ID.
func KeyForID(id uint64) string {
	return fmt.Sprintf("example.com/module-%d", id)
}

// KeyHashForID returns the SHA-256 hash of the deterministic key name.
func KeyHashForID(id uint64) [sha256.Size]byte {
	return sha256.Sum256([]byte(KeyForID(id)))
}
