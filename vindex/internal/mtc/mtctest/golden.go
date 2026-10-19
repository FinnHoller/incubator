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

// Package mtctest provides test utilities and authentic golden datasets for MTC leaf mapping.
package mtctest

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

//go:embed golden_leaves.json
var goldenLeavesJSON []byte

// GoldenLeafCase represents a golden test case for an MTC leaf entry.
type GoldenLeafCase struct {
	Category        string   `json:"category"`
	Description     string   `json:"description"`
	SANs            []string `json:"sans"`
	LeafHex         string   `json:"leaf_hex"`
	ExpectedDomains []string `json:"expected_domains"`
}

// LeafBytes returns the decoded raw bytes of the leaf.
func (c *GoldenLeafCase) LeafBytes() ([]byte, error) {
	b, err := hex.DecodeString(c.LeafHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode leaf hex for %q: %w", c.Category, err)
	}
	return b, nil
}

// MustLeafBytes returns the decoded raw bytes of the leaf, panicking on invalid hex.
func (c *GoldenLeafCase) MustLeafBytes() []byte {
	b, err := c.LeafBytes()
	if err != nil {
		panic(err)
	}
	return b
}

// GoldenLeaves returns the parsed list of golden test cases.
func GoldenLeaves() []GoldenLeafCase {
	var cases []GoldenLeafCase
	if err := json.Unmarshal(goldenLeavesJSON, &cases); err != nil {
		panic(fmt.Sprintf("failed to unmarshal golden_leaves.json: %v", err))
	}
	return cases
}
