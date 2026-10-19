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

package kvstore

import (
	"crypto/sha256"
	"fmt"
	"math"
)

// KVState holds the persisted metadata state of the KV store.
type KVState struct {
	KVSize           uint64
	KVCheckpoint     []byte
	TargetCheckpoint []byte
}

// LoadKVState reads the persisted metadata keys from the database.
func (d *DB) LoadKVState() (*KVState, error) {
	kvSize, err := d.GetUint64(KeyMetaKVSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", string(KeyMetaKVSize), err)
	}

	kvCP, err := d.GetMetadata(KeyMetaKVCheckpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", string(KeyMetaKVCheckpoint), err)
	}

	targetCP, err := d.GetMetadata(KeyMetaTargetCheckpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", string(KeyMetaTargetCheckpoint), err)
	}

	return &KVState{
		KVSize:           kvSize,
		KVCheckpoint:     kvCP,
		TargetCheckpoint: targetCP,
	}, nil
}

// RecomputeValueRoot recomputes the value log root for keyHash from its active chunk.
func (d *DB) RecomputeValueRoot(keyHash [sha256.Size]byte, chunkSize uint64) ([sha256.Size]byte, error) {
	idx := NewKVIndexer(d, chunkSize)
	return idx.GetValueRoot(keyHash, math.MaxUint64)
}

// GetValueRoot calculates the value log root for keyHash up to maxInputLogSize without writes.
func (d *DB) GetValueRoot(keyHash [sha256.Size]byte, maxInputLogSize uint64) ([sha256.Size]byte, error) {
	idx := NewKVIndexer(d, d.ChunkSize())
	return idx.GetValueRoot(keyHash, maxInputLogSize)
}
