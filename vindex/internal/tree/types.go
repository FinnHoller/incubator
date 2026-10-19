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

// Package tree provides Merkle Patricia Trie management and Output Log state publishing.
package tree

import (
	"context"
	"crypto/sha256"

	"github.com/transparency-dev/formats/log"
)

// OutputLogClient describes the client interface to append state commitments to the Output Log and fetch inclusion proofs.
type OutputLogClient interface {
	Append(ctx context.Context, leafData []byte) (leafIdx uint64, checkpoint []byte, err error)
	InclusionProof(ctx context.Context, leafIdx, treeSize uint64) ([][sha256.Size]byte, error)
}

// WitnessClient describes the remote witness client collecting checkpoint cosignatures.
type WitnessClient interface {
	Witness(ctx context.Context, checkpoint []byte) ([]byte, error)
}

// ServingState contains the immutable snapshot of the active serving state.
type ServingState struct {
	OutputLogIndex uint64
	OutputLogSize  uint64
	OutputLogCP    *log.Checkpoint
	RawCheckpoint  []byte // Raw signed checkpoint note bytes preserving witness cosignatures
	OutputLogProof [][sha256.Size]byte
	InputLogCP     *log.Checkpoint
	RawInputLogCP  []byte // Retained signed Input Log checkpoint note bytes (out-of-band)
	InputLogSize   uint64
	MPTRoot        [sha256.Size]byte
	From           uint64
}
