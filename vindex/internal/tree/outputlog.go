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

package tree

import (
	"crypto/sha256"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
)

// ErrOutputLogCorrupted indicates that an Output Log leaf payload is malformed.
var ErrOutputLogCorrupted = wire.ErrOutputLogCorrupted

// OutputLogLeaf is an alias for wire.OutputLogLeaf.
type OutputLogLeaf = wire.OutputLogLeaf

// ParseOutputLogLeafFull parses a raw c2sp.org/tlog-vindex-state@v1 Output Log leaf payload.
func ParseOutputLogLeafFull(leafData []byte) (*wire.OutputLogLeaf, error) {
	return wire.ParseOutputLogLeafFull(leafData)
}

// ParseOutputLogLeaf parses a raw Output Log leaf payload into the 32-byte MPTRoot
// and the unsigned Input Log checkpoint header (Origin, Size, Hash).
func ParseOutputLogLeaf(leafData []byte) (mptRoot [sha256.Size]byte, inCP *log.Checkpoint, err error) {
	return wire.ParseOutputLogLeaf(leafData)
}

// FormatStateEntry formats a 6-line Output Log state commitment entry according to c2sp.org/tlog-vindex-state@v1.
func FormatStateEntry(inputOrigin string, from, inputSize uint64, inputRoot, mptRoot [sha256.Size]byte) []byte {
	return wire.FormatStateEntry(inputOrigin, from, inputSize, inputRoot, mptRoot)
}

// FormatOutputLogLeafFull formats a 6-line Output Log leaf according to c2sp.org/tlog-vindex-state@v1.
func FormatOutputLogLeafFull(mptRoot [sha256.Size]byte, from uint64, inCP *log.Checkpoint) []byte {
	return wire.FormatOutputLogLeafFull(mptRoot, from, inCP)
}

// FormatOutputLogLeaf formats a 6-line Output Log leaf from the MPTRoot and Input Log checkpoint header (with from=0).
func FormatOutputLogLeaf(mptRoot [sha256.Size]byte, inCP *log.Checkpoint) []byte {
	return wire.FormatOutputLogLeaf(mptRoot, inCP)
}
