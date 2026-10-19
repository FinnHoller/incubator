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

// Package mpt provides a pure Sparse Merkle Patricia Trie manager and proof verifier
// without storage or Output Log publishing dependencies.
package mpt

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"

	torchmpt "filippo.io/torchwood/mpt"
	"github.com/transparency-dev/incubator/vindex/internal/wire"
	"golang.org/x/sync/errgroup"
)

func keyHashToHexKey(keyHash [sha256.Size]byte) []byte {
	var hexKey [sha256.Size * 2]byte
	hex.Encode(hexKey[:], keyHash[:])
	return hexKey[:]
}

const (
	// MaxKeyLen is the maximum length in bytes of a canonical key stored in the MPT.
	MaxKeyLen = torchmpt.MaxKeyLen
	// MaxKeyBytes is an alias for MaxKeyLen (1024 bytes).
	MaxKeyBytes = MaxKeyLen
	// MaxValLen is the maximum length in bytes of a value stored in the MPT.
	MaxValLen = torchmpt.MaxValLen
)

var emptyMPTHash = sha256.Sum256(nil)

var (
	// ErrKeySize is returned when an MPT key is empty or exceeds MaxKeyLen (1024 bytes).
	ErrKeySize = torchmpt.ErrKeySize
	// ErrValSize is returned when an MPT value exceeds MaxValLen (1024 bytes).
	ErrValSize = torchmpt.ErrValSize
	// ErrInvalidCanonicalKey is returned when a canonical key is outside 1..1024 printable ASCII bytes (0x21..0x7E).
	ErrInvalidCanonicalKey = errors.New("invalid canonical key: must be 1..1024 printable ASCII bytes (0x21..0x7E) without NUL or whitespace")
	// ErrPrefixTooManyKeys is returned when a prefix scan exceeds the configured maximum key cardinality.
	ErrPrefixTooManyKeys = errors.New("prefix scan exceeded maximum allowed keys")
)

// PrefixKeyVal represents a canonical key and its 32-byte value log root yielded by a prefix scan.
type PrefixKeyVal = wire.KeyValueRoot

// ValidateCanonicalKey checks that key is between 1 and 1024 printable ASCII bytes (0x21..0x7E),
// containing no NUL (0x00) bytes or ASCII whitespace.
func ValidateCanonicalKey(key []byte) error {
	if len(key) == 0 || len(key) > MaxKeyLen {
		return fmt.Errorf("%w: length %d", ErrInvalidCanonicalKey, len(key))
	}
	for _, b := range key {
		if b < 0x21 || b > 0x7E {
			return fmt.Errorf("%w: invalid byte 0x%02x", ErrInvalidCanonicalKey, b)
		}
	}
	return nil
}

func validateMPTKeyLen(key []byte) error {
	return ValidateCanonicalKey(key)
}

func validateMPTValLen(val []byte) error {
	if len(val) > MaxValLen {
		return fmt.Errorf("%w: length %d (max %d)", ErrValSize, len(val), MaxValLen)
	}
	return nil
}

type syncCtl struct {
	deferSync bool
	files     []*deferredSyncFile
}

type deferredSyncFile struct {
	f           *os.File
	ctl         *syncCtl
	pendingSync bool
	dirty       bool
}

func (d *deferredSyncFile) ReadAt(b []byte, off int64) (int, error) {
	return d.f.ReadAt(b, off)
}

func (d *deferredSyncFile) WriteAt(b []byte, off int64) (int, error) {
	if d.pendingSync && d.ctl != nil {
		for _, peer := range d.ctl.files {
			if peer.pendingSync {
				if err := peer.f.Sync(); err != nil {
					return 0, err
				}
				peer.pendingSync = false
				peer.dirty = false
			}
		}
	}
	d.dirty = true
	return d.f.WriteAt(b, off)
}

func (d *deferredSyncFile) Sync() error {
	if d.ctl != nil && d.ctl.deferSync {
		d.pendingSync = true
		return nil
	}
	if err := d.f.Sync(); err != nil {
		return err
	}
	d.pendingSync = false
	d.dirty = false
	return nil
}

func (d *deferredSyncFile) Close() error {
	return d.f.Close()
}

var _ torchmpt.File = (*deferredSyncFile)(nil)

// Manager manages a Merkle Patricia Trie with thread-safe read access and lock-free root prediction.
type Manager struct {
	writeMu     sync.RWMutex // Serializes Commit, Persist, and Close operations
	treeMu      sync.RWMutex // Protects in-memory trie operations (Prove, Predict, Snap, Sync, root swaps)
	tree        torchmpt.Tree
	syncCtl     *syncCtl
	mmapDir     string
	currentRoot [sha256.Size]byte
	durableSize atomic.Uint64
	exact       atomic.Bool
}

// Open opens an existing MPT in the specified directory or creates a new one.
// If mmapDir is empty or ":memory:", an in-memory tree is used.
func Open(mmapDir string) (*Manager, error) {
	var tree torchmpt.Tree
	var ctl *syncCtl
	isNew := false
	if mmapDir == "" || mmapDir == ":memory:" {
		tree = torchmpt.NewMemTree()
		isNew = true
	} else {
		if err := os.MkdirAll(mmapDir, 0o755); err != nil {
			return nil, fmt.Errorf("failed to create mmap dir: %w", err)
		}
		file1 := filepath.Join(mmapDir, "mpt.tree1")
		file2 := filepath.Join(mmapDir, "mpt.tree2")
		disk := filepath.Join(mmapDir, "mpt.disk")

		openThree := func(flag int) (*os.File, *os.File, *os.File, error) {
			f1, err := os.OpenFile(file1, flag, 0o666)
			if err != nil {
				return nil, nil, nil, err
			}
			f2, err := os.OpenFile(file2, flag, 0o666)
			if err != nil {
				_ = f1.Close()
				return nil, nil, nil, err
			}
			f3, err := os.OpenFile(disk, flag, 0o666)
			if err != nil {
				_ = f1.Close()
				_ = f2.Close()
				return nil, nil, nil, err
			}
			return f1, f2, f3, nil
		}

		f1, f2, f3, openErr := openThree(os.O_RDWR)
		if openErr != nil {
			if errors.Is(openErr, os.ErrNotExist) {
				var createErr error
				f1, f2, f3, createErr = openThree(os.O_RDWR | os.O_CREATE | os.O_EXCL)
				if createErr != nil {
					return nil, fmt.Errorf("torchmpt create files failed: %w", createErr)
				}
				isNew = true
			} else {
				return nil, fmt.Errorf("torchmpt open files failed: %w", openErr)
			}
		}

		ctl = &syncCtl{}
		df1 := &deferredSyncFile{f: f1, ctl: ctl}
		df2 := &deferredSyncFile{f: f2, ctl: ctl}
		df3 := &deferredSyncFile{f: f3, ctl: ctl}
		ctl.files = []*deferredSyncFile{df1, df2, df3}

		tree, openErr = torchmpt.New(df1, df2, df3)
		if openErr != nil {
			_ = f1.Close()
			_ = f2.Close()
			_ = f3.Close()
			return nil, fmt.Errorf("torchmpt.New failed: %w", openErr)
		}
	}

	initVer, initExact := tree.Version()

	snap, err := tree.Snap(-1)
	if err != nil {
		_ = tree.Close()
		return nil, fmt.Errorf("initial Snap failed: %w", err)
	}
	if isNew || (initVer == 0 && [sha256.Size]byte(snap.Hash) == emptyMPTHash) {
		initExact = true
	}

	mgr := &Manager{
		tree:        tree,
		syncCtl:     ctl,
		mmapDir:     mmapDir,
		currentRoot: [sha256.Size]byte(snap.Hash),
	}
	if initVer > 0 {
		mgr.durableSize.Store(uint64(initVer))
	}
	mgr.exact.Store(initExact)
	return mgr, nil
}

// NewMem creates a new in-memory MPT manager.
func NewMem() *Manager {
	mgr, _ := Open("")
	return mgr
}

// NewManager opens an existing MPT in the specified directory or creates a new one (alias for Open).
func NewManager(mmapDir string) (*Manager, error) {
	return Open(mmapDir)
}

// RLock acquires the read lock.
func (m *Manager) RLock() {
	m.treeMu.RLock()
}

// RUnlock releases the read lock.
func (m *Manager) RUnlock() {
	m.treeMu.RUnlock()
}

// Lock acquires the write lock.
func (m *Manager) Lock() {
	m.writeMu.Lock()
	m.treeMu.Lock()
}

// Unlock releases the write lock.
func (m *Manager) Unlock() {
	m.treeMu.Unlock()
	m.writeMu.Unlock()
}

// Root returns the current MPT root hash.
func (m *Manager) Root() [sha256.Size]byte {
	m.treeMu.RLock()
	defer m.treeMu.RUnlock()
	return m.currentRoot
}

// SortKeyVals sorts changes by Key using parallel bucket sort across CPU cores when size is large.
func SortKeyVals(changes []torchmpt.KeyVal) {
	const parallelThreshold = 8192
	if len(changes) < parallelThreshold {
		slices.SortFunc(changes, torchmpt.KeyVal.CompareKey)
		return
	}

	var counts [256]int
	for i := range changes {
		var b byte
		if len(changes[i].Key) > 0 {
			b = changes[i].Key[0]
		}
		counts[b]++
	}

	var offsets [257]int
	for i := 0; i < 256; i++ {
		offsets[i+1] = offsets[i] + counts[i]
	}

	aux := make([]torchmpt.KeyVal, len(changes))
	cursor := offsets
	for i := range changes {
		var b byte
		if len(changes[i].Key) > 0 {
			b = changes[i].Key[0]
		}
		aux[cursor[b]] = changes[i]
		cursor[b]++
	}

	var g errgroup.Group
	workers := runtime.GOMAXPROCS(0)
	if workers < 1 {
		workers = 1
	}
	bucketChunk := (256 + workers - 1) / workers
	for w := 0; w < workers; w++ {
		bStart := w * bucketChunk
		bEnd := bStart + bucketChunk
		if bEnd > 256 {
			bEnd = 256
		}
		if bStart >= 256 {
			break
		}
		g.Go(func() error {
			for b := bStart; b < bEnd; b++ {
				start := offsets[b]
				end := offsets[b+1]
				if end-start > 1 {
					slices.SortFunc(aux[start:end], torchmpt.KeyVal.CompareKey)
				}
			}
			return nil
		})
	}
	_ = g.Wait()
	copy(changes, aux)
}

// PredictRootFromKeyBatch calculates the MPT root hash that would result from applying variable-length key mutations without modifying the tree (alias for PredictKeys).
func (m *Manager) PredictRootFromKeyBatch(mutations map[string][sha256.Size]byte) ([sha256.Size]byte, error) {
	return m.PredictKeys(mutations)
}

// PredictKeys calculates the MPT root hash that would result from applying variable-length key mutations without modifying the tree.
func (m *Manager) PredictKeys(mutations map[string][sha256.Size]byte) ([sha256.Size]byte, error) {
	if len(mutations) == 0 {
		return m.Root(), nil
	}

	changes := make([]torchmpt.KeyVal, 0, len(mutations))
	for k, v := range mutations {
		if err := validateMPTKeyLen([]byte(k)); err != nil {
			return [sha256.Size]byte{}, err
		}
		valCopy := v
		changes = append(changes, torchmpt.KeyVal{
			Key: torchmpt.Key(k),
			Val: torchmpt.Val(valCopy[:]),
		})
	}
	SortKeyVals(changes)

	return m.PredictKeyVals(changes)
}

// Predict calculates the MPT root hash that would result from applying fixed 32-byte keyHash mutations (encoded as 64-byte lowercase hex keys) without modifying the tree.
func (m *Manager) Predict(mutations map[[sha256.Size]byte][sha256.Size]byte) ([sha256.Size]byte, error) {
	if len(mutations) == 0 {
		return m.Root(), nil
	}

	changes := make([]torchmpt.KeyVal, 0, len(mutations))
	for k, v := range mutations {
		valCopy := v
		changes = append(changes, torchmpt.KeyVal{
			Key: torchmpt.Key(keyHashToHexKey(k)),
			Val: torchmpt.Val(valCopy[:]),
		})
	}
	SortKeyVals(changes)

	return m.PredictKeyVals(changes)
}

// PredictKeyVals calculates the MPT root hash that would result from applying sorted changes without modifying the tree.
func (m *Manager) PredictKeyVals(changes []torchmpt.KeyVal) ([sha256.Size]byte, error) {
	if len(changes) == 0 {
		return m.Root(), nil
	}
	for i := range changes {
		if err := validateMPTKeyLen(changes[i].Key); err != nil {
			return [sha256.Size]byte{}, err
		}
		if err := validateMPTValLen(changes[i].Val); err != nil {
			return [sha256.Size]byte{}, err
		}
	}

	m.treeMu.RLock()
	defer m.treeMu.RUnlock()

	hash, err := m.tree.Predict(changes)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("tree.Predict failed: %w", err)
	}
	return [sha256.Size]byte(hash), nil
}

// UpdateKey inserts or updates a single variable-length key-value pair in the MPT.
func (m *Manager) UpdateKey(key []byte, valHash [sha256.Size]byte) error {
	if err := validateMPTKeyLen(key); err != nil {
		return err
	}
	keyCopy := slices.Clone(key)
	valCopy := slices.Clone(valHash[:])

	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	m.treeMu.Lock()
	defer m.treeMu.Unlock()

	if err := m.tree.Set(torchmpt.Key(keyCopy), torchmpt.Val(valCopy)); err != nil {
		return fmt.Errorf("tree.Set failed: %w", err)
	}
	snap, err := m.tree.Snap(-1)
	if err != nil {
		return fmt.Errorf("tree.Snap failed: %w", err)
	}
	m.currentRoot = [sha256.Size]byte(snap.Hash)
	m.exact.Store(true)
	return nil
}

// Update inserts or updates a single 32-byte keyHash (encoded as 64-byte lowercase hex) in the MPT.
func (m *Manager) Update(keyHash [sha256.Size]byte, valHash [sha256.Size]byte) error {
	return m.UpdateKey(keyHashToHexKey(keyHash), valHash)
}

// SetKeyBatch applies variable-length key mutations directly to the working tree under writeMu without creating a snapshot.
func (m *Manager) SetKeyBatch(mutations map[string][sha256.Size]byte) error {
	if len(mutations) == 0 {
		return nil
	}
	changes := make([]torchmpt.KeyVal, 0, len(mutations))
	for k, v := range mutations {
		if err := validateMPTKeyLen([]byte(k)); err != nil {
			return err
		}
		valCopy := v
		changes = append(changes, torchmpt.KeyVal{
			Key: torchmpt.Key(k),
			Val: torchmpt.Val(valCopy[:]),
		})
	}
	SortKeyVals(changes)

	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	m.treeMu.Lock()
	defer m.treeMu.Unlock()

	for _, kv := range changes {
		if err := m.tree.Set(kv.Key, kv.Val); err != nil {
			return fmt.Errorf("tree.Set failed for key %q: %w", kv.Key, err)
		}
	}
	m.exact.Store(false)
	return nil
}

// SetBatch applies fixed 32-byte keyHash mutations (encoded as 64-byte lowercase hex) directly to the working tree under writeMu without creating a snapshot.
func (m *Manager) SetBatch(mutations map[[sha256.Size]byte][sha256.Size]byte) error {
	if len(mutations) == 0 {
		return nil
	}
	changes := make([]torchmpt.KeyVal, 0, len(mutations))
	for k, v := range mutations {
		valCopy := v
		changes = append(changes, torchmpt.KeyVal{
			Key: torchmpt.Key(keyHashToHexKey(k)),
			Val: torchmpt.Val(valCopy[:]),
		})
	}
	SortKeyVals(changes)

	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	m.treeMu.Lock()
	defer m.treeMu.Unlock()

	for _, kv := range changes {
		if err := m.tree.Set(kv.Key, kv.Val); err != nil {
			return fmt.Errorf("tree.Set failed for key %x: %w", kv.Key, err)
		}
	}
	m.exact.Store(false)
	return nil
}

// Snap creates a snapshot at the specified version, updates currentRoot, and returns the root hash.
func (m *Manager) Snap(version int64) ([sha256.Size]byte, error) {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	m.treeMu.Lock()
	defer m.treeMu.Unlock()

	snap, err := m.tree.Snap(version)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("tree.Snap failed: %w", err)
	}
	m.currentRoot = [sha256.Size]byte(snap.Hash)
	m.exact.Store(true)
	return m.currentRoot, nil
}

// CommitKeys applies variable-length key mutations to the MPT under the write lock and returns the new root hash.
func (m *Manager) CommitKeys(mutations map[string][sha256.Size]byte) ([sha256.Size]byte, error) {
	return m.CommitKeysWithVersion(mutations, -1)
}

// CommitKeysWithVersion applies variable-length key mutations, records the version watermark, and returns the new root hash.
func (m *Manager) CommitKeysWithVersion(mutations map[string][sha256.Size]byte, version int64) ([sha256.Size]byte, error) {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	m.treeMu.Lock()
	defer m.treeMu.Unlock()

	return m.commitKeysLocked(mutations, version)
}

// CommitKeysWithVersionLocked applies variable-length key mutations without acquiring the lock (caller must hold m.Lock()).
func (m *Manager) CommitKeysWithVersionLocked(mutations map[string][sha256.Size]byte, version int64) ([sha256.Size]byte, error) {
	return m.commitKeysLocked(mutations, version)
}

// Commit applies fixed 32-byte key mutations to the MPT under the write lock and returns the new root hash.
func (m *Manager) Commit(mutations map[[sha256.Size]byte][sha256.Size]byte) ([sha256.Size]byte, error) {
	return m.CommitWithVersion(mutations, -1)
}

// CommitWithVersion applies fixed 32-byte key mutations, records the version watermark, and returns the new root hash.
func (m *Manager) CommitWithVersion(mutations map[[sha256.Size]byte][sha256.Size]byte, version int64) ([sha256.Size]byte, error) {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	m.treeMu.Lock()
	defer m.treeMu.Unlock()

	return m.commitLocked(mutations, version)
}

// CommitWithVersionLocked applies fixed 32-byte key mutations without acquiring the lock (caller must hold m.Lock()).
func (m *Manager) CommitWithVersionLocked(mutations map[[sha256.Size]byte][sha256.Size]byte, version int64) ([sha256.Size]byte, error) {
	return m.commitLocked(mutations, version)
}

// CommitKeyValsLocked applies sorted changes directly without acquiring the lock (caller must hold m.Lock()).
func (m *Manager) CommitKeyValsLocked(changes []torchmpt.KeyVal, version int64) ([sha256.Size]byte, error) {
	for i := range changes {
		if err := validateMPTKeyLen(changes[i].Key); err != nil {
			return [sha256.Size]byte{}, err
		}
		if err := validateMPTValLen(changes[i].Val); err != nil {
			return [sha256.Size]byte{}, err
		}
	}
	for _, kv := range changes {
		if err := m.tree.Set(kv.Key, kv.Val); err != nil {
			return [sha256.Size]byte{}, fmt.Errorf("tree.Set failed for key %x: %w", kv.Key, err)
		}
	}

	snap, err := m.tree.Snap(version)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("tree.Snap failed: %w", err)
	}
	m.currentRoot = [sha256.Size]byte(snap.Hash)
	m.exact.Store(true)
	return m.currentRoot, nil
}

func (m *Manager) commitKeysLocked(mutations map[string][sha256.Size]byte, version int64) ([sha256.Size]byte, error) {
	if len(mutations) == 0 {
		return m.CommitKeyValsLocked(nil, version)
	}
	changes := make([]torchmpt.KeyVal, 0, len(mutations))
	for k, v := range mutations {
		if err := validateMPTKeyLen([]byte(k)); err != nil {
			return [sha256.Size]byte{}, err
		}
		valCopy := v
		changes = append(changes, torchmpt.KeyVal{
			Key: torchmpt.Key(k),
			Val: torchmpt.Val(valCopy[:]),
		})
	}
	SortKeyVals(changes)
	return m.CommitKeyValsLocked(changes, version)
}

func (m *Manager) commitLocked(mutations map[[sha256.Size]byte][sha256.Size]byte, version int64) ([sha256.Size]byte, error) {
	if len(mutations) == 0 {
		return m.CommitKeyValsLocked(nil, version)
	}
	changes := make([]torchmpt.KeyVal, 0, len(mutations))
	for k, v := range mutations {
		valCopy := v
		changes = append(changes, torchmpt.KeyVal{
			Key: torchmpt.Key(keyHashToHexKey(k)),
			Val: torchmpt.Val(valCopy[:]),
		})
	}
	SortKeyVals(changes)
	return m.CommitKeyValsLocked(changes, version)
}

// ProveKey generates an inclusion or non-inclusion proof for the given variable-length key.
func (m *Manager) ProveKey(key []byte) (proof []byte, valueRoot [sha256.Size]byte, exists bool, err error) {
	m.treeMu.RLock()
	defer m.treeMu.RUnlock()
	return m.ProveKeyLocked(key)
}

// ProveKeyLocked generates an inclusion or non-inclusion proof for key without acquiring the lock (caller must hold m.RLock()).
func (m *Manager) ProveKeyLocked(key []byte) (proof []byte, valueRoot [sha256.Size]byte, exists bool, err error) {
	if err := validateMPTKeyLen(key); err != nil {
		return nil, [sha256.Size]byte{}, false, err
	}
	path, err := m.tree.Path(torchmpt.Key(key))
	if err != nil {
		return nil, [sha256.Size]byte{}, false, err
	}
	val, ok, p, err := torchmpt.ProveLookup(torchmpt.Key(key), path)
	if err != nil {
		return nil, [sha256.Size]byte{}, false, err
	}
	var vr [sha256.Size]byte
	if ok {
		if len(val) != sha256.Size {
			return nil, [sha256.Size]byte{}, false, fmt.Errorf("unexpected MPT value length %d, want %d", len(val), sha256.Size)
		}
		copy(vr[:], val)
	}
	return []byte(p), vr, ok, nil
}

// Prove generates an inclusion or non-inclusion proof for the given 32-byte keyHash (encoded as 64-byte lowercase hex).
func (m *Manager) Prove(keyHash [sha256.Size]byte) (proof []byte, valueRoot [sha256.Size]byte, exists bool, err error) {
	return m.ProveKey(keyHashToHexKey(keyHash))
}

// ProveLocked generates an inclusion or non-inclusion proof for keyHash (encoded as 64-byte lowercase hex) without acquiring the lock (caller must hold m.RLock()).
func (m *Manager) ProveLocked(keyHash [sha256.Size]byte) (proof []byte, valueRoot [sha256.Size]byte, exists bool, err error) {
	return m.ProveKeyLocked(keyHashToHexKey(keyHash))
}

// ProvePrefix generates a prefix subtree proof and scans all keys matching prefix up to maxKeys (if maxKeys > 0).
func (m *Manager) ProvePrefix(prefix []byte, maxKeys int) (proof []byte, matches []PrefixKeyVal, err error) {
	m.treeMu.RLock()
	defer m.treeMu.RUnlock()
	return m.ProvePrefixLocked(prefix, maxKeys)
}

// ProvePrefixLocked generates a prefix subtree proof and scans all matching keys without acquiring the lock (caller must hold m.RLock()).
// If maxKeys > 0 and the number of matching keys exceeds maxKeys, iteration aborts immediately with ErrPrefixTooManyKeys.
func (m *Manager) ProvePrefixLocked(prefix []byte, maxKeys int) (proof []byte, matches []PrefixKeyVal, err error) {
	if err := validateMPTKeyLen(prefix); err != nil {
		return nil, nil, err
	}
	path, err := m.tree.Path(torchmpt.Key(prefix))
	if err != nil {
		return nil, nil, err
	}
	_, p, err := torchmpt.ProvePrefix(prefix, path)
	if err != nil {
		return nil, nil, err
	}

	for kv, scanErr := range m.tree.Scan(prefix) {
		if scanErr != nil {
			return nil, nil, scanErr
		}
		if maxKeys > 0 && len(matches) >= maxKeys {
			return nil, nil, fmt.Errorf("%w: prefix %q exceeded limit of %d keys", ErrPrefixTooManyKeys, prefix, maxKeys)
		}
		if len(kv.Val) != sha256.Size {
			return nil, nil, fmt.Errorf("unexpected MPT value length %d for key %q, want %d", len(kv.Val), kv.Key, sha256.Size)
		}
		var vr [sha256.Size]byte
		copy(vr[:], kv.Val)
		matches = append(matches, PrefixKeyVal{
			Key:       string(kv.Key),
			ValueRoot: vr,
		})
	}
	return []byte(p), matches, nil
}

// Version returns the version number of the MPT's last complete snapshot and whether it is exact.
func (m *Manager) Version() (int64, bool) {
	m.writeMu.RLock()
	defer m.writeMu.RUnlock()
	m.treeMu.RLock()
	defer m.treeMu.RUnlock()
	v, _ := m.tree.Version()
	return v, m.exact.Load()
}

// IsExact returns true if the MPT is at an exact committed snapshot without uncommitted SetBatch mutations.
func (m *Manager) IsExact() bool {
	_, exact := m.Version()
	return exact
}

// PersistedVersion returns the version number of the MPT's last complete snapshot.
func (m *Manager) PersistedVersion() int64 {
	v, _ := m.Version()
	return v
}

// PersistedSize returns the tree size corresponding to the durably synced version on disk.
func (m *Manager) PersistedSize() uint64 {
	return m.durableSize.Load()
}

// Persist flushes in-memory MPT patches into the OS page cache under treeMu (preventing races
// with concurrent Path/Scan/Predict readers) while deferring blocking kernel fsync syscalls
// until after treeMu is released.
func (m *Manager) Persist() error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	m.treeMu.Lock()
	if m.syncCtl != nil {
		m.syncCtl.deferSync = true
	}
	syncErr := m.tree.Sync()
	v, _ := m.tree.Version()
	isExact := m.exact.Load()
	if m.syncCtl != nil {
		m.syncCtl.deferSync = false
	}
	m.treeMu.Unlock()

	if syncErr != nil {
		return syncErr
	}

	if m.syncCtl != nil {
		for _, df := range m.syncCtl.files {
			if df.pendingSync || df.dirty {
				if err := df.f.Sync(); err != nil {
					return err
				}
				df.pendingSync = false
				df.dirty = false
			}
		}
	}

	if isExact && v > 0 {
		m.durableSize.Store(uint64(v))
	}
	return nil
}

// Sync flushes changes to disk under writeMu (alias for Persist).
func (m *Manager) Sync() error {
	return m.Persist()
}

// Close closes the underlying MPT files.
func (m *Manager) Close() error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	m.treeMu.Lock()
	defer m.treeMu.Unlock()

	if m.syncCtl != nil {
		m.syncCtl.deferSync = false
	}
	_ = m.tree.Sync()
	if m.syncCtl != nil {
		for _, df := range m.syncCtl.files {
			if df.pendingSync || df.dirty {
				_ = df.f.Sync()
				df.pendingSync = false
				df.dirty = false
			}
		}
	}
	return m.tree.Close()
}

func cutCanonicalUvarint(b []byte) (uint64, []byte, error) {
	val, n := binary.Uvarint(b)
	if n <= 0 {
		return 0, nil, fmt.Errorf("%w: malformed uvarint", torchmpt.ErrInvalidProof)
	}
	if n > 1 && b[n-1] == 0 {
		return 0, nil, fmt.Errorf("%w: non-canonical overlong uvarint", torchmpt.ErrInvalidProof)
	}
	return val, b[n:], nil
}

func validateProofWireBounds(root [sha256.Size]byte, hasTerminalLeaf bool, proof []byte) error {
	steps := proof
	if hasTerminalLeaf {
		if root == emptyMPTHash {
			if len(proof) != 0 {
				return fmt.Errorf("%w: expected empty proof for empty MPT", torchmpt.ErrInvalidProof)
			}
			return nil
		}

		klen, afterKLen, err := cutCanonicalUvarint(steps)
		if err != nil {
			return err
		}
		if klen > uint64(len(afterKLen)) {
			return fmt.Errorf("%w: truncated terminal leaf key", torchmpt.ErrInvalidProof)
		}
		pkey := afterKLen[:klen]
		steps = afterKLen[klen:]
		if err := ValidateCanonicalKey(pkey); err != nil {
			return fmt.Errorf("%w: %w", torchmpt.ErrInvalidProof, err)
		}

		vlen, afterVLen, err := cutCanonicalUvarint(steps)
		if err != nil {
			return err
		}
		if vlen > uint64(len(afterVLen)) {
			return fmt.Errorf("%w: truncated terminal leaf value", torchmpt.ErrInvalidProof)
		}
		pval := afterVLen[:vlen]
		steps = afterVLen[vlen:]
		if len(pval) != sha256.Size {
			return fmt.Errorf("%w: terminal leaf value length %d, want %d", torchmpt.ErrInvalidProof, len(pval), sha256.Size)
		}
	}

	const maxSplitBit = uint64(8 * MaxKeyBytes)
	prevBit := maxSplitBit + 1
	for len(steps) > 0 {
		ub, rest, err := cutCanonicalUvarint(steps)
		if err != nil {
			return err
		}
		if ub > maxSplitBit {
			return fmt.Errorf("%w: split bit %d exceeds maximum %d", torchmpt.ErrInvalidProof, ub, maxSplitBit)
		}
		if ub >= prevBit {
			return fmt.Errorf("%w: split bits not strictly decreasing (%d >= %d)", torchmpt.ErrInvalidProof, ub, prevBit)
		}
		if len(rest) < sha256.Size {
			return fmt.Errorf("%w: truncated sibling hash in path step", torchmpt.ErrInvalidProof)
		}
		steps = rest[sha256.Size:]
		prevBit = ub
	}
	return nil
}

// VerifyKey verifies an inclusion or non-inclusion proof for a variable-length key against an MPT root hash.
func VerifyKey(root [sha256.Size]byte, key []byte, valHash [sha256.Size]byte, exists bool, proof []byte) error {
	if err := ValidateCanonicalKey(key); err != nil {
		return err
	}
	if err := validateProofWireBounds(root, !exists, proof); err != nil {
		return err
	}
	snap := torchmpt.Snapshot{
		Hash:    torchmpt.Hash(root),
		Version: -1,
	}
	var val []byte
	if exists {
		val = valHash[:]
	}
	return torchmpt.VerifyLookup(snap, key, val, exists, torchmpt.Proof(proof))
}

// Verify verifies an inclusion or non-inclusion proof for a 32-byte keyHash (encoded as 64-byte lowercase hex) against an MPT root hash.
func Verify(root [sha256.Size]byte, keyHash [sha256.Size]byte, valHash [sha256.Size]byte, exists bool, proof []byte) error {
	return VerifyKey(root, keyHashToHexKey(keyHash), valHash, exists, proof)
}

// VerifyPrefix verifies a prefix subtree proof and the completeness/soundness of matches against an MPT root hash.
// It enforces the two-sided prefix verification invariant:
//  1. prefix and every returned key must be valid canonical keys (1..1024 printable ASCII bytes in 0x21..0x7E).
//  2. Every returned key k must satisfy mpt.Key(k).HasPrefix(prefix).
//  3. Returned keys must be in strictly ascending mpt.Key.Compare order with no duplicates.
//  4. The reconstructed subtree hash from matches must pass mpt.VerifyPrefix against root.
func VerifyPrefix(root [sha256.Size]byte, prefix []byte, matches []PrefixKeyVal, proof []byte) error {
	if err := ValidateCanonicalKey(prefix); err != nil {
		return err
	}

	kvs := make([]torchmpt.KeyVal, len(matches))
	for i, m := range matches {
		kBytes := []byte(m.Key)
		if err := ValidateCanonicalKey(kBytes); err != nil {
			return fmt.Errorf("invalid key at index %d: %w", i, err)
		}
		k := torchmpt.Key(kBytes)
		if !k.HasPrefix(prefix) {
			return fmt.Errorf("%w: key %q does not have prefix %q", torchmpt.ErrInvalidProof, m.Key, prefix)
		}
		if i > 0 {
			prevKey := kvs[i-1].Key
			if prevKey.Compare(k) >= 0 {
				return fmt.Errorf("%w: keys not in strictly increasing order at index %d (%q >= %q)", torchmpt.ErrInvalidProof, i, prevKey, k)
			}
		}
		valCopy := m.ValueRoot
		kvs[i] = torchmpt.KeyVal{
			Key: k,
			Val: torchmpt.Val(valCopy[:]),
		}
	}

	if err := validateProofWireBounds(root, len(matches) == 0, proof); err != nil {
		return err
	}

	subtreeHash := torchmpt.TreeHash(slices.Values(kvs))
	snap := torchmpt.Snapshot{
		Hash:    torchmpt.Hash(root),
		Version: -1,
	}
	return torchmpt.VerifyPrefix(snap, prefix, subtreeHash, torchmpt.Proof(proof))
}
