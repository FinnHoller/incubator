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

//go:build unix || linux || darwin

package kvstore

import (
	"syscall"

	"k8s.io/klog/v2"
)

// autoTuneMaxOpenFiles inspects and optionally raises the process rlimit to determine a safe,
// high-performance MaxOpenFiles limit for Pebble, avoiding SSTable file descriptor churn at scale.
func autoTuneMaxOpenFiles() int {
	var rlim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlim); err != nil {
		klog.V(2).Infof("kvstore: failed to query RLIMIT_NOFILE: %v; defaulting MaxOpenFiles to 1000", err)
		return 1000
	}

	// Attempt to elevate soft limit to min(hard limit, 65536)
	const desiredLimit = 65536
	if rlim.Cur < desiredLimit && rlim.Max > rlim.Cur {
		newCur := rlim.Max
		if newCur > desiredLimit {
			newCur = desiredLimit
		}
		setLim := rlim
		setLim.Cur = newCur
		if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &setLim); err == nil {
			rlim.Cur = newCur
			klog.V(2).Infof("kvstore: elevated RLIMIT_NOFILE soft limit to %d", rlim.Cur)
		}
	}

	// Reserve 512 descriptors for sockets, tile cache, and MPT mmap handles
	const reservedFDs = 512
	var autoLimit int
	if rlim.Cur > reservedFDs {
		autoLimit = int(rlim.Cur - reservedFDs)
	} else {
		autoLimit = int(rlim.Cur) / 2
	}

	if autoLimit < 500 {
		autoLimit = 500
	}
	if autoLimit > 50000 {
		autoLimit = 50000
	}

	if rlim.Cur < 2048 {
		klog.Warningf("kvstore: system file descriptor limit is low (ulimit -n = %d). Pebble MaxOpenFiles constrained to %d. Run 'ulimit -n 65536' for optimal performance with large transparency logs.", rlim.Cur, autoLimit)
	} else {
		klog.V(2).Infof("kvstore: auto-configured Pebble MaxOpenFiles to %d (system ulimit -n = %d)", autoLimit, rlim.Cur)
	}

	return autoLimit
}
