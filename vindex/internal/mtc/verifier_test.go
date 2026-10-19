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

package mtc

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

func TestMTCVerifier(t *testing.T) {
	name := "oid/1.3.6.1.4.1.44363.47.1.44363.48.8"
	pubKeyB64 := "teYkXkxVoKhT1PxKODAyZFqUk8KZ4tUjzS6yAvvZ8hU="
	cosignerID := "44363.48.9"
	logID := "44363.48.8"

	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		t.Fatalf("Failed to decode pubKey: %v", err)
	}
	pubKey := ed25519.PublicKey(pubKeyBytes)

	v, err := NewMTCVerifier(name, pubKey, cosignerID, logID)
	if err != nil {
		t.Fatalf("NewMTCVerifier failed: %v", err)
	}

	if v.Name() != name {
		t.Errorf("Name() = %q, want %q", v.Name(), name)
	}

	wantKeyHash := uint32(0x8e6a3b1a)
	if v.KeyHash() != wantKeyHash {
		t.Errorf("KeyHash() = 0x%x, want 0x%x", v.KeyHash(), wantKeyHash)
	}

	checkpointText := `bootstrap-mtca.cloudflareresearch.com/logs/shard3
197762974
7NWRnNW49lCjHOLMyMLBYRkRTGxDhVEmQhTw2gD/Pig=`

	sigB64 := "jmo7GsZLYkXSa+C4eXII6rUTN8BECzdUogRIlzML8wqeWnFuTjOjAOGrHu79pnjuZBx1syo5FYNs5sKpj2D93QEkLws="
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("Failed to decode signature: %v", err)
	}
	rawSig := sigBytes[4:]

	if !v.Verify([]byte(checkpointText), rawSig) {
		t.Error("Verification failed")
	}

	parsed, err := ParseVerifier("mtc+" + name + "+" + cosignerID + "+" + logID + "+" + pubKeyB64)
	if err != nil {
		t.Fatalf("ParseVerifier(mtc+...) failed: %v", err)
	}
	if !parsed.Verify([]byte(checkpointText), rawSig) {
		t.Error("ParseVerifier MTC verification failed")
	}
}
