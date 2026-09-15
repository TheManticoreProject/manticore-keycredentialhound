package identifier

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/TheManticoreProject/Manticore/windows/keycredentiallink/version"
)

func TestNormalizeKeyIdentifier(t *testing.T) {
	tests := []struct {
		name       string
		identifier string
		version    uint32
		expected   string
	}{
		{"version 0 hex", "deadbeef", version.KeyCredentialLinkVersion_0, "deadbeef"},
		{"version 1 hex", "deadbeef", version.KeyCredentialLinkVersion_1, "deadbeef"},
		{"version 1 uppercase hex", "DEADBEEF", version.KeyCredentialLinkVersion_1, "deadbeef"},
		{"version 2 base64", "3q2+7w==", version.KeyCredentialLinkVersion_2, "deadbeef"},
		{"version 2 base64 without padding", "3q2+7w", version.KeyCredentialLinkVersion_2, "deadbeef"},
		{"unknown version treated as base64", "3q2+7w==", 0x00000300, "deadbeef"},
		{"empty identifier", "", version.KeyCredentialLinkVersion_2, ""},
		{"undecodable value is left as-is", "not valid !!", version.KeyCredentialLinkVersion_2, "not valid !!"},
		{"odd length hex is left as-is", "abc", version.KeyCredentialLinkVersion_0, "abc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kcv := version.KeyCredentialLinkVersion{Value: tt.version}
			got := NormalizeKeyIdentifier(tt.identifier, kcv)
			if got != tt.expected {
				t.Errorf("NormalizeKeyIdentifier(%q, %#x) = %q, want %q", tt.identifier, tt.version, got, tt.expected)
			}
		})
	}
}

// TestNormalizeKeyIdentifierIsVersionIndependent checks the property the node ids
// rely on: one key material yields one identifier whatever the link version that
// carried it, so the same key registered on two accounts collapses into a single
// key material node.
func TestNormalizeKeyIdentifierIsVersionIndependent(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}

	asVersion1 := NormalizeKeyIdentifier(
		hex.EncodeToString(raw),
		version.KeyCredentialLinkVersion{Value: version.KeyCredentialLinkVersion_1},
	)
	asVersion2 := NormalizeKeyIdentifier(
		base64.StdEncoding.EncodeToString(raw),
		version.KeyCredentialLinkVersion{Value: version.KeyCredentialLinkVersion_2},
	)

	if asVersion1 != asVersion2 {
		t.Errorf("same key material normalized differently across versions: v1=%q, v2=%q", asVersion1, asVersion2)
	}
	if asVersion1 != hex.EncodeToString(raw) {
		t.Errorf("NormalizeKeyIdentifier() = %q, want canonical hex %q", asVersion1, hex.EncodeToString(raw))
	}
}
