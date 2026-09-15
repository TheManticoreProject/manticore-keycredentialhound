package identifier

import (
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/TheManticoreProject/Manticore/windows/keycredentiallink/version"
)

// NormalizeKeyIdentifier converts a KeyCredentialLink KeyID to a canonical
// lowercase hex string.
//
// The KeyID is encoded differently depending on the link version: hex for
// versions 0 and 1, base64 for version 2 and above. Using it as-is in a node id
// makes the id depend on the link version, so the same key registered on two
// accounts under two different versions would yield two distinct key material
// nodes and the "principals sharing key material" query would miss the pair.
// Re-encoding to hex removes that dependency and keeps ids free of the '+', '/'
// and '=' characters base64 introduces.
//
// An identifier that cannot be decoded is returned unchanged so that node ids
// stay stable across runs even for values this function does not understand.
func NormalizeKeyIdentifier(identifier string, kcv version.KeyCredentialLinkVersion) string {
	if identifier == "" {
		return ""
	}

	raw, err := decodeKeyIdentifier(identifier, kcv)
	if err != nil {
		return identifier
	}

	return hex.EncodeToString(raw)
}

func decodeKeyIdentifier(identifier string, kcv version.KeyCredentialLinkVersion) ([]byte, error) {
	switch kcv.Value {
	case version.KeyCredentialLinkVersion_0, version.KeyCredentialLinkVersion_1:
		return hex.DecodeString(identifier)
	default:
		return base64.StdEncoding.DecodeString(padBase64(identifier))
	}
}

func padBase64(s string) string {
	s = strings.TrimRight(s, "=")
	if remainder := len(s) % 4; remainder != 0 {
		s += strings.Repeat("=", 4-remainder)
	}
	return s
}
