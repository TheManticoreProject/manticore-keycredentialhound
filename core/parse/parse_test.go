package parse

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/TheManticoreProject/KeyCredentialHound/core/graph"
	"github.com/TheManticoreProject/KeyCredentialHound/core/principal"
	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt"
	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys"
	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys/blob"
	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys/headers"
	"github.com/TheManticoreProject/Manticore/windows/guid"
	"github.com/TheManticoreProject/Manticore/windows/keycredentiallink"
	"github.com/TheManticoreProject/Manticore/windows/keycredentiallink/version"
	"github.com/TheManticoreProject/winacl/sid"
	"github.com/TheManticoreProject/winacl/sid/authority"
)

func testSID(identifierAuthority uint64, subAuthorities []uint32, relativeIdentifier uint32) *sid.SID {
	return &sid.SID{
		RevisionLevel:       1,
		SubAuthorityCount:   uint8(len(subAuthorities) + 1),
		IdentifierAuthority: authority.SecurityIdentifierAuthority{Value: identifierAuthority},
		SubAuthorities:      subAuthorities,
		RelativeIdentifier:  relativeIdentifier,
	}
}

// testAccount builds the account context of a domain user.
func testAccount() *account {
	accountSid := testSID(5, []uint32{21, 1, 2, 3}, 1104)

	return &account{
		sid:               accountSid,
		distinguishedName: "CN=Alice,CN=Users,DC=corp,DC=com",
		domain:            principal.DomainFromDN("CN=Alice,CN=Users,DC=corp,DC=com"),
		domainSid:         principal.DomainSIDFromAccountSID(accountSid),
	}
}

// testKeyID returns a KeyID of the given filler byte, in the binary form as well
// as in the base64 encoding a version 2 key credential carries and the hex
// encoding node ids use.
func testKeyID(filler byte) (identifier string, keyIdHex string) {
	raw := bytes.Repeat([]byte{filler}, 32)

	return base64.StdEncoding.EncodeToString(raw), hex.EncodeToString(raw)
}

// testRSAPublicKey builds a 2048 bit RSA public key material.
func testRSAPublicKey() bcrypt.KeyMaterial {
	return &keys.BCRYPT_RSA_PUBLIC_KEY{
		Header: headers.BCRYPT_RSA_KEY_BLOB{
			BitLength:   2048,
			CbPublicExp: 3,
			CbModulus:   256,
		},
		Content: blob.BCRYPT_RSA_PUBLIC_BLOB{
			PublicExponent: []byte{0x01, 0x00, 0x01},
			Modulus:        bytes.Repeat([]byte{0x42}, 256),
		},
	}
}

func testKeyCredential(identifier string, keyMaterial bcrypt.KeyMaterial) *keycredentiallink.KeyCredentialLink {
	return &keycredentiallink.KeyCredentialLink{
		Version:     version.KeyCredentialLinkVersion{Value: version.KeyCredentialLinkVersion_2},
		Identifier:  identifier,
		KeyHash:     bytes.Repeat([]byte{0x01}, 32),
		KeyMaterial: keyMaterial,
	}
}

func TestAddKeyCredentialGraphShape(t *testing.T) {
	identifier, keyIdHex := testKeyID(0xab)
	a := testAccount()

	c := NewCollector(graph.SourceKindBase, false)
	c.addKeyCredential(a, testKeyCredential(identifier, testRSAPublicKey()), 0)

	keyCredentialNodeId := "S-1-5-21-1-2-3-1104." + keyIdHex
	keyNodeId := keyIdHex + "." + graph.NodeKindRSAPublicKey

	keyCredentialNode := c.Graph.OG.GetNode(keyCredentialNodeId)
	if keyCredentialNode == nil {
		t.Fatalf("no KeyCredential node with id=%s", keyCredentialNodeId)
	}
	if c.Graph.OG.GetNode(keyNodeId) == nil {
		t.Fatalf("no key material node with id=%s", keyNodeId)
	}

	// The main payload holds the collector's own nodes and the edge between them.
	if count := c.Graph.OG.GetNodeCount(); count != 2 {
		t.Errorf("main graph node count = %d, want 2", count)
	}
	if count := len(c.Graph.OG.GetEdgesByKind(graph.EdgeKindHasKeyMaterial)); count != 1 {
		t.Errorf("%s edge count = %d, want 1", graph.EdgeKindHasKeyMaterial, count)
	}

	// The cross-collector payload holds the two edges to Active Directory, and no
	// node at all: a node there would be stamped with no source kind.
	if count := c.CrossCollector.OG.GetNodeCount(); count != 0 {
		t.Errorf("cross-collector graph node count = %d, want 0", count)
	}
	if count := len(c.CrossCollector.OG.GetEdgesByKind(graph.EdgeKindHasKeyCredential)); count != 1 {
		t.Errorf("%s edge count = %d, want 1", graph.EdgeKindHasKeyCredential, count)
	}

	// The attack edge runs from the key material to the principal it authenticates.
	attackEdges := c.CrossCollector.OG.GetEdgesByKind(graph.EdgeKindCanAuthenticateAs)
	if len(attackEdges) != 1 {
		t.Fatalf("%s edge count = %d, want 1", graph.EdgeKindCanAuthenticateAs, len(attackEdges))
	}
	if got := attackEdges[0].GetStartNodeID(); got != keyNodeId {
		t.Errorf("%s starts at %q, want the key material node %q", graph.EdgeKindCanAuthenticateAs, got, keyNodeId)
	}
	if got := attackEdges[0].GetEndNodeID(); got != a.sid.String() {
		t.Errorf("%s ends at %q, want the principal %q", graph.EdgeKindCanAuthenticateAs, got, a.sid.String())
	}
}

func TestKeyCredentialProperties(t *testing.T) {
	identifier, keyIdHex := testKeyID(0xab)
	a := testAccount()

	c := NewCollector(graph.SourceKindBase, false)
	c.addKeyCredential(a, testKeyCredential(identifier, testRSAPublicKey()), 0)

	n := c.Graph.OG.GetNode("S-1-5-21-1-2-3-1104." + keyIdHex)
	if n == nil {
		t.Fatal("no KeyCredential node")
	}

	expected := map[string]interface{}{
		"identifier":                identifier,
		"key_id_hex":                keyIdHex,
		"account_sid":               "S-1-5-21-1-2-3-1104",
		"account_distinguishedname": "CN=Alice,CN=Users,DC=corp,DC=com",
		"domain":                    "CORP.COM",
		"domainsid":                 "S-1-5-21-1-2-3",
	}
	for key, want := range expected {
		if got := n.GetProperty(key); got != want {
			t.Errorf("property %q = %v, want %v", key, got, want)
		}
	}

	// objectid is forbidden in properties, the id belongs in the node id, and
	// lastseen is injected by BloodHound on ingest.
	for _, forbidden := range []string{"objectid", "lastseen", "reconcile"} {
		if n.GetProperties().HasProperty(forbidden) {
			t.Errorf("property %q is set, it must never be", forbidden)
		}
	}

	// The optional entries of this blob are absent, so they are not reported.
	for _, absent := range []string{"source", "creation_time", "last_logon_time", "legacy_usage"} {
		if n.GetProperties().HasProperty(absent) {
			t.Errorf("property %q is set for a blob that does not carry it", absent)
		}
	}
}

// TestSharedKeyMaterialCollapsesIntoOneNode checks the property the shared key
// material query depends on: one key registered on two principals is one node.
func TestSharedKeyMaterialCollapsesIntoOneNode(t *testing.T) {
	identifier, keyIdHex := testKeyID(0xcd)

	alice := testAccount()
	bob := &account{
		sid:               testSID(5, []uint32{21, 1, 2, 3}, 1105),
		distinguishedName: "CN=Bob,CN=Users,DC=corp,DC=com",
		domain:            "CORP.COM",
		domainSid:         "S-1-5-21-1-2-3",
	}

	c := NewCollector(graph.SourceKindBase, false)
	c.addKeyCredential(alice, testKeyCredential(identifier, testRSAPublicKey()), 0)
	c.addKeyCredential(bob, testKeyCredential(identifier, testRSAPublicKey()), 0)

	keyNodeId := keyIdHex + "." + graph.NodeKindRSAPublicKey
	if c.Graph.OG.GetNode(keyNodeId) == nil {
		t.Fatalf("no key material node with id=%s", keyNodeId)
	}

	// Two KeyCredential nodes, one for each principal, and a single shared key
	// material node.
	if count := c.Graph.OG.GetNodeCount(); count != 3 {
		t.Errorf("node count = %d, want 3", count)
	}
	if count := len(c.Graph.OG.GetEdgesToNode(keyNodeId)); count != 2 {
		t.Errorf("edges into the key material node = %d, want 2", count)
	}
	if count := len(c.CrossCollector.OG.GetEdgesByKind(graph.EdgeKindCanAuthenticateAs)); count != 2 {
		t.Errorf("%s edge count = %d, want 2: the shared key authenticates both principals", graph.EdgeKindCanAuthenticateAs, count)
	}
}

// TestKeyMaterialIsVersionIndependent checks that the same key carried by two
// different link versions still collapses into one key material node.
func TestKeyMaterialIsVersionIndependent(t *testing.T) {
	raw := bytes.Repeat([]byte{0xef}, 32)

	asVersion2 := testKeyCredential(base64.StdEncoding.EncodeToString(raw), testRSAPublicKey())

	asVersion1 := testKeyCredential(hex.EncodeToString(raw), testRSAPublicKey())
	asVersion1.Version = version.KeyCredentialLinkVersion{Value: version.KeyCredentialLinkVersion_1}

	c := NewCollector(graph.SourceKindBase, false)
	c.addKeyCredential(testAccount(), asVersion2, 0)
	c.addKeyCredential(testAccount(), asVersion1, 1)

	if count := len(c.Graph.OG.GetNodesByKind(graph.NodeKindRSAPublicKey)); count != 1 {
		t.Errorf("%s node count = %d, want 1", graph.NodeKindRSAPublicKey, count)
	}
}

func TestKeyMaterialOmitsPrivateComponents(t *testing.T) {
	identifier, keyIdHex := testKeyID(0x11)

	privateKey := &keys.BCRYPT_RSA_PRIVATE_KEY{
		Header: headers.BCRYPT_RSA_KEY_BLOB{
			BitLength:   2048,
			CbPublicExp: 3,
			CbModulus:   256,
			CbPrime1:    128,
			CbPrime2:    128,
		},
		Content: blob.BCRYPT_RSA_PRIVATE_BLOB{
			PublicExponent: []byte{0x01, 0x00, 0x01},
			Modulus:        bytes.Repeat([]byte{0x42}, 256),
			Prime1:         bytes.Repeat([]byte{0x43}, 128),
			Prime2:         bytes.Repeat([]byte{0x44}, 128),
		},
	}

	c := NewCollector(graph.SourceKindBase, false)
	c.addKeyCredential(testAccount(), testKeyCredential(identifier, privateKey), 0)

	n := c.Graph.OG.GetNode(keyIdHex + "." + graph.NodeKindRSAPrivateKey)
	if n == nil {
		t.Fatal("no RSA private key node")
	}

	for _, secret := range []string{"prime1", "prime2", "rsa_prime1", "rsa_prime2", "private_exponent", "d"} {
		if n.GetProperties().HasProperty(secret) {
			t.Errorf("property %q is set: private key components must never be written to the graph", secret)
		}
	}

	if omitted := n.GetProperty("key_secret_omitted"); omitted != true {
		t.Errorf("key_secret_omitted = %v, want true", omitted)
	}
	if isPrivate := n.GetProperty("key_is_private"); isPrivate != true {
		t.Errorf("key_is_private = %v, want true", isPrivate)
	}
	// The public components are still reported.
	if !n.GetProperties().HasProperty("rsa_modulus") {
		t.Error("rsa_modulus is not set, the public components should be kept")
	}
}

// TestKeyCredentialWithoutKeyMaterialIsReachable checks that a credential whose
// key material is missing still gets a node and an edge in the main payload,
// which requires every node it holds to be reachable.
func TestKeyCredentialWithoutKeyMaterialIsReachable(t *testing.T) {
	identifier, keyIdHex := testKeyID(0x22)

	c := NewCollector(graph.SourceKindBase, false)
	c.addKeyCredential(testAccount(), testKeyCredential(identifier, nil), 0)

	keyCredentialNodeId := "S-1-5-21-1-2-3-1104." + keyIdHex
	keyNodeId := keyIdHex + "." + graph.NodeKindUnknownKeyMaterial

	n := c.Graph.OG.GetNode(keyNodeId)
	if n == nil {
		t.Fatalf("no key material node with id=%s", keyNodeId)
	}
	if status := n.GetProperty("key_material_status"); status != "absent" {
		t.Errorf("key_material_status = %v, want absent", status)
	}

	if count := len(c.Graph.OG.GetEdgesFromNode(keyCredentialNodeId)); count != 1 {
		t.Errorf("edges out of the KeyCredential node = %d, want 1", count)
	}

	// Key material nobody holds authenticates nobody: claiming otherwise would be
	// a false attack path.
	if count := len(c.CrossCollector.OG.GetEdgesByKind(graph.EdgeKindCanAuthenticateAs)); count != 0 {
		t.Errorf("%s edge count = %d, want 0 for absent key material", graph.EdgeKindCanAuthenticateAs, count)
	}
}

func TestAddDevice(t *testing.T) {
	identifier, keyIdHex := testKeyID(0x33)
	deviceGuid, err := guid.FromString("11111111-2222-3333-4444-555555555555")
	if err != nil {
		t.Fatalf("guid.FromString() error: %s", err)
	}

	kc := testKeyCredential(identifier, testRSAPublicKey())
	kc.DeviceId = deviceGuid

	c := NewCollector(graph.SourceKindBase, false)
	c.addKeyCredential(testAccount(), kc, 0)

	// The device node id is prefixed with its kind, so that an attacker naming the
	// objectGUID of an existing object cannot make this node merge into it.
	deviceNodeId := graph.NodeKindDevice + "." + deviceGuid.ToFormatD()
	if c.Graph.OG.GetNode(deviceNodeId) == nil {
		t.Fatalf("no device node with id=%s", deviceNodeId)
	}

	edges := c.Graph.OG.GetEdgesByKind(graph.EdgeKindRegisteredKeyCredential)
	if len(edges) != 1 {
		t.Fatalf("%s edge count = %d, want 1", graph.EdgeKindRegisteredKeyCredential, len(edges))
	}
	if got := edges[0].GetStartNodeID(); got != deviceNodeId {
		t.Errorf("%s starts at %q, want the device %q", graph.EdgeKindRegisteredKeyCredential, got, deviceNodeId)
	}
	if got := edges[0].GetEndNodeID(); got != "S-1-5-21-1-2-3-1104."+keyIdHex {
		t.Errorf("%s ends at %q, want the key credential", graph.EdgeKindRegisteredKeyCredential, got)
	}
}

func TestAddDeviceSkipsZeroedGUID(t *testing.T) {
	identifier, _ := testKeyID(0x44)

	kc := testKeyCredential(identifier, testRSAPublicKey())
	kc.DeviceId = &guid.GUID{}

	c := NewCollector(graph.SourceKindBase, false)
	c.addKeyCredential(testAccount(), kc, 0)

	if count := len(c.Graph.OG.GetNodesByKind(graph.NodeKindDevice)); count != 0 {
		t.Errorf("%s node count = %d, want 0: a zeroed GUID names no device", graph.NodeKindDevice, count)
	}
}

func TestKeyMaterialName(t *testing.T) {
	identifier, keyIdHex := testKeyID(0xab)

	c := NewCollector(graph.SourceKindBase, false)
	c.addKeyCredential(testAccount(), testKeyCredential(identifier, testRSAPublicKey()), 0)

	n := c.Graph.OG.GetNode(keyIdHex + "." + graph.NodeKindRSAPublicKey)
	if n == nil {
		t.Fatal("no key material node")
	}

	want := "RSA Public Key 2048 (" + keyIdHex[:8] + ")"
	if got := n.GetProperty("name"); got != want {
		t.Errorf("name = %v, want %v", got, want)
	}
}
