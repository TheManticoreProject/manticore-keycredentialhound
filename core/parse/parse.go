package parse

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/TheManticoreProject/KeyCredentialHound/core/graph"
	"github.com/TheManticoreProject/KeyCredentialHound/core/identifier"
	"github.com/TheManticoreProject/KeyCredentialHound/core/principal"
	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt"
	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys"
	"github.com/TheManticoreProject/Manticore/windows/guid"
	"github.com/TheManticoreProject/Manticore/windows/keycredentiallink"
	"github.com/TheManticoreProject/gopengraph/properties"
	"github.com/TheManticoreProject/winacl/sid"
)

// Collector builds the two graphs of a collection run.
type Collector struct {
	// Graph holds the collector's own nodes and the edges between them, and
	// carries the source_kind.
	Graph *graph.DedupedGraph
	// CrossCollector holds only the edges to pre-existing Active Directory
	// principals. It must NOT carry a source_kind, so that the referenced AD nodes
	// are never stamped with this collector's kind (two-step upload).
	CrossCollector *graph.DedupedGraph

	debug bool
}

func NewCollector(sourceKind string, debug bool) *Collector {
	return &Collector{
		Graph:          graph.NewDedupedGraph(sourceKind),
		CrossCollector: graph.NewDedupedGraph(""),
		debug:          debug,
	}
}

// account is the Active Directory principal a key credential belongs to.
type account struct {
	// sid is the account's objectSid, which is immutable for the lifetime of the
	// principal and is therefore used both as the stable namespace of node ids and
	// as the endpoint of the edges to Active Directory.
	sid               *sid.SID
	distinguishedName string
	domain            string
	domainSid         string
}

func newAccount(entry *ldap.Entry) (*account, error) {
	distinguishedName := entry.GetAttributeValue("distinguishedName")

	rawAccountSid := entry.GetRawAttributeValue("objectSid")
	if len(rawAccountSid) == 0 {
		return nil, fmt.Errorf("account SID is empty")
	}

	accountSid := &sid.SID{}
	if _, err := accountSid.Unmarshal(rawAccountSid); err != nil {
		return nil, fmt.Errorf("error unmarshalling account SID: %w", err)
	}

	return &account{
		sid:               accountSid,
		distinguishedName: distinguishedName,
		domain:            principal.DomainFromDN(distinguishedName),
		domainSid:         principal.DomainSIDFromAccountSID(accountSid),
	}, nil
}

// unmarshalKeyCredentialLink parses a raw msDS-KeyCredentialLink value.
//
// msDS-KeyCredentialLink is writable by anyone able to register a key credential
// on an account, and the parser dereferences optional entries while walking the
// entry list (the KeySource entry is read when converting the creation and last
// logon timestamps, even though it is optional), so a crafted value can panic
// it. Recovering here keeps one malformed value from aborting the whole
// collection, which would otherwise be an easy way to hide key credentials from
// this collector.
func unmarshalKeyCredentialLink(data []byte) (kc *keycredentiallink.KeyCredentialLink, err error) {
	defer func() {
		if r := recover(); r != nil {
			kc = nil
			err = fmt.Errorf("panic while unmarshalling key credential link: %v", r)
		}
	}()

	kc = &keycredentiallink.KeyCredentialLink{}
	if _, unmarshalErr := kc.Unmarshal(data); unmarshalErr != nil {
		return nil, unmarshalErr
	}

	return kc, nil
}

// ParseResults populates the collector's graphs from the LDAP results.
func (c *Collector) ParseResults(ldapResults []*ldap.Entry) {
	for _, entry := range ldapResults {
		c.parseEntry(entry)
	}
}

func (c *Collector) parseEntry(entry *ldap.Entry) {
	a, err := newAccount(entry)
	if err != nil {
		logger.Warn(fmt.Sprintf("Error reading account %s: %s", entry.GetAttributeValue("distinguishedName"), err))
		return
	}

	msDsKeyCredentialLinkValues := entry.GetEqualFoldRawAttributeValues("msDS-KeyCredentialLink")
	lenMsDsKeyCredentialLinkValues := len(msDsKeyCredentialLinkValues)

	if c.debug {
		logger.Info(fmt.Sprintf("Processing %d keycredentials for account: %s", lenMsDsKeyCredentialLinkValues, a.distinguishedName))
	}

	for id, msDsKeyCredentialLinkValue := range msDsKeyCredentialLinkValues {
		if c.debug {
			logger.Debug(fmt.Sprintf("[%d/%d] Unmarshalling msDsKeyCredentialLinkValue=%s", id+1, lenMsDsKeyCredentialLinkValues, msDsKeyCredentialLinkValue))
		}

		dnb := ldap.DNWithBinary{}
		_, err := dnb.Unmarshal([]byte(msDsKeyCredentialLinkValue))
		if err != nil {
			if c.debug {
				logger.Debug(fmt.Sprintf("[%d/%d] Error parsing msDsKeyCredentialLinkValue=%s: %s", id+1, lenMsDsKeyCredentialLinkValues, msDsKeyCredentialLinkValue, err))
			}
			continue
		}

		kc, err := unmarshalKeyCredentialLink(dnb.BinaryData)
		if err != nil {
			if c.debug {
				logger.Debug(fmt.Sprintf("[%d/%d] Error unmarshalling keyCredentialLinkValue=%s: %s", id+1, lenMsDsKeyCredentialLinkValues, hex.EncodeToString(dnb.BinaryData), err))
			}
			continue
		}

		c.addKeyCredential(a, kc, id)
	}
}

// addKeyCredential adds the node of one key credential of an account, links the
// account to it, then adds its key material and the device it was registered
// from.
func (c *Collector) addKeyCredential(a *account, kc *keycredentiallink.KeyCredentialLink, index int) {
	keyIdHex := identifier.NormalizeKeyIdentifier(kc.Identifier, kc.Version)

	placeholderName := fmt.Sprintf("Unknown-%d", index+1)

	// The id is namespaced by the immutable account SID so it stays stable across
	// renames and OU moves. The separator also keeps the id from ever being equal
	// to the bare SID of an Active Directory principal, which would make this node
	// merge into it on ingest.
	keyCredentialNodeId := a.sid.String() + "."
	if keyIdHex == "" {
		keyCredentialNodeId += placeholderName
	} else {
		keyCredentialNodeId += keyIdHex
	}

	p := properties.NewProperties()

	keyCredentialName := kc.Identifier
	if keyCredentialName == "" {
		keyCredentialName = placeholderName
	}
	p.SetProperty("name", keyCredentialName)
	p.SetProperty("displayname", keyCredentialName)

	p.SetProperty("identifier", kc.Identifier)
	p.SetProperty("key_id_hex", keyIdHex)
	p.SetProperty("version", kc.Version.String())
	p.SetProperty("usage", kc.Usage.String())
	p.SetProperty("key_hash", hex.EncodeToString(kc.KeyHash))

	p.SetProperty("account_sid", a.sid.String())
	p.SetProperty("account_distinguishedname", a.distinguishedName)
	p.SetProperty("domain", a.domain)
	p.SetProperty("domainsid", a.domainSid)

	// Source, LegacyUsage, CreationTime, LastLogonTime and CustomKeyInfo come from
	// optional entries of the blob and are only reported when present.
	if kc.Source != nil {
		p.SetProperty("source", kc.Source.String())
	}
	if kc.LegacyUsage != "" {
		p.SetProperty("legacy_usage", kc.LegacyUsage)
	}
	if kc.CreationTime != nil {
		creationTime := kc.CreationTime.ToUniversalTime()
		p.SetProperty("creation_time", creationTime.Unix())
		p.SetProperty("creation_time_iso", creationTime.Format(time.RFC3339))
	}
	if kc.LastLogonTime != nil {
		lastLogonTime := kc.LastLogonTime.ToUniversalTime()
		p.SetProperty("last_logon_time", lastLogonTime.Unix())
		p.SetProperty("last_logon_time_iso", lastLogonTime.Format(time.RFC3339))
	}
	if kc.CustomKeyInfo != nil {
		p.SetProperty("cki_version", kc.CustomKeyInfo.Version)
		p.SetProperty("cki_flags", kc.CustomKeyInfo.Flags.String())
		p.SetProperty("cki_volume_type", kc.CustomKeyInfo.VolumeType.String())
		p.SetProperty("cki_key_strength", kc.CustomKeyInfo.KeyStrength.String())
		p.SetProperty("cki_supports_notification", kc.CustomKeyInfo.SupportsNotification)
	}

	if !c.Graph.EnsureNode(keyCredentialNodeId, []string{graph.NodeKindKeyCredential}, p) {
		return
	}

	c.CrossCollector.AddExternalEdge(a.sid.String(), keyCredentialNodeId, graph.EdgeKindHasKeyCredential, properties.NewProperties())

	c.addDevice(kc, keyCredentialNodeId)
	c.addKeyMaterial(a, kc, keyCredentialNodeId, keyIdHex)
}

// addDevice adds the node of the device a key credential was registered from, as
// named by the optional DeviceId entry of the blob, and links it to the key
// credential. One device registered against several accounts is a pivot between
// them.
func (c *Collector) addDevice(kc *keycredentiallink.KeyCredentialLink, keyCredentialNodeId string) {
	if kc.DeviceId == nil {
		return
	}
	if kc.DeviceId.Equal(&guid.GUID{}) {
		return
	}

	deviceId := kc.DeviceId.ToFormatD()

	// The device id is prefixed with its kind rather than used as-is. The DeviceId
	// entry is attacker controlled, and a bare GUID id would let a crafted key
	// credential name the objectGUID of an existing OU, GPO or container: the
	// device node would then merge into that object, hanging an edge off it and
	// stamping it with this collector's source kind.
	deviceNodeId := graph.NodeKindDevice + "." + deviceId

	p := properties.NewProperties()
	p.SetProperty("name", deviceId)
	p.SetProperty("displayname", deviceId)
	p.SetProperty("device_id", deviceId)

	if !c.Graph.EnsureNode(deviceNodeId, []string{graph.NodeKindDevice}, p) {
		return
	}

	c.Graph.AddEdge(deviceNodeId, keyCredentialNodeId, graph.EdgeKindRegisteredKeyCredential, properties.NewProperties())
}

// addKeyMaterial adds the key material node of a key credential, links the
// credential to it, and links it back to the principal it can authenticate.
//
// A node is emitted even when the key material is absent or of an unrecognized
// type, both to surface such a malformed credential and so that every
// KeyCredential node is reachable by an edge of the main payload.
func (c *Collector) addKeyMaterial(a *account, kc *keycredentiallink.KeyCredentialLink, keyCredentialNodeId string, keyIdHex string) {
	nodeKind := graph.NodeKindUnknownKeyMaterial
	p := properties.NewProperties()

	if kc.KeyMaterial == nil {
		p.SetProperty("key_material_status", "absent")
	} else {
		nodeKind, p = keyMaterialProperties(kc.KeyMaterial)
	}

	name := keyMaterialName(p, keyIdHex)
	p.SetProperty("name", name)
	p.SetProperty("displayname", name)

	keyNodeId := keyIdHex + "." + nodeKind
	if keyIdHex == "" {
		keyNodeId = keyCredentialNodeId + "." + nodeKind
	}

	if !c.Graph.EnsureNode(keyNodeId, []string{nodeKind}, p) {
		return
	}

	if !c.Graph.AddEdge(keyCredentialNodeId, keyNodeId, graph.EdgeKindHasKeyMaterial, properties.NewProperties()) {
		return
	}

	if nodeKind == graph.NodeKindUnknownKeyMaterial {
		return
	}

	edgeProperties := properties.NewProperties()
	edgeProperties.SetProperty("description", graph.DescriptionCanAuthenticateAs)
	c.CrossCollector.AddExternalEdge(keyNodeId, a.sid.String(), graph.EdgeKindCanAuthenticateAs, edgeProperties)
}

// keyMaterialProperties returns the node kind and the properties describing a
// piece of key material.
//
// The secret components of a private key are deliberately left out: they would
// turn the graph database, and the JSON exported to reach it, into a store of
// private keys readable by everyone with access to either. Only sizes and public
// components are reported. In practice msDS-KeyCredentialLink carries public key
// blobs, so a private key node is itself the finding.
func keyMaterialProperties(keyMaterial bcrypt.KeyMaterial) (string, *properties.Properties) {
	p := properties.NewProperties()
	p.SetProperty("key_material_status", "parsed")

	switch km := keyMaterial.(type) {
	case *keys.BCRYPT_DSA_PRIVATE_KEY:
		p.SetProperty("key_type", "DSA Private Key")
		p.SetProperty("key_algorithm", "DSA")
		p.SetProperty("key_is_private", true)
		p.SetProperty("key_secret_omitted", true)
		p.SetProperty("key_size_bits", int(km.Header.CbKey)*8)

		p.SetProperty("dsa_cb_key", km.Header.CbKey)
		p.SetProperty("dsa_count", hex.EncodeToString(km.Header.Count[:]))
		p.SetProperty("dsa_q", hex.EncodeToString(km.Header.Q[:]))
		p.SetProperty("dsa_seed", hex.EncodeToString(km.Header.Seed[:]))

		p.SetProperty("dsa_modulus", hex.EncodeToString(km.Content.Modulus[:]))
		p.SetProperty("dsa_public", hex.EncodeToString(km.Content.Public[:]))

		return graph.NodeKindDSAPrivateKey, p

	case *keys.BCRYPT_DSA_PUBLIC_KEY:
		p.SetProperty("key_type", "DSA Public Key")
		p.SetProperty("key_algorithm", "DSA")
		p.SetProperty("key_is_private", false)
		p.SetProperty("key_size_bits", int(km.Header.CbKey)*8)

		p.SetProperty("dsa_cb_key", km.Header.CbKey)
		p.SetProperty("dsa_count", hex.EncodeToString(km.Header.Count[:]))
		p.SetProperty("dsa_q", hex.EncodeToString(km.Header.Q[:]))
		p.SetProperty("dsa_seed", hex.EncodeToString(km.Header.Seed[:]))

		p.SetProperty("dsa_modulus", hex.EncodeToString(km.Content.Modulus[:]))
		p.SetProperty("dsa_public", hex.EncodeToString(km.Content.Public[:]))
		p.SetProperty("dsa_generator", hex.EncodeToString(km.Content.Generator[:]))

		return graph.NodeKindDSAPublicKey, p

	case *keys.BCRYPT_RSA_PRIVATE_KEY:
		p.SetProperty("key_type", "RSA Private Key")
		p.SetProperty("key_algorithm", "RSA")
		p.SetProperty("key_is_private", true)
		p.SetProperty("key_secret_omitted", true)
		p.SetProperty("key_size_bits", int(km.Header.BitLength))

		p.SetProperty("rsa_bit_length", km.Header.BitLength)
		p.SetProperty("rsa_cb_modulus", km.Header.CbModulus)
		p.SetProperty("rsa_cb_prime1", km.Header.CbPrime1)
		p.SetProperty("rsa_cb_prime2", km.Header.CbPrime2)
		p.SetProperty("rsa_cb_public_exp", km.Header.CbPublicExp)

		p.SetProperty("rsa_modulus", hex.EncodeToString(km.Content.Modulus[:]))
		p.SetProperty("rsa_public_exponent", hex.EncodeToString(km.Content.PublicExponent[:]))

		return graph.NodeKindRSAPrivateKey, p

	case *keys.BCRYPT_RSA_PUBLIC_KEY:
		p.SetProperty("key_type", "RSA Public Key")
		p.SetProperty("key_algorithm", "RSA")
		p.SetProperty("key_is_private", false)
		p.SetProperty("key_size_bits", int(km.Header.BitLength))

		p.SetProperty("rsa_bit_length", km.Header.BitLength)
		p.SetProperty("rsa_cb_modulus", km.Header.CbModulus)
		p.SetProperty("rsa_cb_prime1", km.Header.CbPrime1)
		p.SetProperty("rsa_cb_prime2", km.Header.CbPrime2)
		p.SetProperty("rsa_cb_public_exp", km.Header.CbPublicExp)

		p.SetProperty("rsa_modulus", hex.EncodeToString(km.Content.Modulus[:]))
		p.SetProperty("rsa_public_exponent", hex.EncodeToString(km.Content.PublicExponent[:]))

		return graph.NodeKindRSAPublicKey, p

	case *keys.BCRYPT_ECC_PRIVATE_KEY:
		p.SetProperty("key_type", "ECC Private Key")
		p.SetProperty("key_algorithm", "ECC")
		p.SetProperty("key_is_private", true)
		p.SetProperty("key_secret_omitted", true)
		// KeySize is the length in bytes of each coordinate of the curve point.
		p.SetProperty("key_size_bits", int(km.Header.KeySize)*8)

		p.SetProperty("ecc_key_size", km.Header.KeySize)

		p.SetProperty("ecc_x", hex.EncodeToString(km.Content.X[:]))
		p.SetProperty("ecc_y", hex.EncodeToString(km.Content.Y[:]))

		return graph.NodeKindECCPrivateKey, p

	case *keys.BCRYPT_ECC_PUBLIC_KEY:
		p.SetProperty("key_type", "ECC Public Key")
		p.SetProperty("key_algorithm", "ECC")
		p.SetProperty("key_is_private", false)
		p.SetProperty("key_size_bits", int(km.Header.KeySize)*8)

		p.SetProperty("ecc_key_size", km.Header.KeySize)

		p.SetProperty("ecc_x", hex.EncodeToString(km.Content.X[:]))
		p.SetProperty("ecc_y", hex.EncodeToString(km.Content.Y[:]))

		return graph.NodeKindECCPublicKey, p

	default:
		p.SetProperty("key_material_status", "unrecognized")

		return graph.NodeKindUnknownKeyMaterial, p
	}
}

// keyMaterialName builds a name that tells key material nodes apart in the
// interface. Naming every node after its type alone puts hundreds of nodes named
// "RSA PUBLIC KEY" in the graph, which makes search and tooltips useless.
func keyMaterialName(p *properties.Properties, keyIdHex string) string {
	name := fmt.Sprintf("%v", p.GetProperty("key_type", "Unknown Key Material"))

	if bits, ok := p.GetProperty("key_size_bits", 0).(int); ok && bits > 0 {
		name += fmt.Sprintf(" %d", bits)
	}

	if len(keyIdHex) >= 8 {
		name += fmt.Sprintf(" (%s)", keyIdHex[:8])
	}

	return name
}
