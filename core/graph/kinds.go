package graph

// Every kind emitted by this collector is prefixed with the KC_ namespace. This
// keeps them clear of BloodHound built-ins and of other extensions, and it is
// also the form structured graph extension schemas require of kind names
// ({namespace}_{Name}).
const (
	// SourceKindBase is the source kind BloodHound uses to scope this
	// collector's data, and is appended to the kinds of every node it owns.
	SourceKindBase = "KC_Base"

	NodeKindKeyCredential = "KC_KeyCredential"

	// NodeKindDevice is the device a key credential was registered from, as named
	// by the optional DeviceId entry of the blob.
	NodeKindDevice = "KC_Device"

	// NodeKindUnknownKeyMaterial covers key credentials whose key material is
	// absent from the blob or of a type this collector cannot parse. The
	// key_material_status property tells the two apart.
	NodeKindUnknownKeyMaterial = "KC_UnknownKeyMaterial"

	NodeKindDSAPrivateKey = "KC_DSAPrivateKey"
	NodeKindRSAPrivateKey = "KC_RSAPrivateKey"
	NodeKindDSAPublicKey  = "KC_DSAPublicKey"
	NodeKindRSAPublicKey  = "KC_RSAPublicKey"
	NodeKindECCPrivateKey = "KC_ECCPrivateKey"
	NodeKindECCPublicKey  = "KC_ECCPublicKey"
)

// Edge kinds.
//
// HasKeyCredential, HasKeyMaterial and RegisteredKeyCredential describe how the
// collected objects relate to each other. CanAuthenticateAs is the one that
// carries an attack: it runs from key material to the principal it authenticates,
// which is the direction an attacker moves in, and is therefore the edge to mark
// traversable in an extension schema.
const (
	EdgeKindHasKeyCredential        = "KC_HasKeyCredential"
	EdgeKindHasKeyMaterial          = "KC_HasKeyMaterial"
	EdgeKindRegisteredKeyCredential = "KC_RegisteredKeyCredential"
	EdgeKindCanAuthenticateAs       = "KC_CanAuthenticateAs"
)

// DescriptionCanAuthenticateAs is surfaced by BloodHound when hovering the edge.
const DescriptionCanAuthenticateAs = "Whoever holds the private key matching this registered public key can authenticate as this principal through PKINIT, and recover its NT hash from the PAC (shadow credentials)."
