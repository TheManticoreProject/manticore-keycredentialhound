package principal

import (
	"fmt"
	"strings"

	"github.com/TheManticoreProject/winacl/sid"
)

// DomainFromDN builds the FQDN of the domain an object belongs to from the DC
// components of its distinguished name, so that nodes carry the domain they were
// collected from and queries can be scoped in a collection spanning several
// domains.
//
// Returns an empty string for a distinguished name carrying no DC component.
func DomainFromDN(distinguishedName string) string {
	const prefix = "DC="

	labels := []string{}

	// Splitting on the comma is enough here: a value containing an escaped comma
	// yields fragments that do not start with "DC=" and are therefore ignored.
	for _, component := range strings.Split(distinguishedName, ",") {
		component = strings.TrimSpace(component)
		if len(component) > len(prefix) && strings.EqualFold(component[:len(prefix)], prefix) {
			labels = append(labels, component[len(prefix):])
		}
	}

	return strings.ToUpper(strings.Join(labels, "."))
}

// DomainSIDFromAccountSID derives the SID of the domain an account belongs to by
// dropping the account's relative identifier.
//
// Returns an empty string for a SID that is not a domain account SID, that is
// anything but S-1-5-21 followed by the three sub-authorities identifying the
// domain and the account's relative identifier. The well-known SIDs of built-in
// principals belong to no domain and are reported as such.
func DomainSIDFromAccountSID(accountSid *sid.SID) string {
	const ntAuthority = 5
	const domainSubAuthority = 21
	const domainSubAuthorityCount = 4

	if accountSid.IdentifierAuthority.Value != ntAuthority {
		return ""
	}
	if len(accountSid.SubAuthorities) != domainSubAuthorityCount {
		return ""
	}
	if accountSid.SubAuthorities[0] != domainSubAuthority {
		return ""
	}

	domainSid := fmt.Sprintf("S-%d-%d", accountSid.RevisionLevel, accountSid.IdentifierAuthority.Value)
	for _, subAuthority := range accountSid.SubAuthorities {
		domainSid += fmt.Sprintf("-%d", subAuthority)
	}

	return domainSid
}
