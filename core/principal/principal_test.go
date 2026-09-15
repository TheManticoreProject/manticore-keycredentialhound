package principal

import (
	"fmt"
	"testing"

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

func TestDomainFromDN(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"user", "CN=Alice,CN=Users,DC=corp,DC=com", "CORP.COM"},
		{"already uppercase", "CN=ALICE,DC=CORP,DC=COM", "CORP.COM"},
		{"lowercase dc attribute", "cn=alice,dc=corp,dc=com", "CORP.COM"},
		{"spaces after commas", "CN=Alice, DC=corp, DC=com", "CORP.COM"},
		{"single label domain", "CN=Alice,DC=corp", "CORP"},
		{"three label domain", "CN=Alice,DC=ad,DC=corp,DC=com", "AD.CORP.COM"},
		{"escaped comma in name", "CN=Doe\\, John,OU=Staff,DC=corp,DC=com", "CORP.COM"},
		{"no dc component", "CN=Alice,CN=Users", ""},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DomainFromDN(tt.input)
			if got != tt.expected {
				t.Errorf("DomainFromDN(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestDomainSIDFromAccountSID(t *testing.T) {
	tests := []struct {
		name     string
		sid      *sid.SID
		expected string
	}{
		{
			"domain user",
			testSID(5, []uint32{21, 1111111111, 2222222222, 3333333333}, 1104),
			"S-1-5-21-1111111111-2222222222-3333333333",
		},
		{
			"domain administrator",
			testSID(5, []uint32{21, 1, 2, 3}, 500),
			"S-1-5-21-1-2-3",
		},
		{
			// S-1-5-32-544, the built-in Administrators group, belongs to no domain.
			"builtin group",
			testSID(5, []uint32{32}, 544),
			"",
		},
		{
			// S-1-5-18, LocalSystem.
			"well known sid",
			testSID(5, []uint32{}, 18),
			"",
		},
		{
			// S-1-1-0, Everyone, under the world authority.
			"world authority",
			testSID(1, []uint32{}, 0),
			"",
		},
		{
			// S-1-5-80-..., an NT service SID, has the right shape but not the
			// domain sub-authority.
			"service sid",
			testSID(5, []uint32{80, 1, 2, 3}, 4),
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DomainSIDFromAccountSID(tt.sid)
			if got != tt.expected {
				t.Errorf("DomainSIDFromAccountSID(%q) = %q, want %q", tt.sid.String(), got, tt.expected)
			}
		})
	}
}

// TestDomainSIDIsAccountSIDWithoutRID checks that the derived domain SID is
// exactly the account SID stripped of its relative identifier.
func TestDomainSIDIsAccountSIDWithoutRID(t *testing.T) {
	accountSid := testSID(5, []uint32{21, 1111111111, 2222222222, 3333333333}, 1104)

	domainSid := DomainSIDFromAccountSID(accountSid)
	rebuilt := fmt.Sprintf("%s-%d", domainSid, accountSid.RelativeIdentifier)

	if rebuilt != accountSid.String() {
		t.Errorf("domain SID %q plus RID %d = %q, want %q", domainSid, accountSid.RelativeIdentifier, rebuilt, accountSid.String())
	}
}
