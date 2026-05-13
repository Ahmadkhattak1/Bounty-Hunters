package tlscipher

import (
	"crypto/tls"
	"testing"
)

func TestNegotiateSuiteHandlesUnknownAndValidSuites(t *testing.T) {
	reg := NewSuiteRegistry(StrengthLegacy)

	if name, err := reg.NegotiateSuite([]uint16{0xffff}); err == nil {
		t.Fatalf("expected error for unknown suite, got name %q", name)
	}

	name, err := reg.NegotiateSuite([]uint16{tls.TLS_AES_128_GCM_SHA256})
	if err != nil {
		t.Fatalf("expected valid suite negotiation to succeed: %v", err)
	}
	if name != "TLS_AES_128_GCM_SHA256" {
		t.Fatalf("unexpected negotiated suite: %q", name)
	}
}

func TestFilterWeakSuitesRejectsRC4And3DES(t *testing.T) {
	reg := NewSuiteRegistry(StrengthWeak)

	filtered := reg.FilterWeakSuites(reg.knownSuites)

	if containsSuiteID(filtered, 0x0005) {
		t.Fatal("expected TLS_RSA_WITH_RC4_128_SHA to be filtered")
	}
	if containsSuiteID(filtered, 0x000a) {
		t.Fatal("expected TLS_RSA_WITH_3DES_EDE_CBC_SHA to be filtered")
	}
	if !containsSuiteID(filtered, tls.TLS_AES_128_GCM_SHA256) {
		t.Fatal("expected TLS_AES_128_GCM_SHA256 to remain allowed")
	}
}

func TestSortByPreferenceRanksAEADBeforeNonAEADAndPreservesStrength(t *testing.T) {
	reg := NewSuiteRegistry(StrengthWeak)
	suites := []*CipherSuite{
		{
			ID:       tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			Name:     "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
			KeySize:  128,
			IsAEAD:   false,
			Strength: StrengthLegacy,
		},
		{
			ID:       tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			Name:     "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
			KeySize:  128,
			IsAEAD:   true,
			Strength: StrengthModern,
		},
		{
			ID:       tls.TLS_AES_256_GCM_SHA384,
			Name:     "TLS_AES_256_GCM_SHA384",
			KeySize:  256,
			IsAEAD:   true,
			Strength: StrengthAdvanced,
		},
	}

	sorted := reg.SortByPreference(suites)

	if sorted[0].ID != tls.TLS_AES_256_GCM_SHA384 {
		t.Fatalf("expected advanced AEAD first, got %s", sorted[0].Name)
	}
	if sorted[1].ID != tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 {
		t.Fatalf("expected modern AEAD before non-AEAD, got %s", sorted[1].Name)
	}
	if sorted[2].ID != tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 {
		t.Fatalf("expected non-AEAD last, got %s", sorted[2].Name)
	}
}

func TestSortByPreferencePrefersChaChaWithoutAESNI(t *testing.T) {
	reg := NewSuiteRegistry(StrengthWeak)
	suites := []*CipherSuite{
		{
			ID:       tls.TLS_AES_256_GCM_SHA384,
			Name:     "TLS_AES_256_GCM_SHA384",
			KeySize:  256,
			IsAEAD:   true,
			Strength: StrengthAdvanced,
		},
		{
			ID:       tls.TLS_CHACHA20_POLY1305_SHA256,
			Name:     "TLS_CHACHA20_POLY1305_SHA256",
			KeySize:  256,
			IsAEAD:   true,
			Strength: StrengthAdvanced,
		},
	}

	originalHasAESNI := hasAESNI
	defer func() { hasAESNI = originalHasAESNI }()

	hasAESNI = func() bool { return false }
	sorted := reg.SortByPreference(suites)
	if sorted[0].ID != tls.TLS_CHACHA20_POLY1305_SHA256 {
		t.Fatalf("expected ChaCha first without AES-NI, got %s", sorted[0].Name)
	}

	hasAESNI = func() bool { return true }
	sorted = reg.SortByPreference(suites)
	if sorted[0].ID != tls.TLS_AES_256_GCM_SHA384 {
		t.Fatalf("expected original AES-GCM ordering with AES-NI, got %s", sorted[0].Name)
	}
}

func TestConcurrentLookupUsesSynchronizedCache(t *testing.T) {
	reg := NewSuiteRegistry(StrengthWeak)
	ids := make([]uint16, 100)
	for i := range ids {
		if i%2 == 0 {
			ids[i] = tls.TLS_AES_128_GCM_SHA256
		} else {
			ids[i] = tls.TLS_CHACHA20_POLY1305_SHA256
		}
	}

	results, err := reg.ConcurrentLookup(ids)
	if err != nil {
		t.Fatalf("expected concurrent lookup to succeed: %v", err)
	}
	if len(results) != len(ids) {
		t.Fatalf("expected %d results, got %d", len(ids), len(results))
	}
	if got := reg.lookupSuite(tls.TLS_AES_128_GCM_SHA256); got == nil || got.Name != "TLS_AES_128_GCM_SHA256" {
		t.Fatalf("cached lookup returned wrong suite: %#v", got)
	}
}

func containsSuiteID(suites []*CipherSuite, id uint16) bool {
	for _, suite := range suites {
		if suite.ID == id {
			return true
		}
	}
	return false
}
