package authz

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	samlSecurityIDPEntityID = "https://idp.example.test/metadata"
	samlSecuritySPEntityID  = "https://firewall.example.test/saml/metadata"
	samlSecurityACSURL      = "https://firewall.example.test/api/v1/auth/saml/acs"
	samlSecurityRequestID   = "_openngfw-security-request"
)

type samlSecurityFixture struct {
	now             time.Time
	certificate     *x509.Certificate
	privateKey      *rsa.PrivateKey
	signingContext  *dsig.SigningContext
	serviceProvider *saml.ServiceProvider
}

func newSAMLSecurityFixture(t *testing.T) *samlSecurityFixture {
	t.Helper()

	now := time.Now().UTC().Truncate(time.Second)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate SAML signing key: %v", err)
	}
	certificateTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "OpenNGFW SAML security test IdP"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certificateDER, err := x509.CreateCertificate(
		rand.Reader,
		certificateTemplate,
		certificateTemplate,
		&privateKey.PublicKey,
		privateKey,
	)
	if err != nil {
		t.Fatalf("create SAML signing certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatalf("parse SAML signing certificate: %v", err)
	}

	keyStore := dsig.TLSCertKeyStore(tls.Certificate{
		Certificate: [][]byte{certificateDER},
		PrivateKey:  privateKey,
	})
	signingContext := dsig.NewDefaultSigningContext(keyStore)
	if err := signingContext.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		t.Fatalf("configure SAML signature method: %v", err)
	}

	acsURL := mustSAMLTestURL(t, samlSecurityACSURL)
	metadataURL := mustSAMLTestURL(t, samlSecuritySPEntityID)
	idpCertificate := base64.StdEncoding.EncodeToString(certificateDER)

	return &samlSecurityFixture{
		now:            now,
		certificate:    certificate,
		privateKey:     privateKey,
		signingContext: signingContext,
		serviceProvider: &saml.ServiceProvider{
			EntityID:                    samlSecuritySPEntityID,
			MetadataURL:                 metadataURL,
			AcsURL:                      acsURL,
			IDPMetadata:                 &saml.EntityDescriptor{EntityID: samlSecurityIDPEntityID},
			IDPCertificate:              &idpCertificate,
			ValidateAudienceRestriction: strictSAMLAudienceValidator(samlSecuritySPEntityID),
		},
	}
}

func mustSAMLTestURL(t *testing.T, rawURL string) url.URL {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse SAML test URL %q: %v", rawURL, err)
	}
	return *parsed
}

func TestSAMLServiceProviderInstallsStrictAudienceValidation(t *testing.T) {
	provider, err := samlServiceProvider(context.Background(), normalizeSAMLConfig(SAMLConfig{
		IDPEntityID: samlSecurityIDPEntityID,
		SSOURL:      "https://idp.example.test/sso",
		SPEntityID:  samlSecuritySPEntityID,
		ACSURL:      samlSecurityACSURL,
	}))
	if err != nil {
		t.Fatalf("build SAML service provider: %v", err)
	}
	if provider.ValidateAudienceRestriction == nil {
		t.Fatal("SAML service provider has no strict audience validator")
	}

	tests := []struct {
		name      string
		assertion *saml.Assertion
		wantErr   bool
	}{
		{name: "nil assertion", wantErr: true},
		{name: "missing conditions", assertion: &saml.Assertion{}, wantErr: true},
		{
			name:      "missing audience restriction",
			assertion: &saml.Assertion{Conditions: &saml.Conditions{}},
			wantErr:   true,
		},
		{
			name: "matching audience restriction",
			assertion: &saml.Assertion{Conditions: &saml.Conditions{
				AudienceRestrictions: []saml.AudienceRestriction{{
					Audience: saml.Audience{Value: samlSecuritySPEntityID},
				}},
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := provider.ValidateAudienceRestriction(test.assertion)
			if test.wantErr && err == nil {
				t.Fatal("expected strict audience validation error")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("strict audience validation failed: %v", err)
			}
		})
	}
}

func (f *samlSecurityFixture) assertion() *saml.Assertion {
	return &saml.Assertion{
		ID:           "_openngfw-security-assertion",
		IssueInstant: f.now,
		Version:      "2.0",
		Issuer:       saml.Issuer{Value: samlSecurityIDPEntityID},
		Subject: &saml.Subject{
			NameID: &saml.NameID{Value: "alice@example.test"},
			SubjectConfirmations: []saml.SubjectConfirmation{{
				Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
				SubjectConfirmationData: &saml.SubjectConfirmationData{
					InResponseTo: samlSecurityRequestID,
					Recipient:    samlSecurityACSURL,
					NotOnOrAfter: f.now.Add(10 * time.Minute),
				},
			}},
		},
		Conditions: &saml.Conditions{
			NotBefore:    f.now.Add(-time.Minute),
			NotOnOrAfter: f.now.Add(10 * time.Minute),
			AudienceRestrictions: []saml.AudienceRestriction{{
				Audience: saml.Audience{Value: samlSecuritySPEntityID},
			}},
		},
	}
}

func (f *samlSecurityFixture) signedResponseXML(t *testing.T, assertion *saml.Assertion) []byte {
	t.Helper()

	response := &saml.Response{
		ID:           "_openngfw-security-response",
		InResponseTo: samlSecurityRequestID,
		Version:      "2.0",
		IssueInstant: f.now,
		Destination:  samlSecurityACSURL,
		Issuer:       &saml.Issuer{Value: samlSecurityIDPEntityID},
		Status: saml.Status{
			StatusCode: saml.StatusCode{Value: saml.StatusSuccess},
		},
		Assertion: assertion,
	}

	signedResponse, err := f.signingContext.SignEnveloped(response.Element())
	if err != nil {
		t.Fatalf("sign SAML response: %v", err)
	}
	children := signedResponse.ChildElements()
	if len(children) == 0 {
		t.Fatal("signed SAML response has no children")
	}
	response.Signature = children[len(children)-1]

	document := etree.NewDocument()
	document.SetRoot(response.Element())
	responseXML, err := document.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize SAML response: %v", err)
	}
	return responseXML
}

func TestSAMLResponseSecurityValidation(t *testing.T) {
	fixture := newSAMLSecurityFixture(t)

	tests := []struct {
		name    string
		mutate  func(*saml.Assertion)
		wantErr bool
	}{
		{
			name: "valid signed response",
		},
		{
			name: "issuer mismatch",
			mutate: func(assertion *saml.Assertion) {
				assertion.Issuer.Value = "https://attacker.example.test/metadata"
			},
			wantErr: true,
		},
		{
			name: "audience mismatch",
			mutate: func(assertion *saml.Assertion) {
				assertion.Conditions.AudienceRestrictions[0].Audience.Value = "https://attacker.example.test/service"
			},
			wantErr: true,
		},
		{
			name: "missing audience restriction",
			mutate: func(assertion *saml.Assertion) {
				assertion.Conditions.AudienceRestrictions = nil
			},
			wantErr: true,
		},
		{
			name: "mixed audience restrictions",
			mutate: func(assertion *saml.Assertion) {
				assertion.Conditions.AudienceRestrictions = append(
					assertion.Conditions.AudienceRestrictions,
					saml.AudienceRestriction{Audience: saml.Audience{Value: "https://attacker.example.test/service"}},
				)
			},
			wantErr: true,
		},
		{
			name: "future NotBefore",
			mutate: func(assertion *saml.Assertion) {
				assertion.Conditions.NotBefore = fixture.now.Add(saml.MaxClockSkew + time.Minute)
			},
			wantErr: true,
		},
		{
			name: "expired NotOnOrAfter",
			mutate: func(assertion *saml.Assertion) {
				assertion.Conditions.NotOnOrAfter = fixture.now.Add(-saml.MaxClockSkew - time.Minute)
			},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertion := fixture.assertion()
			if test.mutate != nil {
				test.mutate(assertion)
			}

			responseXML := fixture.signedResponseXML(t, assertion)
			parsedAssertion, err := fixture.serviceProvider.ParseXMLResponse(
				responseXML,
				[]string{samlSecurityRequestID},
				fixture.serviceProvider.AcsURL,
			)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected signed SAML response to be rejected")
				}
				return
			}
			if err != nil {
				t.Fatalf("valid signed SAML response rejected: %v", err)
			}
			if parsedAssertion == nil || parsedAssertion.Subject == nil || parsedAssertion.Subject.NameID == nil {
				t.Fatal("valid signed SAML response returned no subject")
			}
			if got := parsedAssertion.Subject.NameID.Value; got != "alice@example.test" {
				t.Fatalf("subject = %q, want alice@example.test", got)
			}
		})
	}
}

// TestGoXMLDSigRejectsMultiReferenceConfusion is a regression test for
// CVE-2026-33487 / GHSA-479m-364c-43vc. A signature over SignedInfo is valid,
// but its first matching Reference describes different content. Validation
// must bind the digest check to that matching reference and reject the XML.
func TestGoXMLDSigRejectsMultiReferenceConfusion(t *testing.T) {
	fixture := newSAMLSecurityFixture(t)

	malicious := etree.NewElement("Root")
	malicious.CreateAttr("ID", "target")
	malicious.SetText("Malicious Content")

	signature, err := fixture.signingContext.ConstructSignature(malicious, true)
	if err != nil {
		t.Fatalf("construct malicious-content signature: %v", err)
	}
	signedInfo := signature.FindElement("./SignedInfo")
	existingReference := signedInfo.FindElement("./Reference")
	existingReference.CreateAttr("URI", "#dummy")

	original := etree.NewElement("Root")
	original.CreateAttr("ID", "target")
	original.SetText("Original Content")
	originalSignature, err := fixture.signingContext.ConstructSignature(original, true)
	if err != nil {
		t.Fatalf("construct original-content signature: %v", err)
	}
	originalReference := originalSignature.FindElement("./SignedInfo/Reference").Copy()
	signedInfo.InsertChildAt(existingReference.Index(), originalReference)

	detachedSignedInfo := signedInfo.Copy()
	if detachedSignedInfo.SelectAttr("xmlns:"+dsig.DefaultPrefix) == nil {
		detachedSignedInfo.CreateAttr("xmlns:"+dsig.DefaultPrefix, dsig.Namespace)
	}
	canonicalSignedInfo, err := fixture.signingContext.Canonicalizer.Canonicalize(detachedSignedInfo)
	if err != nil {
		t.Fatalf("canonicalize crafted SignedInfo: %v", err)
	}
	hash := fixture.signingContext.Hash.New()
	if _, err := hash.Write(canonicalSignedInfo); err != nil {
		t.Fatalf("hash crafted SignedInfo: %v", err)
	}
	rawSignature, err := rsa.SignPKCS1v15(rand.Reader, fixture.privateKey, fixture.signingContext.Hash, hash.Sum(nil))
	if err != nil {
		t.Fatalf("sign crafted SignedInfo: %v", err)
	}
	signature.FindElement("./SignatureValue").SetText(base64.StdEncoding.EncodeToString(rawSignature))
	malicious.AddChild(signature)

	certificateStore := &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{fixture.certificate}}
	validationContext := dsig.NewDefaultValidationContext(certificateStore)
	if _, err := validationContext.Validate(malicious); err == nil {
		t.Fatal("multi-reference signature confusion was accepted")
	}
}
