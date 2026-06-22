package fleet

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

const (
	SchemaVersion       = "phragma.fleet.local-template-registry.v1"
	APISchemaVersion    = "phragma.fleet.local-api.v1"
	MaxTemplates        = 100
	MaxApplyResults     = 50
	MaxPolicyJSONBytes  = 2 << 20
	MaxTemplateNameSize = 120
	MaxDescriptionSize  = 1024
)

var (
	ErrNotFound             = errors.New("fleet template not found")
	ErrTemplateLimit        = errors.New("fleet template limit exceeded")
	templateIDRE            = regexp.MustCompile(`^tmpl-[a-z0-9][a-z0-9_.-]{1,79}$`)
	templateSlugUnsafeRE    = regexp.MustCompile(`[^a-z0-9_.-]+`)
	templatePolicyMarshal   = protojson.MarshalOptions{UseProtoNames: false, EmitUnpopulated: false}
	templatePolicyUnmarshal = protojson.UnmarshalOptions{
		DiscardUnknown: true,
	}
)

type Store struct {
	path string
	mu   sync.Mutex
}

type Registry struct {
	SchemaVersion string           `json:"schemaVersion"`
	Templates     []TemplateRecord `json:"templates"`
	ApplyResults  []ApplyRecord    `json:"applyResults,omitempty"`
}

type TemplateRecord struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	Description   string          `json:"description,omitempty"`
	Scope         string          `json:"scope"`
	Labels        []string        `json:"labels,omitempty"`
	Policy        json.RawMessage `json:"policy"`
	PolicySummary PolicySummary   `json:"policySummary"`
	Revision      string          `json:"revision"`
	CreatedAt     string          `json:"createdAt"`
	UpdatedAt     string          `json:"updatedAt"`
	CreatedBy     string          `json:"createdBy"`
	CreatedByRole string          `json:"createdByRole"`
	AuthSource    string          `json:"authSource"`
}

type PolicySummary struct {
	Zones            int  `json:"zones"`
	Rules            int  `json:"rules"`
	SourceNAT        int  `json:"sourceNat"`
	DestinationNAT   int  `json:"destinationNat"`
	StaticRoutes     int  `json:"staticRoutes"`
	IPsecTunnels     int  `json:"ipsecTunnels"`
	WireGuardPeers   int  `json:"wireGuardPeers"`
	HostInputRules   int  `json:"hostInputRules"`
	DynamicRouting   bool `json:"dynamicRouting"`
	SecurityProfiles int  `json:"securityProfiles"`
	Applications     int  `json:"applications"`
}

type ApplyRecord struct {
	ID                      string            `json:"id"`
	TemplateID              string            `json:"templateId"`
	TemplateName            string            `json:"templateName"`
	TemplateRevision        string            `json:"templateRevision"`
	RequestedBy             string            `json:"requestedBy"`
	RequestedByRole         string            `json:"requestedByRole"`
	AuthSource              string            `json:"authSource"`
	Comment                 string            `json:"comment,omitempty"`
	StartedAt               string            `json:"startedAt"`
	FinishedAt              string            `json:"finishedAt"`
	Status                  string            `json:"status"`
	CandidateRevisionBefore string            `json:"candidateRevisionBefore,omitempty"`
	CandidateRevisionAfter  string            `json:"candidateRevisionAfter,omitempty"`
	NodeResults             []ApplyNodeResult `json:"nodeResults"`
	CustodyBoundary         string            `json:"custodyBoundary"`
}

type ApplyNodeResult struct {
	NodeID           string   `json:"nodeId"`
	NodeName         string   `json:"nodeName"`
	Role             string   `json:"role"`
	Scope            string   `json:"scope"`
	RuntimeState     string   `json:"runtimeState"`
	RunningVersion   string   `json:"runningVersion,omitempty"`
	Result           string   `json:"result"`
	Reason           string   `json:"reason"`
	PositiveEvidence []string `json:"positiveEvidence,omitempty"`
	Blockers         []string `json:"blockers,omitempty"`
	Mutation         string   `json:"mutation"`
	Custody          string   `json:"custody"`
}

type CreateTemplateInput struct {
	Name          string
	Description   string
	Scope         string
	Labels        []string
	Policy        *openngfwv1.Policy
	CreatedBy     string
	CreatedByRole string
	AuthSource    string
}

func NewStore(path string) *Store {
	return &Store{path: path}
}

func DefaultStorePath(dataDir string) string {
	base := strings.TrimSpace(dataDir)
	if base == "" {
		base = "."
	}
	return filepath.Join(base, "fleet", "templates.json")
}

func (s *Store) ListTemplates() ([]TemplateRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	registry, err := readRegistry(s.path)
	if err != nil {
		return nil, err
	}
	records := append([]TemplateRecord(nil), registry.Templates...)
	sort.Slice(records, func(i, j int) bool {
		if records[i].UpdatedAt == records[j].UpdatedAt {
			return records[i].ID < records[j].ID
		}
		return records[i].UpdatedAt > records[j].UpdatedAt
	})
	return records, nil
}

func (s *Store) GetTemplate(id string) (TemplateRecord, error) {
	id, err := NormalizeTemplateID(id)
	if err != nil {
		return TemplateRecord{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	registry, err := readRegistry(s.path)
	if err != nil {
		return TemplateRecord{}, err
	}
	for _, record := range registry.Templates {
		if record.ID == id {
			return record, nil
		}
	}
	return TemplateRecord{}, ErrNotFound
}

func (s *Store) DeleteTemplate(id string) error {
	id, err := NormalizeTemplateID(id)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	registry, err := readRegistry(s.path)
	if err != nil {
		return err
	}
	next := registry.Templates[:0]
	deleted := false
	for _, record := range registry.Templates {
		if record.ID == id {
			deleted = true
			continue
		}
		next = append(next, record)
	}
	if !deleted {
		return ErrNotFound
	}
	registry.Templates = next
	return writeRegistry(s.path, registry)
}

func (s *Store) ListApplyResults(templateID string) ([]ApplyRecord, error) {
	templateID = strings.TrimSpace(strings.ToLower(templateID))
	s.mu.Lock()
	defer s.mu.Unlock()
	registry, err := readRegistry(s.path)
	if err != nil {
		return nil, err
	}
	out := make([]ApplyRecord, 0, len(registry.ApplyResults))
	for _, record := range registry.ApplyResults {
		if templateID == "" || record.TemplateID == templateID {
			out = append(out, record)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].FinishedAt == out[j].FinishedAt {
			return out[i].ID < out[j].ID
		}
		return out[i].FinishedAt > out[j].FinishedAt
	})
	return out, nil
}

func (s *Store) RecordApplyResult(record ApplyRecord) (ApplyRecord, error) {
	record.TemplateID = strings.TrimSpace(strings.ToLower(record.TemplateID))
	if record.TemplateID == "" {
		return ApplyRecord{}, errors.New("template id is required")
	}
	if record.ID == "" {
		record.ID = "apply-" + time.Now().UTC().Format("20060102T150405Z") + "-" + randomSuffix(3)
	}
	if record.StartedAt == "" {
		record.StartedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if record.FinishedAt == "" {
		record.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if record.CustodyBoundary == "" {
		record.CustodyBoundary = "server-retained local Fleet apply result; unsigned and not distributed custody"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	registry, err := readRegistry(s.path)
	if err != nil {
		return ApplyRecord{}, err
	}
	registry.ApplyResults = append([]ApplyRecord{record}, registry.ApplyResults...)
	if len(registry.ApplyResults) > MaxApplyResults {
		registry.ApplyResults = registry.ApplyResults[:MaxApplyResults]
	}
	if err := writeRegistry(s.path, registry); err != nil {
		return ApplyRecord{}, err
	}
	return record, nil
}

func (s *Store) CreateTemplate(input CreateTemplateInput) (TemplateRecord, error) {
	if input.Policy == nil {
		return TemplateRecord{}, errors.New("policy is required")
	}
	name := cleanTemplateName(input.Name)
	if name == "" {
		return TemplateRecord{}, errors.New("name is required")
	}
	description := trimSized(input.Description, MaxDescriptionSize)
	scope := strings.TrimSpace(input.Scope)
	if scope == "" {
		scope = "local-appliance"
	}
	policyJSON, err := templatePolicyMarshal.Marshal(input.Policy)
	if err != nil {
		return TemplateRecord{}, fmt.Errorf("marshal policy: %w", err)
	}
	if len(policyJSON) > MaxPolicyJSONBytes {
		return TemplateRecord{}, fmt.Errorf("policy JSON exceeds %d bytes", MaxPolicyJSONBytes)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	record := TemplateRecord{
		ID:            newTemplateID(name),
		Name:          name,
		Description:   description,
		Scope:         scope,
		Labels:        cleanLabels(input.Labels),
		Policy:        append(json.RawMessage(nil), policyJSON...),
		PolicySummary: SummarizePolicy(input.Policy),
		CreatedAt:     now,
		UpdatedAt:     now,
		CreatedBy:     trimSized(input.CreatedBy, 120),
		CreatedByRole: trimSized(input.CreatedByRole, 60),
		AuthSource:    trimSized(input.AuthSource, 80),
	}
	record.Revision = TemplateRevision(record)

	s.mu.Lock()
	defer s.mu.Unlock()
	registry, err := readRegistry(s.path)
	if err != nil {
		return TemplateRecord{}, err
	}
	if len(registry.Templates) >= MaxTemplates {
		return TemplateRecord{}, ErrTemplateLimit
	}
	existing := map[string]bool{}
	for _, item := range registry.Templates {
		existing[item.ID] = true
	}
	baseID := record.ID
	for i := 2; existing[record.ID]; i++ {
		record.ID = fmt.Sprintf("%s-%d", baseID, i)
	}
	registry.Templates = append([]TemplateRecord{record}, registry.Templates...)
	if err := writeRegistry(s.path, registry); err != nil {
		return TemplateRecord{}, err
	}
	return record, nil
}

func DecodePolicy(raw json.RawMessage) (*openngfwv1.Policy, error) {
	if len(raw) == 0 {
		return nil, errors.New("policy is required")
	}
	if len(raw) > MaxPolicyJSONBytes {
		return nil, fmt.Errorf("policy JSON exceeds %d bytes", MaxPolicyJSONBytes)
	}
	p := &openngfwv1.Policy{}
	if err := templatePolicyUnmarshal.Unmarshal(raw, p); err != nil {
		return nil, err
	}
	return p, nil
}

func TemplateRevision(record TemplateRecord) string {
	h := sha256.New()
	_, _ = h.Write([]byte(record.Name))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(record.Policy)
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(record.Scope))
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func SummarizePolicy(p *openngfwv1.Policy) PolicySummary {
	if p == nil {
		return PolicySummary{}
	}
	summary := PolicySummary{
		Zones:            len(p.GetZones()),
		Rules:            len(p.GetRules()),
		SourceNAT:        len(p.GetNat().GetSource()),
		DestinationNAT:   len(p.GetNat().GetDestination()),
		StaticRoutes:     len(p.GetStaticRoutes()),
		IPsecTunnels:     len(p.GetVpn().GetIpsecTunnels()),
		WireGuardPeers:   len(p.GetVpn().GetWireguardInterfaces()),
		HostInputRules:   len(p.GetHostInput().GetRules()),
		SecurityProfiles: len(p.GetSecurityProfiles()),
		Applications:     len(p.GetApplications()),
	}
	summary.DynamicRouting = p.GetRouting().GetBgp().GetEnabled() || p.GetRouting().GetOspf().GetEnabled()
	return summary
}

func NormalizeTemplateID(id string) (string, error) {
	clean := strings.TrimSpace(strings.ToLower(id))
	if clean == "" {
		return "", errors.New("template id is required")
	}
	if !templateIDRE.MatchString(clean) {
		return "", errors.New("invalid template id")
	}
	return clean, nil
}

func readRegistry(path string) (Registry, error) {
	registry := Registry{SchemaVersion: SchemaVersion, Templates: []TemplateRecord{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return registry, nil
	}
	if err != nil {
		return registry, err
	}
	if len(data) == 0 {
		return registry, nil
	}
	if err := json.Unmarshal(data, &registry); err != nil {
		return registry, err
	}
	if registry.SchemaVersion == "" {
		registry.SchemaVersion = SchemaVersion
	}
	if registry.Templates == nil {
		registry.Templates = []TemplateRecord{}
	}
	if registry.ApplyResults == nil {
		registry.ApplyResults = []ApplyRecord{}
	}
	return registry, nil
}

func writeRegistry(path string, registry Registry) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	registry.SchemaVersion = SchemaVersion
	if registry.Templates == nil {
		registry.Templates = []TemplateRecord{}
	}
	if registry.ApplyResults == nil {
		registry.ApplyResults = []ApplyRecord{}
	}
	data, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func newTemplateID(name string) string {
	slug := strings.Trim(templateSlugUnsafeRE.ReplaceAllString(strings.ToLower(name), "-"), "-_.")
	if slug == "" {
		slug = "template"
	}
	if len(slug) > 48 {
		slug = slug[:48]
		slug = strings.Trim(slug, "-_.")
	}
	return "tmpl-" + slug + "-" + randomSuffix(3)
}

func randomSuffix(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "000000"
	}
	return hex.EncodeToString(buf)
}

func cleanTemplateName(value string) string {
	return trimSized(strings.Join(strings.Fields(value), " "), MaxTemplateNameSize)
}

func cleanLabels(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		label := strings.ToLower(trimSized(strings.Join(strings.Fields(value), "-"), 48))
		label = strings.Trim(templateSlugUnsafeRE.ReplaceAllString(label, "-"), "-_.")
		if label == "" || seen[label] {
			continue
		}
		seen[label] = true
		out = append(out, label)
		if len(out) >= 12 {
			break
		}
	}
	return out
}

func trimSized(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return strings.TrimSpace(value[:limit])
}
