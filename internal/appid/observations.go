package appid

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DefaultObservationConfidenceThreshold is the fallback confidence cutoff for App-ID review queues.
const DefaultObservationConfidenceThreshold uint32 = 70

// ObservationKind identifies why a flow cluster needs App-ID review.
type ObservationKind string

const (
	// ObservationKindUnknown marks flows without an identified application.
	ObservationKindUnknown ObservationKind = "unknown"
	// ObservationKindLowConfidence marks flows with App-ID evidence below the review threshold.
	ObservationKindLowConfidence ObservationKind = "low_confidence"
	// ObservationKindConflictingEvidence marks flows whose App-ID evidence disagrees.
	ObservationKindConflictingEvidence ObservationKind = "conflicting_evidence"
)

// ObservedFlow is the App-ID evidence needed to build review queues. It is
// intentionally independent of protobufs so App-ID grouping is testable on its
// own.
type ObservedFlow struct {
	Timestamp          time.Time
	SrcIP              string
	SrcPort            int
	DestIP             string
	DestPort           int
	Protocol           string
	EngineSignal       string
	EngineSignalSource string
	AppID              string
	AppName            string
	AppCategory        string
	AppConfidence      uint32
	AppEvidence        []string
	BytesToServer      uint64
	BytesToClient      uint64
	Packets            uint64
	FlowID             string
	PolicyVersion      uint64
}

// ObservationOptions controls how App-ID observations are filtered and capped.
type ObservationOptions struct {
	Limit               int
	ConfidenceThreshold uint32
}

// Observation is one grouped App-ID review item.
type Observation struct {
	QueueID              string
	Kind                 ObservationKind
	AppID                string
	AppName              string
	AppCategory          string
	AppConfidence        uint32
	EngineSignal         string
	EngineSignalSource   string
	Protocol             string
	DestPort             uint32
	Count                uint64
	FirstSeen            time.Time
	LastSeen             time.Time
	Bytes                uint64
	Packets              uint64
	SampleFlowID         string
	SampleSrcIP          string
	SampleSrcPort        uint32
	SampleDestIP         string
	AppEvidence          []string
	SuggestedApplication Definition
}

// BuildObservations groups unknown, low-confidence, and conflicting App-ID
// evidence into stable review items. Input order does not affect queue IDs,
// counters, or grouping.
func BuildObservations(flows []ObservedFlow, opts ObservationOptions) []Observation {
	threshold := opts.ConfidenceThreshold
	if threshold == 0 {
		threshold = DefaultObservationConfidenceThreshold
	}
	groups := map[string]*Observation{}
	for _, flow := range flows {
		kind, ok := classifyObservation(flow, threshold)
		if !ok {
			continue
		}
		key := observationKey(kind, flow)
		id := stableQueueID(key)
		obs := groups[id]
		if obs == nil {
			obs = &Observation{
				QueueID:              id,
				Kind:                 kind,
				AppID:                stringOr(flow.AppID, "unknown"),
				AppName:              stringOr(flow.AppName, "Unknown"),
				AppCategory:          stringOr(flow.AppCategory, "unknown"),
				AppConfidence:        flow.AppConfidence,
				EngineSignal:         normalize(flow.EngineSignal),
				EngineSignalSource:   engineSignalSource(flow),
				Protocol:             strings.ToUpper(strings.TrimSpace(flow.Protocol)),
				DestPort:             uint32(validPort(flow.DestPort)),
				SuggestedApplication: suggestDefinition(flow, kind),
			}
			groups[id] = obs
		}
		obs.Count++
		obs.Bytes += flow.BytesToServer + flow.BytesToClient
		obs.Packets += flow.Packets
		obs.AppEvidence = mergeEvidence(obs.AppEvidence, flow.AppEvidence)
		if obs.FirstSeen.IsZero() || (!flow.Timestamp.IsZero() && flow.Timestamp.Before(obs.FirstSeen)) {
			obs.FirstSeen = flow.Timestamp
		}
		if obs.LastSeen.IsZero() || (!flow.Timestamp.IsZero() && flow.Timestamp.After(obs.LastSeen)) {
			obs.LastSeen = flow.Timestamp
			obs.SampleFlowID = flow.FlowID
			obs.SampleSrcIP = flow.SrcIP
			obs.SampleSrcPort = uint32(validPort(flow.SrcPort))
			obs.SampleDestIP = flow.DestIP
			obs.AppConfidence = flow.AppConfidence
			obs.AppName = stringOr(flow.AppName, obs.AppName)
			obs.AppCategory = stringOr(flow.AppCategory, obs.AppCategory)
		}
	}
	out := make([]Observation, 0, len(groups))
	for _, obs := range groups {
		out = append(out, *obs)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if rankObservation(out[i].Kind) != rankObservation(out[j].Kind) {
			return rankObservation(out[i].Kind) < rankObservation(out[j].Kind)
		}
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].QueueID < out[j].QueueID
	})
	if opts.Limit > 0 && len(out) > opts.Limit {
		out = out[:opts.Limit]
	}
	return out
}

func classifyObservation(flow ObservedFlow, threshold uint32) (ObservationKind, bool) {
	if normalize(flow.AppID) == "" || normalize(flow.AppID) == "unknown" {
		return ObservationKindUnknown, true
	}
	if evidenceConflicts(flow.AppEvidence) {
		return ObservationKindConflictingEvidence, true
	}
	if flow.AppConfidence < threshold {
		return ObservationKindLowConfidence, true
	}
	return "", false
}

func evidenceConflicts(evidence []string) bool {
	for _, item := range evidence {
		s := strings.ToLower(item)
		if strings.Contains(s, "reduced confidence") || strings.Contains(s, "conflicting") || strings.Contains(s, "conflict") {
			return true
		}
	}
	return false
}

func observationKey(kind ObservationKind, flow ObservedFlow) string {
	return strings.Join([]string{
		string(kind),
		normalize(flow.AppID),
		normalize(flow.EngineSignal),
		strings.ToLower(strings.TrimSpace(flow.Protocol)),
		strconv.Itoa(validPort(flow.DestPort)),
	}, "|")
}

func stableQueueID(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])[:16]
}

func rankObservation(kind ObservationKind) int {
	switch kind {
	case ObservationKindConflictingEvidence:
		return 0
	case ObservationKindUnknown:
		return 1
	case ObservationKindLowConfidence:
		return 2
	default:
		return 3
	}
}

func mergeEvidence(existing, incoming []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(existing)+len(incoming))
	for _, item := range existing {
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	for _, item := range incoming {
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

func engineSignalSource(flow ObservedFlow) string {
	if strings.TrimSpace(flow.EngineSignalSource) != "" {
		return strings.TrimSpace(flow.EngineSignalSource)
	}
	if normalize(flow.EngineSignal) != "" {
		return "suricata.app_proto"
	}
	return ""
}

func suggestDefinition(flow ObservedFlow, kind ObservationKind) Definition {
	signal := normalize(flow.EngineSignal)
	proto := strings.ToLower(strings.TrimSpace(flow.Protocol))
	port := validPort(flow.DestPort)
	category := sanitizeDefinitionID(flow.AppCategory)
	if category == "" || category == "unknown" {
		category = "business-app"
	}

	var base string
	var signals []string
	if signal != "" && signal != "unknown" && signal != "failed" {
		base = signal
		signals = []string{signal}
	} else if normalize(flow.AppID) != "" && normalize(flow.AppID) != "unknown" {
		base = normalize(flow.AppID)
		if port > 0 {
			base = fmt.Sprintf("%s-%d", base, port)
		}
	} else if port > 0 {
		base = fmt.Sprintf("%s-%d-app", proto, port)
	} else {
		base = "custom-app"
	}

	id := sanitizeDefinitionID(base)
	name := strings.TrimSpace(flow.AppName)
	if name == "" || strings.EqualFold(name, "unknown") {
		name = titleFromID(id)
	}
	if kind == ObservationKindUnknown && signal != "" {
		name = titleFromID(id)
	}
	def := Definition{
		ID:            id,
		Name:          name,
		Category:      category,
		EngineSignals: signals,
	}
	if (proto == "tcp" || proto == "udp") && port > 0 {
		def.Ports = []PortMatch{{Protocol: proto, Start: uint16(port), End: uint16(port)}}
	}
	return def
}

func sanitizeDefinitionID(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-'
		if ok {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	out := strings.Trim(b.String(), "-_")
	if out == "" {
		return ""
	}
	if len(out) > 63 {
		out = strings.Trim(out[:63], "-_")
	}
	if out == "" {
		return ""
	}
	if !isLowerAlnum(out[0]) {
		out = "app-" + out
	}
	if !isLowerAlnum(out[len(out)-1]) {
		out = strings.TrimRight(out, "-_") + "1"
	}
	return out
}

func titleFromID(id string) string {
	parts := strings.FieldsFunc(id, func(r rune) bool { return r == '-' || r == '_' })
	for i, part := range parts {
		if part == "" {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	if len(parts) == 0 {
		return "Custom App"
	}
	return strings.Join(parts, " ")
}

func isLowerAlnum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

func validPort(port int) int {
	if port < 1 || port > 65535 {
		return 0
	}
	return port
}

func stringOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}
