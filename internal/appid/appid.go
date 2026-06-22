// Package appid owns OpenNGFW's first-party application identity layer.
// Engine labels such as Suricata app_proto or future nDPI output are
// treated as evidence and normalized into this package's taxonomy.
package appid

import (
	"strconv"
	"strings"
)

// Result is the canonical App-ID verdict for one observed flow.
type Result struct {
	ID         string
	Name       string
	Category   string
	Confidence uint32
	Evidence   []string
}

// Definition is a policy/content supplied App-ID definition. Engine signals
// are exact normalized labels; ports are fallback hints used only when no
// engine signal is available.
type Definition struct {
	ID            string
	Name          string
	Category      string
	EngineSignals []string
	Ports         []PortMatch
	Source        string
}

// PortMatch describes one protocol/port fallback hint for a custom app.
type PortMatch struct {
	Protocol string
	Start    uint16
	End      uint16
}

type appDef struct {
	id       string
	name     string
	category string
}

var signalMap = map[string]appDef{
	"http":       {"web-browsing", "Web Browsing", "web"},
	"tls":        {"ssl", "SSL/TLS", "encrypted"},
	"ssl":        {"ssl", "SSL/TLS", "encrypted"},
	"quic":       {"quic", "QUIC", "encrypted"},
	"dns":        {"dns", "DNS", "network-service"},
	"ssh":        {"ssh", "SSH", "remote-access"},
	"ntp":        {"ntp", "NTP", "network-service"},
	"dhcp":       {"dhcp", "DHCP", "network-service"},
	"smtp":       {"smtp", "SMTP", "email"},
	"imap":       {"imap", "IMAP", "email"},
	"pop3":       {"pop3", "POP3", "email"},
	"ftp":        {"ftp", "FTP", "file-transfer"},
	"smb":        {"smb", "SMB", "file-sharing"},
	"rdp":        {"rdp", "RDP", "remote-access"},
	"bittorrent": {"bittorrent", "BitTorrent", "file-sharing"},
}

var portMap = map[string]appDef{
	"tcp/80":   {"web-browsing", "Web Browsing", "web"},
	"tcp/8080": {"web-browsing", "Web Browsing", "web"},
	"tcp/443":  {"ssl", "SSL/TLS", "encrypted"},
	"udp/443":  {"quic", "QUIC", "encrypted"},
	"udp/53":   {"dns", "DNS", "network-service"},
	"tcp/53":   {"dns", "DNS", "network-service"},
	"tcp/22":   {"ssh", "SSH", "remote-access"},
	"udp/123":  {"ntp", "NTP", "network-service"},
	"udp/67":   {"dhcp", "DHCP", "network-service"},
	"udp/68":   {"dhcp", "DHCP", "network-service"},
	"tcp/25":   {"smtp", "SMTP", "email"},
	"tcp/587":  {"smtp", "SMTP", "email"},
	"tcp/465":  {"smtp", "SMTP", "email"},
	"tcp/143":  {"imap", "IMAP", "email"},
	"tcp/993":  {"imap", "IMAP", "email"},
	"tcp/110":  {"pop3", "POP3", "email"},
	"tcp/995":  {"pop3", "POP3", "email"},
	"tcp/21":   {"ftp", "FTP", "file-transfer"},
	"tcp/445":  {"smb", "SMB", "file-sharing"},
	"tcp/3389": {"rdp", "RDP", "remote-access"},
}

// Classify normalizes engine-native application evidence into OpenNGFW App-ID.
func Classify(engineSignal, proto string, destPort int) Result {
	return ClassifyWithDefinitions(engineSignal, proto, destPort, nil)
}

// ClassifyWithDefinitions classifies a flow using custom OpenNGFW App-ID
// definitions before the built-in taxonomy. Custom port matches are considered
// only when no usable engine signal exists, preventing port-only guesses from
// overriding observed engine evidence.
func ClassifyWithDefinitions(engineSignal, proto string, destPort int, definitions []Definition) Result {
	signal := normalize(engineSignal)
	portKey := strings.ToLower(proto) + "/" + strconv.Itoa(destPort)
	portDef, portKnown := portMap[portKey]
	if signal != "" && signal != "unknown" && signal != "failed" {
		if def, source, ok := customSignalMatch(definitions, signal); ok {
			return result(def, 92, []string{
				"engine signal suricata.app_proto=" + signal,
				definitionEvidencePrefix(source) + " App-ID taxonomy match " + signal + " -> " + def.id,
			})
		}
		if def, ok := signalMap[signal]; ok {
			confidence := uint32(90)
			evidence := []string{
				"engine signal suricata.app_proto=" + signal,
				"OpenNGFW taxonomy match " + signal + " -> " + def.id,
			}
			if portKnown {
				if portDef.id == def.id {
					confidence = 95
					evidence = append(evidence, "port heuristic "+portKey+" confirms "+def.id)
				} else {
					confidence = 80
					evidence = append(evidence, "port heuristic "+portKey+" suggests "+portDef.id+"; reduced confidence for engine signal "+signal+" -> "+def.id)
				}
			}
			return result(def, confidence, evidence)
		}
		out := Result{
			ID:         "unknown",
			Name:       "Unknown",
			Category:   "unknown",
			Confidence: 35,
			Evidence: []string{
				"engine signal suricata.app_proto=" + signal,
				"no OpenNGFW taxonomy match for engine signal",
			},
		}
		if portKnown {
			out.Evidence = append(out.Evidence, "port heuristic "+portKey+" suggests "+portDef.id+" but engine signal is unmapped; retaining unknown App-ID")
		}
		return out
	}

	if def, source, ok := customPortMatch(definitions, proto, destPort); ok {
		return result(def, 65, []string{
			"no engine application signal",
			definitionEvidencePrefix(source) + " port heuristic " + portKey + " -> " + def.id,
		})
	}

	if portKnown {
		return result(portDef, 60, []string{
			"no engine application signal",
			"port heuristic " + portKey + " -> " + portDef.id,
		})
	}

	return Result{
		ID:         "unknown",
		Name:       "Unknown",
		Category:   "unknown",
		Confidence: 10,
		Evidence: []string{
			"no engine application signal",
			"no OpenNGFW port heuristic for " + portKey,
		},
	}
}

func customSignalMatch(definitions []Definition, signal string) (appDef, string, bool) {
	for _, d := range definitions {
		for _, candidate := range d.EngineSignals {
			if normalize(candidate) == signal {
				return definitionAppDef(d), strings.TrimSpace(d.Source), true
			}
		}
	}
	return appDef{}, "", false
}

func customPortMatch(definitions []Definition, proto string, destPort int) (appDef, string, bool) {
	if destPort <= 0 || destPort > 65535 {
		return appDef{}, "", false
	}
	wantProto := strings.ToLower(proto)
	for _, d := range definitions {
		for _, port := range d.Ports {
			if strings.ToLower(port.Protocol) != wantProto {
				continue
			}
			if port.Start == 0 {
				continue
			}
			end := port.End
			if end == 0 {
				end = port.Start
			}
			if end < port.Start {
				continue
			}
			if port.Start <= uint16(destPort) && uint16(destPort) <= end {
				return definitionAppDef(d), strings.TrimSpace(d.Source), true
			}
		}
	}
	return appDef{}, "", false
}

func definitionAppDef(d Definition) appDef {
	return appDef{id: d.ID, name: d.Name, category: d.Category}
}

func result(def appDef, confidence uint32, evidence []string) Result {
	return Result{
		ID:         def.id,
		Name:       def.name,
		Category:   def.category,
		Confidence: confidence,
		Evidence:   evidence,
	}
}

func definitionEvidencePrefix(source string) string {
	if source != "" {
		return source
	}
	return "custom OpenNGFW"
}

func normalize(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
