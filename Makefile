# Phragma build entrypoints. CI runs exactly these targets; keep them
# the single source of truth for how the project is built and checked.

MODULE      := github.com/detailtech/oss-ngfw
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
BUILD_DATE  ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS     := -X $(MODULE)/internal/version.Version=$(VERSION) \
               -X $(MODULE)/internal/version.Commit=$(COMMIT) \
               -X $(MODULE)/internal/version.BuildDate=$(BUILD_DATE)

BIN_DIR     := bin
TOOLS_DIR   := $(BIN_DIR)/tools
OPENAPI_GENERATED_SPEC := api/gen/openapi/api-spec.swagger.yaml
OPENAPI_PUBLISHED_SPEC := docs/api-spec.yaml
OPENAPI_WEBUI_SPEC := internal/webui/static/api-spec.yaml
OPENAPI_CONFIG := api/openapi.yaml
API_CONTRACT_INPUTS := api/proto $(OPENAPI_CONFIG) buf.yaml buf.gen.yaml cmd/ngfwopenapi
API_CONTRACT_OUTPUTS := api/gen $(OPENAPI_PUBLISHED_SPEC) $(OPENAPI_WEBUI_SPEC)
RELEASE_PERF_RESULTS ?= perf/release-results
RELEASE_ACCEPTANCE_MANIFEST ?= release/acceptance.json
RELEASE_OPERATOR ?= $(USER)
RELEASE_EVIDENCE_DIR ?= release/evidence
RELEASE_EVIDENCE_RECORD_FLAGS ?=
RELEASE_FUNCTIONAL_HARDENING_DEFERRED_FLAGS ?= --functional-hardening-deferred
RELEASE_BENCHMARK_SUMMARY ?=
RELEASE_NO_PERFORMANCE_CLAIMS ?= 0
RELEASE_BUILD_VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
RELEASE_BUILD_ARGS := VERSION="$(RELEASE_BUILD_VERSION)" COMMIT="$(COMMIT)" BUILD_DATE="$(BUILD_DATE)"
BENCHMARK_RUN ?=
BENCHMARK_CITATION_PATHS ?= README.md SECURITY.md docs release
M3_FIELD_EVIDENCE_DIR ?= release/field-evidence/m3
OIDC_FIELD_EVIDENCE_DIR ?= release/field-evidence/oidc
SAML_FIELD_EVIDENCE_DIR ?= release/field-evidence/saml
CONTENT_PRODUCTION_EVIDENCE_DIR ?= release/field-evidence/content-production
EBPF_OL9_FIELD_EVIDENCE_DIR ?= release/field-evidence/ebpf-ol9
WEBUI_NODE_TEST_PRELOAD := ./internal/webui/static/js/node_test_polyfills.cjs
WEBUI_CHECK_REQUIRE_NODE ?= 0
WEBUI_SMOKE_REQUIRE_BROWSER ?= 1
WEBUI_ENTERPRISE_SMOKE_TOTAL_TIMEOUT_MS ?= 1800000
WEBUI_ENTERPRISE_SMOKE_PATHS ?= /,/dashboard,/setup,/rules,/objects,/nat,/inspection,/threats,/traffic,/logs,/troubleshoot,/performance,/investigation,/fleet,/intel,/netvpn,/proxy,/compliance,/changes,/settings
WEBUI_ENTERPRISE_SMOKE_VIEWPORTS ?= desktop
WEBUI_ENTERPRISE_SMOKE_ARTIFACT_DIR ?= $${TMPDIR:-/tmp}/openngfw-webui-smoke-enterprise-$$(date -u +%Y%m%dT%H%M%SZ)
WEBUI_SMOKE_REPLAY_FAILURE_MANIFEST ?=

# Pinned build and verification tool versions. Bump deliberately; generated
# API output is committed, so CI verifies `make proto` produces no diff.
BUF_VERSION                 := v1.50.1
PROTOC_GEN_GO_VERSION       := v1.36.11
PROTOC_GEN_GO_GRPC_VERSION  := v1.5.1
PROTOC_GEN_GW_VERSION       := v2.27.7
PROTOC_GEN_OPENAPIV2_VERSION := $(PROTOC_GEN_GW_VERSION)
GOVULNCHECK_VERSION          := v1.5.0

.PHONY: all build test webui-check webui-visual-smoke webui-visual-smoke-self-check webui-visual-smoke-replay-failures webui-enterprise-smoke lint vet vuln-check proto proto-status proto-verify tools clean integration-compile integration-test privileged-integration-evidence-check deploy-hardening-check policy-restore-drill-check ha-readiness-recovery-check m3-live-networking-check m3-live-networking m3-field-evidence-check ebpf-ol9-attach-drill-check ebpf-ol9-attach-drill ebpf-ol9-field-evidence-check m5-oidc-field-evidence-check m5-saml-field-evidence-check content-production-readiness-check e2e-install-check e2e-install e2e-auth-runtime-smoke e2e-oidc-runtime-smoke content-package-smoke benchmark-verify benchmark-verify-release benchmark-citation-check benchmark-stage-release benchmark-check benchmark benchmark-netns-check benchmark-netns release-evidence-rootless release-evidence-proto-verify release-evidence-privileged-integration release-evidence-deploy-hardening release-evidence-policy-restore-drill release-evidence-ha-readiness-recovery release-evidence-e2e-install release-evidence-content-package-verification release-evidence-content-production-readiness release-evidence-m3-live-networking release-evidence-m3-field-evidence release-evidence-ebpf-ol9-field-evidence release-evidence-m5-auth-ui release-evidence-m5-oidc-provider release-evidence-m5-oidc-field-evidence release-evidence-m5-saml-field-evidence release-evidence-webui-enterprise-smoke release-evidence-release-benchmark release-acceptance-status release-acceptance-status-functional release-recordability-check release-recordability-diagnostics release-acceptance-assemble release-acceptance-assemble-functional release-acceptance-verify release-check-rootless release-verify

all: build test lint

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/ ./cmd/...

test: webui-check
	go test -race ./...

webui-check:
	@set -eu; \
	if command -v node >/dev/null 2>&1; then \
		find internal/webui/static/js -type f ! -name '._*' \( -name '*.js' -o -name '*.mjs' \) -print | sort | xargs -n1 node --check; \
		find internal/webui/static/js -type f ! -name '._*' -name '*.test.mjs' -print | sort | xargs -n1 node --require $(WEBUI_NODE_TEST_PRELOAD); \
		echo "webui_js_checks=passed"; \
		echo "javascript_checks=required"; \
	else \
		if [ "$(WEBUI_CHECK_REQUIRE_NODE)" = "1" ]; then \
			echo "node not found; WebUI JavaScript checks are required"; \
			exit 1; \
		fi; \
		echo "node not found; skipping WebUI JavaScript checks"; \
		echo "javascript_checks=skipped"; \
	fi

webui-visual-smoke: webui-check
	@if command -v node >/dev/null 2>&1; then \
		WEBUI_SMOKE_REQUIRE_BROWSER="$(WEBUI_SMOKE_REQUIRE_BROWSER)" node e2e/webui-visual-smoke.mjs; \
	else \
		echo "node not found; WebUI visual smoke requires Node.js"; \
		exit 1; \
	fi

webui-visual-smoke-self-check:
	@if command -v node >/dev/null 2>&1; then \
		WEBUI_SMOKE_SELF_CHECK=1 node e2e/webui-visual-smoke.mjs; \
	else \
		echo "node not found; WebUI visual smoke self-check requires Node.js"; \
		exit 1; \
	fi

webui-visual-smoke-replay-failures: webui-check
	@if [ -z "$(WEBUI_SMOKE_REPLAY_FAILURE_MANIFEST)" ]; then \
		echo "WEBUI_SMOKE_REPLAY_FAILURE_MANIFEST must point to a previous webui-smoke-evidence.json"; \
		exit 2; \
	fi
	@if command -v node >/dev/null 2>&1; then \
		WEBUI_SMOKE_REQUIRE_BROWSER="$(WEBUI_SMOKE_REQUIRE_BROWSER)" \
		WEBUI_SMOKE_REPLAY_FAILURE_MANIFEST="$(WEBUI_SMOKE_REPLAY_FAILURE_MANIFEST)" \
		node e2e/webui-visual-smoke.mjs; \
	else \
		echo "node not found; WebUI visual smoke replay requires Node.js"; \
		exit 1; \
	fi

webui-enterprise-smoke:
	@set -eu; \
	if command -v node >/dev/null 2>&1; then \
		$(MAKE) webui-check WEBUI_CHECK_REQUIRE_NODE=1; \
		echo "release_smoke_mode=desktop-enterprise"; \
		echo "browser_required=$(WEBUI_SMOKE_REQUIRE_BROWSER)"; \
		echo "viewport_coverage=$(WEBUI_ENTERPRISE_SMOKE_VIEWPORTS)"; \
		WEBUI_SMOKE_REQUIRE_BROWSER="$(WEBUI_SMOKE_REQUIRE_BROWSER)" \
		WEBUI_SMOKE_PATHS="$(WEBUI_ENTERPRISE_SMOKE_PATHS)" \
		WEBUI_SMOKE_VIEWPORTS="$(WEBUI_ENTERPRISE_SMOKE_VIEWPORTS)" \
		WEBUI_SMOKE_TOTAL_TIMEOUT_MS="$(WEBUI_ENTERPRISE_SMOKE_TOTAL_TIMEOUT_MS)" \
		WEBUI_SMOKE_ARTIFACT_DIR="$(WEBUI_ENTERPRISE_SMOKE_ARTIFACT_DIR)" \
		node e2e/webui-visual-smoke.mjs; \
	else \
		echo "node not found; WebUI enterprise visual smoke requires Node.js"; \
		exit 1; \
	fi

# Real-engine tests: nftables + network namespaces + live traffic, plus
# privileged packet capture. Requires root, nft, ip, nc, and tcpdump; tests
# skip themselves when a dependency is unavailable.
integration-compile:
	go test -c -tags integration -o $${TMPDIR:-/tmp}/openngfw-itest ./test/integration

integration-test:
	go test -tags integration -count=1 -v ./test/integration/

privileged-integration-evidence-check:
	bash release/privileged-integration-no-skip.sh -- $(MAKE) integration-test VERSION="$(VERSION)" COMMIT="$(COMMIT)" BUILD_DATE="$(BUILD_DATE)"

deploy-hardening-check:
	bash release/deploy-hardening-check.sh --check

policy-restore-drill-check:
	bash release/policy-restore-drill.sh --check

ha-readiness-recovery-check:
	bash release/ha-readiness-recovery.sh --check

m3-live-networking-check:
	bash release/m3-live-networking.sh --check

m3-live-networking:
	bash release/m3-live-networking.sh --run

m3-field-evidence-check:
	bash release/m3-field-evidence.sh --evidence-dir "$(M3_FIELD_EVIDENCE_DIR)"

ebpf-ol9-attach-drill-check:
	bash release/ebpf-ol9-attach-drill.sh --check --evidence-dir "$(EBPF_OL9_FIELD_EVIDENCE_DIR)"

ebpf-ol9-attach-drill:
	bash release/ebpf-ol9-attach-drill.sh --run --evidence-dir "$(EBPF_OL9_FIELD_EVIDENCE_DIR)"

ebpf-ol9-field-evidence-check:
	bash release/ebpf-ol9-field-evidence.sh --evidence-dir "$(EBPF_OL9_FIELD_EVIDENCE_DIR)"

m5-oidc-field-evidence-check:
	bash release/oidc-field-evidence.sh --evidence-dir "$(OIDC_FIELD_EVIDENCE_DIR)"

m5-saml-field-evidence-check:
	bash release/saml-field-evidence.sh --evidence-dir "$(SAML_FIELD_EVIDENCE_DIR)"

content-production-readiness-check:
	bash release/content-production-readiness.sh --evidence-dir "$(CONTENT_PRODUCTION_EVIDENCE_DIR)"

e2e-install-check:
	bash e2e/install-smoke.sh --check

e2e-install:
	bash e2e/install-smoke.sh --run

e2e-auth-runtime-smoke: build webui-check
	bash e2e/auth-runtime-smoke.sh

e2e-oidc-runtime-smoke:
	go test -count=1 -run TestOIDCRuntimeSmoke -v ./cmd/controld

content-package-smoke:
	bash e2e/content-package-smoke.sh --check

benchmark-verify:
	go run ./cmd/ngfwperf verify perf/results

benchmark-verify-release:
	@summary="$$(find $(RELEASE_PERF_RESULTS) -name summary.json -print -quit 2>/dev/null)"; \
	if [ -n "$$summary" ]; then \
		go run ./cmd/ngfwperf verify --strict --publishable $(RELEASE_PERF_RESULTS); \
	elif [ "$(RELEASE_NO_PERFORMANCE_CLAIMS)" = "1" ]; then \
		echo "no release benchmark summaries under $(RELEASE_PERF_RESULTS); release is explicitly marked as publishing no performance claims"; \
	else \
		echo "no release benchmark summaries under $(RELEASE_PERF_RESULTS); set RELEASE_NO_PERFORMANCE_CLAIMS=1 only for releases that publish no performance claims"; \
		exit 1; \
	fi

benchmark-citation-check:
	@files="$$(find $(BENCHMARK_CITATION_PATHS) \
		-path release/evidence -prune -o \
		-path release/field-evidence -prune -o \
		-type f \( -name '*.md' -o -name '*.txt' \) -print 2>/dev/null | sort)"; \
	if [ -z "$$files" ]; then \
		echo "no benchmark citation files found under $(BENCHMARK_CITATION_PATHS)"; \
	else \
		go run ./cmd/ngfwperf check-citations $$files; \
	fi

benchmark-stage-release:
	@if [ -z "$(BENCHMARK_RUN)" ]; then \
		echo "BENCHMARK_RUN is required, for example BENCHMARK_RUN=perf/results/<run>"; \
		exit 1; \
	fi
	go run ./cmd/ngfwperf stage-release --release-dir "$(RELEASE_PERF_RESULTS)" "$(BENCHMARK_RUN)"

benchmark-check:
	bash perf/bench.sh --check

benchmark:
	bash perf/bench.sh --run

benchmark-netns-check:
	bash perf/netns.sh --check

benchmark-netns:
	bash perf/netns.sh --run

release-evidence-rootless: release-evidence-proto-verify release-evidence-deploy-hardening release-evidence-policy-restore-drill release-evidence-ha-readiness-recovery release-evidence-content-package-verification release-evidence-m5-auth-ui release-evidence-m5-oidc-provider release-evidence-webui-enterprise-smoke release-evidence-release-benchmark

release-evidence-proto-verify:
	go run ./cmd/ngfwrelease record --evidence-dir "$(RELEASE_EVIDENCE_DIR)" --check proto-verify --commit "$(COMMIT)" --detail "rootless release gate: generated API code is current for $(COMMIT)" $(RELEASE_EVIDENCE_RECORD_FLAGS) -- make proto-verify $(RELEASE_BUILD_ARGS)

release-evidence-privileged-integration:
	go run ./cmd/ngfwrelease record --evidence-dir "$(RELEASE_EVIDENCE_DIR)" --check privileged-integration --commit "$(COMMIT)" --detail "privileged release gate: nftables, network namespace, packet capture, and live integration tests for $(COMMIT); skipped integration tests are rejected" $(RELEASE_EVIDENCE_RECORD_FLAGS) -- make privileged-integration-evidence-check $(RELEASE_BUILD_ARGS)

release-evidence-deploy-hardening:
	go run ./cmd/ngfwrelease record --evidence-dir "$(RELEASE_EVIDENCE_DIR)" --check deploy-hardening --commit "$(COMMIT)" --detail "rootless release gate: packaged systemd unit and installer hardening posture for $(COMMIT)" $(RELEASE_EVIDENCE_RECORD_FLAGS) -- make deploy-hardening-check $(RELEASE_BUILD_ARGS)

release-evidence-policy-restore-drill:
	go run ./cmd/ngfwrelease record --evidence-dir "$(RELEASE_EVIDENCE_DIR)" --check policy-restore-drill --commit "$(COMMIT)" --detail "rootless release gate: emergency policy restore drill for $(COMMIT)" $(RELEASE_EVIDENCE_RECORD_FLAGS) -- make policy-restore-drill-check $(RELEASE_BUILD_ARGS)

release-evidence-ha-readiness-recovery:
	go run ./cmd/ngfwrelease record --evidence-dir "$(RELEASE_EVIDENCE_DIR)" --check ha-readiness-recovery --commit "$(COMMIT)" --detail "rootless release gate: active/passive HA readiness and control-plane recovery evidence for $(COMMIT); does not certify VIP/route promotion, fencing, or connection-state sync" $(RELEASE_EVIDENCE_RECORD_FLAGS) -- make ha-readiness-recovery-check $(RELEASE_BUILD_ARGS)

release-evidence-e2e-install:
	go run ./cmd/ngfwrelease record --evidence-dir "$(RELEASE_EVIDENCE_DIR)" --check e2e-install --commit "$(COMMIT)" --detail "privileged release gate: installed service commit, allow/deny policy enforcement, and namespace traffic filtering for $(COMMIT)" $(RELEASE_EVIDENCE_RECORD_FLAGS) -- sudo -E make e2e-install $(RELEASE_BUILD_ARGS)

release-evidence-content-package-verification:
	go run ./cmd/ngfwrelease record --evidence-dir "$(RELEASE_EVIDENCE_DIR)" --check content-package-verification --commit "$(COMMIT)" --detail "rootless release gate: demo-only signed content package mechanics for $(COMMIT); does not certify production App-ID, Threat-ID, or intel-feed content" $(RELEASE_EVIDENCE_RECORD_FLAGS) -- make content-package-smoke $(RELEASE_BUILD_ARGS)

release-evidence-content-production-readiness:
	go run ./cmd/ngfwrelease record --evidence-dir "$(RELEASE_EVIDENCE_DIR)" --check content-production-readiness --commit "$(COMMIT)" --detail "release gate: signed production App-ID, Threat-ID, and intel-feed content readiness evidence for $(COMMIT)" $(RELEASE_EVIDENCE_RECORD_FLAGS) -- make content-production-readiness-check $(RELEASE_BUILD_ARGS)

release-evidence-m3-live-networking:
	go run ./cmd/ngfwrelease record --evidence-dir "$(RELEASE_EVIDENCE_DIR)" --check m3-live-networking --commit "$(COMMIT)" --detail "privileged release gate: static-route live forwarding, local FRR BGP netns route programming, and WireGuard handshake/peer-traffic validation for $(COMMIT)" $(RELEASE_EVIDENCE_RECORD_FLAGS) -- make m3-live-networking $(RELEASE_BUILD_ARGS)

release-evidence-m3-field-evidence:
	go run ./cmd/ngfwrelease record --evidence-dir "$(RELEASE_EVIDENCE_DIR)" --check m3-field-evidence --commit "$(COMMIT)" --detail "release gate: external BGP peer, IPsec SA/protected-subnet traffic, and external WireGuard client field evidence bundle for $(COMMIT)" $(RELEASE_EVIDENCE_RECORD_FLAGS) -- make m3-field-evidence-check $(RELEASE_BUILD_ARGS)

release-evidence-ebpf-ol9-field-evidence:
	go run ./cmd/ngfwrelease record --evidence-dir "$(RELEASE_EVIDENCE_DIR)" --check ebpf-ol9-field-evidence --commit "$(COMMIT)" --detail "release gate: OL9/OCI Linux-root eBPF XDP/tc attach and status field evidence bundle for $(COMMIT)" $(RELEASE_EVIDENCE_RECORD_FLAGS) -- make ebpf-ol9-field-evidence-check $(RELEASE_BUILD_ARGS)

release-evidence-m5-auth-ui:
	go run ./cmd/ngfwrelease record --evidence-dir "$(RELEASE_EVIDENCE_DIR)" --check m5-auth-ui --commit "$(COMMIT)" --detail "rootless release gate: WebUI syntax, JavaScript unit tests, and loopback auth/UI runtime smoke for $(COMMIT)" $(RELEASE_EVIDENCE_RECORD_FLAGS) -- make e2e-auth-runtime-smoke $(RELEASE_BUILD_ARGS)

release-evidence-m5-oidc-provider:
	go run ./cmd/ngfwrelease record --evidence-dir "$(RELEASE_EVIDENCE_DIR)" --check m5-oidc-provider --commit "$(COMMIT)" --detail "rootless release gate: loopback mock-provider OIDC authorization-code session and API-driven runtime provider lifecycle smoke for $(COMMIT)" $(RELEASE_EVIDENCE_RECORD_FLAGS) -- make e2e-oidc-runtime-smoke $(RELEASE_BUILD_ARGS)

release-evidence-m5-oidc-field-evidence:
	go run ./cmd/ngfwrelease record --evidence-dir "$(RELEASE_EVIDENCE_DIR)" --check m5-oidc-field-evidence --commit "$(COMMIT)" --detail "release gate: redacted real-provider OIDC browser SSO field evidence bundle for $(COMMIT)" $(RELEASE_EVIDENCE_RECORD_FLAGS) -- make m5-oidc-field-evidence-check $(RELEASE_BUILD_ARGS)

release-evidence-m5-saml-field-evidence:
	go run ./cmd/ngfwrelease record --evidence-dir "$(RELEASE_EVIDENCE_DIR)" --check m5-saml-field-evidence --commit "$(COMMIT)" --detail "release gate: redacted real-provider SAML browser SSO field evidence bundle for $(COMMIT)" $(RELEASE_EVIDENCE_RECORD_FLAGS) -- make m5-saml-field-evidence-check $(RELEASE_BUILD_ARGS)

release-evidence-webui-enterprise-smoke:
	go run ./cmd/ngfwrelease record --evidence-dir "$(RELEASE_EVIDENCE_DIR)" --check webui-enterprise-smoke --commit "$(COMMIT)" --detail "release gate: browser-required broad desktop WebUI enterprise smoke across the current 19-route canonical route set including /compliance for $(COMMIT); continuation, tablet/mobile, or targeted repair evidence is diagnostic only until repo-local release evidence is recorded for the accepted source snapshot" $(RELEASE_EVIDENCE_RECORD_FLAGS) -- make webui-enterprise-smoke $(RELEASE_BUILD_ARGS)

release-evidence-release-benchmark:
	@if [ "$(RELEASE_NO_PERFORMANCE_CLAIMS)" = "1" ]; then \
		echo "no release-benchmark evidence artifact is recorded when RELEASE_NO_PERFORMANCE_CLAIMS=1"; \
		echo "assemble with RELEASE_NO_PERFORMANCE_CLAIMS=1 so release-benchmark is not_applicable; release notes must contain no throughput, latency, connection-rate, or comparison claims"; \
	else \
		go run ./cmd/ngfwrelease record --evidence-dir "$(RELEASE_EVIDENCE_DIR)" --check release-benchmark --commit "$(COMMIT)" --detail "rootless release gate: strict publishable benchmark verifier for $(RELEASE_PERF_RESULTS)" $(RELEASE_EVIDENCE_RECORD_FLAGS) -- make benchmark-verify-release $(RELEASE_BUILD_ARGS); \
	fi

release-acceptance-status:
	@if [ "$(RELEASE_NO_PERFORMANCE_CLAIMS)" = "1" ]; then \
		go run ./cmd/ngfwrelease status --manifest $(RELEASE_ACCEPTANCE_MANIFEST) --evidence-dir $(RELEASE_EVIDENCE_DIR) --commit $(COMMIT) --version $(VERSION) --allow-no-performance-claims --recordability; \
	else \
		go run ./cmd/ngfwrelease status --manifest $(RELEASE_ACCEPTANCE_MANIFEST) --evidence-dir $(RELEASE_EVIDENCE_DIR) --commit $(COMMIT) --version $(VERSION) --recordability; \
	fi

release-acceptance-status-functional:
	@if [ "$(RELEASE_NO_PERFORMANCE_CLAIMS)" = "1" ]; then \
		go run ./cmd/ngfwrelease status --manifest $(RELEASE_ACCEPTANCE_MANIFEST) --evidence-dir $(RELEASE_EVIDENCE_DIR) --commit $(COMMIT) --version $(VERSION) --allow-no-performance-claims $(RELEASE_FUNCTIONAL_HARDENING_DEFERRED_FLAGS) --recordability; \
	else \
		go run ./cmd/ngfwrelease status --manifest $(RELEASE_ACCEPTANCE_MANIFEST) --evidence-dir $(RELEASE_EVIDENCE_DIR) --commit $(COMMIT) --version $(VERSION) $(RELEASE_FUNCTIONAL_HARDENING_DEFERRED_FLAGS) --recordability; \
	fi

release-recordability-check:
	go run ./cmd/ngfwrelease recordability --evidence-dir $(RELEASE_EVIDENCE_DIR) --commit $(COMMIT) --strict

release-recordability-diagnostics:
	@status=0; \
	echo "== API contract recordability diagnostics =="; \
	if ! $(MAKE) proto-status; then \
		status=1; \
	fi; \
	echo; \
	echo "== Release evidence recordability diagnostics =="; \
	if ! $(MAKE) release-recordability-check; then \
		status=1; \
	fi; \
	if [ "$$status" -ne 0 ]; then \
		echo; \
		echo "release recordability diagnostics found blockers; this target is diagnostic only and records no evidence"; \
	fi; \
	exit "$$status"

release-acceptance-assemble:
	@if [ "$(RELEASE_NO_PERFORMANCE_CLAIMS)" = "1" ]; then \
		go run ./cmd/ngfwrelease assemble --manifest $(RELEASE_ACCEPTANCE_MANIFEST) --version $(VERSION) --commit $(COMMIT) --operator "$(RELEASE_OPERATOR)" --evidence-dir $(RELEASE_EVIDENCE_DIR) --no-performance-claims --no-performance-detail "This tag publishes no throughput, latency, connection-rate, or comparison claims."; \
	else \
		if [ -z "$(RELEASE_BENCHMARK_SUMMARY)" ]; then \
			echo "RELEASE_BENCHMARK_SUMMARY is required, for example perf/release-results/<run>/summary.json"; \
			exit 1; \
		fi; \
		go run ./cmd/ngfwrelease assemble --manifest $(RELEASE_ACCEPTANCE_MANIFEST) --version $(VERSION) --commit $(COMMIT) --operator "$(RELEASE_OPERATOR)" --evidence-dir $(RELEASE_EVIDENCE_DIR) --benchmark-summary $(RELEASE_BENCHMARK_SUMMARY); \
	fi

release-acceptance-assemble-functional:
	@if [ "$(RELEASE_NO_PERFORMANCE_CLAIMS)" = "1" ]; then \
		go run ./cmd/ngfwrelease assemble --manifest $(RELEASE_ACCEPTANCE_MANIFEST) --version $(VERSION) --commit $(COMMIT) --operator "$(RELEASE_OPERATOR)" --evidence-dir $(RELEASE_EVIDENCE_DIR) --no-performance-claims --no-performance-detail "This tag publishes no throughput, latency, connection-rate, or comparison claims." $(RELEASE_FUNCTIONAL_HARDENING_DEFERRED_FLAGS); \
	else \
		if [ -z "$(RELEASE_BENCHMARK_SUMMARY)" ]; then \
			echo "RELEASE_BENCHMARK_SUMMARY is required, for example perf/release-results/<run>/summary.json"; \
			exit 1; \
		fi; \
		go run ./cmd/ngfwrelease assemble --manifest $(RELEASE_ACCEPTANCE_MANIFEST) --version $(VERSION) --commit $(COMMIT) --operator "$(RELEASE_OPERATOR)" --evidence-dir $(RELEASE_EVIDENCE_DIR) --benchmark-summary $(RELEASE_BENCHMARK_SUMMARY) $(RELEASE_FUNCTIONAL_HARDENING_DEFERRED_FLAGS); \
	fi

lint:
	golangci-lint run ./...

vet:
	go vet ./...

vuln-check:
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

release-acceptance-verify:
	@if [ "$(RELEASE_NO_PERFORMANCE_CLAIMS)" = "1" ]; then \
		go run ./cmd/ngfwrelease verify --manifest $(RELEASE_ACCEPTANCE_MANIFEST) --commit $(COMMIT) --version $(VERSION) --allow-no-performance-claims; \
	else \
		go run ./cmd/ngfwrelease verify --manifest $(RELEASE_ACCEPTANCE_MANIFEST) --commit $(COMMIT) --version $(VERSION); \
	fi

release-check-rootless: build test vet vuln-check integration-compile deploy-hardening-check policy-restore-drill-check ha-readiness-recovery-check e2e-install-check content-package-smoke e2e-auth-runtime-smoke e2e-oidc-runtime-smoke webui-enterprise-smoke benchmark-verify-release benchmark-citation-check

release-verify: proto-verify release-check-rootless release-acceptance-verify release-recordability-check

tools:
	GOBIN=$(abspath $(TOOLS_DIR)) go install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	GOBIN=$(abspath $(TOOLS_DIR)) go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GO_GRPC_VERSION)
	GOBIN=$(abspath $(TOOLS_DIR)) go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@$(PROTOC_GEN_GW_VERSION)
	GOBIN=$(abspath $(TOOLS_DIR)) go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2@$(PROTOC_GEN_OPENAPIV2_VERSION)
	GOBIN=$(abspath $(TOOLS_DIR)) go install github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION)

proto: tools
	PATH=$(abspath $(TOOLS_DIR)):$$PATH $(TOOLS_DIR)/buf lint
	PATH=$(abspath $(TOOLS_DIR)):$$PATH $(TOOLS_DIR)/buf generate
	@test -s "$(OPENAPI_GENERATED_SPEC)"
	go run ./cmd/ngfwopenapi --in "$(OPENAPI_GENERATED_SPEC)" --out "$(OPENAPI_GENERATED_SPEC)"
	cp "$(OPENAPI_GENERATED_SPEC)" "$(OPENAPI_PUBLISHED_SPEC)"
	cp "$(OPENAPI_GENERATED_SPEC)" "$(OPENAPI_WEBUI_SPEC)"

# Fails if the API contract inputs or generated code/specs are not clean.
proto-verify: proto
	@status=0; \
	if ! git diff --exit-code --quiet -- $(API_CONTRACT_INPUTS); then \
		echo "API contract inputs differ from the index; commit proto/OpenAPI inputs, generator config, and cmd/ngfwopenapi changes with matching generated outputs before recording release evidence"; \
		git diff --name-only -- $(API_CONTRACT_INPUTS); \
		status=1; \
	fi; \
	if ! git diff --exit-code --quiet -- $(API_CONTRACT_OUTPUTS); then \
		echo "generated API files differ from the index; run make proto and include api/gen, $(OPENAPI_PUBLISHED_SPEC), and $(OPENAPI_WEBUI_SPEC) changes"; \
		git diff --name-only -- $(API_CONTRACT_OUTPUTS); \
		status=1; \
	fi; \
	if ! git diff --cached --exit-code --quiet -- $(API_CONTRACT_INPUTS) $(API_CONTRACT_OUTPUTS); then \
		echo "API contract inputs or generated outputs are staged relative to HEAD; commit them before recording release evidence"; \
		git diff --cached --name-only -- $(API_CONTRACT_INPUTS) $(API_CONTRACT_OUTPUTS); \
		status=1; \
	fi; \
	untracked_inputs="$$(git ls-files --others --exclude-standard -- $(API_CONTRACT_INPUTS))"; \
	if [ -n "$$untracked_inputs" ]; then \
		echo "untracked API contract inputs:"; \
		printf '%s\n' "$$untracked_inputs"; \
		status=1; \
	fi; \
	untracked="$$(git ls-files --others --exclude-standard -- $(API_CONTRACT_OUTPUTS))"; \
	if [ -n "$$untracked" ]; then \
		echo "untracked generated API files/specs:"; \
		printf '%s\n' "$$untracked"; \
		status=1; \
	fi; \
	exit "$$status"

# Read-only diagnostic for generated API drift. Unlike proto-verify, this does
# not regenerate files; use it to see why release evidence cannot be recorded.
proto-status:
	@status=0; \
	echo "API contract source/generated diff against index:"; \
	if git diff --quiet -- $(API_CONTRACT_INPUTS) $(API_CONTRACT_OUTPUTS); then \
		echo "  none"; \
	else \
		git diff --name-status -- $(API_CONTRACT_INPUTS) $(API_CONTRACT_OUTPUTS); \
		status=1; \
	fi; \
	echo "staged API contract source/generated diff:"; \
	if git diff --cached --quiet -- $(API_CONTRACT_INPUTS) $(API_CONTRACT_OUTPUTS); then \
		echo "  none"; \
	else \
		git diff --cached --name-status -- $(API_CONTRACT_INPUTS) $(API_CONTRACT_OUTPUTS); \
		status=1; \
	fi; \
	echo "untracked API contract inputs:"; \
	untracked_inputs="$$(git ls-files --others --exclude-standard -- $(API_CONTRACT_INPUTS))"; \
	if [ -n "$$untracked_inputs" ]; then \
		printf '  %s\n' $$untracked_inputs; \
		status=1; \
	else \
		echo "  none"; \
	fi; \
	echo "untracked generated files/specs:"; \
	untracked="$$(git ls-files --others --exclude-standard -- $(API_CONTRACT_OUTPUTS))"; \
	if [ -n "$$untracked" ]; then \
		printf '  %s\n' $$untracked; \
		status=1; \
	else \
		echo "  none"; \
	fi; \
	echo "OpenAPI spec copy consistency:"; \
	if [ -f "$(OPENAPI_GENERATED_SPEC)" ] && [ -f "$(OPENAPI_PUBLISHED_SPEC)" ] && cmp -s "$(OPENAPI_GENERATED_SPEC)" "$(OPENAPI_PUBLISHED_SPEC)"; then \
		echo "  generated -> docs: ok"; \
	else \
		echo "  generated -> docs: differ or missing"; \
		status=1; \
	fi; \
	if [ -f "$(OPENAPI_PUBLISHED_SPEC)" ] && [ -f "$(OPENAPI_WEBUI_SPEC)" ] && cmp -s "$(OPENAPI_PUBLISHED_SPEC)" "$(OPENAPI_WEBUI_SPEC)"; then \
		echo "  docs -> webui: ok"; \
	else \
		echo "  docs -> webui: differ or missing"; \
		status=1; \
	fi; \
	exit "$$status"

clean:
	rm -rf $(BIN_DIR)
