// Porygon Alpine.js State & Chart Controller — fully wired to backend (v0.8.0)

// Chart.js instances live outside Alpine's reactive scope. If stored directly
// as a component property (e.g. `charts: {}` inside Alpine.data()), Alpine
// wraps the object -- and everything inside it, including each Chart.js
// instance's large, self-referencing internal state -- in a reactive Proxy.
// Chart.js's own internal mutations then re-trigger Alpine's reactive
// getters recursively, which is exactly the
// "RangeError: Maximum call stack size exceeded" observed in the browser
// console on the Process Graph tab (traced to Object.get in alpinejs's
// reactivity implementation, called from inside chart.js's rendering path).
// Keeping the real Chart.js instances in this plain, non-reactive object and
// exposing them to the component via a getter fixes it without touching any
// of the many `chartRegistry.X` call sites throughout this file.
const chartRegistry = {};
let ruleWorkbenchReturnFocus = null;
let ruleWorkbenchTokenReturnFocus = null;

document.addEventListener('alpine:init', () => {
  Alpine.data('porygonApp', () => ({
    // Navigation
    activeTab: (typeof window !== 'undefined' && window.location.hash && ['overview', 'pathway', 'telemetry', 'anomalies', 'incidents', 'pipeline', 'vulnerabilities', 'simulator', 'ml'].includes(window.location.hash.slice(1))) ? window.location.hash.slice(1) : 'overview',
    navOpen: false,

    // System & Health Data
    systemInfo: {},
    assessmentStatus: null,
    services: [],
    containers: [],
    selectedContainer: null,
    selectedContainerName: null,
    isLoadingEvents: false,

    // Telemetry & Events (process-level eBPF)
    events: [], // ProcessExecEventOut[]
    eventFilter: '',
    get filteredEvents() {
      if (!this.eventFilter) return this.events || [];
      const q = this.eventFilter.toLowerCase();
      return (this.events || []).filter(e =>
        (e.process_name && e.process_name.toLowerCase().includes(q)) ||
        (e.executable && e.executable.toLowerCase().includes(q)) ||
        (e.container_name && e.container_name.toLowerCase().includes(q)) ||
        (e.command_line && e.command_line.toLowerCase().includes(q)) ||
        String(e.process_pid).includes(q)
      );
    },
    processSummary: null,
    runtimeSummary: null,
    kernelEvents: [],
    kernelActionFilter: '',
    kernelHostFilter: '',
    kernelLoading: false,
    kernelError: '',
    kernelRequestId: 0,

    // Behavioural Anomaly & Distance
    scores: [],
    anomalyConfig: null,
    activeProfile: null,
    currentAnomalyScore: 0,
    currentScoreBand: 'no_data',
    // Real window_start of the scoring window backing currentAnomalyScore, so a
    // "CURRENT" label can show the actual timestamp instead of implying a live
    // score when it's really the last window that could be scored.
    currentScoreWindowStart: null,
    // True when the most recent window returned by the backend has
    // status === 'insufficient_data' — i.e. there wasn't enough telemetry to
    // score it yet. currentAnomalyScore may still reflect an older scored
    // window in this case; this flag is what makes that visible instead of
    // silently mislabeling a stale window as current.
    latestWindowInsufficientData: false,
    scoreContributors: [],
    unseenTokens: [],

    // AI Security Inspector State
    aiConfig: {
      apiKey: (typeof localStorage !== 'undefined' && localStorage.getItem('porygon_ai_api_key')) || '',
      provider: (typeof localStorage !== 'undefined' && localStorage.getItem('porygon_ai_provider')) || 'gemini',
      model: (typeof localStorage !== 'undefined' && localStorage.getItem('porygon_ai_model')) || '',
    },
    aiModal: { show: false, apiKey: '', provider: 'gemini', model: '' },
    aiAuditModal: { show: false, loading: false, error: null, result: null, container: null },
    mlClassifyModal: { show: false, loading: false, error: null, result: null, container: null },
    mlClassifications: {},
    mlLoadingBatch: false,
    mlTacticFilter: 'all',
    mlSearchQuery: '',

    // Rules & Incidents
    rules: [],
    rulesMeta: {},
    incidents: [],
    selectedIncident: null,
    incidentFilter: 'open',
    get filteredIncidents() {
      if (this.incidentFilter === 'open') {
        return (this.incidents || []).filter(i => i.status === 'open' || i.status === 'acknowledged');
      } else if (this.incidentFilter === 'resolved' || this.incidentFilter === 'clean') {
        return (this.incidents || []).filter(i => i.status === 'resolved' || i.status === 'closed' || i.status === 'dismissed');
      }
      return this.incidents || [];
    },
    get openIncidentsCount() {
      return (this.incidents || []).filter(i => i.status === 'open' || i.status === 'acknowledged').length;
    },

    // Unified view of built-in + custom detection rules for the Incidents
    // tab's single rules list. Custom rules are mapped onto the same shape
    // as built-in rules (rule_id, name, description, severity_weight,
    // confidence_weight) plus lifecycle state and a back-reference for workbench review.
    get allRules() {
      const mappedCustom = this.customRules.map(r => ({
        rule_id: r.rule_id || `POR-CUS-${r.slug}`,
        name: r.name,
        description: r.description,
        severity_weight: r.severity_weight,
        confidence_weight: r.confidence_weight,
        enabled: r.enabled,
        lifecycle_state: r.lifecycle_state,
        candidate_state: r.candidate_state,
        revision_hash: r.revision_hash,
        active_revision_hash: r.active_revision_hash,
        category: r.category,
        target: r.target,
        // Canonical text form of the rule's condition, rendered by the backend from
        // the stored tree, so builder- and text-authored rules read the same here.
        expression: r.expression,
        is_custom: true,
        _customRule: r,
      }));
      return [...this.rules, ...mappedCustom];
    },

    // Custom detection rules
    customRules: [],
    showAddRuleModal: false,
    ruleFormError: '',
    newRuleDraft: {
      slug: '',
      name: '',
      description: '',
      category: 'custom',
      target: 'process',
      severity_weight: 0.6,
      confidence_weight: 0.8,
      incident_eligible: true,
      expression: '',
    },
    ruleWorkbench: {
      selectedRule: null,
      mode: 'manual',
      eventIds: '',
      fixtures: '',
      reference: '',
      rollbackRevisionHash: '',
      revisions: [],
      result: null,
      message: '',
      busy: false,
    },
    ruleAssistant: {
      objective: '', recipes: [], loadingRecipes: false, busy: false,
      recipeId: '', parameters: {}, recommendations: [], triage: null,
      proposal: null, proposalExpression: '', ready: false, message: '', requestId: 0,
      suggestedParameters: null,
    },

    // Pipeline trace (raw event -> rule match -> incident)
    pipelineIncidentId: '',
    pipelineTimeline: [],
    pipelineLoading: false,
    pipelineError: '',
    // Real divergence detail for the incident's triggering score
    // (GET /api/v1/anomaly-scores/{score_id}): per-feature-family
    // Jensen-Shannon distance, novelty, and the exact unseen tokens that
    // pushed the score out of the baseline_like band.
    pipelineScoreDetail: null,
    pipelineScoreLoading: false,
    pipelineScoreError: '',

    // Vulnerability & Evidence Ladder
    vulnerabilityFindings: [],
    reachabilityFilter: 'all',
    selectedReachabilityFinding: null,
    evidenceCounts: {
      package_present: 0,
      deployed: 0,
      runtime_observed: 0,
      runtime_observed_and_port_published: 0
    },

    // Process Pathway Graph State & Metadata
    selectedGraphNode: 'ebpf',
    graphPathwayMode: (typeof window !== 'undefined' && window.location.search.includes('mode=attack')) ? 'attack' : (typeof window !== 'undefined' && window.location.search.includes('mode=reachability')) ? 'reachability' : 'all',
    processGraphNodes: {
      ebpf: {
        id: 'ebpf',
        name: 'eBPF Probes',
        stageNumber: 1,
        tier: 'Tier 1: Kernel & System Sources',
        tierShort: 'Tier 1',
        layer: 'Linux Kernel Space (Ring Buffer)',
        icon: 'ph-cpu',
        tag: 'KERNEL HOOK',
        badgeColor: 'text-cyan-400 bg-cyan-400/10 border-cyan-400/20',
        summary: 'Falco\'s modern-eBPF driver attaches to process-execution tracepoints without modifying container binaries or kernel source. Execve/execveat feed behavioral scoring. Outbound connections, memory-backed file creation, and sensitive-path writes are stored separately as typed kernel evidence.',
        technicalHook: 'evt.type in (execve, execveat)  [falco/porygon_rules.yaml]',
        inputSource: 'Process-execution syscalls from containerized processes.',
        outputArtifact: 'Process-exec records (process name, executable path, full command line, ppid, uid/gid, parent context) -- see falco/porygon_rules.yaml for the exact output fields.',
        liveMetricKey: 'Kernel Events',
        metricType: 'events',
        status: 'ATTACHED & STREAMING',
        statusColor: 'text-emerald-400',
        targetTab: 'telemetry',
        modes: ['all', 'attack', 'reachability']
      },
      docker: {
        id: 'docker',
        name: 'Docker Lifecycle Spool',
        stageNumber: 2,
        tier: 'Tier 1: Kernel & System Sources',
        tierShort: 'Tier 1',
        layer: 'Host Container Runtime (/var/run/docker.sock)',
        icon: 'ph-cube',
        tag: 'RUNTIME SPOOL',
        badgeColor: 'text-blue-400 bg-blue-400/10 border-blue-400/20',
        summary: 'Monitors Docker Engine events via durable SQLite outbox spool (outbox.db), extracting immutable SHA-256 image digests and container namespace PID maps.',
        technicalHook: 'GET /events?filters={"type":["container"]}\nSQLite outbox spool: /var/lib/porygon/outbox.db (spool.py::OutboxStore)',
        inputSource: 'Docker daemon container start, exec_create, and die life-cycle broadcasts.',
        outputArtifact: 'Shared-secret image_digest (SHA-256) binding + Host-to-Container PID translation map.',
        liveMetricKey: 'Active Containers',
        metricType: 'containers',
        status: 'SYNCHRONIZED',
        statusColor: 'text-emerald-400',
        targetTab: 'telemetry',
        modes: ['all', 'attack', 'reachability']
      },
      sbom: {
        id: 'sbom',
        name: 'CycloneDX SBOM & Trivy',
        stageNumber: 3,
        tier: 'Tier 1: Kernel & System Sources',
        tierShort: 'Tier 1',
        layer: 'Static Supply Chain Analysis',
        icon: 'ph-shield-check',
        tag: 'STATIC AUDIT',
        badgeColor: 'text-indigo-400 bg-indigo-400/10 border-indigo-400/20',
        summary: 'Static vulnerability scanner indexing package manifests, lockfiles, and binaries inside base images with EPSS probability and CISA KEV tags.',
        technicalHook: 'CycloneDX v1.5 JSON • Trivy Vulnerability DB • EPSS API • CISA KEV Catalog',
        inputSource: 'Container image layer tarballs and software package manifests (npm, pip, deb, apk).',
        outputArtifact: 'Cataloged CVE finding records with CVSS scores, fix versions, and baseline presence markers.',
        liveMetricKey: 'Cataloged CVEs',
        metricType: 'scans',
        status: 'INDEXED',
        statusColor: 'text-emerald-400',
        targetTab: 'vulnerabilities',
        modes: ['all', 'reachability']
      },
      collector: {
        id: 'collector',
        name: 'Ingestion Gateway & Normalizer',
        stageNumber: 4,
        tier: 'Tier 2: Ingestion & Normalization',
        tierShort: 'Tier 2',
        layer: 'Porygon Gateway (FastAPI / PostgreSQL 17)',
        icon: 'ph-brackets-curly',
        tag: 'PIPELINE GATEWAY',
        badgeColor: 'text-violet-400 bg-violet-400/10 border-violet-400/20',
        summary: 'Event ingestion gateway. Lowercases busybox/toybox basenames (detection.py::_resolve_multicall_name), resolves parent-child execution trees (best-effort 600s lookback), and persists to PostgreSQL via an outbox spool. Raw command-line strings are stored as-received; no argument sanitization is currently implemented.',
        technicalHook: 'POST /api/v1/events\nOutbox-pattern batcher (MET-OTP-001 occurrence-to-persistence latency has not yet been measured/reported)',
        inputSource: 'Uncorrelated eBPF syscall records + Docker runtime container lifecycle metadata.',
        outputArtifact: 'Enriched ProcessExecEventOut records with resolved container_name, image_digest, and ppid lineage.',
        liveMetricKey: 'Gateway Health',
        metricType: 'collector',
        status: 'BUFFERING & NORMALIZING',
        statusColor: 'text-emerald-400',
        targetTab: 'telemetry',
        modes: ['all', 'attack']
      },
      js_engine: {
        id: 'js_engine',
        name: 'Jensen-Shannon Distance Engine',
        stageNumber: 5,
        tier: 'Tier 3: Analytics & Rules Matrix',
        tierShort: 'Tier 3',
        layer: 'Information-Theoretic Mathematical Engine',
        icon: 'ph-function',
        tag: 'D_JS DIVERGENCE',
        badgeColor: 'text-amber-400 bg-amber-400/10 border-amber-400/20',
        summary: 'Calculates symmetric information-theoretic distance between baseline empirical probability P(x) and live sliding window Q(x) across categorical, novelty, and numeric distributions.',
        technicalHook: 'D_JS(P || Q) = sqrt(1/2 * D_KL(P || M) + 1/2 * D_KL(Q || M))  base-2, range [0,1]\nWeights: Categorical 50% • Novelty 30% • Numeric 20% (numeric_deviation is Robust Z, scoring.py::_numeric_deviation)',
        inputSource: 'Configurable sliding window (default 60s, operator-adjustable 5-3600s) of normalized execution tokens compared against digest-bound training profile.',
        outputArtifact: 'Continuous anomaly distance score [0.00, 1.00] with token-level attribution vectors.',
        liveMetricKey: 'Current Distance',
        metricType: 'distance',
        status: 'EVALUATING WINDOWS',
        statusColor: 'text-emerald-400',
        targetTab: 'anomalies',
        modes: ['all', 'attack']
      },
      rules: {
        id: 'rules',
        name: 'Deterministic Rules Matrix',
        stageNumber: 6,
        tier: 'Tier 3: Analytics & Rules Matrix',
        tierShort: 'Tier 3',
        layer: 'Deterministic Verification Layer',
        icon: 'ph-list-checks',
        tag: 'GUARDRAIL MATRIX',
        badgeColor: 'text-orange-400 bg-orange-400/10 border-orange-400/20',
        summary: 'Auditable deterministic rules evaluating behavioral threshold breaches, shell invocations, privilege jumps, reconnaissance, and dropper evasion.',
        technicalHook: 'POR-DET-001 through POR-DET-007\nEvaluates boolean predicates against event metadata and D_JS scores',
        inputSource: 'Enriched execution events, process ancestry chains, and anomaly score updates.',
        outputArtifact: 'Structured detection alerts containing matched rule_id, severity, confidence, and recommended lease.',
        liveMetricKey: 'Active Rules',
        metricType: 'rules',
        status: 'MONITORING',
        statusColor: 'text-emerald-400',
        targetTab: 'pipeline',
        modes: ['all', 'attack']
      },
      incidents: {
        id: 'incidents',
        name: 'Incident Evidence Graph',
        stageNumber: 7,
        tier: 'Tier 4: Correlation, Funnel & Actuation',
        tierShort: 'Tier 4',
        layer: 'Security Incident State Machine',
        icon: 'ph-warning-octagon',
        tag: 'CORRELATION ENGINE',
        badgeColor: 'text-red-400 bg-red-400/10 border-red-400/20',
        summary: 'Time-windowed correlation engine. Groups related detection findings, anomaly score spikes, and container digests into unified Incident records with automated containment proposals.',
        technicalHook: 'Container digest clustering • 120s shell-to-tool correlation window (POR-DET-005) • State: open/acknowledged/resolved',
        inputSource: 'Triggered deterministic rule findings + elevated Jensen-Shannon anomaly events.',
        outputArtifact: 'Unified Incident objects with severity scoring, container target, and recommended action.',
        liveMetricKey: 'Security Incidents',
        metricType: 'incidents',
        status: 'CORRELATING',
        statusColor: 'text-amber-400',
        targetTab: 'incidents',
        modes: ['all', 'attack', 'reachability']
      },
      reachability: {
        id: 'reachability',
        name: '4-Stage Reachability Funnel',
        stageNumber: 8,
        tier: 'Tier 4: Correlation, Funnel & Actuation',
        tierShort: 'Tier 4',
        layer: 'Dynamic Attack Surface Verification',
        icon: 'ph-funnel',
        tag: 'REACHABILITY ENGINE',
        badgeColor: 'text-emerald-400 bg-emerald-400/10 border-emerald-400/20',
        summary: 'Correlates package inventories with deployment, process execution, and published-port evidence to prioritize vulnerability review.',
        technicalHook: 'Evidence Ladder:\n1. Package Present -> 2. Deployed -> 3. Runtime Observed -> 4. Port Published',
        inputSource: 'CycloneDX SBOM packages (Tier 1) intersected with eBPF execve telemetry (Tier 1).',
        outputArtifact: 'Vulnerability findings partitioned by evidence stage (package present / deployed / runtime-observed / port-published); no aggregate noise-reduction percentage has been measured.',
        liveMetricKey: 'Runtime Observed',
        metricType: 'reachability',
        status: 'FILTERING',
        statusColor: 'text-emerald-400',
        targetTab: 'vulnerabilities',
        modes: ['all', 'reachability']
      },
      containment: {
        id: 'containment',
        name: 'Containment Actuator (Lease Engine)',
        stageNumber: 9,
        tier: 'Tier 4: Correlation, Funnel & Actuation',
        tierShort: 'Tier 4',
        layer: 'Human-Governed Execution Guard',
        icon: 'ph-lock-key',
        tag: 'FAIL-SAFE ACTUATOR',
        badgeColor: 'text-rose-400 bg-rose-400/10 border-rose-400/20',
        summary: 'Issues operator-approved containment actions (observe_only, pause_container, stop_container — no isolate action exists) gated behind a shared-secret operator token (secrets.compare_digest, PORYGON_OPERATOR_API_TOKEN, security.py::require_operator_token). Reversal is operator-initiated via a dedicated rollback call, not an automatic timer; a separate lease-expiry requeue only reassigns a stalled executor claim to another responder instance. Not PKI/JWT.',
        technicalHook: 'POST /operator/v1/response-recommendations/{recommendation_id}/approve\nPOST /operator/v1/response-executions/{execution_id}/rollback (operator-initiated)\nHeader: X-Porygon-Operator-Token (shared secret, secrets.compare_digest)',
        inputSource: 'Approved incident containment recommendations from authorized human operators.',
        outputArtifact: 'Enforced container pause/stop execution; reversal requires an explicit operator-approved rollback call, not automatic lease expiration.',
        liveMetricKey: 'Operator Posture',
        metricType: 'containment',
        status: 'ARMED & FAIL-SAFE',
        statusColor: 'text-emerald-400',
        targetTab: 'incidents',
        modes: ['all', 'attack']
      }
    },

    selectGraphNode(nodeId) {
      this.selectedGraphNode = nodeId;
    },

    setGraphMode(mode) {
      this.graphPathwayMode = mode;
      const current = this.processGraphNodes[this.selectedGraphNode];
      if (current && !current.modes.includes(mode)) {
        const first = Object.values(this.processGraphNodes).find(n => n.modes.includes(mode));
        if (first) this.selectedGraphNode = first.id;
      }
    },

    isNodeInCurrentMode(nodeId) {
      if (this.graphPathwayMode === 'all') return true;
      const node = this.processGraphNodes[nodeId];
      return node ? node.modes.includes(this.graphPathwayMode) : true;
    },

    jumpToNodeTab(tabId) {
      this.activeTab = tabId;
      window.scrollTo({ top: 0, behavior: 'smooth' });
    },

    getNodeMetricValue(nodeId) {
      const node = this.processGraphNodes[nodeId];
      if (!node) return '—';
      const info = this.systemInfo || {};
      switch (node.metricType) {
        case 'events':
          // Real lifetime process-exec count from GET /api/v1/system/info
          // (process_exec_events), not a hardcoded "2.7M" string. Shows a
          // neutral placeholder rather than a fake number if info hasn't
          // loaded yet.
          return info.process_exec_events != null
            ? `${(this.events?.length || 0)} buffered (${info.process_exec_events.toLocaleString()} lifetime)`
            : 'loading…';
        case 'containers':
          // Real total from system/info.known_containers, not
          // this.containers.length, which is capped at the /api/v1/containers
          // fetch's limit=100 and would silently under-report past 100.
          return info.known_containers != null ? `${info.known_containers.toLocaleString()} containers mapped` : 'loading…';
        case 'scans':
          return info.vulnerability_findings != null ? `${info.vulnerability_findings.toLocaleString()} static CVEs` : 'loading…';
        case 'collector':
          return info.registered_services != null ? `${info.registered_services} services online` : 'loading…';
        case 'distance':
          return (this.currentAnomalyScore || 0).toFixed(3) + ' [' + (this.currentScoreBand || 'normal').toUpperCase() + ']';
        case 'rules':
          return (this.rules?.length || 0) + ' active rules';
        case 'incidents':
          return info.incidents != null ? `${info.incidents} total (${info.open_incidents ?? 0} open)` : `${this.incidents?.length || 0} total`;
        case 'reachability':
          return (this.evidenceCounts?.runtime_observed ?? 0) + ' CVEs heuristic runtime-observed (package ∩ process)';
        case 'containment':
          return this.operatorToken ? 'AUTHORIZED (Token Set)' : 'LOCKED (Token Required)';
        default:
          return 'Active';
      }
    },

    // Simulator & Terminal Console
    terminalLogs: [],
    scenarioResults: {},
    isExecutingAttack: false,
    authorizingIncidentId: null,
    toasts: [],
    feedUnavailable: {
      health: false,
      inventory: false,
      telemetry: false,
      incidents: false,
      vulnerabilities: false,
    },
    get unavailableFeeds() {
      const labels = {
        health: 'service health',
        inventory: 'container inventory',
        telemetry: 'process telemetry',
        incidents: 'incident feed',
        vulnerabilities: 'vulnerability scans',
      };
      return Object.keys(labels).filter(feed => this.feedUnavailable[feed]).map(feed => labels[feed]);
    },
    showDocsModal: false,
    docsTab: 'mental_model',

    // Human credentials persist in sessionStorage for this tab only.
    _humanToken: (typeof sessionStorage !== 'undefined' && sessionStorage.getItem('porygon_operator_token')) || '',
    get operatorToken() { return this._humanToken; },
    set operatorToken(value) {
      this._humanToken = value || '';
      try {
        if (value) sessionStorage.setItem('porygon_operator_token', value);
        else sessionStorage.removeItem('porygon_operator_token');
      } catch (e) { }
    },

    // Styled operator-token entry modal — replaces window.prompt() everywhere a
    // human operator needs to authorize a write. Returns the entered token (or
    // null if cancelled) via a Promise so call sites can `await` it exactly like
    // the old prompt()-based flow did.
    tokenModal: { show: false, title: '', message: '', value: '', resolve: null },

    requestOperatorToken(message, title = 'Operator authorization required') {
      return new Promise((resolve) => {
        if (this.showAddRuleModal) ruleWorkbenchTokenReturnFocus = document.activeElement;
        this.tokenModal.title = title;
        this.tokenModal.message = message;
        this.tokenModal.value = '';
        this.tokenModal.show = true;
        this.tokenModal.resolve = resolve;
        if (this.showAddRuleModal) this.$nextTick(() => document.getElementById('human-access-token')?.focus({ preventScroll: true }));
      });
    },

    restoreRuleWorkbenchTokenFocus() {
      this.$nextTick(() => {
        if (this.showAddRuleModal && ruleWorkbenchTokenReturnFocus?.isConnected) {
          ruleWorkbenchTokenReturnFocus.focus({ preventScroll: true });
        }
        ruleWorkbenchTokenReturnFocus = null;
      });
    },

    submitTokenModal() {
      const value = (this.tokenModal.value || '').trim();
      const resolve = this.tokenModal.resolve;
      this.tokenModal.show = false;
      this.tokenModal.value = '';
      this.tokenModal.resolve = null;
      if (resolve) resolve(value || null);
      this.restoreRuleWorkbenchTokenFocus();
    },

    cancelTokenModal() {
      const resolve = this.tokenModal.resolve;
      this.tokenModal.show = false;
      this.tokenModal.value = '';
      this.tokenModal.resolve = null;
      if (resolve) resolve(null);
      this.restoreRuleWorkbenchTokenFocus();
    },

    // Styled confirmation modal — replaces raw window.confirm() for destructive
    // actions (disabling a custom rule, clearing the operator token), matching
    // the same Promise-returning pattern as the operator-token modal above.
    confirmModal: { show: false, title: '', message: '', confirmLabel: 'Confirm', danger: true, resolve: null },

    requestConfirm(message, title = 'Confirm action', confirmLabel = 'Confirm', danger = true) {
      return new Promise((resolve) => {
        this.confirmModal.title = title;
        this.confirmModal.message = message;
        this.confirmModal.confirmLabel = confirmLabel;
        this.confirmModal.danger = danger;
        this.confirmModal.show = true;
        this.confirmModal.resolve = resolve;
      });
    },

    submitConfirmModal(result) {
      const resolve = this.confirmModal.resolve;
      this.confirmModal.show = false;
      this.confirmModal.resolve = null;
      if (resolve) resolve(result);
    },

    // AI Security Inspector Methods
    openAiKeyModal() {
      this.aiModal.apiKey = this.aiConfig.apiKey || '';
      this.aiModal.provider = this.aiConfig.provider || 'gemini';
      this.aiModal.model = this.aiConfig.model || '';
      this.aiModal.show = true;
    },

    saveAiKey() {
      this.aiConfig.apiKey = (this.aiModal.apiKey || '').trim();
      this.aiConfig.provider = this.aiModal.provider || 'gemini';
      this.aiConfig.model = (this.aiModal.model || '').trim();
      try {
        if (this.aiConfig.apiKey) {
          localStorage.setItem('porygon_ai_api_key', this.aiConfig.apiKey);
        } else {
          localStorage.removeItem('porygon_ai_api_key');
        }
        localStorage.setItem('porygon_ai_provider', this.aiConfig.provider);
        localStorage.setItem('porygon_ai_model', this.aiConfig.model);
      } catch (e) { }
      this.aiModal.show = false;
    },

    clearAiKey() {
      this.aiConfig.apiKey = '';
      try {
        localStorage.removeItem('porygon_ai_api_key');
      } catch (e) { }
      this.aiModal.apiKey = '';
      this.aiModal.show = false;
    },

    async auditContainerWithAi(container) {
      if (!this.aiConfig.apiKey) {
        this.openAiKeyModal();
        return;
      }
      this.aiAuditModal.container = container;
      this.aiAuditModal.loading = true;
      this.aiAuditModal.error = null;
      this.aiAuditModal.result = null;
      this.aiAuditModal.show = true;

      try {
        const resp = await this._apiFetch('/api/v1/ai/audit', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Porygon-AI-Key': this.aiConfig.apiKey,
            'X-Porygon-AI-Provider': this.aiConfig.provider,
          },
          body: JSON.stringify({
            container_id: container.container_id || container.id,
            provider: this.aiConfig.provider,
            api_key: this.aiConfig.apiKey,
            model: this.aiConfig.model || null,
            event_limit: 40,
          }),
        });

        const data = await resp.json();
        if (!resp.ok) {
          const detail = data.detail;
          this.aiAuditModal.error = typeof detail === 'string' ? detail : (Array.isArray(detail) ? detail.map(d => d.msg || d).join(', ') : 'AI audit request failed');
        } else {
          this.aiAuditModal.result = data;
        }
      } catch (err) {
        this.aiAuditModal.error = err.message || 'Network error communicating with AI audit API';
      } finally {
        this.aiAuditModal.loading = false;
      }
    },

    async classifyContainerWithML(container) {
      this.mlClassifyModal.container = container;
      this.mlClassifyModal.loading = true;
      this.mlClassifyModal.error = null;
      this.mlClassifyModal.result = null;
      this.mlClassifyModal.show = true;

      try {
        const cid = container.container_id || container.id;
        const resp = await this._apiFetch(`/api/v1/ml/classify-container/${encodeURIComponent(cid)}`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
        });

        const text = await resp.text();
        let data;
        try {
          data = JSON.parse(text);
        } catch (_) {
          data = { detail: text || `HTTP ${resp.status} ${resp.statusText}` };
        }

        if (!resp.ok) {
          const detail = data.detail;
          this.mlClassifyModal.error = typeof detail === 'string' ? detail : (Array.isArray(detail) ? detail.map(d => d.msg || d).join(', ') : 'ML classification failed');
        } else {
          this.mlClassifyModal.result = data;
          if (cid) {
            this.mlClassifications = { ...this.mlClassifications, [cid]: data };
          }
        }
      } catch (err) {
        this.mlClassifyModal.error = err.message || 'Network error communicating with ML classification API';
      } finally {
        this.mlClassifyModal.loading = false;
      }
    },

    async classifyFleetForMLView() {
      if (!this.containers || this.containers.length === 0) return;
      this.mlLoadingBatch = true;
      try {
        const promises = this.containers.map(async (c) => {
          const cid = c.container_id || c.id;
          if (!cid) return;
          try {
            const resp = await this._apiFetch(`/api/v1/ml/classify-container/${encodeURIComponent(cid)}`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
            });
            if (resp.ok) {
              const data = await resp.json();
              this.mlClassifications = { ...this.mlClassifications, [cid]: data };
            }
          } catch (e) {
            console.warn(`Failed ML classification for ${cid}:`, e);
          }
        });
        await Promise.all(promises);
      } finally {
        this.mlLoadingBatch = false;
      }
    },

    inspectMLFromTable(container) {
      const cid = container.container_id || container.id;
      if (this.mlClassifications[cid]) {
        this.mlClassifyModal.container = container;
        this.mlClassifyModal.result = this.mlClassifications[cid];
        this.mlClassifyModal.error = null;
        this.mlClassifyModal.loading = false;
        this.mlClassifyModal.show = true;
      } else {
        this.classifyContainerWithML(container);
      }
    },

    get filteredMLWorkloads() {
      let list = (this.containers || []).map(c => {
        const cid = c.container_id || c.id;
        const ml = this.mlClassifications[cid] || null;
        return {
          container: c,
          ml: ml
        };
      });

      if (this.mlTacticFilter === 'clean' || this.mlTacticFilter === 'benign') {
        list = list.filter(item => item.ml && item.ml.predicted_class === 'benign');
      } else if (this.mlTacticFilter === 'threats') {
        list = list.filter(item => item.ml && item.ml.predicted_class !== 'benign');
      } else if (this.mlTacticFilter && this.mlTacticFilter !== 'all') {
        list = list.filter(item => item.ml && item.ml.predicted_class === this.mlTacticFilter);
      }

      if (this.mlSearchQuery) {
        const q = this.mlSearchQuery.toLowerCase().trim();
        list = list.filter(item =>
          (item.container.container_name && item.container.container_name.toLowerCase().includes(q)) ||
          (item.container.container_id && item.container.container_id.toLowerCase().includes(q)) ||
          (item.ml && item.ml.predicted_class && item.ml.predicted_class.toLowerCase().includes(q))
        );
      }

      return list;
    },

    get mlSummaryStats() {
      const total = (this.containers || []).length;
      const keys = Object.keys(this.mlClassifications);
      const classified = keys.length;
      let benign = 0;
      let threats = 0;
      for (const cid of keys) {
        const res = this.mlClassifications[cid];
        if (res && res.predicted_class === 'benign') {
          benign++;
        } else if (res) {
          threats++;
        }
      }
      return { total, classified, benign, threats };
    },

    // Chart.js instances are NOT kept as an Alpine component property at
    // all (no `charts: {}`, no getter). Even a getter returning the plain
    // chartRegistry object still let Alpine's underlying @vue/reactivity
    // wrap it once accessed as `this.charts.x`, reproducing the exact
    // "Maximum call stack size exceeded" crash traced into Chart.js's
    // render path. Every call site in this file uses the module-level
    // `chartRegistry` constant directly (see top of file) instead of
    // `this.charts`, which never puts a Chart.js instance anywhere near
    // Alpine's reactive proxy.

    async init() {
      console.log('Initializing Porygon Dashboard with Alpine.js — ethreal glass');
      // expose reveal
      if (typeof window.initReveal === 'function') window.initReveal();
      await this.fetchRules();
      await this.fetchCustomRules();
      await this.refreshAllData();
      await this.fetchKernelEvents();
      this.initCharts();
      // after DOM for charts, init reveal again for bento
      if (typeof window.initReveal === 'function') window.initReveal();

      if (typeof window !== 'undefined' && window.location && window.location.search) {
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.get('assistant') === '1') {
          setTimeout(async () => {
            await this.startGuidedRuleAuthoring();
            await this.fillAndTriageObjective('Detect successful writes under /etc/ by a process');
            await this.proposeRuleDraft();
          }, 800);
        }
      }

      // Watch activeTab to resize charts and trigger pipeline auto-selection
      if (typeof this.$watch === 'function') {
        this.$watch('activeTab', (newTab) => {
          if (typeof window !== 'undefined' && window.location) {
            try { window.location.hash = newTab; } catch (e) { }
          }
          if (newTab === 'pipeline' && !this.pipelineIncidentId && this.incidents.length > 0) {
            this.openPipelineForIncident(this.incidents[0]);
          }
          if (newTab === 'ml' && Object.keys(this.mlClassifications).length === 0) {
            this.classifyFleetForMLView();
          }
          const triggerResize = () => {
            if (newTab === 'overview') {
              if (!chartRegistry.timeline || chartRegistry.timeline.width === 0) {
                this.initCharts();
              } else {
                this.updateTimelineChart();
              }
            }
            Object.values(chartRegistry).forEach(c => {
              if (c) {
                if (typeof c.resize === 'function') c.resize();
                if (typeof c.update === 'function') c.update();
              }
            });
            if (typeof window.initReveal === 'function') window.initReveal();
          };
          if (typeof this.$nextTick === 'function') {
            this.$nextTick(triggerResize);
          } else {
            setTimeout(triggerResize, 50);
          }
        });
      }

      // Auto-refresh interval every 3 seconds (lightweight polling without heavy summaries)
      setInterval(() => {
        this.pollLiveTelemetry();
        if (this.activeTab === 'telemetry') this.fetchKernelEvents();
      }, 3000);
      // heavier refresh for system info every 10s
      setInterval(() => { this.fetchSystemInfo(); this.fetchAnomalyScores(); this.fetchAssessmentStatus(); }, 10000);
    },

    // helpers
    _authPrompt: null,
    _authPromptShown: false,
    async _apiFetch(path, opts = {}) {
      // Attach the tab credential to same-origin API reads and writes.
      const headers = Object.assign({}, opts.headers || {});
      const token = this.operatorToken;
      if (token && path.startsWith('/')) {
        headers['X-Porygon-Operator-Token'] = token;
      }
      // for demo route via dashboard server, keep same host
      let response = await fetch(path, Object.assign({}, opts, { headers }));
      if ((response.status === 401 || (response.status === 422 && !token)) && !token && !this._authPromptShown) {
        this._authPromptShown = true;
        this._authPrompt = this.requestOperatorToken('Enter your enrolled human access token to load this deployment.', 'Access token required');
      }
      if ((response.status === 401 || (response.status === 422 && !token)) && !token && this._authPrompt) {
        const entered = await this._authPrompt;
        if (entered) this.operatorToken = entered;
        if (this.operatorToken) {
          headers['X-Porygon-Operator-Token'] = this.operatorToken;
          response = await fetch(path, Object.assign({}, opts, { headers }));
        }
        this._authPrompt = null;
      }
      return response;
    },

    formatCompactNumber(num) {
      if (num == null) return '0';
      const n = Number(num);
      if (isNaN(n) || n === 0) return '0';
      if (n >= 1000000) return (n / 1000000).toFixed(1).replace(/\.0$/, '') + 'M';
      if (n >= 1000) return (n / 1000).toFixed(1).replace(/\.0$/, '') + 'k';
      return n.toLocaleString();
    },

    async fetchProcessSummary() {
      try {
        const res = await this._apiFetch('/api/v1/process-events/summary');
        if (res.ok) {
          this.processSummary = await res.json();
        }
      } catch (e) {
        console.warn('process-events/summary failed', e);
      }
    },

    showToast(message, type = 'info') {
      if (this.toasts.some(toast => toast.message === message && toast.type === type)) return;
      const id = Date.now() + Math.random();
      this.toasts = [...this.toasts.slice(-1), { id, message, type }];
      setTimeout(() => {
        this.toasts = this.toasts.filter(t => t.id !== id);
      }, 4500);
    },

    logTerminal(tag, msg, type = 'info') {
      const time = new Date().toLocaleTimeString();
      let message = 'Signal dispatched';
      if (typeof msg === 'string' && msg.trim()) {
        message = msg.trim();
      } else if (msg && typeof msg === 'object') {
        message = msg.message || msg.msg || msg.error || JSON.stringify(msg);
      } else if (msg !== undefined && msg !== null) {
        message = String(msg);
      }
      this.terminalLogs.unshift({ time, tag: tag || 'INFO', msg: message, message, type, level: type });
      if (this.terminalLogs.length > 120) this.terminalLogs.pop();
    },

    formatRuleId(ruleId) {
      if (!ruleId) return 'RULE 01';
      const m = String(ruleId).match(/POR-DET-0*([0-9]+)/i);
      if (m) {
        return `RULE ${m[1].padStart(2, '0')}`;
      }
      return String(ruleId);
    },

    formatAuthorizeAction(action) {
      if (!action) return 'AUTHORIZE: PAUSE';
      const clean = String(action)
        .replace(/_container$/i, '')
        .replace(/_only$/i, '')
        .toUpperCase();
      return `AUTHORIZE: ${clean}`;
    },

    // ---- Backend wiring ----

    async fetchRules() {
      try {
        const res = await this._apiFetch('/api/v1/detection-rules/config');
        if (res.ok) {
          const data = await res.json();
          this.rules = data.rules || [];
          // Index rules by rule_id for O(1) property lookup
          this.rulesMeta = Object.fromEntries((data.rules || []).map(r => [r.rule_id, r]));
          this.rulesConfig = data;
        } else {
          console.warn('detection-rules/config non-200', res.status);
        }
      } catch (err) {
        console.warn('Could not load detection rules config:', err);
      }
      try {
        const cfg = await this._apiFetch('/api/v1/anomaly-scores/config');
        if (cfg.ok) this.anomalyConfig = await cfg.json();
      } catch (e) { }
    },

    async fetchCustomRules() {
      try {
        const res = await this._apiFetch('/api/v1/rule-workbench/rules');
        if (res.ok) {
          this.customRules = await res.json();
          // Index custom rules into rulesMeta too, so a custom-rule match
          // shown elsewhere (e.g. Pipeline evidence-chain rows) can look up
          // its description alongside the built-in rules.
          for (const r of this.customRules) {
            const ruleId = r.rule_id || `POR-CUS-${r.slug}`;
            this.rulesMeta[ruleId] = { ...r, rule_id: ruleId };
          }
        }
      } catch (err) {
        console.warn('Could not load custom detection rules:', err);
      }
    },

    openAddRuleModal(rule = null) {
      ruleWorkbenchReturnFocus = typeof document !== 'undefined' ? document.activeElement : null;
      this.ruleWorkbench = {
        selectedRule: rule,
        mode: 'manual',
        eventIds: '',
        fixtures: '',
        reference: '',
        rollbackRevisionHash: '',
        revisions: [],
        result: null,
        message: '',
        busy: false,
      };
      this.newRuleDraft = {
        slug: rule?.slug || '',
        name: rule?.name || '',
        description: rule?.description || '',
        category: rule?.category || 'custom',
        target: rule?.target || 'process',
        severity_weight: rule?.severity_weight ?? 0.6,
        confidence_weight: rule?.confidence_weight ?? 0.8,
        incident_eligible: rule?.incident_eligible ?? true,
        mode: 'expression',
        expression: rule?.expression || '',
        conditions: [{ field: 'executable', op: 'equals', value: '', scope: 'event' }],
      };
      this.ruleFormError = '';
      this.ruleAssistant = { objective: '', recipes: [], loadingRecipes: false, busy: false, recipeId: '', parameters: {}, recommendations: [], triage: null, suggestedParameters: null, proposal: null, proposalExpression: '', ready: false, message: '', requestId: 0 };
      this.showAddRuleModal = true;
      this.$nextTick(() => {
        const target = this.ruleWorkbench.mode === 'guided'
          ? document.getElementById('rule-assistant-objective')
          : (rule?.custom_rule_id ? document.getElementById('rule-workbench-expression') : document.getElementById('rule-workbench-slug'));
        target?.focus({ preventScroll: true });
      });
      if (rule) this.fetchRuleRevisions(rule.custom_rule_id);
    },

    closeRuleWorkbench() {
      this.showAddRuleModal = false;
      this.$nextTick(() => {
        if (ruleWorkbenchReturnFocus?.isConnected && typeof ruleWorkbenchReturnFocus.focus === 'function') {
          ruleWorkbenchReturnFocus.focus({ preventScroll: true });
        }
        ruleWorkbenchReturnFocus = null;
      });
    },

    trapRuleWorkbenchFocus(event) {
      const dialog = event.currentTarget;
      const focusable = [...dialog.querySelectorAll('button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), a[href], [tabindex]:not([tabindex="-1"])')]
        .filter(element => element.getClientRects().length && getComputedStyle(element).visibility !== 'hidden');
      if (!focusable.length) {
        event.preventDefault();
        dialog.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && (document.activeElement === first || !dialog.contains(document.activeElement))) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && (document.activeElement === last || !dialog.contains(document.activeElement))) {
        event.preventDefault();
        first.focus();
      }
    },

    async openRuleAssistant() {
      if (!this.ruleWorkbench.selectedRule) this.ruleWorkbench.mode = 'guided';
      if (!await this._ensureRuleOperator()) return;
      if (this.ruleAssistant.recipes.length || this.ruleAssistant.loadingRecipes) return;
      this.ruleAssistant.loadingRecipes = true;
      this.ruleAssistant.message = '';
      try {
        const response = await this._apiFetch('/api/v1/rule-workbench/assistant');
        if (!response.ok) throw new Error(await this._extractApiError(response));
        const body = await response.json();
        this.ruleAssistant.recipes = Array.isArray(body.recipes) ? body.recipes : [];
        if (!this.ruleAssistant.recipes.length) this.ruleAssistant.message = 'No local playbooks are available. Use the manual editor.';
      } catch (err) {
        this.ruleAssistant.message = `Could not load playbooks: ${err.message}`;
      } finally {
        this.ruleAssistant.loadingRecipes = false;
      }
    },

    startGuidedRuleAuthoring() {
      this.openAddRuleModal();
      this.ruleWorkbench.mode = 'guided';
      return this.openRuleAssistant();
    },

    fillAndTriageObjective(text) {
      this.ruleAssistant.objective = text;
      this.invalidateRuleObjective();
      return this.triageRuleObjective();
    },

    selectedRecipe() {
      return this.ruleAssistant.recipes.find(recipe => recipe.id === this.ruleAssistant.recipeId) || null;
    },

    recipeTitle(id) {
      return this.ruleAssistant.recipes.find(recipe => recipe.id === id)?.title || id;
    },

    recipeDescription(id) {
      return this.ruleAssistant.recipes.find(recipe => recipe.id === id)?.description || '';
    },

    invalidateRuleObjective() {
      this.ruleAssistant.requestId += 1;
      this.ruleAssistant.busy = false;
      this.ruleAssistant.recipeId = '';
      this.ruleAssistant.parameters = {};
      this.ruleAssistant.recommendations = [];
      this.ruleAssistant.triage = null;
      this.ruleAssistant.proposal = null;
      this.ruleAssistant.proposalExpression = '';
      this.ruleAssistant.ready = false;
      this.ruleAssistant.message = '';
    },

    invalidateRuleParameters() {
      this.ruleAssistant.requestId += 1;
      this.ruleAssistant.busy = false;
      this.ruleAssistant.proposal = null;
      this.ruleAssistant.proposalExpression = '';
      this.ruleAssistant.ready = false;
      this.ruleAssistant.message = '';
    },

    invalidateRuleExpression() {
      this.ruleAssistant.requestId += 1;
      this.ruleAssistant.busy = false;
      this.ruleAssistant.ready = false;
      this.ruleAssistant.message = 'Expression changed. Run the checks again before applying.';
    },

    selectRuleRecipe(id) {
      if (this.ruleAssistant.recipeId === id) return;
      this.ruleAssistant.requestId += 1;
      this.ruleAssistant.busy = false;
      this.ruleAssistant.recipeId = id;
      const recipe = this.selectedRecipe();
      this.ruleAssistant.parameters = Object.fromEntries((recipe?.parameters || []).map(param => [param.id, Array.isArray(param.default) ? param.default.join(', ') : String(param.default ?? '')]));
      this.ruleAssistant.proposal = null;
      this.ruleAssistant.proposalExpression = '';
      this.ruleAssistant.ready = false;
      this.ruleAssistant.suggestedParameters = null;
    },

    async triageRuleObjective() {
      if (this.ruleAssistant.busy || !this.ruleAssistant.objective.trim()) return;
      if (!await this._ensureRuleOperator()) return;
      this.ruleAssistant.busy = true;
      const requestId = ++this.ruleAssistant.requestId;
      const objective = this.ruleAssistant.objective.trim();
      this.ruleAssistant.message = '';
      this.ruleAssistant.triage = null;
      this.ruleAssistant.recommendations = [];
      this.ruleAssistant.proposal = null;
      try {
        const response = await this._apiFetch('/operator/v1/rule-workbench/assistant/triage', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ objective }),
        });
        if (!response.ok) throw new Error(await this._extractApiError(response));
        const result = await response.json();
        if (requestId !== this.ruleAssistant.requestId || objective !== this.ruleAssistant.objective.trim()) return;
        this.ruleAssistant.triage = result;
        this.ruleAssistant.recommendations = (result.recommendations || []).map(item => typeof item === 'string' ? { id: item, rationale: '' } : ({ ...item, id: item.id || item.recipe_id }));
        const selectedId = result.selected_recipe_id;
        if (selectedId && this.ruleAssistant.recipes.some(recipe => recipe.id === selectedId)) {
          const alreadySelected = this.ruleAssistant.recipeId === selectedId;
          this.selectRuleRecipe(selectedId);
          if (!alreadySelected) {
            const suggestions = result.suggested_parameters || {};
            for (const param of this.selectedRecipe()?.parameters || []) {
              if (Object.prototype.hasOwnProperty.call(suggestions, param.id)) {
                const value = suggestions[param.id];
                this.ruleAssistant.parameters[param.id] = Array.isArray(value) ? value.join(', ') : String(value);
              }
            }
            this.ruleAssistant.suggestedParameters = Object.keys(suggestions).length ? suggestions : null;
          }
        }
        else if (!this.ruleAssistant.recommendations.length) this.ruleAssistant.message = 'No close playbook match. Refine the objective or continue in the manual editor.';
      } catch (err) {
        if (requestId !== this.ruleAssistant.requestId) return;
        this.ruleAssistant.message = `Objective routing failed: ${err.message}`;
      } finally {
        if (requestId === this.ruleAssistant.requestId) this.ruleAssistant.busy = false;
      }
    },

    async proposeRuleDraft() {
      if (this.ruleAssistant.busy || !this.ruleAssistant.recipeId) return;
      if (!await this._ensureRuleOperator()) return;
      const recipe = this.selectedRecipe();
      const parameters = {};
      try {
        for (const param of recipe?.parameters || []) {
          const raw = String(this.ruleAssistant.parameters[param.id] ?? '').trim();
          if (param.type === 'integer_list' || param.type === 'string_list') {
            const items = raw.split(',').map(value => value.trim()).filter(Boolean);
            parameters[param.id] = param.type === 'integer_list' ? items.map(value => {
              if (!/^\d+$/.test(value)) throw new Error(`${param.label} must contain comma-separated integers.`);
              return Number(value);
            }) : items;
          } else parameters[param.id] = raw;
        }
      } catch (err) {
        this.ruleAssistant.message = err.message;
        return;
      }
      this.ruleAssistant.busy = true;
      const requestId = ++this.ruleAssistant.requestId;
      const recipeId = this.ruleAssistant.recipeId;
      const objective = this.ruleAssistant.objective.trim();
      const proposalExpression = this.ruleAssistant.proposalExpression.trim();
      this.ruleAssistant.message = '';
      this.ruleAssistant.proposal = null;
      this.ruleAssistant.ready = false;
      try {
        const response = await this._apiFetch('/operator/v1/rule-workbench/assistant/propose', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ recipe_id: recipeId, parameters, ...(proposalExpression ? { expression: proposalExpression } : {}) }),
        });
        if (!response.ok) throw new Error(await this._extractApiError(response));
        const proposal = await response.json();
        if (requestId !== this.ruleAssistant.requestId || recipeId !== this.ruleAssistant.recipeId || objective !== this.ruleAssistant.objective.trim()) return;
        this.ruleAssistant.proposal = proposal;
        this.ruleAssistant.proposalExpression = proposal.rule?.expression || '';
        this.ruleAssistant.ready = Array.isArray(proposal.checks) && proposal.checks.length > 0 && proposal.checks.every(check => check.passed);
        if (!proposal.checks?.length) this.ruleAssistant.message = 'Proposal returned without checks. It cannot be applied until checks are available.';
      } catch (err) {
        if (requestId !== this.ruleAssistant.requestId) return;
        this.ruleAssistant.message = `Proposal could not be generated: ${err.message}`;
      } finally {
        if (requestId === this.ruleAssistant.requestId) this.ruleAssistant.busy = false;
      }
    },

    applyRuleProposal() {
      const proposal = this.ruleAssistant.proposal;
      if (!proposal || !this.ruleAssistant.ready) return;
      const rule = proposal.rule || {};
      this.newRuleDraft = {
        slug: rule.slug || '', name: rule.name || '', description: rule.description || '',
        category: rule.category || 'custom', target: rule.target || 'process',
        severity_weight: rule.severity_weight ?? 0.25, confidence_weight: rule.confidence_weight ?? 0.25,
        incident_eligible: rule.incident_eligible ?? false, mode: 'expression',
        expression: rule.expression || '', conditions: [{ field: 'executable', op: 'equals', value: '', scope: 'event' }],
      };
      this.ruleWorkbench.fixtures = JSON.stringify(proposal.fixtures || [], null, 2);
      this.ruleWorkbench.eventIds = '';
      this.ruleWorkbench.mode = 'manual';
      this.ruleWorkbench.message = 'Proposal copied into the editor. Review it, then save explicitly as a draft.';
    },

    openRuleWorkbench(rule) {
      this.openAddRuleModal(rule);
    },

    async _ensureRuleOperator() {
      if (this.operatorToken) return true;
      const token = await this.requestOperatorToken('Rule authoring and lifecycle actions require operator authorization.', 'Authorize rule workbench');
      if (!token) return false;
      this.operatorToken = token;
      return true;
    },

    _ruleWorkbenchPayload() {
      const draft = this.newRuleDraft;
      return {
        slug: String(draft.slug || '').trim(),
        name: String(draft.name || '').trim(),
        description: String(draft.description || '').trim(),
        category: String(draft.category || '').trim(),
        target: draft.target,
        expression: String(draft.expression || '').trim(),
        severity_weight: Number(draft.severity_weight),
        confidence_weight: Number(draft.confidence_weight),
        incident_eligible: !!draft.incident_eligible,
      };
    },

    async _ruleWorkbenchRequest(path, method = 'POST', body = null) {
      const response = await this._apiFetch(path, {
        method,
        headers: body ? { 'Content-Type': 'application/json' } : {},
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
      if (!response.ok) throw new Error(await this._extractApiError(response));
      return response.status === 204 ? null : response.json();
    },

    async fetchRuleRevisions(ruleId) {
      try {
        const revisions = await this._ruleWorkbenchRequest(`/api/v1/rule-workbench/rules/${ruleId}/revisions`, 'GET');
        this.ruleWorkbench.revisions = revisions;
      } catch (err) {
        this.ruleWorkbench.message = `Could not load revision history: ${err.message}`;
      }
    },

    // Field vocabulary shown as a reference alongside the expression editor. It
    // mirrors _PROCESS_FIELDS/_RUNTIME_FIELDS in backend detection.py; the backend
    // validator remains the authority and rejects anything outside it.
    get expressionFields() {
      if (this.newRuleDraft.target === 'process') {
        return ['executable', 'executable_path', 'process_name', 'parent_executable', 'parent_name', 'command_line', 'user_uid', 'container_id', 'exe_from_memfd', 'exe_writable'];
      }
      if (this.newRuleDraft.target === 'runtime') return ['action', 'privileged', 'image_digest', 'container_id'];
      return ['runtime_action', 'event_type', 'return_value', 'exe_from_memfd', 'exe_writable', 'file_path', 'remote_address', 'remote_port', 'process_name', 'executable', 'executable_path', 'user_uid', 'process_pid', 'process_start_ns', 'pid_namespace_start_ns', 'sensor_epoch', 'docker_host_id', 'container_id'];
    },

    addRuleCondition() {
      this.newRuleDraft.conditions.push({ field: 'executable', op: 'equals', value: '', scope: 'event' });
    },

    removeRuleCondition(index) {
      this.newRuleDraft.conditions.splice(index, 1);
    },

    async validateRuleDraft() {
      if (this.ruleWorkbench.busy) return;
      this.ruleWorkbench.busy = true;
      try {
        if (!await this._ensureRuleOperator()) return;
        const result = await this._ruleWorkbenchRequest('/operator/v1/rule-workbench/validate', 'POST', this._ruleWorkbenchPayload());
        this.ruleWorkbench.message = `Valid · ${result.document_hash}`;
      } catch (err) {
        this.ruleWorkbench.message = err.message;
      } finally {
        this.ruleWorkbench.busy = false;
      }
    },

    async saveRuleDraft() {
      if (this.ruleWorkbench.busy) return;
      const rule = this.ruleWorkbench.selectedRule;
      const payload = this._ruleWorkbenchPayload();
      if (!payload.expression) {
        this.ruleWorkbench.message = 'Write a condition expression before saving.';
        return;
      }
      this.ruleWorkbench.busy = true;
      try {
        if (!await this._ensureRuleOperator()) return;
        const path = rule
          ? `/operator/v1/rule-workbench/rules/${rule.custom_rule_id}/revisions`
          : '/operator/v1/rule-workbench/rules';
        const body = rule ? { ...payload, reference: this.ruleWorkbench.reference.trim(),
          expected_revision_hash: rule.revision_hash } : payload;
        if (rule && !body.reference) throw new Error('Enter an operator reference before saving a revision.');
        const saved = await this._ruleWorkbenchRequest(path, 'POST', body);
        this.ruleWorkbench.selectedRule = saved;
        this.ruleWorkbench.message = `Draft saved · ${saved.revision_hash}`;
        this.showToast('Draft saved; it is not active', 'success');
        await Promise.all([this.fetchCustomRules(), this.fetchRuleRevisions(saved.custom_rule_id)]);
      } catch (err) {
        this.ruleWorkbench.message = err.message;
      } finally {
        this.ruleWorkbench.busy = false;
      }
    },

    async runRuleWorkbench(action) {
      if (this.ruleWorkbench.busy) return;
      const rule = this.ruleWorkbench.selectedRule;
      if (!rule) {
        this.ruleWorkbench.message = 'Save the draft before preview, shadow review, activation, or rollback.';
        return;
      }
      this.ruleWorkbench.busy = true;
      this.ruleWorkbench.message = '';
      try {
        if (!await this._ensureRuleOperator()) return;
        let path = `/operator/v1/rule-workbench/rules/${rule.custom_rule_id}/${action}`;
        let body;
        if (action === 'preview' || action === 'shadow') {
          const eventIds = this.ruleWorkbench.eventIds.split(/[\s,]+/).map(id => id.trim()).filter(Boolean);
          const fixtures = String(this.ruleWorkbench.fixtures || '').trim()
            ? JSON.parse(this.ruleWorkbench.fixtures) : [];
          if (eventIds.length && fixtures.length) throw new Error('Use event IDs or labeled fixtures, not both.');
          body = { event_ids: eventIds, fixtures, expected_revision_hash: rule.revision_hash };
          if (!rule.revision_hash) throw new Error('Refresh the rule to load its current immutable revision before preview.');
        } else {
          const reference = String(this.ruleWorkbench.reference || '').trim();
          if (!reference) throw new Error('Enter an operator reference for this lifecycle action.');
          body = { reference, expected_revision_hash: rule.revision_hash || undefined };
          if (action === 'disable' && rule.revision_hash) body.expected_revision_hash = rule.revision_hash;
          if (action === 'activate' || action === 'rollback') {
            if (!rule.revision_hash) throw new Error('Refresh the rule to load its current immutable revision before this action.');
          }
          if (action === 'rollback') {
            if (!this.ruleWorkbench.rollbackRevisionHash) throw new Error('Select an immutable revision to stage.');
            body.revision_hash = this.ruleWorkbench.rollbackRevisionHash;
          }
        }
        const result = await this._ruleWorkbenchRequest(path, 'POST', body);
        if (action === 'preview' || action === 'shadow') {
          this.ruleWorkbench.result = result;
          if (action === 'shadow') {
            this.ruleWorkbench.selectedRule.candidate_state = 'shadow';
            await this.fetchCustomRules();
          }
        }
        else {
          this.ruleWorkbench.selectedRule = result;
          this.ruleWorkbench.result = null;
          await Promise.all([this.fetchCustomRules(), this.fetchRuleRevisions(rule.custom_rule_id)]);
        }
        this.ruleWorkbench.message = action === 'activate'
          ? 'Revision activated after receipt and operator-reference checks.'
          : action === 'rollback' ? 'Rollback staged as a shadow revision; preview and shadow it before activation.'
            : `${action === 'shadow' ? 'Shadow' : 'Preview'} receipt ${result.receipt_hash}`;
      } catch (err) {
        this.ruleWorkbench.message = err.message;
      } finally {
        this.ruleWorkbench.busy = false;
      }
    },

    // FastAPI validation failures arrive as a list of {loc, msg, ...}; the useful part
    // for an operator writing an expression is the parser's own message, not the envelope.
    async _extractApiError(res) {
      const body = await res.json().catch(() => null);
      const detail = body && body.detail;
      if (typeof detail === 'string') return detail;
      if (Array.isArray(detail)) {
        const messages = detail
          .map(item => (item && typeof item.msg === 'string' ? item.msg.replace(/^Value error, /, '') : null))
          .filter(Boolean);
        if (messages.length) return messages.join('; ');
      }
      return `HTTP ${res.status}`;
    },

    async disableCustomRule(rule) {
      const confirmed = await this.requestConfirm(`Disable custom rule '${rule.name}'?`, 'Disable custom rule', 'Disable');
      if (!confirmed) return;
      if (!this.operatorToken) {
        const t = await this.requestOperatorToken(`Disabling '${rule.name}' requires operator authorization.`, 'Authorize disable');
        if (!t) return;
        this.operatorToken = t;
      }
      try {
        const res = await this._apiFetch(`/operator/v1/custom-detection-rules/${rule.custom_rule_id}/disable`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ actor: 'dashboard-operator' }),
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        await this.fetchCustomRules();
      } catch (err) {
        this.showToast(`Failed to disable rule: ${err.message}`, 'error');
      }
    },

    async fetchSystemInfo() {
      try {
        const res = await this._apiFetch('/api/v1/system/info');
        if (res.ok) {
          this.systemInfo = await res.json();
          // sync counters that were previously hardcoded
          // keep in terminal
        }
      } catch (e) { console.warn('system/info failed', e); }
    },

    async fetchServices() {
      try {
        const res = await this._apiFetch('/api/v1/services');
        if (res.ok) {
          this.services = await res.json();
          this.feedUnavailable.health = false;
        } else throw new Error('non-200');
      } catch (err) {
        // An unavailable health endpoint must not look like a healthy fleet.
        this.services = [];
        this.feedUnavailable.health = true;
      }
    },

    async fetchContainers() {
      try {
        const res = await this._apiFetch('/api/v1/containers?limit=100');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        this.containers = Array.isArray(data) ? data : (data.items || []);
        this.feedUnavailable.inventory = false;
      } catch (err) {
        // An unavailable containers endpoint must not look like an empty,
        // fully-monitored fleet — clear stale data and signal the gap.
        console.warn('Could not fetch containers:', err);
        this.containers = [];
        this.feedUnavailable.inventory = true;
      }
    },

    async fetchKernelEvents() {
      const requestId = ++this.kernelRequestId;
      this.kernelLoading = true;
      this.kernelError = '';
      const query = new URLSearchParams({ limit: '100' });
      if (this.kernelActionFilter) query.set('runtime_action', this.kernelActionFilter);
      if (this.kernelHostFilter.trim()) query.set('docker_host_id', this.kernelHostFilter.trim());
      if (this.selectedContainer) query.set('container_id', this.selectedContainer);
      try {
        const response = await this._apiFetch(`/api/v1/kernel-events?${query}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const events = await response.json();
        if (!Array.isArray(events)) throw new Error('Invalid kernel event response');
        if (requestId === this.kernelRequestId) this.kernelEvents = events;
      } catch (error) {
        if (requestId === this.kernelRequestId) {
          this.kernelEvents = [];
          this.kernelError = 'Kernel activity is unavailable. Refresh to retry.';
        }
      } finally {
        if (requestId === this.kernelRequestId) this.kernelLoading = false;
      }
    },

    kernelActionLabel(event) {
      return ({ net_outbound: 'Outbound connection', memfd_create: 'Memory-backed file',
        file_write_open: 'Writable file open', file_write: 'File write' })[event.runtime_action] || event.runtime_action;
    },

    kernelTarget(event) {
      if (event.remote_address) {
        const address = event.remote_address.includes(':') ? `[${event.remote_address}]` : event.remote_address;
        return `${address}:${event.remote_port}`;
      }
      return event.file_path || event.memory_name || '—';
    },

    kernelOutcome(event) {
      if (event.runtime_action === 'net_outbound') return event.return_value < 0 ? 'In progress' : 'Connected';
      if (event.runtime_action === 'file_write') return `${event.return_value} bytes`;
      return `fd ${event.return_value}`;
    },

    async fetchEvents() {
      this.isLoadingEvents = true;
      try {
        let endpoint = '/api/v1/process-events?limit=100';
        let fallbackEndpoint = '/api/v1/events?limit=100';

        if (this.selectedContainerName) {
          endpoint += `&container_name=${encodeURIComponent(this.selectedContainerName)}`;
          fallbackEndpoint += `&container_name=${encodeURIComponent(this.selectedContainerName)}`;
        } else if (this.selectedContainer) {
          endpoint += `&container_id=${encodeURIComponent(this.selectedContainer)}`;
          fallbackEndpoint += `&container_id=${encodeURIComponent(this.selectedContainer)}`;
        }

        const res = await this._apiFetch(endpoint);
        if (res.ok) {
          const data = await res.json();
          // If container_name query returned empty (e.g. name mismatch), fallback to container_id prefix if available
          if (Array.isArray(data) && data.length === 0 && this.selectedContainer && this.selectedContainerName) {
            const resById = await this._apiFetch(`/api/v1/process-events?limit=100&container_id=${encodeURIComponent(this.selectedContainer.substring(0, 12))}`);
            if (resById.ok) {
              const dataById = await resById.json();
              if (Array.isArray(dataById) && dataById.length > 0) {
                this.events = dataById;
                this.feedUnavailable.telemetry = false;
                return;
              }
            }
          }
          this.events = data;
          this.feedUnavailable.telemetry = false;
          return;
        }

        const r2 = await this._apiFetch(fallbackEndpoint);
        if (r2.ok) {
          this.events = await r2.json();
          this.feedUnavailable.telemetry = false;
          return;
        }
        throw new Error(`process-events HTTP ${res.status}, events fallback HTTP ${r2.status}`);
      } catch (err) {
        console.warn('Could not fetch process-events:', err);
        this.events = [];
        this.feedUnavailable.telemetry = true;
      } finally {
        this.isLoadingEvents = false;
      }
    },

    async fetchAnomalyScores() {
      try {
        const res = await this._apiFetch('/api/v1/anomaly-scores?limit=20');
        if (res.ok) {
          const list = await res.json();
          if (Array.isArray(list) && list.length) {
            this.scores = list;
            // The most recent window (list[0]) may not have enough telemetry to
            // be scored yet — surface that explicitly rather than silently
            // falling back to an older scored window and mislabeling it CURRENT.
            this.latestWindowInsufficientData = list[0]?.status === 'insufficient_data';
            // use most recent scored window
            const latest = list.find(s => s.status === 'scored') || list[0];
            if (latest && latest.total_score != null) {
              this.currentAnomalyScore = latest.total_score;
              this.currentScoreBand = latest.score_band || this._bandForScore(latest.total_score);
              // Real timestamp of the window backing the score above, so a
              // "CURRENT" label can show it and make a stale window visibly stale.
              this.currentScoreWindowStart = latest.window_start || null;
              // extract unseen tokens / contributors from explanation if present.
              // Real bug found live: GET /api/v1/anomaly-scores/{id}'s
              // explanation.unseen_tokens is an array of objects
              // ({feature, token, proportion} — verified against the live
              // backend), but this.unseenTokens is rendered with
              // `x-for="tok in unseenTokens" :key="tok"` and used as
              // `'unseen: ' + tok`, both of which expect plain strings.
              // Assigning the raw objects here made Alpine use a whole
              // object as an x-for key (console warning, once per real
              // score fetched) and made every token render as
              // "unseen: [object Object]" instead of the real value.
              // Extracting .token fixes both.
              const exp = latest.explanation || {};
              const families = (latest.components && latest.components.categorical_distance && latest.components.categorical_distance.families) || {};
              const asTokenStrings = (arr) => arr.map(t => (t && typeof t === 'object') ? (t.token ?? JSON.stringify(t)) : t);
              // fallback: explanation.novel_executables etc.
              if (exp.unseen_tokens) this.unseenTokens = [...new Set(asTokenStrings(exp.unseen_tokens))].slice(0, 12);
              else if (exp.novel_tokens) this.unseenTokens = [...new Set(asTokenStrings(exp.novel_tokens))].slice(0, 12);
              else {
                // synthesize from categorical families top_observed where baseline_support small
                const toks = [];
                Object.values(families).forEach(f => {
                  if (f.distance > 0.5 && f.top_observed) {
                    f.top_observed.slice(0, 2).forEach(t => toks.push(t.token));
                  }
                });
                if (toks.length) this.unseenTokens = [...new Set(toks)].slice(0, 10);
              }
              this.scoreContributors = latest.components ? Object.entries(latest.components).map(([k, v]) => ({ token: k, weight: v.score || 0 })) : [];
              this.activeProfile = { profile_id: latest.profile_id, version: latest.profile_version };
              this.updateTimelineChart();
              this.updateScoreFromLatest();
            }
          }
        }
      } catch (err) {
        console.warn('Could not fetch anomaly-scores:', err);
      }
    },

    _bandForScore(s) {
      if (s >= 0.75) return 'extreme';
      if (s >= 0.50) return 'high';
      if (s >= 0.25) return 'elevated';
      return 'baseline_like';
    },

    updateScoreFromLatest() {
      if (this.currentAnomalyScore != null) {
        this.currentScoreBand = this._bandForScore(this.currentAnomalyScore);
      }
    },

    async fetchIncidents() {
      try {
        const res = await this._apiFetch('/api/v1/incidents?limit=50');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const fetched = await res.json();
        const getTime = (x) => {
          const d = new Date(x.created_at || x.first_seen_at || x.occurred_at || 0);
          return isNaN(d.getTime()) ? 0 : d.getTime();
        };
        this.incidents = fetched.sort((a, b) => getTime(b) - getTime(a));
        this.feedUnavailable.incidents = false;
        if (this.incidents.length > 0 && !this.selectedIncident) {
          this.selectedIncident = this.incidents[0];
        }
      } catch (err) {
        // An unavailable incidents endpoint must not read as "all clear" —
        // clear stale data and signal the gap instead of leaving whatever
        // was last fetched on screen with no indicator.
        console.warn('Could not fetch incidents:', err);
        this.incidents = [];
        this.feedUnavailable.incidents = true;
      }
    },

    async fetchScans() {
      try {
        const res = await this._apiFetch('/api/v1/image-scans?limit=20');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const scans = await res.json();
        this.feedUnavailable.vulnerabilities = false;
        if (Array.isArray(scans) && scans.length > 0) {
          const completedScans = scans.filter(s => s.status === 'completed');
          // Real bug found live: this used to cap detail fetches at the first
          // 3 prioritized scans (`.slice(0, 3)`) while the reachability funnel
          // and its counts implied full coverage of all completed scans.
          // Fetching detail for every completed scan (bounded by the
          // image-scans limit=20 above) keeps the funnel counts honest.
          const targets = completedScans;

          const allFindings = [];
          for (const scan of targets) {
            try {
              const detailRes = await this._apiFetch(`/api/v1/image-scans/${scan.scan_id}`);
              if (detailRes.ok) {
                const detail = await detailRes.json();
                if (Array.isArray(detail.vulnerabilities)) {
                  allFindings.push(...detail.vulnerabilities);
                }
              }
            } catch (e) { }
          }

          // Deduplicate findings by finding_id or cve_id + package_name
          const seen = new Set();
          this.vulnerabilityFindings = allFindings.filter(f => {
            const key = f.finding_id || `${f.cve_id}-${f.package_name}`;
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
          });
          this.calculateEvidenceCounts();
        } else {
          this.vulnerabilityFindings = [];
          this.calculateEvidenceCounts();
        }
      } catch (err) {
        // An unavailable scan endpoint must not leave a stale reachability
        // funnel on screen with no indicator that it's out of date.
        console.warn('Could not fetch scans:', err);
        this.vulnerabilityFindings = [];
        this.calculateEvidenceCounts();
        this.feedUnavailable.vulnerabilities = true;
      }
    },

    calculateEvidenceCounts() {
      const counts = {
        package_present: 0,
        deployed: 0,
        runtime_observed: 0,
        runtime_observed_and_port_published: 0
      };
      this.vulnerabilityFindings.forEach(f => {
        // Every finding is present on disk inside the scanned package
        counts.package_present++;
        if (['deployed', 'runtime_observed', 'runtime_observed_and_port_published'].includes(f.evidence_stage)) {
          counts.deployed++;
        }
        if (['runtime_observed', 'runtime_observed_and_port_published'].includes(f.evidence_stage)) {
          counts.runtime_observed++;
        }
        if (f.evidence_stage === 'runtime_observed_and_port_published') {
          counts.runtime_observed_and_port_published++;
        }
      });
      this.evidenceCounts = counts;
      this.updateEvidenceLadderChart();
    },

    matchesReachabilityFilter(v, filter) {
      if (!filter || filter === 'all') return true;
      if (filter === 'package_present') return true;
      if (filter === 'deployed') {
        return ['deployed', 'runtime_observed', 'runtime_observed_and_port_published'].includes(v.evidence_stage);
      }
      if (filter === 'runtime_observed') {
        return ['runtime_observed', 'runtime_observed_and_port_published'].includes(v.evidence_stage);
      }
      if (filter === 'runtime_observed_and_port_published') {
        return v.evidence_stage === 'runtime_observed_and_port_published';
      }
      return v.evidence_stage === filter;
    },

    get filteredVulnerabilities() {
      return this.vulnerabilityFindings.filter(v => this.matchesReachabilityFilter(v, this.reachabilityFilter));
    },

    async fetchAssessmentStatus() {
      try {
        const response = await this._apiFetch('/api/v1/assessment-worker/status');
        this.assessmentStatus = response.ok ? await response.json() : null;
      } catch (_) { this.assessmentStatus = null; }
    },

    async refreshAllData() {
      await this.fetchSystemInfo();
      await Promise.all([
        this.fetchAssessmentStatus(),
        this.fetchServices(),
        this.fetchContainers(),
        this.fetchEvents(),
        this.fetchProcessSummary(),
        this.fetchIncidents(),
        this.fetchScans(),
        this.fetchAnomalyScores()
      ]);
    },

    async pollLiveTelemetry() {
      await Promise.all([
        this.fetchContainers(),
        this.fetchEvents(),
        this.fetchIncidents(),
        this.fetchAnomalyScores()
      ]);
      this.updateTimelineChart();
    },

    // Chart Initializations: Newsprint styling
    initCharts() {
      Chart.defaults.font.family = 'JetBrains Mono';
      Chart.defaults.color = '#111111';
      Chart.defaults.borderColor = '#E5E5E0';

      // 1. Behavioural Distance Timeline Chart
      const timelineCtx = document.getElementById('anomalyTimelineChart');
      if (timelineCtx) {
        if (chartRegistry.timeline) {
          try { chartRegistry.timeline.destroy(); } catch (e) { }
          chartRegistry.timeline = null;
        }
        const hasScores = this.scores && this.scores.length > 0;
        const labels = hasScores ? this.scores.slice(0, 7).reverse().map(s => new Date(s.window_start).toLocaleTimeString().slice(0, 5)) : ['W-6', 'W-5', 'W-4', 'W-3', 'W-2', 'W-1', 'Now'];
        const dataPoints = hasScores ? this.scores.slice(0, 7).reverse().map(s => s.total_score ?? 0) : [0, 0, 0, 0, 0, 0, this.currentAnomalyScore];
        // ensure last point reflects current
        if (dataPoints.length) dataPoints[dataPoints.length - 1] = this.currentAnomalyScore;
        chartRegistry.timeline = new Chart(timelineCtx, {
          type: 'line',
          data: {
            labels,
            datasets: [
              {
                label: 'JENSEN-SHANNON D_JS',
                data: dataPoints,
                borderColor: '#111111',
                backgroundColor: 'rgba(17, 17, 17, 0.06)',
                borderWidth: 2,
                // 0, not smoothed: scored windows can have real time gaps between
                // them (a window that couldn't be scored, a restart, a burst of
                // polling misses). A smoothed curve (tension>0) visually implies
                // continuous monitoring across those gaps that didn't happen.
                tension: 0,
                fill: true,
                pointBackgroundColor: '#111111',
                pointBorderColor: '#FFFFFF',
                pointBorderWidth: 1.5,
                pointRadius: 4,
                pointHoverRadius: 6,
                stepped: false
              },
              {
                label: 'ELEVATED DRIFT (0.50)',
                data: Array(labels.length).fill(0.50),
                borderColor: '#D97706',
                borderWidth: 1.5,
                borderDash: [6, 4],
                pointRadius: 0,
                fill: false
              },
              {
                label: 'CRITICAL ANOMALY (0.75)',
                data: Array(labels.length).fill(0.75),
                borderColor: '#CC0000',
                borderWidth: 1.5,
                borderDash: [4, 4],
                pointRadius: 0,
                fill: false
              }
            ]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
              y: {
                min: 0.0,
                max: 1.0,
                grid: { color: '#E5E5E0', lineWidth: 1 },
                ticks: {
                  color: '#111111',
                  font: { family: 'JetBrains Mono', size: 10, weight: 'bold' },
                  stepSize: 0.25,
                  callback: function(v) { return Number(v).toFixed(2); }
                },
                title: {
                  display: true,
                  text: 'D_JS DISTANCE',
                  color: '#525252',
                  font: { family: 'JetBrains Mono', size: 9, weight: 'bold' }
                },
                border: { color: '#111111', width: 1 }
              },
              x: {
                grid: { color: '#E5E5E0', lineWidth: 1 },
                ticks: {
                  color: '#111111',
                  font: { family: 'JetBrains Mono', size: 10, weight: 'bold' }
                },
                title: {
                  display: true,
                  text: 'OBSERVATION WINDOWS (60S)',
                  color: '#525252',
                  font: { family: 'JetBrains Mono', size: 9, weight: 'bold' }
                },
                border: { color: '#111111', width: 1 }
              }
            },
            plugins: {
              legend: {
                display: true,
                position: 'top',
                align: 'center',
                labels: {
                  color: '#111111',
                  font: { family: 'JetBrains Mono', size: 10, weight: 'bold' },
                  boxWidth: 12,
                  boxHeight: 12,
                  padding: 16,
                  usePointStyle: false
                }
              },
              tooltip: {
                backgroundColor: '#111111',
                titleColor: '#FFFFFF',
                bodyColor: '#E5E5E0',
                titleFont: { family: 'JetBrains Mono', weight: 'bold', size: 11 },
                bodyFont: { family: 'JetBrains Mono', size: 11 },
                borderColor: '#111111',
                borderWidth: 1,
                cornerRadius: 0,
                padding: 8,
                displayColors: true
              }
            }
          }
        });
      }

      // 2. Score Composition Doughnut Chart: Newsprint styling
      const compCtx = document.getElementById('anomalyCompositionChart');
      if (compCtx) {
        if (chartRegistry.composition) {
          try { chartRegistry.composition.destroy(); } catch (e) { }
          chartRegistry.composition = null;
        }
        chartRegistry.composition = new Chart(compCtx, {
          type: 'doughnut',
          data: {
            labels: ['CATEGORICAL (50%)', 'NOVELTY (30%)', 'NUMERIC (20%)'],
            datasets: [{
              data: [50, 30, 20],
              backgroundColor: [
                '#111111',
                '#525252',
                '#CC0000'
              ],
              borderColor: '#FFFFFF',
              borderWidth: 2,
              hoverOffset: 4
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '70%',
            plugins: {
              legend: {
                position: 'bottom',
                labels: {
                  color: '#111111',
                  font: { family: 'JetBrains Mono', size: 10, weight: 'bold' },
                  boxWidth: 10,
                  boxHeight: 10,
                  usePointStyle: false,
                  padding: 10
                }
              },
              tooltip: {
                backgroundColor: '#111111',
                titleColor: '#FFFFFF',
                bodyColor: '#E5E5E0',
                titleFont: { family: 'JetBrains Mono', weight: 'bold', size: 11 },
                bodyFont: { family: 'JetBrains Mono', size: 11 },
                borderColor: '#111111',
                borderWidth: 1,
                cornerRadius: 0,
                padding: 8,
                displayColors: true
              }
            }
          }
        });
      }

      // 3. Evidence Ladder Bar Chart: Newsprint styling
      const ladderCtx = document.getElementById('evidenceLadderChart');
      if (ladderCtx) {
        if (chartRegistry.ladder) {
          try { chartRegistry.ladder.destroy(); } catch (e) { }
          chartRegistry.ladder = null;
        }
        chartRegistry.ladder = new Chart(ladderCtx, {
          type: 'bar',
          data: {
            labels: ['[01] PACKAGE_PRESENT', '[02] DEPLOYED', '[03] RUNTIME_OBSERVED', '[04] PORT_PUBLISHED'],
            datasets: [{
              label: 'FINDINGS',
              data: [
                this.evidenceCounts.package_present,
                this.evidenceCounts.deployed,
                this.evidenceCounts.runtime_observed,
                this.evidenceCounts.runtime_observed_and_port_published
              ],
              backgroundColor: [
                '#E5E5E0',
                '#888888',
                '#D97706',
                '#CC0000'
              ],
              borderColor: '#111111',
              borderWidth: 1,
              borderSkipped: false,
              borderRadius: 0
            }]
          },
          options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            scales: {
              x: {
                grid: { color: '#E5E5E0', lineWidth: 1 },
                ticks: { color: '#111111', font: { family: 'JetBrains Mono', size: 10, weight: 'bold' } },
                border: { color: '#111111' }
              },
              y: {
                grid: { display: false },
                ticks: { color: '#111111', font: { family: 'JetBrains Mono', weight: 'bold', size: 10 } },
                border: { color: '#111111' }
              }
            },
            plugins: {
              legend: { display: false },
              tooltip: {
                backgroundColor: '#111111',
                titleColor: '#FFFFFF',
                bodyColor: '#E5E5E0',
                titleFont: { family: 'JetBrains Mono', weight: 'bold', size: 11 },
                bodyFont: { family: 'JetBrains Mono', size: 11 },
                borderColor: '#111111',
                borderWidth: 1,
                cornerRadius: 0,
                padding: 8
              }
            }
          }
        });
      }

      // NOTE: System Call Flow Deviation Radar chart was intentionally removed
      // because behavioral profiles retain the execve/execveat contract
      // (see docs/research/threat-model.md). Separate typed kernel evidence
      // does not provide a complete per-syscall frequency distribution.
    },

    updateTimelineChart() {
      if (!chartRegistry.timeline) return;
      const chart = chartRegistry.timeline;
      // if we have real scores, rebuild labels+data from this.scores
      if (this.scores && this.scores.length) {
        const recent = this.scores.slice(0, 7).reverse();
        chart.data.labels = recent.map(s => new Date(s.window_start).toLocaleTimeString().slice(0, 5));
        chart.data.datasets[0].data = recent.map(s => s.total_score != null ? s.total_score : 0);
        // overlay current if newer
        chart.data.datasets[0].data[chart.data.datasets[0].data.length - 1] = this.currentAnomalyScore;
        const n = chart.data.labels.length;
        chart.data.datasets[1].data = Array(n).fill(0.50);
        chart.data.datasets[2].data = Array(n).fill(0.75);
      } else {
        const idx = chart.data.datasets[0].data.length - 1;
        chart.data.datasets[0].data[idx] = this.currentAnomalyScore;
      }
      chart.update('none');
    },

    updateEvidenceLadderChart() {
      if (!chartRegistry.ladder) return;
      const chart = chartRegistry.ladder;
      chart.data.datasets[0].data = [
        this.evidenceCounts.package_present,
        this.evidenceCounts.deployed,
        this.evidenceCounts.runtime_observed,
        this.evidenceCounts.runtime_observed_and_port_published
      ];
      chart.update();
    },

    // Interactive Attack Scenario Execution — backend-only; never fabricate telemetry.
    async triggerAttackScenario(scenario) {
      this.isExecutingAttack = true;
      const scenarioName = scenario?.name || scenario?.id || 'Canary Scenario';
      const scenarioId = scenario?.id || scenario;
      this.scenarioResults[scenarioId] = { status: 'running', message: 'Spooling real Docker container workload...' };
      this.logTerminal('SIMULATOR', `Triggering scenario: ${scenarioName} (${scenarioId})...`, 'info');
      this.showToast(`Launching ${scenarioName}...`, 'info');

      try {
        const headers = { 'Content-Type': 'application/json' };
        const token = this.operatorToken;
        if (token) {
          headers['X-Porygon-Operator-Token'] = token;
        }

        const res = await this._apiFetch('/api/demo/run-scenario', {
          method: 'POST',
          headers,
          body: JSON.stringify({ scenario_id: scenarioId })
        });
        if (res.ok) {
          const data = await res.json();
          if (data.success) {
            this.scenarioResults[scenarioId] = {
              status: 'success',
              command: data.command || scenarioId,
              output: data.output || 'Process executed successfully with code 0',
              time: new Date().toLocaleTimeString(),
              telemetryIngested: Boolean(data.telemetry_ingested)
            };
            this.logTerminal('EXEC', data.command || scenarioId, 'success');
            if (data.output) this.logTerminal('OUTPUT', String(data.output).slice(0, 400), 'info');
            this.showToast('Canary workload dispatched & ingested into Live Telemetry.', 'success');
          } else {
            this.scenarioResults[scenarioId] = {
              status: 'error',
              error: data.error || 'Execution failed',
              time: new Date().toLocaleTimeString()
            };
            this.logTerminal('ERROR', data.error || 'Execution failed', 'error');
            this.showToast(data.error || 'Attack execution failed', 'danger');
          }
        } else if (res.status === 401) {
          this.scenarioResults[scenarioId] = { status: 'error', error: '401 Unauthorized: Operator Token Required' };
          this.logTerminal('ERROR', '401 Unauthorized: Invalid or missing operator token', 'error');
          this.showToast('Operator authorization token invalid or missing', 'danger');
        } else if (res.status === 403) {
          this.scenarioResults[scenarioId] = { status: 'error', error: '403 Forbidden: Demo Mode Disabled' };
          this.logTerminal('ERROR', '403 Forbidden: Demo mode is not enabled on server', 'error');
          this.showToast('Demo scenario routes are disabled on server', 'danger');
        } else if (res.status === 404) {
          this.scenarioResults[scenarioId] = { status: 'error', error: '404 Simulator Endpoint Not Found' };
          throw new Error('Attack simulator endpoint is unavailable in this deployment');
        } else {
          const txt = await res.text();
          this.scenarioResults[scenarioId] = { status: 'error', error: `HTTP ${res.status}` };
          this.logTerminal('ERROR', `HTTP ${res.status}: ${txt.slice(0, 100)}`, 'error');
          throw new Error(`HTTP ${res.status}`);
        }
      } catch (err) {
        this.scenarioResults[scenarioId] = { status: 'error', error: err.message };
        this.logTerminal('ERROR', err.message, 'error');
        this.showToast(`Attack simulator unavailable: ${err.message}`, 'danger');
      } finally {
        this.isExecutingAttack = false;
        await this.pollLiveTelemetry();
        await this.fetchContainers();
        await this.classifyFleetForMLView();
      }
    },

    // Mirrors backend/src/porygon_api/response.py::allowed_actions_for_incident()
    // and its RESPONSE_POLICY["decision_thresholds"] constants. This is a
    // client-side convenience only — the backend remains the sole authority
    // and will still 422 any action these thresholds don't actually allow.
    // Keeping this in sync with response.py lets the dashboard disable
    // Pause/Stop up front (and explain why) instead of only reacting to a
    // raw backend error after the operator has already clicked.
    incidentAllowedActions(incident) {
      const thresholds = {
        pause_min_severity: 0.70,
        pause_min_confidence: 0.55,
        stop_min_severity: 0.90,
        stop_min_confidence: 0.75,
      };
      const strongRuleIds = new Set(['POR-DET-005', 'POR-DET-007']);
      const allowed = ['observe_only'];
      // Mirrors main.py's recommendation generation: targets are derived
      // from incident.container_ids (sorted set), falling back to [None]
      // when empty — i.e. has_target is true only when container_ids is
      // non-empty. The Incident API response has no top-level
      // target_container_id field.
      const hasTarget = !!(incident && Array.isArray(incident.container_ids) && incident.container_ids.length > 0);
      if (!incident || !hasTarget) return allowed;

      const severity = incident.severity_score || 0;
      const confidence = incident.confidence_score || 0;

      if (severity >= thresholds.pause_min_severity && confidence >= thresholds.pause_min_confidence) {
        allowed.push('pause_container');
      }

      const ruleIds = new Set((incident.findings || []).map(f => f.rule_id).filter(Boolean));
      const strongRule = [...strongRuleIds].some(id => ruleIds.has(id));
      if (
        severity >= thresholds.stop_min_severity &&
        confidence >= thresholds.stop_min_confidence &&
        strongRule
      ) {
        allowed.push('stop_container');
      }
      return allowed;
    },

    // Human-readable explanation for why `action` is (or would be) blocked
    // for `incident` — used both as a button tooltip and as the toast
    // message when the backend rejects the approval. Reuses the same
    // thresholds as incidentAllowedActions() so they're defined in one place.
    containmentBlockReason(incident, action) {
      const severity = (incident?.severity_score || 0).toFixed(2);
      const confidence = (incident?.confidence_score || 0).toFixed(2);
      if (action === 'pause_container') {
        return `Pause requires severity ≥ 0.70 and confidence ≥ 0.55 (currently severity ${severity}, confidence ${confidence}).`;
      }
      if (action === 'stop_container') {
        return `Stop requires severity ≥ 0.90, confidence ≥ 0.75, and a strong rule match (POR-DET-005/POR-DET-007) (currently severity ${severity}, confidence ${confidence}).`;
      }
      return '';
    },

    // Containment Action Approval — operates only on persisted backend incidents.
    async approveContainment(incident, action) {
      if (incident?.status === 'closed' || incident?.status === 'resolved') {
        this.showToast('Incident is already closed. Closed incidents cannot receive new response recommendations.', 'warning');
        this.logTerminal('RESPONDER', `Incident ${incident.incident_id} is already closed — action ignored.`, 'info');
        return;
      }
      this.logTerminal('RESPONDER', `Operator approving ${action} for ${incident.target_container_name || incident.container_ids?.[0] || incident.incident_id}`, 'info');
      this.showToast(`Containment '${action}' requested`, 'info');

      // Real incident: need to generate recommendation then approve via operator token
      this.authorizingIncidentId = incident.incident_id;
      try {
        if (!this.operatorToken) {
          const t = await this.requestOperatorToken('Approving containment actions requires operator authorization.', 'Authorize containment');
          if (!t) { this.showToast('Operator token required — approval cancelled', 'danger'); return; }
          this.operatorToken = t;
        }

        // 1) Generate recommendation for this incident (idempotent)
        this.logTerminal('RESPONDER', `Generating recommendation for incident ${incident.incident_id}...`, 'info');
        const genRes = await this._apiFetch(`/operator/v1/incidents/${incident.incident_id}/response-recommendations`, { method: 'POST', headers: { 'Content-Type': 'application/json' } });
        let recommendationId = null;
        if (genRes.ok) {
          const genData = await genRes.json();
          const recs = genData.recommendations || genData.items || [];
          // pick proposed or most recent matching allowed_actions includes desired action
          const match = recs.find(r => r.allowed_actions && r.allowed_actions.includes(action) && r.status === 'proposed') || recs.find(r => r.status === 'proposed') || recs[0];
          recommendationId = match?.recommendation_id;
        } else {
          // if already generated, list existing
          const listRes = await this._apiFetch(`/api/v1/response-recommendations?incident_id=${incident.incident_id}`);
          if (listRes.ok) {
            const list = await listRes.json();
            const match = list.find(r => r.incident_id === incident.incident_id && r.status === 'proposed');
            recommendationId = match?.recommendation_id;
          }
          if (!recommendationId) {
            const txt = await genRes.text();
            throw new Error(`Recommendation generation failed ${genRes.status}: ${txt.slice(0, 300)}`);
          }
        }

        if (!recommendationId) throw new Error('No recommendation available for approval');

        // 2) Approve with exact action
        this.logTerminal('RESPONDER', `Approving recommendation ${recommendationId} as ${action}...`, 'info');
        const approveRes = await this._apiFetch(`/operator/v1/response-recommendations/${recommendationId}/approve`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ actor: 'operator-dashboard', note: `Approved via dashboard as ${action}`, action_type: action, acknowledge_disruption: action !== 'observe_only' })
        });

        if (approveRes.ok) {
          const approved = await approveRes.json();
          incident.status = 'acknowledged';
          incident.approved_action = approved.approved_action || action;
          this.logTerminal('RESPONDER', `Containment approved — execution ${approved.recommendation_id} now pending responder`, 'success');
          this.showToast(`Containment ${action} approved — responder dispatched`, 'success');
          await this.fetchIncidents();
        } else {
          const txt = await approveRes.text();
          if (approveRes.status === 401) {
            this.operatorToken = '';
            throw new Error('Operator token invalid — cleared, try again');
          }
          let policyRejected = false;
          try {
            const parsed = JSON.parse(txt);
            policyRejected = approveRes.status === 422
              && typeof parsed.detail === 'string'
              && parsed.detail.toLowerCase().includes('not allowed by the recorded response policy');
          } catch (_) { /* not JSON — fall through to generic error */ }

          if (policyRejected) {
            throw new Error(this.containmentBlockReason(incident, action) || `${action} is not yet allowed by the response policy for this incident.`);
          }
          throw new Error(`Approve failed ${approveRes.status}: ${txt.slice(0, 400)}`);
        }
      } catch (err) {
        console.warn('Containment approve error', err);
        this.logTerminal('ERROR', err.message, 'error');
        this.showToast(`Approval failed: ${err.message.slice(0, 220)}`, 'danger');
      } finally {
        this.authorizingIncidentId = null;
      }
    },

    // Operator incident workflow resolution
    async resolveIncident(incident) {
      if (!incident) return;
      if (incident.status === 'closed' || incident.status === 'resolved') {
        this.showToast('Incident is already resolved/closed.', 'info');
        return;
      }
      try {
        if (!this.operatorToken) {
          const t = await this.requestOperatorToken('Resolving incidents requires operator clearance.', 'Resolve Incident');
          if (!t) { this.showToast('Operator clearance cancelled', 'danger'); return; }
          this.operatorToken = t;
        }

        const res = await this._apiFetch(`/operator/v1/incidents/${incident.incident_id}/status`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            status: 'resolved',
            actor: 'operator-dashboard',
            note: 'Resolved after operator review'
          })
        });

        if (res.ok) {
          this.showToast(`Incident resolved.`, 'success');
          this.logTerminal('OPERATOR', `Incident ${incident.incident_id} resolved after operator review`, 'success');
          await this.fetchIncidents();
        } else {
          const err = await res.json().catch(() => ({}));
          throw new Error(err.detail || `HTTP ${res.status}`);
        }
      } catch (err) {
        this.showToast(`Failed to resolve incident: ${err.message}`, 'danger');
      }
    },

    // Resolve one bounded batch and then reload the server's incident state.
    async cleanAllIncidents() {
      const openCount = (this.incidents || []).filter(i => i.status === 'open' || i.status === 'acknowledged').length;
      if (openCount === 0) {
        this.showToast('No active incidents in the current list.', 'info');
        return;
      }
      if (!confirm('Resolve up to 100 active incidents after operator review?')) return;
      try {
        if (!this.operatorToken) {
          const t = await this.requestOperatorToken('Resolving an incident batch requires operator clearance.', 'Resolve Incident Batch');
          if (!t) { this.showToast('Operator clearance cancelled', 'danger'); return; }
          this.operatorToken = t;
        }

        const res = await this._apiFetch('/operator/v1/incidents/clean-all?limit=100', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' }
        });

        if (res.ok) {
          const data = await res.json();
          const count = Number.isInteger(data.resolved_count) ? data.resolved_count : 0;
          const remaining = data.more_pending ? ' More active incidents remain; review another batch.' : '';
          await this.fetchIncidents();
          this.showToast(`Resolved ${count} incident(s).${remaining}`, data.more_pending ? 'info' : 'success');
          this.logTerminal('OPERATOR', `Resolved batch of ${count} incident(s).${remaining}`, 'success');
        } else {
          const err = await res.json().catch(() => ({}));
          throw new Error(err.detail || `HTTP ${res.status}`);
        }
      } catch (err) {
        this.showToast(`Failed to resolve incident batch: ${err.message}`, 'danger');
      }
    },

    // quick helper to clear stored token
    clearOperatorToken() {
      this.operatorToken = '';
      this.showToast('Operator token cleared', 'info');
    },

    // Pipeline trace: raw event -> deterministic rule match -> incident.
    // Pulls the exact ordered evidence chain for one incident from
    // GET /api/v1/incidents/{id}/timeline (backend main.py: get_incident_timeline),
    // which returns IncidentEvidence rows in sequence_no order — the same
    // rows the detection engine (backend/detection.py) recorded when a rule
    // matched. This is real data, not a mock: every node in the rendered
    // graph is a row that exists in Postgres right now for that incident.
    openPipelineForIncident(incident) {
      if (!incident || !incident.incident_id) return;
      this.activeTab = 'pipeline';
      this.pipelineIncidentId = incident.incident_id;
      this.fetchPipelineTimeline(incident.incident_id);
      this.fetchPipelineScoreDetail(incident.score_id);
    },

    // Fetches the full scoring breakdown for the anomaly score that
    // triggered this incident: per-feature-family Jensen-Shannon distance
    // (categorical_distance), probability-mass novelty, numeric deviation,
    // and the exact tokens (process names, executables, etc) that were
    // absent from the trained baseline. This is the real "how much did it
    // diverge and why" data backend/src/porygon_api/scoring.py computes —
    // not a placeholder, not re-derived client-side.
    async fetchPipelineScoreDetail(scoreId) {
      this.pipelineScoreDetail = null;
      this.pipelineScoreError = '';
      if (!scoreId) return;
      this.pipelineScoreLoading = true;
      try {
        const res = await this._apiFetch(`/api/v1/anomaly-scores/${scoreId}`);
        if (!res.ok) throw new Error(`score fetch failed: ${res.status}`);
        this.pipelineScoreDetail = await res.json();
      } catch (err) {
        console.warn('Pipeline score detail fetch error', err);
        this.pipelineScoreError = err.message;
      } finally {
        this.pipelineScoreLoading = false;
      }
    },

    // Percent width helper for divergence bars, clamped to [0,100].
    divergencePercent(value) {
      if (value === null || value === undefined) return 0;
      return Math.max(0, Math.min(100, Math.round(value * 100)));
    },

    async fetchPipelineTimeline(incidentId) {
      if (!incidentId) { this.pipelineTimeline = []; return; }
      this.pipelineLoading = true;
      this.pipelineError = '';
      try {
        const res = await this._apiFetch(`/api/v1/incidents/${incidentId}/timeline`);
        if (!res.ok) throw new Error(`timeline fetch failed: ${res.status}`);
        const rows = await res.json();
        this.pipelineTimeline = rows;
      } catch (err) {
        console.warn('Pipeline timeline fetch error', err);
        this.pipelineError = err.message;
        this.pipelineTimeline = [];
      } finally {
        this.pipelineLoading = false;
      }
    },

    pipelineStageLabel(row) {
      if (row.source_type === 'process_event') return 'Falco → process_exec_events';
      if (row.source_type === 'runtime_event') return 'Falco → runtime_events';
      if (row.source_type === 'anomaly_score') return 'Scoring engine → anomaly_scores';
      if (row.source_type === 'derived_correlation') return 'Correlation window → derived match';
      return row.source_type || 'evidence';
    },

    // Interactive helpers for table rows, operators, and incident getters
    async selectContainer(c) {
      if (!c) return;
      if (this.selectedContainer === c.container_id) {
        await this.clearContainerFilter();
      } else {
        this.selectedContainer = c.container_id;
        this.selectedContainerName = c.container_name || null;
        this.eventFilter = '';
        this.activeTab = 'telemetry';
        this.showToast(`Loading telemetry for ${c.container_name || c.container_id.substring(0, 12)}...`, 'info');
        await this.fetchEvents();
      }
    },

    async clearContainerFilter() {
      this.selectedContainer = null;
      this.selectedContainerName = null;
      this.eventFilter = '';
      this.showToast('Container filter cleared — showing latest telemetry', 'info');
      await this.fetchEvents();
    },

    async manageOperatorToken() {
      if (this.operatorToken) {
        const confirmed = await this.requestConfirm(`Operator token is active (configured). Log out this tab?`, 'Clear operator token', 'Clear', false);
        if (confirmed) {
          this.clearOperatorToken();
        }
      } else {
        const val = await this.requestOperatorToken('Paste your enrolled human access token. It stays in this tab until logout or reload.', 'Set operator token');
        if (val) {
          this.operatorToken = val;
          this.showToast('Access token configured for this tab', 'success');
          this.logTerminal('OPERATOR', 'Operator token configured for human-in-the-loop containment', 'success');
        }
      }
    },

    getIncidentContainerName(inc) {
      if (!inc) return 'porygon-workload';
      if (inc.target_container_name && inc.target_container_name !== 'porygon-demo-test') {
        return inc.target_container_name;
      }
      const cid = inc.container_ids?.[0];
      if (!cid) return inc.target_container_name || 'porygon-workload';
      const match = this.containers.find(c => c.container_id === cid || c.container_id.startsWith(cid) || cid.startsWith(c.container_id));
      return match?.container_name || cid.substring(0, 12);
    },

    getIncidentRules(inc) {
      if (!inc) return ['POR-DET-001'];
      if (Array.isArray(inc.rules_triggered) && inc.rules_triggered.length) {
        return inc.rules_triggered;
      }
      if (Array.isArray(inc.findings) && inc.findings.length) {
        const ids = inc.findings.map(f => f.rule_id).filter(Boolean);
        if (ids.length) return [...new Set(ids)];
      }
      return ['POR-DET-001'];
    }
  }));
});
