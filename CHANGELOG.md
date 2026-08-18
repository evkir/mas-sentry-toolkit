# Changelog

## [Unreleased]

### Added
- MCP now audits the consent surface: `elicitation_url` and
  `elicitation_secret_field`, both tagged ASI09. An elicitation is the one point
  in the protocol where a server addresses the operator rather than the agent -
  URL mode sends a browser somewhere, form mode asks for values to be typed -
  and both are trust decisions made by a person who sees only what the client
  renders. Severity is spent only where that person could not have checked the
  surface even in principle: credentials embedded ahead of the host or a
  cleartext scheme off loopback are HIGH, a bare IP host is MEDIUM, and a
  consent address that leaves the scanned origin is INFO, because an off-origin
  address is what an identity provider is and a severity there would fire on
  every honest OAuth flow. Form mode is specified for non-sensitive input, so a
  schema collecting a secret is HIGH when the property is named for it and
  MEDIUM when only the description is - a name is chosen, prose says "no
  password is required" as readily as it asks for one. MST declines every
  elicitation by never retrying; nothing here completes a flow, follows a
  redirect or fills a field. Both directions are pinned: an https address on the
  scanned origin and a form collecting a workspace name produce nothing.
- MCP declares the elicitation modes a server needs to see before it will
  elicit. The client sent an empty capability object, and the reference SDK
  checks the declaration before rendering the request - so a resolver-backed
  tool answered `-32021` and the consent URL or credential schema behind it was
  never shown. The routes are declared differently on purpose: 2026-07-28 gets
  `{form, url}` because the request arrives inside an `input_required` result
  and the server moves on, while the 2025 line gets url-only because form mode
  there is a server-to-client request the server then blocks on, and a client
  that never answers would trade a fast rejection for a read timeout and a
  wedged server. Sampling and roots stay undeclared; both ask the client to act.
  A bare `elicitation: {}` reads as form support to the reference SDK and a
  url-only object does not, so the modes are named explicitly.

### Removed
- `exploits/mqtt_fuzzer.py`. Run against a live broker every case it sends -
  null byte, newline, unicode, traversal and SQL metacharacters in topic names,
  oversized payloads, 65535-character topics - was recorded as `OK`, because a
  paho `publish()` does not raise on a malformed topic and the module read
  neither the return code nor whether the broker was still alive afterwards. It
  had no branch in which it could report anything, so its output was a list of
  passes that no target could fail. Establishing what a broker does with a
  malformed topic needs a round trip and a liveness check after each case; that
  is a detector to write, not a line to patch.
- `exploits/mqtt_command_injection.py`. Its canned payloads - an actuator
  shutdown, telemetry forced to 999.9, a config override - were aimed at fixed
  production-looking topics, and it reported success on a publish that returned
  without error. Mosquitto drops a publish denied by an ACL silently, so that
  success was not a claim it could make. Replaced by `mqtt exploit --attack
  command-inject`, which subscribes before it publishes and reports only what
  came back, sends an inert marker unless the operator passes `--payload`, and
  writes without the retain flag so the probe leaves nothing behind.
- `exploits/mqtt_retained.py`. Its scan half duplicated
  `protocols/mqtt_retained_audit.py`, which is reachable from
  `mqtt scan --checks retained`, emits Findings rather than a table and audits
  the content of what it reads. Its poison half is
  `exploits/mqtt_retained_poison.py`, now reachable as `mqtt exploit`.

### Fixed
- MCP kept only the method name of an elicitation and dropped its params, which
  is where the address and the requested schema live. A scan could record that a
  server had asked a human to authorize somewhere and lose the somewhere. Both
  routes now land in the same record - `input_requests` on 2026-07-28, the
  `-32042` payload on the 2025 line. `elicitationId` is deliberately not read:
  2026-07-28 removed it from URL mode, and a parser that required it would stop
  working against current servers for a value that identifies nothing to us. A
  schema arriving with no declared `mode` still reads as form, which is the
  shape a server predating modes sends.
- MCP read `-32021` as an ordinary error. The refusal means the call never
  reached the tool, so a probe aimed at it established nothing - and an
  unexercised surface that reports like a clean one is the failure mode this
  scanner exists to avoid. Recorded as `capability_required` (MEDIUM), carrying
  the capabilities the server named. Left out of the taxonomy table on purpose,
  alongside the other findings that describe the scan rather than the target.
  The walk over the refusal payload is bounded in depth and breadth, because
  that payload is written by the target.

- MCP now speaks the stateless 2026-07-28 route, falling back to the handshake.
  The revision removes both the `initialize` handshake and `Mcp-Session-Id`:
  every request carries the protocol version, client info and capabilities in
  `params._meta`, routes on the `Mcp-Method` and `Mcp-Name` headers, and a client
  wanting capabilities up front calls `server/discover`. MST spoke only the 2025
  line, so a modern server would have answered -32602 to every request and the
  scan would have reported an empty target - the same shape as the session
  defect the reference rig exposed in 0.8.0. `connect()` tries discover first and
  falls back, because that direction stays correct as the ecosystem moves. Only
  -32601 (method unknown) and -32022 (revision rejected, with the supported list
  attached) are read as "not this generation"; any other error falls through to
  the handshake without being recorded as a protocol fact, so a merely broken
  server is not reported as a 2025 server.
- New check `header_body_desync` (`--checks desync`), a conformance test with a
  direct security consequence. The new revision makes the routing headers
  mandatory so a gateway can authorize a call without parsing the body, which
  means two parties now read the same request and only one reads the body. The
  spec therefore requires the server to reject any request whose headers
  disagree with its body; a server that does not hands an attacker a request the
  policy layer authorizes as one operation and the server executes as another -
  `Mcp-Method: tools/list` past a gateway permitting only enumeration while the
  body says `tools/call`, or a matching method where only `Mcp-Name` differs so
  an allow-list sees the approved tool and the server runs another. Four probes,
  verified in both directions against live servers: the reference SDK rejects all
  four with -32020, a deliberately permissive server is reported HIGH on all four.

- New command `mas-sentry mcp audit-source --path <dir>`, which makes the
  STDIO command-injection auditor reachable. `StdioConfigAuditor` had unit
  coverage and no caller anywhere under `mas_sentry`, so the OX Security RCE
  class it detects could not produce a row from any scan - the same defect as
  the MQTT probes fixed in 0.8.0. It is a separate command rather than a
  `--checks` flag because it reads source instead of the wire: by the time a
  live scan can talk to a server, its stdio command line is already built.
  Findings carry the file, line and matched pattern as evidence and are
  classified ASI05 Unexpected Code Execution / CWE-78 / Elevation of
  Privilege, which also gives ASI05 a detector that runs.
- MCP checks that previously reached SARIF carrying only their own check name
  are now classified: `ssrf` (CWE-918), `path_traversal` (CWE-22),
  `resource_content` and `resource_template` (CWE-1427 with AML.T0051),
  `header_body_desync` (CWE-436), `dns_rebind` (CWE-346) and `known_cve`
  (CWE-1395). Ten of sixteen checks arrived untagged, so an operator
  filtering GitHub code scanning by weakness class saw a CRITICAL SSRF as
  untriaged noise. `fingerprint`, `enumeration_gap` and `input_required` stay
  untagged on purpose: they report what the scan reached, not that something
  is wrong.

### Changed
- **Breaking.** ASI category numbers now follow the OWASP Top 10 for Agentic
  Applications published on 9 December 2025. MST carried a pre-release
  ordering, so four numbers named the wrong category: supply chain moves from
  ASI08 to ASI04, memory poisoning from ASI04 to ASI06, cascading failure from
  ASI05 to ASI08, and inter-agent communication from ASI06 to ASI07. These are
  SARIF tags, so an operator filtering GitHub code scanning on ASI04 for
  supply-chain risk was served memory poisoning. Untraceable actions and
  resource exhaustion were dropped from the list between draft and release;
  they are now tagged `MST_Untraceable_Actions` and `MST_Resource_Exhaustion`
  rather than occupying a number that means something else. Reports produced
  before this release cannot be compared by ASI number with reports produced
  after it.
- **Breaking.** The agentic pipeline selectors lost their numeric prefix:
  `asi08_supply_chain` is now `supply_chain`, `asi05_cascade` is `cascade`,
  and so on. `mas-sentry agentic scan --asi` still accepts a number, but it is
  resolved through the category values rather than matched as a substring of
  the module name, so `--asi asi04` selects supply chain. Finding module ids
  changed with them (`agentic.asi08` is now `agentic.supply_chain`), which
  also keeps the two MST_-prefixed categories from collapsing onto one id.

### Fixed
- MQTT broker auditing as a command (`mas-sentry mqtt scan`). The MQTT probes
  predate the pivot and had never been reachable from the product: nothing in
  `cli/`, `agents/` or `agentic/` imported `MQTTAuthChecker`, `MQTTTopicWalker`
  or `MQTTBrokerFingerprinter`, and no adapter existed to turn what they return
  - a dict of booleans, a list of strings, a dict of $SYS values - into anything
  the reporting pipeline could carry. They had unit coverage and no reachable
  output, which is the same defect class as the MCP finding adapter that was
  fully tested and never called. Meanwhile the README advertised a
  `mas-sentry mqtt scan` that did not exist, so the first command a new user ran
  failed. The orchestrator (`protocols/mqtt_runtime.py`) emits the unified
  `Finding` directly rather than inventing a fourth raw row format plus an
  adapter to translate it, so MQTT findings reach `report convert` through the
  path A2A already uses: SARIF now carries `MAS-SENTRY-MQTT.ANONYMOUS_ACCESS`
  instead of an unknown ruleId. Checks: `auth`, `fingerprint`, `topics`,
  `retained`, selectable individually.
- Retained-payload auditing (`--checks retained`). The topic walk reported which
  topics existed and never opened one, and retained state is the wrong content
  to skip: the broker stores one retained message per topic and replays it to
  every client the moment it subscribes. No agent asks for it and none can
  decline it. That makes a poisoned retained message the MQTT twin of a poisoned
  MCP resource, with two differences that favour the attacker - it persists with
  the attacker gone, because the broker holds it until someone overwrites it,
  and it is delivered on subscribe rather than on request, so it reaches every
  agent that reconnects long after the attacker left. Content goes through the
  same two core primitives the MCP resource audit uses: `injection_scan` for
  directives arriving inside the data, `output_exfil` for auto-fetch beacons
  embedded in it. Collection costs nothing extra - retained messages arrive on
  the wildcard subscription the topic walk already holds, so both checks share
  one connection.

### Fixed
- Four MCP audits sent their requests straight to the transport, bypassing the
  client. `ssrf`, both `path_traversal` probes and `resource_content` called
  `client.transport.send()` directly, so their requests carried no `params._meta`
  envelope. Against a modern server every one of them would have been rejected
  and SSRF, traversal and poisoned resource content would all have been reported
  as not confirmed. They had integration coverage the whole time - against a
  server that did not require the envelope. They now go through `client.send()`,
  which is the single place the envelope is added.
- A 4xx response no longer discards the JSON-RPC error it carried. The transport
  replaced the body with the HTTP status, which threw away the only place a
  rejection states its reason: -32022 names the revisions the server supports,
  and without that payload a version-aware client cannot fall back at all. A body
  that is not JSON still reports the status rather than inventing a -32700.
- The lab-rig test module skipped on an mcp 1.x SDK instead of failing against
  it. `pytest.importorskip("mcp")` checks only that the package imports, and the
  rig needs `mcp.server.mcpserver`, which exists only in the 2.x line - so an
  interpreter holding an mcp 1.x (a sibling project pinning `mcp<2` into the same
  system Python will produce exactly that) passed the guard and then failed every
  case with `initialize failed`, an error shaped like a protocol defect and caused
  by a missing module. pytest `minversion` is unusable here because the mcp
  package exposes no `__version__`; the check reads the distribution metadata.
- An unreachable MQTT broker is no longer indistinguishable from an empty one.
  The three probes each reported a failed connection differently: the auth
  checker swallowed `BrokerUnreachable` and returned its partial mapping, the
  topic walker let a raw `ConnectionRefusedError` escape, and the fingerprinter
  returned a dict with `broker_type` "unreachable". None of them read the CONNACK
  reason code, so a broker enforcing authentication accepted the socket, rejected
  the CONNECT, subscribed the walker to nothing and produced an empty topic list
  - the same value an idle broker produces. A shared `protocols/mqtt_connect.py`
  gives all three the same two outcomes, and a probe that could not run now
  appears in the report as an `mqtt.enumeration_gap` finding: INFO when the
  broker refused us (authentication is enforced, but the surface behind it went
  unaudited), MEDIUM when it was unreachable. Verified against live Mosquitto in
  both postures.
- Two MQTT false positives caught on the live rig before they shipped. A broker
  allowing anonymous access accepts *any* credential pair, so the `guest:guest`
  and `admin:admin` probes both succeed against it; reporting them separately
  produced two HIGH false positives on every open broker, and they are now one
  INFO note explaining why they are not separately assessable. And an accepted
  wildcard subscription is not evidence of read access: Mosquitto answers a `#`
  SUBSCRIBE with "Granted QoS 0" while its ACL withholds the topics - in the rig
  the SUBACK was granted and only the one ACL-permitted topic was delivered - so
  the exposure finding is keyed on messages that actually arrived.
- `paho` v2 hands `on_connect` a `ReasonCode` object, not an int: it compares
  equal to 0 but `int()` on it raises `TypeError`, which an exception swallowed
  inside a paho callback would have turned into a silent failure. The reason
  helpers read `.value`.

### Documentation
- The README was the Day 15 planning text, frozen before the code existed. It
  described a module tree that was never built (`threat_modeling/`,
  `agentic/asi01-10`) and exporters that were never written (PDF, a HackerOne
  preset), pointed twice at `lab/docker-compose.yml` when the compose file is in
  the repository root, and led its positioning with MQTT while the frontier this
  tool follows is MCP and A2A. Every command in it is now verified by running
  it. AMQP was removed from the capability table for the same reason MQTT was
  broken: `amqp_analyzer.py` has no CLI entry point and no import outside its
  tests. It returns when it is wired up. A "Reading a report" section was added
  covering what each severity establishes and why `enumeration_gap` and
  `inconclusive` describe the limits of a scan rather than the health of a
  target.
- `docs/usage/mqtt-scanning.md` and `docs/usage/attack-scenarios.md` documented a
  CLI that has never existed in this repository - `mas-sentry scan --protocol
  mqtt` with `--port` / `--timeout` / `--output`, `abfp --save-baseline`,
  `report --session <id>`. Rewritten around commands that exist, verified by
  execution. Doing so corrected the mesh manifest shape: edges are pairs,
  `[["from", "to"]]`, not `{from, to}` objects.
- `docs/api/README.md`, `docs/methodology/threat-modeling.md` and
  `docs/ARCHITECTURE.md` documented seven modules under
  `mas_sentry.threat_modeling` plus `reporting.report_model`. All eight raise
  `ModuleNotFoundError` - that subsystem was deleted in 0.5.0 as orphaned, and
  the documentation of it survived the removal. Both pages are in the mkdocs
  nav, so this was a published API reference where every example failed on
  import. Rewritten around what exists, including the rule for when a taxonomy
  tag is deliberately left off, and two admissions recorded rather than papered
  over: CVSS is not implemented and not planned, and STRIDE Repudiation has no
  protocol detector.
- `lab/README.md` carried no false claims but omitted the reference-SDK MCP rig
  and the `mcp_ref` / `agent_a2a` compose services, so the lab documentation was
  silent about the thing that makes the lab worth having.


## [0.8.0] - 2026-07-29 - Reference-SDK rigs for A2A and MCP; eleven wire-level defects

### Added
- A2A integration rig built on the reference `a2a-sdk` (`lab/a2a/agent.py`,
  `pip install -e '.[lab]'`). Every A2A test so far drove the client through
  `httpx.MockTransport`, which only ever confirms that MAS-Sentry agrees with
  its own idea of the wire - a circular check, and the reason five protocol
  defects survived to this release. The lab agent publishes a deliberately weak
  v1.0 AgentCard and echoes task text back as an artifact, so the passive audit
  and the injection canary both have something real to find. It serves strict
  v1.0 by default and the legacy v0.3.x vocabulary under `A2A_LAB_COMPAT=1`,
  and the CI integration job installs the extra so the rig runs rather than
  skipping.
- MCP resource-content auditing (`--checks resources`). Resources were
  enumerated and never read, leaving their contents the one agent-facing MCP
  surface with no audit at all - and the wrong one to skip, since a resource is
  what an agent pulls into its own context on its own initiative. That makes a
  poisoned resource the textbook indirect-injection vector: the instruction does
  not come from the user, it arrives with data the agent fetched and trusted.
  Reading is safe here in a way that calling arbitrary tools is not, because
  `resources/read` returns application-controlled data with no side effects by
  design, whereas invoking an unknown tool could write, delete or spend - so the
  audit reads what a client would read and nothing more. Each resource is
  scanned on two axes with the shared core primitives: `injection_scan` for
  directives arriving in the content, and `output_exfil` for auto-fetch beacons
  embedded in it, making this the third consumer of that primitive after the A2A
  probe and the ABFP message bus. HIGH is reserved for unambiguous signal, a
  strong injection pattern or a concrete external beacon; softer phrasing
  matches stay MEDIUM. Wired through `run_mcp_scan` so findings reach every
  report format rather than stopping at the audit layer.
- Structured reading of MCP `CallToolResult` payloads
  (`protocols/mcp/content.py`): content-block extraction across text, image,
  audio, embedded-resource and resource-link types, base64 decoding for inline
  payloads, top-level `text` / `blob` handling for `resources/read`, and an
  `is_tool_error` helper. A non-conforming server falls back to a JSON dump
  rather than being scanned as an empty string.
- MCP integration rig built on the reference `mcp` SDK (`lab/mcp/server.py`,
  `pip install -e '.[lab]'`, plus a compose service). Every MCP test until now
  drove the client through hand-written JSON-RPC fixtures or the hand-rolled
  `lab/vuln-mcp` script, which answers only the three methods the scanner
  already knew how to ask for - both validate the scanner against its own idea
  of the wire, the same circular check that let five A2A defects survive. The
  rig serves both transports and both protocol generations from one endpoint,
  and is deliberately vulnerable along each detector axis: a poisoned tool
  description, an unguarded `read_file`, a `fetch_url` that dereferences
  anything including `file://`, a resource carrying both an injection directive
  and a Markdown-image beacon, and a templated resource whose description
  smuggles a directive of its own. It found four transport and reporting
  defects within the first hour.
- Paginated listings are walked to the end. MCP list results carry a
  `nextCursor` and expect the client to keep asking; all three list methods read
  page one and stopped, so a server with more tools than fit a page was audited
  on a prefix - and there is no reason the interesting tools sit before the cut
  rather than after it. Two hostile shapes are bounded rather than trusted: a
  server that repeats a cursor, or that never stops issuing them, would spin the
  scanner in place, so both end the walk and are recorded as gaps. The rig
  paginates behind `MCP_LAB_PAGE_SIZE`, built on the SDK result model so the
  page shape is the reference one.
- Templated resources are enumerated and scanned (`resources/templates/list`,
  check `resource_template`). They never appear in `resources/list`, so a server
  exposing half its resource surface through templates was audited on the other
  half and the omission read as a clean result. A template body needs a
  parameter value and stays out of reach, but its name and description do not,
  and those are the text an agent weighs before expanding the template and
  pulling the result into context - the same ingestion surface as a tool
  description, open to the same directive smuggling.

### Fixed
- A fully secured A2A v0.3.x AgentCard was reported HIGH as enforcing no
  authentication. Both generations publish securitySchemes and then name the
  mandatory subset under a different key - securityRequirements in v1.0,
  security in v0.3.x - and only the v1.0 spelling was read, so a legacy agent
  that had configured OAuth2 correctly was told it had no auth at all. A false
  positive at HIGH, aimed precisely at the operators who got it right. Both
  requirement keys are now honoured. The remaining authentication.schemes
  fallback is kept for genuinely old cards but described accurately: 0.3 had
  already moved to securitySchemes, so that shape predates the versions this
  scanner claims to support.
- Removed the streaming rate-limit and push webhook-signing card checks. They
  read capabilities.rateLimits and authentication.webhookSigning, neither of
  which exists in A2A v1.0 or v0.3.x - AgentCapabilities carries exactly
  streaming, pushNotifications, extensions and extendedAgentCard - so both
  fired on every card advertising the capability and no configuration could
  clear them. Neither has a card-side replacement: rate limiting is not
  card-expressible, and push-callback authentication is negotiated per task in
  TaskPushNotificationConfig.authentication at runtime rather than declared up
  front. The motivating threats are real; the signal was not. The clean-card
  test fixture asserted zero findings for a card carrying both invented
  fields, which meant the only card able to score clean was one no agent could
  publish; it now uses the real v1.0 shape.
- An agent replying with a Message instead of a Task went unscanned.
  SendMessageResponse is a oneof, so an agent that answers in one turn never
  creates a Task at all - v1.0 wraps the reply as result.message, v0.3.x
  returns it flat under kind: message. The client looked only for a Task,
  parsed an empty result, then polled a task id it had never been given, and
  the canary the agent had just echoed went unseen. TaskResult now carries
  those replies in a separate messages field, marked terminal so nothing polls
  a phantom id, and the injection probe scans both carriers. Task history is
  deliberately excluded from that scan: it contains the probe payload itself
  and would make every agent self-match.
- The A2A client spoke the v0.3.x JSON-RPC vocabulary unconditionally and sent
  no `A2A-Version` header, so a reference v1.0 server answered -32601 Method
  not found to every call. Two of the three active probes were swallowed by the
  per-probe error handler and the third reported success, so an active scan
  returned a clean result for an endpoint it had never reached. The dialect is
  now resolved from the discovered card, mirroring how the endpoint already
  was: `supportedInterfaces` means v1.0, a top-level `url` with
  `preferredTransport` means v0.3.x, and an explicit `protocolVersion` on the
  JSONRPC interface overrides the shape for an operator still fronting a legacy
  endpoint. An undiscovered card resolves to v0.3 because a server reads an
  absent version header the same way.
- v1.0 returns the Task inside the `SendMessageResponse` oneof while `GetTask`
  and `CancelTask` return it flat in both generations, so the send response is
  unwrapped and the others deliberately are not - unwrapping everywhere would
  have blanked out task polling.
- Dropped the invented `params.id`. Neither generation lets a client choose the
  id of a task it is creating; `Message.taskId` references an existing task and
  a compliant server answers -32001 for one it never issued. The identifier now
  labels the message, which is what the wire actually carries. Seven unit mocks
  asserted that invented field, which is precisely why the divergence survived;
  they now model the real shape.
- `probe_unauthorized_cancel` accepted any JSON-RPC error as proof the server
  had rejected the call, so -32601 Method not found was reported to the operator
  as "server behaved safely". A protocol error laundered into a positive
  assurance is worse than a missing finding. Only the task-domain codes A2A
  defines for the operation (-32001, -32002) count as a rejection, along with an
  HTTP 401/403 from a fronting gateway; every other code now yields an
  inconclusive verdict carrying the code it was drawn from.
- A probe that raised a transport error was written to the audit log and
  dropped, leaving the report looking as though the check had run and found
  nothing - the same silent-loss class as the propagation and coordination
  blocks, one level further up. Skipped probes are now reported as inconclusive
  findings that claim nothing about the target.
- The MCP SSRF and path-traversal probes matched indicators against a truncated
  stringification of the raw result object, which failed twice over against
  spec-conforming servers. A Python repr leads with dict scaffolding, so a fixed
  prefix was spent before reaching the content and an indicator further in was
  never seen; and content delivered as a base64 image or resource blob could not
  match a plaintext indicator at all - the same false negative the A2A artifact
  reader closed. Matching now runs over decoded content-block text, with
  truncation applied only to recorded evidence.
- Those probes treated only JSON-RPC errors as denials, but MCP routes
  tool-raised failures into a *successful* response with `isError: true`,
  reserving protocol errors for malformed requests and unknown tools. A server
  that firmly refused a probe payload therefore fell through to indicator
  matching, matched nothing, and was discarded as an unremarkable success,
  making a properly guarded tool indistinguishable from a silent one. All three
  probes now treat a tool-level error as a denial alongside a protocol-level
  one. Note that the scan report still surfaces only confirmed findings, so a
  denial refines classification rather than adding report noise.
- These probe bodies had no test coverage at all; 24 tests were added across
  content extraction and probe behaviour, including a refusal delivered as
  `isError`, an indicator inside base64, and one past the old truncation
  boundary.
- A populated MCP server reached over Streamable HTTP scanned completely clean.
  The transport dropped both pieces of per-connection state the generation
  carries: a server that mints an `Mcp-Session-Id` on `initialize` rejects every
  later request that does not carry it back, and since the enumeration helpers
  turned an error into an empty list, a reference server with four tools, a
  prompt and two resources fingerprinted as zero tools with every downstream
  audit running over nothing. Remote and hosted servers are exactly the ones an
  operator points a scanner at, so the blind spot covered the whole practical
  MCP surface. The negotiated revision had a quieter failure alongside it: with
  no `MCP-Protocol-Version` header the spec tells a server to assume 2025-03-26,
  so the scanner silently reasoned about a generation the server was not
  speaking. Both are now read off whatever the server returns rather than
  assumed, so a stateless deployment that mints no session is not handed one,
  and `close()` releases the session with a DELETE instead of leaving it to
  expire.
- A refused listing was reported as an empty inventory. `list_tools`,
  `list_prompts` and `list_resources` each returned `[]` on error, which is the
  same value they return for a server that genuinely has none, so a server that
  would not enumerate produced a scan with no findings and nothing to say about
  why - the coverage claim and the clean result were indistinguishable. This is
  the same silent-loss class as the propagation and coordination blocks, and the
  sixth instance across three cycles. Failures are now recorded once per method
  with the JSON-RPC code and surface as an `enumeration_gap` check, with the
  code deciding severity: -32601 means the method was never implemented and the
  surface does not exist, so INFO; anything else - an authorization refusal, a
  transport error, an HTTP status folded into the error field - means the
  surface may exist and went unexamined, so MEDIUM.
- Every MCP finding reached HTML, Markdown, SARIF and JUnit as module `unknown`
  with a blank title and no taxonomy - a CRITICAL tool-poisoning hit filed under
  SARIF ruleId `MAS-SENTRY-UNKNOWN`. `from_mcp_check` synthesizes the title and
  attaches the ASI/CWE/STRIDE/ATLAS tags for each check; it was written,
  unit-tested and never called, because `report convert` fell through to the
  unified-Finding branch, which looks for `module`/`title`/`tags` while the MCP
  scan writes `{check, severity, detail}`. Rows carrying `check` without
  `module` now route to the adapter, the way ABFP agent rows already did. The
  new tests drive the CLI rather than the adapter, since full coverage of the
  function was exactly what hid the missing call.
- `StdioConfig.timeout` was declared and never applied: the transport called a
  blocking readline, so a server that accepted a request and answered nothing
  stopped the scan for good - and whether it answers is the target choice. A
  pentest tool the scanned host can hang is a denial of service on its own
  operator, and in CI a job that runs until the runner is killed. Reads now poll
  with a deadline and buffer across calls, since framing is by newline rather
  than by read boundary. A timeout and a closed pipe both come back as JSON-RPC
  errors instead of raising, so they land in the report as enumeration gaps and
  the rest of the scan proceeds; a closed pipe reports the exit code and the
  tail of stderr, which is what identifies a server that died during startup.
  Writing to a dead pipe raised too, and is handled the same way. `select()` on
  a pipe is POSIX-only, so elsewhere the unbounded read remains, documented as
  such rather than silently pretending to be bounded.

## [0.7.0] - 2026-07-19 - Delegation-mesh auditing, agent-output exfiltration detection, coordination side-channel

### Added
- A2A delegation-mesh auditing (`mas-sentry a2a mesh`). The single-target card
  audit reasons over one agent in isolation, but cross-agent weaknesses live on
  the delegation edges between agents, invisible to any one card - the
  overbroad-scope check shipped in 0.6.0 names cross-agent privilege escalation
  as its motive yet structurally cannot see it. The mesh scan takes an
  operator-declared topology (`{agents: [{id, url}], edges: [[from, to]]}`),
  fetches every card through the existing scope-enforced passive discovery, and
  builds a delegation graph carrying each agent OAuth2 scopes as node data.
  Topology is declared rather than inferred, mirroring `--confirm-scope`: the
  pentester maps the mesh they are authorised to test, instead of the scanner
  guessing edges from free-form card text (speculative) or observing them at
  runtime (needs authentication a passive scanner does not assume).
- Mesh detector: cross-agent privilege escalation through scope
  non-attenuation. Privilege attenuation, the 2026 A2A delegation consensus,
  requires every hop to carry equal or lesser authority than the hop before it.
  An edge `A -> B` where B advertises OAuth2 scopes absent from A is a
  non-attenuating hop: a task handed down it reaches authority A never held.
  Severity follows the contamination depth ladder - HIGH for a first-hop
  widening, CRITICAL when it sits two or more hops deep and compounds an
  already-transitive chain. Scope extraction reuses the card-audit helpers, so
  the mesh and the single-target check share one definition of granted scope.
  Gained scopes and the full delegation chain travel as evidence rather than
  asserting exploitability. Tagged ASI03 / CWE-269 / STRIDE Elevation of
  Privilege; no ATLAS id, no clean verified match.
- Mesh detector: recursive re-delegation (delegation cycles). Delegation should
  form a DAG - a coordinator hands work down to specialists, never back up. A
  cycle lets a task be re-delegated around the loop with no base case, the
  recursive-DoS / delegation-deadlock vector where a single entering task
  exhausts agent workers. Elementary cycles are enumerated and normalised to a
  stable starting node; multi-agent cycles score HIGH, self-delegation loops
  MEDIUM, since bounded self-recursion is at least a common intentional
  pattern. Both mesh detectors run over the same graph in one pass. Tagged
  ASI07 / CWE-674 / STRIDE Denial of Service. Documented in the A2A scanning
  methodology page.
- Structured extraction of A2A artifact Parts across spec generations
  (`protocols/a2a/parts.py`). A2A v1.0 redesigned Part into a single
  member-discriminated shape (`text`, `data`, `url`, `raw`), dropping the
  v0.3.x `kind` field and the nested `file.fileWithBytes` / `fileWithUri`.
  Discrimination is by member presence, which covers both generations for text
  and data; both file shapes are read. Data parts are JSON-serialised so an
  embedded canary is still found, inline base64 is decoded, and URI references
  contribute their URL string without being fetched.
- Agent-output exfiltration-channel scanning (`core/output_exfil.py`), a
  neutral primitive sibling to `injection_scan`: that flags hidden directives
  entering a model, this flags exfiltration channels in what an agent emits.
  The 2026 disclosure class (EchoLeak CVE-2025-32711, Salesforce ForcedLeak)
  weaponises agent output - the model is induced to embed a Markdown image or
  link at an external URL that the rendering client auto-fetches, leaking any
  data folded into the URL before a human sees it. Detects Markdown images,
  reference-style link definitions (the EchoLeak link-redaction bypass) and
  HTML img tags pointing at http(s) targets; data URIs and relative paths are
  ignored because they trigger no external fetch. Maps to CWE-201 / OWASP
  LLM05.
- The A2A indirect-injection probe now also scans decoded artifact text for
  those channels. A probe that fed an injection payload and receives output
  embedding an auto-fetch beacon has found the EchoLeak effect - the injected
  instruction manifested as a data-leak channel - and that fails the probe even
  when the exact canary was never echoed verbatim.
- ABFP: exfiltration channels detected on the inter-agent message bus, as a new
  `exfil` scoring dimension. Where `payload_injection` flags the directive that
  arrived, this flags the beacon that went out; a payload carrying both raises
  two dimensions rather than one blurred signal. The 2026 AgentLeak evaluation
  found inter-agent coordination channels to be the highest-yield exfiltration
  vector precisely because they stay invisible to output-level defenses, which
  is exactly what response-side probing is. Scored per distinct (channel kind,
  destination host) rather than per message, and weighted below injection at
  0.45: a legitimate agent may publish an external image, so one hit informs
  the operator rather than convicting alone, and the destination is always
  named in the reason. Payloads are scanned in flight and never retained.
- ABFP: unexplained temporal coupling between agents, a coordination side
  channel. This is deliberately **not** a collusion detector - state-of-the-art
  collusion detection reads model activations a network scanner does not have,
  and against steganographic collusion plain-text monitoring is theoretically
  defeated by schemes computationally indistinguishable from good-faith
  traffic. What a passive observer can measure is the consequence: whether one
  agent systematically publishes inside the response window of another. That
  raw fraction is meaningless on its own, since two agents on a shared timer
  score high while coordinating nothing, so it is standardised against a
  circular-shift surrogate null which preserves each series own cadence and
  destroys only the phase relation. A standardised z is used rather than a
  permutation p-value, whose resolution floor of 1/(K+1) cannot clear a
  multiple-comparison threshold at mesh pair counts. On synthetic meshes the
  null measures as N(0,1): the largest clean-pair z was 2.94 against 9.5 for
  partial coupling and 24.9 for full, and a shared-timer pair scores 1.9, so
  the six-sigma default has wide margin. Pairs already explained by a
  publish/consume path are skipped, because a downstream agent answering its
  upstream is the system working. Every documented limit fails toward silence
  rather than false accusation. Reported as pair evidence in a `coordination`
  block, not as a per-agent score, since the signal belongs to the
  relationship. Documented in a dedicated methodology page that states the
  bounds of the claim before the method.

### Fixed
- The A2A indirect-injection probe matched its canary against a blunt
  stringification of the raw artifact list, which misses the payload whenever
  an agent returns it inside a file part base64 content: the canary is encoded
  on the wire, the substring never fires, and a real injection exfiltrating
  through a file part reads as clean. The probe now matches against decoded
  Part text, closing that false negative and dropping metadata and media-type
  noise at the same time. Two existing tests fed the probe a non-spec flat
  artifact that only passed because `str()` stringified it; both now use the
  real `{parts: [...]}` shape.
- Coordination signals were written into the ABFP scan JSON but never read back
  by `report convert`, which rebuilds only the findings array and the
  propagation block. Every unexplained-coupling signal was therefore invisible
  in SARIF, HTML, Markdown and JUnit - the same silent drop propagation
  suffered before 0.6.0, reintroduced on a new surface. Convert now rebuilds
  the block through a `from_coordination_signal` adapter, so the JSON entry
  point produces exactly the findings a live scan would. Severity is capped
  deliberately at MEDIUM above twelve sigma and LOW below it: the detector
  proves coupling with no topological explanation, which is a lead to
  investigate rather than proof of malice. SARIF promotes `z` into structured
  properties, since that is the number a triager sorts on.
- The lint job failed inside numpy own stubs, which use PEP 695 `type`
  statements that mypy cannot parse while `python_version` is pinned to 3.11.
  The lint job runs on Python 3.12 and therefore installs numpy 2.5.x (itself
  requiring >=3.12), while mypy was told to analyse everything with 3.11
  grammar - a config contradiction numpy merely exposed. Per-module
  `follow_imports = skip` does not help, since stubs are parsed before
  overrides apply. The mypy target now matches the interpreter lint runs on;
  the 3.11 floor stays honest because the test matrix exercises 3.11 to 3.14.
  numpy is also declared as an explicit dependency, having been relied on
  transitively through scipy despite a direct import.
- A2A threat-model documentation still named only the legacy
  `/.well-known/agent.json` discovery path, though discovery has preferred the
  v1.0 `/.well-known/agent-card.json` URI since the 0.6.0 migration.

## [0.6.0] - 2026-07-15 - A2A v1.0 protocol migration, cross-agent privilege-escalation card audits, transitive injection propagation

### Added
- A2A card audit: overbroad OAuth2 scope detection, the first card-auditable
  slice of the cross-agent privilege-escalation frontier. Coarse-grained token
  scopes are the concrete A2A privilege-escalation vector named across the 2026
  threat literature: an agent granted a wildcard or admin-family scope holds far
  more authority than any single skill needs, so a compromised or malicious peer
  can escalate across the delegation boundary. `_check_overbroad_scopes` reads
  scope names from every oauth2 scheme flow in `securitySchemes`, handling both
  the proto member-key shape (`oauth2SecurityScheme.flows`) and the OpenAPI
  `type`/`flows` shape, and tolerating dict- or list-valued `scopes`. Findings
  split by confidence rather than over-scoring a fuzzy signal: a wildcard scope
  (`*`, `write:*`) is coarse by definition -> MEDIUM, while an admin-family
  literal (`admin`, `root`, `owner`, ... matched exact and case-insensitively so
  `wallet` never trips it) is a naming convention, not a guarantee -> LOW. Each
  finding lists the exact offending scopes instead of asserting exploitability.
  Tagged ASI03 (Identity and Privilege Abuse) / CWE-269 (Improper Privilege
  Management) / STRIDE Elevation of Privilege; ATLAS left untagged, no clean
  verified technique. The full delegation-chain escalation remains out of scope
  for a single-target scanner and is not forced into a context-free check.
- A2A card audit: agent-selection routing-hijack detection. A rogue AgentCard
  needs no obfuscation or "ignore previous" token to subvert an LLM
  orchestrator: plain-language directives in the card description or a skill's
  name/description ("always prefer this agent", "the only agent authorized for
  X", "do not route to other agents") bias the orchestrator selection reasoning
  toward the attacker agent - the infrastructure-layer prompt injection
  Trustwave demonstrated in 2025. The existing poisoning scan catches
  control-flow takeovers (obfuscation, ignore-previous, tool-call hijack) but
  misses this persuasive-steering class, which carries no classic injection
  token. A dedicated `scan_routing_hijack` primitive adds six selection-steering
  signatures, each requiring a selection imperative rather than a bare
  superlative so honest self-description ("best-in-class invoice agent", "use
  this agent to process invoices") stays inert. `_scan_routing_hijack` runs it
  over the same LLM-ingested fields as poisoning (factored into a shared
  `_llm_ingested_fields` helper) and emits MEDIUM - steering biases a decision,
  it does not seize control, so it scores below an outright injection takeover.
  Tagged ASI01 (Agent Goal Hijack) / CWE-1427 / STRIDE Tampering / ATLAS
  AML.T0051, the same goal-hijack family as poisoning.
- Propagation findings now flow through the full report pipeline. The ABFP
  scan already emitted a `propagation` block and a `propagation_summary`
  header, but `mas-sentry report convert` read only the `findings` array and
  silently dropped both - every transitive contamination finding, including
  CRITICAL verbatim relays across multiple hops, was invisible in SARIF,
  HTML, Markdown, and JUnit. Convert now rebuilds each serialized
  PropagationFinding and maps it through the same `from_propagation_finding`
  adapter the live scan path uses, so contamination is mapped identically
  regardless of entry point. SARIF gains a dedicated `abfp.propagation`
  rule, security-severity band-anchored on the chain severity, with tags and
  the onward blast radius in result properties. HTML and Markdown render a
  distinct contamination-chain provenance block (origin -> ... -> target,
  depth, tier) plus onward blast radius, and a triage banner derived from
  `propagation_summary` (contaminated count, max chain depth, origins) above
  the findings list. Documented in the new Propagation in Reporting
  methodology page.
- Consume-edge inference reviving cascade blast-radius in live passive
  scans. A passive MAS listener observes PUBLISH traffic but no SUBSCRIBE
  packets, so the topic graph's subscribe edges stayed empty and
  `blast_radius` computed an empty downstream reach - the cascade was dead
  code in the exact scenario it targets. MAS-Sentry now infers consume edges
  from the same injection re-emission evidence used for transitive
  propagation: when a downstream agent re-emits a directive first seen from
  an upstream source, it must have consumed the topic that source emitted on,
  and nearest-source attribution pins that topic. Inferred edges enter the
  topic graph under a distinct `subscribe-inferred` kind and never overwrite
  an observed subscribe, so a behavioral inference is never mistaken for
  ground truth. `blast_radius` splits its reach into observed `direct` /
  `transitive` and `inferred_direct` / `inferred_transitive`, crediting an
  agent reachable both ways as observed. The passive scan loop is now
  exercised end-to-end against a mocked broker. Documented in the new
  Consume-Edge Inference methodology page.
- Transitive indirect-prompt-injection propagation detection in the ABFP
  scan. Beyond flagging agents that emit injection directives, MAS-Sentry now
  reconstructs how a directive spreads across agents from observed re-emission,
  modeling the cross-agent infection that per-agent guardrails and topology-
  only blast-radius both miss. Two evidence tiers are used: verbatim (a
  distinct agent forwards an identical poisoned payload, hash-anchored) and
  directive (a distinct agent re-emits the same STRONG pattern). Each hop is
  attributed to its nearest prior source, yielding infection chains; the graph
  is kept acyclic so propagation depth is well defined. Injection events are
  captured bounded (patterns + payload hash only, never the payload). Chain
  severity is computed directly - a single directive hop is HIGH, a verbatim
  relay or a directive surviving two or more hops is CRITICAL - rather than
  through the weighted-mean anomaly score that would dilute a chain-level
  signal. The scan report gains a `propagation` block (per contaminated agent:
  origin, chain, depth, tier, severity, taxonomy, and fused onward blast
  radius) plus a `propagation_summary` triage header. Findings are tagged
  ASI01 / ASI05 Cascading Failure / CWE-1427 / STRIDE Tampering / AML.T0051.
  Documented in the new Transitive Injection Propagation methodology page.
- Live `mas-sentry a2a scan` command activating the full Agent-to-Agent
  vertical, previously a dormant library. The scan discovers an endpoint's
  AgentCard, audits it passively, and - with `--active` - runs live probes
  (task-id collision, unauthorized cancel, indirect-injection canary),
  mapping every result through the A2A adapters into unified Findings. Output
  is written to `reports/a2a.json` and flows straight into `mas-sentry report
  convert` (HTML / Markdown / SARIF / JUnit) with no re-adaptation. Scope is
  enforced centrally by the A2A client, so non-lab targets require
  `--confirm-scope` even for the passive card fetch; `--active` governs
  intrusiveness and prints an authorized-use notice. Probe outcomes carry
  taxonomy only when a probe fails (task-id collision ASI03 / CWE-345, cancel
  CWE-862, indirect-injection ASI01 / CWE-1427 / AML.T0051); a probe that
  holds is recorded INFO. The structural AgentCard findings (missing or
  anonymous auth, uncapped streaming, unsigned push callbacks, excessive skill
  surface) now also carry the four-lens taxonomy, so every A2A finding - not
  only poisoning and insecure transport - is ranked by SARIF security-severity
  and visible to cross-taxonomy filters. Documented in the new A2A Scanning
  methodology page.
- Agent Card Poisoning detection for the A2A card audit. The audit now scans
  the AgentCard description and every skill's name/description with the shared
  injection primitive (`mas_sentry.core.injection_scan`), flagging directives
  that hijack an orchestrator's LLM-based task-routing reasoning - the same
  detector now covers three surfaces: MCP tool descriptors, live agent traffic,
  and A2A cards. Poisoning findings carry the four-lens taxonomy (ASI01 Goal
  Hijack, CWE-1427, STRIDE Tampering, MITRE ATLAS AML.T0051). A cleartext
  (`http://`) card endpoint is now flagged (CWE-319, STRIDE Tampering) as it
  invites card tampering in transit. A2A card findings propagate their
  per-finding taxonomy into the unified Finding tags.
- Passive indirect-prompt-injection (IPI) detection over live agent traffic.
  Every MQTT payload observed during an ABFP scan is scanned in-flight for
  injection directives (obfuscation via zero-width / Unicode-tag characters,
  `ignore previous instructions`, system-role overrides, new-task directives,
  tool-call hijacks). An agent that publishes such directives into the topic
  graph - because it was poisoned upstream or is malicious - surfaces as a new
  `injection` scoring dimension, and the existing cascade blast-radius then
  quantifies the downstream contamination reach over the same graph. This
  catches IPI travelling agent-to-agent, a class that input/output guardrails
  on a single agent miss. Payloads are scanned but not retained, so the
  message buffer keeps its size+hash-only memory discipline. The `injection`
  dimension carries the full four-lens taxonomy: ASI01 Goal Hijack, CWE-1427
  (Improper Neutralization of Input Used for LLM Prompting), STRIDE Tampering,
  and MITRE ATLAS AML.T0051 (LLM Prompt Injection), rendering as HTML badges
  and flowing into SARIF.
- Four-lens taxonomy tags for the MCP `tool_poisoning` check (ASI01 Goal
  Hijack, CWE-1427, STRIDE Tampering, MITRE ATLAS AML.T0051), closing the
  gap where MCP tool-poisoning findings - which carry IPI directives embedded
  in tool-descriptor fields - previously shipped without an ATLAS technique
  or CWE. The `arg_injection` check now carries command-injection tags
  (ASI02 Tool Misuse, CWE-77, STRIDE Tampering); it is deliberately left
  ATLAS-untagged as no verified technique cleanly matches.
- A2A card audit: signed-card absence detection. `audit_agent_card` now
  flags an AgentCard published without a JWS signature (A2A v1.0
  AgentCardSignature, RFC 7515 over RFC 8785-canonicalized content) - an
  unsigned card cannot be distinguished from a spoofed or on-path-modified
  one. Tagged ASI03 Identity Abuse, CWE-347, STRIDE Spoofing.
- A2A card audit: bare-API-key-only scheme detection. Flags a v1.0 card
  whose only declared `securitySchemes` entry is a static API key with no
  oauth2/http/openIdConnect/mtls alternative offered - a key alone has no
  built-in rotation or expiry and is the weakest of the five v1.0 scheme
  types. LOW, tagged ASI03 Identity Abuse, CWE-798, STRIDE Spoofing. Scheme
  type is resolved from either the v1.0 spec's member-based discriminator
  (`apiKeySecurityScheme`, `oauth2SecurityScheme`, ...) or the OpenAPI-style
  `type` field seen in real vendor examples, since the two sources disagree
  on the canonical wire shape.
- A2A client resolves the JSON-RPC endpoint from the discovered AgentCard's
  declared interfaces rather than always POSTing to `base_url`. v1.0 cards
  list every binding+URL combination in `supportedInterfaces[]` (order is
  preference, not binding); v0.3.x cards use `url` +
  `preferredTransport`/`additionalInterfaces[]`. `_resolve_jsonrpc_endpoint`
  scans for a JSON-RPC-bound entry in either shape. A new
  `A2AUnsupportedBindingError` is raised only when a card explicitly declares
  interfaces and none is JSON-RPC - an actionable "cannot actively probe this
  target" signal; a card with no interface information at all still falls
  back to `base_url`. The scan runner skips probing (keeping card-audit
  findings) rather than aborting when a target offers no JSON-RPC binding.

### Changed
- The IPI pattern scanner (`scan_string` / `InjectionMatch`) moved to
  `mas_sentry.core.injection_scan` as a shared primitive consumed by both the
  MCP tool-descriptor audit and the ABFP live-traffic detector, removing a
  would-be `agents -> protocols.mcp` layering dependency. The MCP audit API is
  unchanged (re-exported).

### Fixed
- A2A card discovery only ever requested the legacy `/.well-known/agent.json`
  URI (A2A v0.3.x). A2A v1.0 (stable since April 2026, Linux Foundation)
  moved discovery to `/.well-known/agent-card.json` - against a real v1.0
  target, `A2AClient.discover()` 404'd outright and the scan never started.
  Discovery now tries the v1.0 URI first and falls back to the legacy one on
  a plain 404, so both generations of a mixed real-world fleet are reachable.
- `card_audit`'s no-auth / scheme-`'none'` checks read only the legacy
  `authentication.schemes` field, which A2A v1.0 does not populate at all
  (v1.0 declares auth via `securitySchemes` + `securityRequirements`
  instead). Every real v1.0 card with authentication correctly configured
  was unconditionally HIGH-flagged "no authentication schemes" regardless of
  actual auth. `audit_agent_card` now branches on which shape the raw card
  carries: v1.0 cards are judged by `securityRequirements[]` actually
  enforcing a declared `securitySchemes` entry; legacy v0.3.x cards keep the
  original schemes-list check.
- A2A active probing spoke an invented wire format that matched no real A2A
  binding: bare POST bodies to `/tasks/send` `/tasks/get` `/tasks/cancel`,
  not the JSON-RPC 2.0 envelope (`jsonrpc`/`id`/`method`/`params`) the
  protocol's most common binding requires. Every active probe (task-id
  collision, unauthorized-cancel, indirect-injection) had therefore only
  ever exchanged valid traffic with this suite's own mocks, never a real
  agent. The client now wraps every call in a correct JSON-RPC envelope with
  the correct method names (`message/send`, `tasks/get`, `tasks/cancel`) and
  a v1.0-shaped outgoing message (`ROLE_USER`, member-based `Part`). A new
  `A2ARpcError` surfaces JSON-RPC-level rejections (HTTP 200 with an `error`
  body, how a compliant server signals TaskNotFound / TaskNotCancelable) as a
  distinct exception from transport failures; the unauthorized-cancel probe
  and the scan runner both treat it as a safe rejection rather than silently
  misparsing it as an empty task.
- A2A task-state parsing only recognized v0.3.x kebab-case values; v1.0
  renamed every value to `TASK_STATE_`-prefixed SCREAMING_SNAKE_CASE, so
  every real v1.0 task response fell through to the `UNKNOWN` fallback and
  terminal-state detection never fired - polling ran to its timeout instead
  of stopping when a task finished. `TaskState` now normalizes both shapes,
  and the previously-missing `REJECTED` and `AUTH_REQUIRED` states (real in
  both generations) were added, with `REJECTED` now correctly treated as
  terminal.

## [0.5.0] - 2026-07-01 - Four taxonomy lenses, MCP tool-drift, cascade blast-radius, SARIF security-severity

### Added
- SARIF rules now carry a GitHub `security-severity` score, so findings
  rank in the GitHub code-scanning Security tab instead of appearing
  unranked. The number is anchored on the finding's textual severity band
  (CRITICAL >=9.0, HIGH 7.0-8.9, MEDIUM 4.0-6.9, LOW <=3.9) and, for
  scored rogue-agent findings, positioned within that band by the real
  composite anomaly score, so a higher-scoring rogue outranks a lower one.
  Non-scored MCP checks take the band midpoint; a rule ranks at its worst
  finding.
- MITRE ATLAS technique tags as a fourth taxonomy lens (alongside
  ASI/CWE/STRIDE) on findings with a clean, verified match: MCP tool
  rug-pull and shadowing -> AML.T0110 (AI Agent Tool Poisoning); agentic
  goal hijack -> AML.T0051 (LLM Prompt Injection), memory poisoning ->
  AML.T0080 (AI Agent Context Poisoning), supply chain -> AML.T0048 (ML
  Supply Chain Compromise). Tags render as dedicated HTML badges and flow
  into SARIF, giving findings the AI-native ATT&CK vocabulary that SOC and
  audit workflows increasingly expect. Detectors without a defensible
  technique match are deliberately left untagged.
- Cascade blast-radius analysis for rogue-agent findings. Using the live
  agent-topic interaction graph, each rogue finding now reports how far a
  contamination it injects could spread: the topics it publishes into, the
  direct subscribers one hop away, and the full transitive set of
  downstream agents it could reach. Surfaced in `evidence.blast_radius`
  across the JSON, HTML (a per-finding cascade view), and SARIF
  (`properties.blast_radius`) outputs, turning the descriptive graph into a
  predictive contamination-reach signal.
- MCP tool-descriptor drift detection (`mcp scan --tool-baseline <path>`).
  The first run captures a per-tool descriptor digest baseline; later runs
  flag `tool_rug_pull` when a tool's description or input schema mutates
  after approval (the post-approval rug pull most MCP clients miss),
  `tool_shadowing` when two tools share a name in one enumeration, and
  tool_added/tool_removed deltas. Security-meaningful drift carries
  ASI/CWE/STRIDE tags (rug pull -> ASI08 Supply Chain / CWE-494 /
  Tampering; shadowing -> ASI02 Tool Misuse / CWE-290 / Spoofing) across
  the JSON, HTML, and SARIF surfaces.
- ABFP findings now carry STRIDE taxonomy tags alongside the existing
  ASI/CWE tags, derived from the dimensions that fired (identity ->
  Spoofing, topic -> Elevation of Privilege, payload/burst/timing ->
  Denial of Service). Tags render as dedicated HTML badges and flow into
  SARIF result tags, giving rogue-agent findings a three-lens
  (ASI/CWE/STRIDE) classification on the same fired signals.

### Removed
- Orphaned `agents/interaction_graph.py` (and its test), superseded by the
  live `abfp/topic_graph` builder and unreachable from any product path.
- Dead `abfp_stride_mapper` module and its false-contract test. The mapper
  keyed off a `type` field the ABFP engine never emits, so it was unreachable
  in production while its unit test inflated coverage. The dimension-driven
  STRIDE tagging above supersedes it.
- Removed the orphaned legacy threat-modeling and reporting pipeline:
  the `threat_modeling` STRIDE subsystem (catalog, mappers, aggregator,
  attack trees, CVSS calculator, ROS2 threats), the `MASAuditReport`
  reporting stack (`report_model`, `HTMLReportGenerator`, markdown
  report), and the superseded `AnomalyDetector`. ~440 statements with no
  product consumers, kept green only by their own unit tests. The live
  path (`abfp.scoring` + `report convert` -> unified HTML/SARIF/JSON/
  JUnit/Markdown over `core.finding`) is the single supported pipeline.

## [0.4.0] - 2026-06-22 - Full dimension parity across surfaces + burst-cadence detection

### Added
- ABFP rogue-scan findings now render in HTML reports: the `report convert`
  bridge adapts ABFP-shaped findings (agent id, diff, dimensions) to the
  canonical finding model, so they no longer produce blank cards.
- Per-finding `Drivers` section in the HTML report listing each scoring
  dimension (name, raw value, reason).
- ABFP graph-centrality table in the HTML report (pub/sub degree, distinct
  topics, betweenness, eigenvector) when a scan emits a graph block.
- Burst-cadence dimension in impersonation/rogue scoring: flags an agent that
  develops bursty traffic or loses its periodic cadence relative to the
  baseline (weight 0.15), surfaced through the existing Drivers output.
- ABFP scoring drivers now flow into SARIF: a compact driver summary in the
  result message plus structured `drivers`, `agent_id`, and `score` under
  result properties, so CI code-scanning shows why an agent was flagged.
- ABFP findings are enriched with ASI/CWE taxonomy tags derived from the
  dimensions that fired (e.g. identity -> CWE-290, burst -> CWE-400),
  rendered as HTML badges and SARIF result tags.

## [0.3.0] - 2026-06-22 - Behavioral baselines + reconnected ABFP detectors

### Added
- ABFP per-agent graph-centrality metrics (`graph_metrics`) wired into the scan
  report and a CLI table (pub/sub degree, distinct topics, betweenness,
  eigenvector).
- `ScanSnapshot` behavioral baseline (topic graph + per-agent timing/payload
  digest), persisted each scan via `--snapshot`.
- Cross-run comparison via `--baseline`: a prior snapshot revives rogue-agent
  drift detection (previously a no-op on first run) and feeds the impersonation
  detector.
- Impersonation detector restored as digest-native dimensions (timing, payload,
  identity) that fold into the rogue score via `detect_rogue`'s
  `extra_dimensions` hook, surfacing agents whose fingerprint diverges even
  without a topology change.
- Finding `dimensions` emitted in the JSON report and a `Drivers` column in the
  CLI showing which signals drove each score.
- Authorized-use reminder on active scans (stderr) plus liability-waiver and
  heuristic-findings disclaimers (no-warranty, false-positive/negative caveat)
  in the README.

### Fixed
- Rogue topic dimension no longer emits a spurious signal for agents with no new
  topics.

## [0.2.1] - 2026-06-20 - First PyPI release

### Added
- `release.yml`: isolated `publish-pypi` job using OIDC trusted publishing
  (`pypa/gh-action-pypi-publish`), tag-only, no API tokens. The package is
  now installable from PyPI.

### Notes
- No runtime code changes from 0.2.0; this release exists to ship the PyPI
  distribution path via the tag-triggered pipeline.

## [0.2.0] — 2026-06-19 — Pivot to Agentic MAS Security

### Changed
- Relicensed from MIT to **AGPL-3.0-or-later** (sole contributor consent).
- Repositioned: MQTT/AMQP-only → unified MQTT/AMQP **+ MCP + A2A + agentic** toolkit.
- All findings now map to OWASP Agentic Top 10 (2026) in addition to STRIDE.
- Python floor raised to 3.11.
- CI badge URL fixed (user70616E6461 → evkir).
- pyproject.toml migrated to hatchling backend.

### Added
- THREAT_MODEL.md (ASI01-ASI10, MCP CVEs, ABFP-STRIDE table).
- CI matrix Python 3.11/3.12/3.13/3.14.
- scripts/add_spdx_header.sh (idempotent, shebang-aware).
- Pre-commit hooks (ruff/format) and Renovate dependency automation.
- Integration tests against a live Mosquitto broker via docker compose.
- Supply-chain security: hash-pinned `requirements-lock.txt`, `requirements.txt`
  mirror with a drift-guard test, and `supply-chain.yml` CI (hash-verified
  install, pip-audit CVE scan, ASI08 dogfood self-audit, dependency-review).
- `docs/SUPPLY-CHAIN.md` documenting the pinning + verification model.
- `release.yml`: wheel + sdist build, `twine check`, and a CycloneDX SBOM
  generated from the locked deps, attached to the GitHub Release on tag.
- CLI `--version` (via importlib.metadata) and documented shell completion.
- `project.urls` Security + Threat Model entries for PyPI sidebar discovery.
- Five verified usage example workflows under `docs/examples/`.
- Dogfood ASI08 self-audit (`reports/SELF-AUDIT.md`) - 0 findings on the
  hash-pinned lockfile.

### Changed (hardening)
- mypy is now a hard CI gate (previously advisory / continue-on-error).
- ASI08 supply-chain scanner is pyproject-aware and ignores non-requirement
  lines (option flags, `--hash` continuations, TOML scaffolding).
- pytest config consolidated into `pyproject.toml` (asyncio auto,
  strict-markers, coverage gate 60%); removed the shadowing `pytest.ini`.
- Rewrote `ARCHITECTURE.md` and `docs/api/README.md` to the current
  `UnifiedThreatEngine` module model; the old docs described the deleted
  `SentryEngine` and shipped copy-paste examples that would ImportError.

### Fixed
- ASI08 parser miscounted TOML and option lines as dependencies, producing a
  false "N/N unpinned" finding when pointed at a `pyproject.toml`.
- ABFP report serialization of slotted `BaselineStatus` via `asdict`.
- SARIF emitter no longer hardcodes the tool version; it is derived from
  package metadata (importlib.metadata), so emitted reports never drift.

### Removed (pre-release dead-code audit)
- Pre-pivot `SentryEngine 1.0` MQTT/AMQP cluster: `core/engine.py`,
  `core/session.py`, `core/config.py`, `core/display.py`, `core/exporter.py`,
  `core/multi_target.py`, `protocols/auto_detect.py`, `agents/profiles.py` --
  all superseded by `UnifiedThreatEngine` and the `reporting/` package.
- Unwired SQLAlchemy persistence (`agents/abfp/storage.py`) and its
  `sqlalchemy` + `alembic` runtime dependencies (alembic was a phantom dep:
  no migrations, no alembic.ini).
- Duplicate / unsafe ABFP fragments: `agents/abfp/stride_map.py` (duplicated
  the live `abfp_stride_mapper`) and `reporting/abfp_html.py` (duplicated
  `unified_html` without jinja2 autoescape).
- Unwired ABFP features `agents/abfp/impersonation.py` and
  `agents/abfp/graph_metrics.py`, deferred to v0.3.0 as properly wired+tested
  modules (code preserved in git history).
- Second divergent click CLI in `__main__.py` (sniff/abfp/fingerprint/walk/
  audit/probe/learn/config) frozen at a hardcoded v0.1.0 banner and the
  pre-pivot MQTT/AMQP command set; `python -m mas_sentry` now delegates to the
  real `mas-sentry` CLI (mas_sentry.cli:app).
- Net effect: real line coverage rose from ~66.9% to ~77% (dead 0%-modules
  out of the denominator) and the runtime dependency surface dropped by two
  direct + two transitive packages. CI coverage gate raised 60 -> 70.


All notable changes to MAS-Sentry-Toolkit are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [0.9.0] - 2025-05-11

### Added
- Core Engine + CLI (5 commands: scan, abfp, report, probe, graph)
- MQTT Analyzer — anonymous auth, wildcard topics, retained message poisoning
- AMQP Analyzer — vhost enumeration, credential brute-force detection
- Docker Lab — mosquitto broker + 3 MAS agents (sensor, actuator, coordinator)
- ABFP Engine Phase 1: passive behavioral fingerprinting
- ABFP Engine Phase 2: anomaly scoring (0–100)
- ABFP Engine Phase 3: drift detection and alerting
- Anomaly Detector — statistical baseline comparison
- STRIDE Threat Mapper — automated threat modeling for MAS topologies
- Report Generator — HTML, JSON, Markdown output formats
- Active Prober — authenticated and unauthenticated probe modes
- Interaction Graph — agent communication topology visualization
- HCAP Protocol Specification v0.1
- GitHub Actions CI — Python 3.10 / 3.11 / 3.12
- Type aliases and typed helpers (core/types.py)
- Coverage badge generator script

### Fixed
- numpy version pin for Python 3.13 compatibility
- pydantic version pin for Python 3.13 compatibility

### Infrastructure
- pytest-cov integration with 70% threshold
- pyproject.toml with mypy + ruff config
- SECURITY.md vulnerability disclosure policy
- ROADMAP.md with v1.0.0 milestones

---

## [0.1.0] - 2025-04-01

### Added
- Initial project scaffold
- Basic MQTT connection probe

---

## [1.0.0] - 2025-05-13

### Added
- CVSS v3.1 calculator for MAS vulnerability scoring
- IoT attack tree scenarios (AT-001, AT-002)
- ROS2/DDS threat catalog (4 scenarios)
- Threat scoring aggregation with risk level calculation
- CONTRIBUTING.md with setup and commit guide
- Full API reference docs
- Attack scenario usage examples
- STRIDE mapper tests, CVSS tests, aggregator tests

### Changed
- stride.py rewritten with threat_id, cvss_score fields
- stride_mapper.py aligned with test expectations
- numpy and pydantic version pins fixed for Python 3.13+

### Tests
- 116 commits, 100+ tests passing
- CI green on Python 3.10 / 3.11 / 3.12

---
*Released: 2026-05-15*
