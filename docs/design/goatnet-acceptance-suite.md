# Goatnet e2e acceptance suite — every provisioned aspect proves itself live

**Status:** built (ADR [1115](../adr/1115-goatnet-e2e-acceptance-suite.md)): 78 rows,
the runner, value derivation, standup phase 13 in both avenues, and the verb
`goatbuilder assay <site>` (2026-10-29), and every probe type in the library,
`oidc-flow`, `bus-roundtrip` and `enroll-probe` included (§"The three live-plane
probes"). Not built:
the ledger watcher (v2).

## The assay: prove a goatnet was built correctly

`goatbuilder assay <site>` runs every row that applies to the site against
values derived from its own group_vars, and grades the goatnet layer by layer.
It is standup phase 13 as a command of its own (`goat-standup.sh` and
`goatbuilder standup` run the same two commands, under the standup parity gate),
so a goatnet can be re-proven at any time after it is built.

```text
goatbuilder assay dev                                        # every applicable row, a table per layer
goatbuilder assay dev --var probe_via=operator@<host>        # run the goat CLI rows where a context is
goatbuilder assay dev --only goat-health-time                # one row after a fix
goatbuilder assay zagros --values <fixture values> --plan    # which rows apply; probe nothing
```

Exit 0 only when every applicable row is PASS; 3 while any row FAILs or is
UNKNOWN, or none passed (GB-048); 1 when it cannot run (GB-049). The same
commands without the binary:
`python3 ops/validation/generate-values.py <site> && python3 ops/validation/run-acceptance.py --env <site> --values ops/validation/values-<site>.yaml --all-eligible --by-layer`.

**Layers and rows** (layer = the first segment of a row's `aspect`):

| Layer | Rows | What the rows prove |
|---|---|---|
| host | 8 | data root on its declared mount, operator SSH per class, unattended boot, the node's own connection inventory (`goat health --domain net`) |
| mgmt-stack | 6 | NetBird service identities, management API with and without a token, signal TLS, the enrolment entrypoint's certificate |
| dns | 3 | every declared service resolves to its host; the name snapshot is served; the mesh's fallback answer for the enrolment name is this goatnet's own relays |
| relays | 3 | each relay's certificate is trusted for the enrolment name (443) and on the relay port |
| mesh | 3 | `goat health --domain mesh` green and fresh; the declared ACL assertions hold (`goat acl test`) |
| identity | 4 | a login starts for the NetBird dashboard and for every running fence's client; admin fences enforce; the roster an operator reads (`goat who`) |
| fabric | 13 | router identity and storages, a mesh beat under the site's own key, `goat status` chain, a `goat hello` round trip, a put/subscribe round trip, presence, fabric and presence health, the adminspace refuses a write |
| time | 1 | `goat health --domain time` green and fresh |
| observability | 6 | scrape targets up, alert rules loaded, Alertmanager reached, the deadman firing and routed outside |
| deploy | 2 | every declared component's ledger names main's ref (`goatbuilder diff`); `goat health --domain consistency` |
| federation | 9 | joiner only: replication both ways, seeded from the founder, a sample from the joiner received through the founder's router, site-local tables kept out of the replicated set |
| others | 20 | onboarding intake and review gate, portal, microscope, surfaces, services, audit, data, rescue nodes, enrolment |

Four rows are **must_refuse** negatives, each paired with the positive that
proves the path was carrying (mgmt API without a token, the default certificate,
an adminspace write, site-local tables).

**The goat CLI rows** (`probe: goat-cli`, twelve) run the operator's own binary
with its JSON output: `goat status --json`, `goat hello --json`, `goat presence
--json`, `goat health --domain <d> --json` for fabric, mesh, presence, time, net
and consistency, `goat who --once`, `goat acl test --json`, and `goatbuilder
diff`. The rows that read the fabric need a goat context holding this
goatnet's fabric identity: `probe_context` on `probe_via`, which is the
goatnet's own probe identity where it declares one (below) and otherwise the
operator's `goat_context` on the operator's own machine. A management host
never holds an operator context for these rows: there, a goatnet with no probe
identity reads UNKNOWN. The probe grades the probe's own locus apart from the goatnet. Only
an answer from the goatnet is FAIL; a probe that could not speak for it is
UNKNOWN with the reason:

| goat says | Code (exit) | Grade |
|---|---|---|
| no profile, no identity, expired probe certificate, own clock wrong | `E_PROFILE_*`, `E_TOKEN_INVALID`, `E_BUNDLE_INVALID`, `E_CERT_EXPIRED`, `E_CLOCK_SKEW` | UNKNOWN |
| off the mesh, the router or portal never reached | `E_OFF_MESH`, `E_ROUTER_UNREACHABLE`, `E_PORTAL_UNREACHABLE` | UNKNOWN |
| a goat older than the row's `min_goat` (default 0.5.4), or one without the verb or flag | — | UNKNOWN, naming `goat update` |
| the portal answered 404, 429, 5xx, or refused | `E_PORTAL_NOT_FOUND`, `E_PORTAL_RATE_LIMITED`, `E_PORTAL_SERVER_ERROR` (7, 8, 9), `E_PORTAL_REFUSED`, … | FAIL with the code |
| a clean exit whose JSON does not satisfy the row | `expect_jq` false | FAIL |
| an answer that cannot grade the row either way (an empty presence set: idle, or a silently denied query, F-177) | `unknown_jq` true | UNKNOWN, with the row's `unknown_reason` |
| a verb whose exit code summarises legs the row grades one by one (`goat status`) | `expect_rc: graded-by-json` | the JSON decides; no JSON is FAIL |

A goat older than #2111 prints no code; its exit decides (3–6 UNKNOWN, 7–9 FAIL).
A health beat nobody publishes is FAIL, never green. A control-node Python
probe runs under the assay runner's own interpreter (which imports PyYAML), and
a module missing on the probing machine is UNKNOWN with X-PY-001, never a FAIL
of the goatnet.

### The probe identity

The assay speaks for the goatnet as a non-person: the fabric leaf
`CN=goat-assay-probe-trial-peer`, installed as the goat context `assay-probe` on
the goatnet's first management machine. A person's context is the wrong tool for
an unattended probe — a person's fabric slot comes from three-stage onboarding,
approved by a second admin, and carries that person's writes and attribution —
so the probe is an infra peer like fabric-health or mesh-health.

| Fact | Where |
|---|---|
| Declared | `assay_probe_enabled: true` in the goatnet's `group_vars/<site>_hosts/vars.yml`; `generate-values.py` then sets `probe_context: assay-probe` and `probe_via: <first-mgmt-node>` |
| Leaf | row `assay-probe` in `ops/enrollment/manifests/<site>-certs.yaml`, URI `urn:goat:<site>:infra:assay-probe`, from the goatnet's offline CA |
| Read | the universal read (on a partitioned goatnet, the CN in `zenoh_universal_read_cns`), which keeps the operator-audit deny |
| Write | rule `infra-w-assay-probe`, bound alone to subject `infra-assay-probe` (roles/goat-zenoh): `hello/assay-probe` and `volatile/goat-assay/**`, nothing else |
| Portal, NetBird | none: the context's `portal.token` is an empty file (goat requires the file to exist), so requests carry no key; every row it runs reads the portal's public endpoints or degrades without one |
| Installed | `ops/scripts/create-assay-probe-identity.sh <site>`: mints the leaf (idempotent), writes the context on the management machine over ssh with the key in a 0600 file, and proves it with `goat --context assay-probe status --json`. Operator-run, never a playbook side effect |
| Revoked | `create-assay-probe-identity.sh <site> --revoke` removes the context; the ACL half is the CN leaving the universal read and the subject, then a router deploy |
| Gated | `ops/ci/check-assay-probe-identity.py` (coupled-fact-guards): a goatnet that declares the probe carries all four facts above |

ADR 1207 names non-person acceptance identities as one concept with two
halves, and this is the fabric half. The other is the portal sponsor identity
`goat-acceptance` (context `acceptance`, browse-capped), which the rows that
mint an invite (the intake smoke) run as, through `goat_sponsor_context`.

`--var probe_context=… --var probe_via=…` points one run at another context; a
`--var goat_context`/`goat_via` on the run also moves the fabric rows to that
context.

**Rehearsed** on the Hello Galaxy fixtures (`--values …/assay-values.yaml
--plan`, tutorial checkpoints) and, against a real portal, console and router,
in the goat CLI e2e suite (`ops/e2e/suites/goat/run.sh`, the `assay-*` cases).
Every probe type, the goat CLI probe included, is proven red then green by
`run-acceptance.py --self-test` in CI (`acceptance-pairings.yml`).

## The three live-plane probes

**`oidc-flow`** proves the identity plane the way a browser uses it, without a
person. Discovery names the issuer and its JWKS has signing keys; each named
client exists in Hydra (the admin API on the host's loopback, read once) and the
authorization endpoint *starts a login* for it: a redirect carrying a
`login_challenge`, and the login UI answers. The negative: the authorization
endpoint refuses a client nobody registered. Optional legs read a consumer's
config (`assert_nonempty` + `config_file`: NetBird's `HttpConfig.AuthIssuer` and
`AuthAudience` set, the issuer matching) and mint a client-credentials token
(`token_client` + `token_secret_env`, a wrong secret refused).
`clients_from_containers: true` takes the clients from the running fences, every
container whose `*CLIENT_ID` env names a client of this issuer, so the row
follows what is deployed. Writes only login requests that expire unused.

**`bus-roundtrip`** proves the fabric carries a sample to a reader under the key
it should. `subscribe: <key>` waits for one sample and checks `expect_field` on
its payload (a JSON object, or EnvHealthV1 protobuf, whose `scope` is the
`site`); `publish: true` publishes a nonce on a volatile key and reads it back.
It goes through the operator's `goat` CLI when a context speaks for the goatnet,
else through the router's REST plugin on the host's loopback (server-sent
events); the evidence names which. Nothing heard by the deadline is FAIL.

**`enroll-probe`** is Gate 1's fresh peer (`fresh-peer-probe.sh`, F-188): a
throwaway NetBird client container enrols with an ephemeral one-off setup key it
mints, a peer with a made-up key must get no address, the enrolled peer reaches
the management host across the mesh, and then the containers, the peer and the
key are removed and the peer is confirmed gone. A cleanup that fails is a FAIL
naming what was left. It writes, so it runs only when asked:
`--var enroll_probe=1 --var enroll_peer_host=<docker host>` with
`$<SITE>_NB_API_TOKEN` in the environment (without the token it does not start,
since it could not clean up). Otherwise its rows read SKIPPED.

Each is proven red then green against stubs in `run-acceptance.py --self-test`
(a stub Hydra, login UI, router REST and NetBird API in one local server; stub
`goat` and `docker`). The fabric legs also run against the real router in the
goat CLI e2e suite (`assay-router-round-trip-passes`,
`assay-health-beat-under-own-key-passes`, and
`assay-health-beat-naming-another-site-fails`).

## What this is (and is not)

One **manifest of acceptance tests**, each proving one provisioned aspect works end-to-end
on the live environment, **triggered progressively**: a test becomes eligible the moment
the components it depends on have completed deployment, not at a single end-of-standup
gate. The standup-end gate (phase 13) then degenerates to "every applicable row is
green" — and stays useful after standup as a re-runnable regression surface.

Not this:
- **isitup** — runtime up/down monitoring. Acceptance asks "does it *work*", once, per
  provisioning event; isitup asks "is it *up*", forever. Both stay.
  isitup's answer is only as good as what it dials: a `type=container` row
  probes the container IP through the docker socket and, until
  F-405,
  never touched the public hostname printed beside it. `check.sh` now also
  probes `https://<host>` on those rows and grades **degraded** when the
  container is healthy but the front door answers 404/502/503/000.
- **Environment-health (`EnvHealthV1`)** — self-reported by each node. Acceptance probes
  from the *outside* (operator controller over the mesh).
- **site-bootstrap Phase 7 smoke** — inline, deploy-time, per-play. Stays; acceptance is
  post-hoc, cross-service, re-runnable without re-deploying.
- **`fresh-peer-probe.sh`** (Gate 1) — a hand-built composite of four checks. It becomes
  the first four rows of the manifest; the suite is its generalization.

## The model — rows parameterize probes; probes are a small library

"Hundreds of tests" stays maintainable only if a test is a **row**, not a script. The
manifest (`ops/validation/acceptance-tests.yaml`) is the SoT; each row:

```yaml
- id: signal-wss-handshake
  aspect: mgmt-stack/signal
  probe: tls-alpn                      # probe TYPE from the library
  params: {host: "netbird.{{ zone }}", port: 443, expect_proto: h2}
  requires: [signal-server, traefik]   # deploy-ledger component names
  applies_when: always                 # or a capability-flag / pins expression
  severity: gate                       # gate | warn
  caught_would_have: "friction row 22 — cleartext h2c, peers Signal-disconnected"
```

The **probe library** is deliberately small (each type is one function, reused by many
rows): `http-ok`, `tls-identity` (SAN/issuer match), `tls-alpn`, `dns-resolve`
(mesh CoreDNS), `bus-liveliness`, `bus-roundtrip` (publish + read back **under the
expected site key** — row 43's lesson), `container-health`, `cmd-assert` (delegated via
ansible; e.g. `findmnt`, `pg_isready`, replication-lag SQL), `oidc-flow` (client-creds
token mint), `enroll-probe` (the fresh-peer-probe checks). New aspect ≈ new row; new
probe type only when no existing one fits.

**Applicability is derived, never hand-listed:** the same joins parity already uses —
capability flags + fleet-pins components + cloud-parity rows — decide which rows apply to
which goatnet. A row whose `applies_when` is false renders N/A, not green.

## Triggering — the deploy ledger is the event source

ADR 1060 already gives every deploy a universal, CI-ratcheted ledger write (repo ledger +
on-host `deploy-history.jsonl`). The runner keys on it:

1. **v1 (build first):** `goat validate <env> [--phase N | --component X | --all-eligible]`
   — operator- or orchestrator-fired after each phase; computes eligible rows
   (`requires` ⊆ deployed components per the ledger), runs them, appends results.
2. **v2:** a watcher subscribes to ledger writes and fires newly-eligible rows
   automatically — the operator sees aspects go green as the standup proceeds.
3. **Release candidates (ADR 1173, built 2026-09-08):** a `<component>/v<semver>-rc.<n>` tag
   computes the rows the change affects (`ops/validation/flow-map.yaml` +
   `affected-flows.py`) and prints the `run-acceptance.py --env dev --only <rows>`
   command the mesh-connected controller runs; that PASS is the dev→preprod
   validation evidence. [release-candidate-validation.md](release-candidate-validation.md).

Results are append-only JSONL (`<state-dir>/<env>-acceptance/results.jsonl` +
optional bus publish), each `{id, verdict, evidence, ts, deployed_set_hash}`.

**Honesty grammar is non-negotiable** (ADR 1034 discipline): verdicts are
`PASS | FAIL | UNKNOWN | SKIPPED(dep-unmet) | N/A(not-applicable)`. Nothing-heard is
never green; a probe that cannot run is UNKNOWN, not PASS; the gate counts only PASS.
Every new probe type must be **proven red first** against a known-broken fixture before
its green is trusted — the cloud-parity checker's first run passed by matching the very
comment that documented an absence (friction row 42); that mistake is a class.

## Execution locus + credentials

The runner runs on the **operator controller, mesh-connected** (the F-189 lesson: hosts
cannot reach their own portal/DNS the way peers do — probing from the controller tests
the path users actually traverse). Probes needing host-side context delegate via ansible
(`cmd-assert`). Probe credentials are least-privilege: a dedicated acceptance leaf cert
(one manifest row in `<env>-certs.yaml`) + read-only tokens; never operator-admin
credentials inside probe code.

## Seeding — today's defects are the first corpus

The seed manifest ships with rows that would have caught the 2026-08-04 defects, each
citing its friction-log row: signal ALPN (22), OIDC auth-field login (21), router
storage-spawn (25), health-key site attribution (43), obs data-root mount (27),
replication lag + hba admit (36/38/44), enrollment-entrypoint cert identity (40),
cert/key pair match (41), declared-service-vs-deployed join (30), relay `rels://` trust
(Hazard 2), DNS resolve per declared service, pgBackRest stanza + first backup
(37). Gate 1's four fresh-peer checks migrate in as rows. Target for the first build
increment: ~40 rows covering the standup's phases 5–13; growth to hundreds happens
row-by-row as aspects are added — the manifest is the register.

## Build order (each increment independently useful)

1. Manifest schema + probe library core (`http-ok`, `dns-resolve`, `tls-identity`,
   `cmd-assert`) + `goat validate <env> --all-eligible` with ledger-derived eligibility.
   Red-first fixtures per probe type.
2. Seed rows above; wire as the standup's acceptance gate (phase 13) for prod (replacing
   "docker ps + log greps").
3. Ledger-watch auto-trigger (v2) + bus publish of verdicts.
4. Surface: `goat health --domain acceptance` arm / consistency-console panel (display
   only — the JSONL stays the record).
5. CI: manifest schema check + row-vs-capability-flag join check (a declared aspect with
   no acceptance row fails, closing the row-30 class permanently).

## Fit with the turnkey program

This suite is the **verification half** of `goatnet-standup-human-executable`: the
orchestrator sequences, the preflight gate proves config before any play, and acceptance
proves function after each deploy — a no-AI operator then needs judgment only when a row
goes red, and the row's `caught_would_have` text tells them what it means. The cold-read
drill's success criterion becomes mechanical: all applicable rows green, zero operator
improvisation.

## Runner configuration gate

Status: built. `onboard-runner-knows-this-goatnet` reads the default profile
materialized by the onboard-runner entrypoint inside the running container.
It requires the portal, router, NetBird URL/token-environment-name/group-prefix,
and Ory URL/SSH-host/SSH-user settings. A profile naming another goatnet fails;
the entrypoint's unnamed profile is valid for its configured goatnet. Missing
or unreadable profile settings fail. Container/transport failures are UNKNOWN.
The probe follows goat-cli's flat profile-field reader and emits field names
only, never values or token contents. This proves configuration presence, not
credential validity or a successful mint; reachability and onboarding checks
remain separate. The role retains the binary version and container-restart checks.

Regression tests: `python3 -m unittest discover -s tests -p test_onboard_runner_profile.py`.
