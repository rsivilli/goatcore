"""probes.py — the acceptance-suite probe library (ADR 1115).

One function per probe TYPE; manifest rows parameterize them. Every probe
returns a Verdict with honest grammar — a probe that CANNOT run returns
UNKNOWN, never PASS. Nothing-heard is never green.

Network/bus/oidc probes make a real attempt and return UNKNOWN (with the
reason) when the target is unreachable from where the runner sits — that is
the correct answer for "I could not determine", and it is why the runner must
execute from a mesh-connected controller. The offline-testable probes
(http_ok against a fixture, dns_resolve, tls_identity of a PEM, cmd_assert of a
local command) are exercised red-first in run-acceptance.py --self-test.
"""
from __future__ import annotations

import os
import shlex
import shutil
import ssl
import subprocess
import socket
import sys
from dataclasses import dataclass, field

PASS = "PASS"
FAIL = "FAIL"
UNKNOWN = "UNKNOWN"          # could not determine — never treat as green
SKIPPED = "SKIPPED"          # dependency unmet
NA = "N/A"                   # not applicable to this env


@dataclass
class Verdict:
    status: str
    evidence: str = ""
    probe: str = ""
    meta: dict = field(default_factory=dict)

    @property
    def green(self) -> bool:
        return self.status == PASS


def _timeout(params, default=8):
    # The manifest writes `timeout:` on 22 rows and `timeout_s:` on 2; both are
    # the row's budget in seconds. Reading only `timeout_s` left every `timeout:`
    # row on this default (20 s for cmd-assert), so the intake smoke, which
    # takes about 12 s warm and longer cold, timed out under the runner while
    # passing by hand (zagros-dev).
    for key in ("timeout_s", "timeout"):
        if key in params:
            try:
                return float(params[key])
            except (TypeError, ValueError):
                return default
    return default


# --------------------------------------------------------------------------
# http_ok — an HTTP(S) GET returns an expected status. Uses curl so it shares
# the operator's proxy/trust/mesh context exactly (the path a human takes).
# --------------------------------------------------------------------------
def http_ok(params) -> Verdict:
    url = params.get("url")
    if not url:
        return Verdict(UNKNOWN, "no url in params", "http-ok")
    expect = params.get("expect", 200)
    expect = [expect] if isinstance(expect, int) else list(expect)
    if not shutil.which("curl"):
        return Verdict(UNKNOWN, "curl not on PATH — probe kit incomplete", "http-ok")
    cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
           "--max-time", str(int(_timeout(params)))]
    hdr = params.get("auth_header")
    if hdr:
        cmd += ["-H", hdr]
    cmd.append(url)
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=_timeout(params) + 4)
    except subprocess.TimeoutExpired:
        return Verdict(UNKNOWN, f"{url}: timed out", "http-ok")
    code = out.stdout.strip()
    if code in ("", "000"):
        return Verdict(UNKNOWN, f"{url}: no response (HTTP 000) — unreachable "
                       "from here, not proof of failure", "http-ok")
    ok = int(code) in expect if code.isdigit() else False
    return Verdict(PASS if ok else FAIL,
                   f"{url} -> HTTP {code} (expected {expect})", "http-ok")


# --------------------------------------------------------------------------
# dns_resolve — a name resolves (optionally to an expected answer) via a
# specific resolver. Mesh CoreDNS check.
# --------------------------------------------------------------------------
def dns_resolve(params) -> Verdict:
    name = params.get("name")
    if not name:
        return Verdict(UNKNOWN, "no name in params", "dns-resolve")
    want = params.get("expect")
    server = params.get("resolver")
    if shutil.which("dig"):
        cmd = ["dig", "+short", name]
        if server:
            # resolver is host[:port]; a mesh CoreDNS listens on :5353, so the
            # port must reach dig via -p — dropping it queried :53 and every
            # mesh name came back empty (a false "declared-but-unresolvable").
            host, _, port = server.partition(":")
            cmd = ["dig", "+short", f"@{host}"]
            if port:
                cmd += ["-p", port]
            cmd.append(name)
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=_timeout(params))
        except subprocess.TimeoutExpired:
            return Verdict(UNKNOWN, f"{name}: dig timed out", "dns-resolve")
        answers = [a for a in out.stdout.split() if a]
        if not answers and not server:
            # no explicit mesh resolver requested: honor the OS resolver
            # (nsswitch/hosts) before declaring failure. With a `resolver` set
            # (the real F-197 mesh check) an empty answer IS a failure.
            try:
                return Verdict(PASS, f"{name} -> {socket.gethostbyname(name)} (OS resolver)", "dns-resolve")
            except OSError:
                pass  # OS resolver failed: fall through
        if not answers:
            return Verdict(FAIL, f"{name}: no record (server={server or 'default'})", "dns-resolve")
        if want and want not in answers:
            return Verdict(FAIL, f"{name} -> {answers} (expected {want})", "dns-resolve")
        return Verdict(PASS, f"{name} -> {answers}", "dns-resolve")
    # fallback: system resolver, no server targeting
    try:
        ip = socket.gethostbyname(name)
    except OSError as e:
        return Verdict(FAIL, f"{name}: {e}", "dns-resolve")
    if want and ip != want:
        return Verdict(FAIL, f"{name} -> {ip} (expected {want})", "dns-resolve")
    return Verdict(PASS, f"{name} -> {ip} (system resolver; no server targeting)", "dns-resolve")


# --------------------------------------------------------------------------
# tls_identity — the cert served (or a PEM file) carries the expected CN / SAN
# / issuer. Catches stale mesh-IP SANs, wrong-goatnet identity, default certs.
# --------------------------------------------------------------------------
def tls_identity(params) -> Verdict:
    pem = params.get("pem_file")
    host, port = params.get("host"), int(params.get("port", 443))
    cert_text = None
    if pem:
        try:
            cert_text = _openssl_text_from_pem(pem)
        except Exception as e:  # noqa: BLE001
            return Verdict(UNKNOWN, f"{pem}: {e}", "tls-identity")
    elif host:
        cert_text = _fetch_cert_text(host, port, _timeout(params))
        if cert_text is None:
            return Verdict(UNKNOWN, f"{host}:{port}: no cert retrieved (unreachable)", "tls-identity")
    else:
        return Verdict(UNKNOWN, "need pem_file or host", "tls-identity")

    checks = []
    for cn in _aslist(params.get("expect_cn")):
        checks.append((f"CN~{cn}", f"CN={cn}" in cert_text or f"CN = {cn}" in cert_text))
    for san in _aslist(params.get("expect_san_ip")) + _aslist(params.get("expect_san")):
        checks.append((f"SAN~{san}", san in cert_text))
    for iss in _aslist(params.get("expect_issuer")):
        checks.append((f"issuer~{iss}", iss in cert_text))
    for bad in _aslist(params.get("refuse_cn")):
        checks.append((f"refuse~{bad}", bad not in cert_text))
    # Trust, as the system would judge it: chain, hostname AND expiry. This is
    # the only assertion here that can see a certificate that is well-formed
    # and simply out of date, which is the failure that actually happens.
    if params.get("expect_system_trust"):
        if not host:
            checks.append(("system-trust", False))
        else:
            err = _system_trust_error(host, int(params.get("port", 443)), _timeout(params),
                                      params.get("sni"), params.get("verify_name", True))
            checks.append((f"system-trust{'' if err is None else ' (' + err[:60] + ')'}", err is None))
    if not checks:
        return Verdict(UNKNOWN, "no identity assertions in params", "tls-identity")
    failed = [name for name, ok in checks if not ok]
    if failed:
        return Verdict(FAIL, "failed: " + ", ".join(failed), "tls-identity")
    return Verdict(PASS, "matched: " + ", ".join(n for n, _ in checks), "tls-identity")


def _openssl_text_from_pem(pem_path) -> str:
    out = subprocess.run(["openssl", "x509", "-in", pem_path, "-noout",
                          "-subject", "-issuer", "-ext", "subjectAltName"],
                         capture_output=True, text=True, timeout=8)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip() or "openssl failed")
    return out.stdout


def _system_trust_error(host, port, timeout, sni=None, verify_name=True) -> str | None:
    """None when a VERIFYING TLS handshake succeeds; the reason when it does not.

    _fetch_cert_text below sets verify_mode = CERT_NONE on purpose — it exists
    to read a certificate's fields, and it must keep working against a cert the
    system would reject, or every identity assertion would go UNKNOWN at the
    moment a cert went bad. That deliberate blindness is why
    `expect_system_trust` needed its own path: for two months it was accepted
    as a parameter, matched no assertion, and rendered the row UNKNOWN. The
    relay row carrying it read UNKNOWN throughout the 2026-09-07 expiry it was
    written to catch.

    `sni` is the name to ask for and verify when `host` is an address: a relay
    reached by its public IP presents the certificate for the enrolment name,
    and judged against the bare IP it can only ever fail. `verify_name: false`
    checks the chain and the dates only, for a fleet whose members each carry
    their own name (relay-<code>.<zone> on the relay port).
    """
    try:
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        if verify_name in (False, "false", "False"):
            ctx.check_hostname = False
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni or host):
                return None
    except ssl.SSLCertVerificationError as e:
        return f"certificate not trusted: {e.verify_message or e}"
    except ssl.SSLError as e:
        return f"TLS error: {e}"
    except OSError as e:
        return f"unreachable: {e}"


def _fetch_cert_text(host, port, timeout) -> str | None:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                der = ss.getpeercert(binary_form=True)
        out = subprocess.run(["openssl", "x509", "-inform", "DER", "-noout",
                              "-subject", "-issuer", "-ext", "subjectAltName"],
                             input=der, capture_output=True, timeout=8)
        return out.stdout.decode(errors="replace") if out.returncode == 0 else None
    except (OSError, ssl.SSLError, subprocess.SubprocessError):
        return None


# --------------------------------------------------------------------------
# tls_alpn — the endpoint speaks TLS (not cleartext). Catches signal_proto=http.
# --------------------------------------------------------------------------
def tls_alpn(params) -> Verdict:
    host, port = params.get("host"), int(params.get("port", 443))
    if not host:
        return Verdict(UNKNOWN, "no host", "tls-alpn")
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=_timeout(params)) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                ver = ss.version()
        return Verdict(PASS, f"{host}:{port} negotiated {ver}", "tls-alpn")
    except ssl.SSLError as e:
        return Verdict(FAIL, f"{host}:{port}: TLS handshake failed ({e}) — cleartext?", "tls-alpn")
    except OSError as e:
        return Verdict(UNKNOWN, f"{host}:{port}: unreachable ({e})", "tls-alpn")


# --------------------------------------------------------------------------
# A goatnet this laptop is not meshed to is reached through its door
# (docs/design/env-doors.md): rc.sh opens it and sets GOAT_ROWS_SSH_JUMP to the
# door's user@127.0.0.1:port, and every host row jumps through it to the
# host's mesh address. The door host forwards TCP only; ssh still
# authenticates end to end with the operator's key.
# --------------------------------------------------------------------------
def _ssh_jump():
    # A ProxyCommand rather than ProxyJump: the door is a local tunnel port
    # whose host key churns (a door port is reused across goatnets; env-door.sh
    # pairs it with StrictHostKeyChecking=no), and ProxyJump would check that
    # hop against known_hosts and, in BatchMode, refuse it. The tunnel hop is
    # not trusted for anything; the final hop's host key is still verified,
    # end to end, by the outer ssh.
    jump = os.environ.get("GOAT_ROWS_SSH_JUMP", "").strip()
    if not jump:
        return ""
    target, _, port = jump.rpartition(":")
    if not target or not port.isdigit():
        target, port = jump, "22"
    inner = (f"ssh -o BatchMode=yes -o ConnectTimeout=6 -o StrictHostKeyChecking=no "
             f"-o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p {port} -W %h:%p {target}")
    return f"-o ProxyCommand={shlex.quote(inner)} "


# --------------------------------------------------------------------------
# cmd_assert — run a command (optionally on a host via ssh) and assert output.
# The workhorse for host-local truths (findmnt, pg_isready, replication SQL).
# --------------------------------------------------------------------------
def cmd_assert(params) -> Verdict:
    cmd = params.get("cmd")
    if not cmd:
        return Verdict(UNKNOWN, "no cmd", "cmd-assert")
    host = params.get("host")
    local = not host or host in ("localhost", "127.0.0.1")
    first = cmd.split(maxsplit=1)
    if local and first and first[0].endswith(".py"):
        # A control-node script runs under this runner's own interpreter, which
        # imports PyYAML (the runner refuses to start without it), not under
        # whichever python3 its shebang finds first on PATH (X-PY-001).
        cmd = f"{shlex.quote(sys.executable)} {cmd}"
    full = cmd
    if not local:
        # mgmt hosts are key-only SSH + NOPASSWD sudo (os-baseline day-1 auth) and
        # the host-shell user is deliberately NOT in the docker group, so a host
        # inspection (`docker ps`, reads under /etc or /opt) must run under sudo -n.
        # Without it these rows FAILed on "permission denied ... docker.sock".
        remote = cmd if cmd.lstrip().startswith("sudo ") else f"sudo -n {cmd}"
        # StrictHostKeyChecking=accept-new: a probe is read-only validation, and a
        # host it has never reached before (a freshly-enrolled joiner's mesh IP —
        # delta-core-b) would otherwise be rejected "Host key verification failed" and
        # graded FAIL for a host that is perfectly healthy. accept-new trusts on
        # first contact and pins thereafter, which is the right posture for a gate.
        full = (f"ssh -o BatchMode=yes -o ConnectTimeout=6 {_ssh_jump()}"
                f"-o StrictHostKeyChecking=accept-new {host} {shlex.quote(remote)}")
    try:
        out = subprocess.run(full, shell=True, capture_output=True, text=True,
                             timeout=_timeout(params, 20))
    except subprocess.TimeoutExpired:
        return Verdict(UNKNOWN, "command timed out", "cmd-assert")
    stdout = out.stdout.strip()
    # A script that exits with one of `unknown_rc` is saying it could not run
    # its check from here (a missing tool, a missing credential), which says
    # nothing about the goatnet.
    if out.returncode in [int(x) for x in _aslist(params.get("unknown_rc"))]:
        return Verdict(UNKNOWN, f"rc={out.returncode}: could not run here — "
                       f"{out.stderr.strip()[-120:] or stdout[:120]}", "cmd-assert")
    if local and "ModuleNotFoundError: No module named" in out.stderr:
        # A module missing on this machine says nothing about the goatnet.
        mod = out.stderr.split("No module named", 1)[1].strip().split()[0].strip("'\"")
        return Verdict(UNKNOWN, f"X-PY-001: this machine's python cannot import {mod}; "
                       f"pip install {mod} (or run under a python that has it)", "cmd-assert")
    if out.returncode != 0 and "expect_rc" not in params:
        # a nonzero rc with no expectation: FAIL only if we actually reached it
        if host and ("Connection" in out.stderr or "Could not resolve" in out.stderr):
            return Verdict(UNKNOWN, f"{host}: unreachable ({out.stderr.strip()[:80]})", "cmd-assert")
        return Verdict(FAIL, f"rc={out.returncode}: {out.stderr.strip()[:120] or stdout[:120]}", "cmd-assert")
    want = params.get("expect")
    if want is not None and str(want) not in stdout:
        return Verdict(FAIL, f"output {stdout[:120]!r} lacks {want!r}", "cmd-assert")
    if params.get("expect_nonempty") and not stdout:
        return Verdict(FAIL, "expected nonempty output, got none", "cmd-assert")
    if "expect_min" in params:
        try:
            n = int(stdout.split()[0])
        except (ValueError, IndexError):
            return Verdict(FAIL, f"expected a number ≥ {params['expect_min']}, got {stdout[:60]!r}", "cmd-assert")
        if n < int(params["expect_min"]):
            return Verdict(FAIL, f"{n} < expect_min {params['expect_min']}", "cmd-assert")
    if "expect_jq" in params:
        if not shutil.which("jq"):
            return Verdict(UNKNOWN, "expect_jq needs jq on PATH", "cmd-assert")
        jq = subprocess.run(["jq", "-e", params["expect_jq"]], input=stdout,
                            capture_output=True, text=True)
        if jq.returncode != 0:
            return Verdict(FAIL, f"jq '{params['expect_jq']}' false/failed on output", "cmd-assert")
    return Verdict(PASS, f"ok: {stdout[:120]}", "cmd-assert")


# --------------------------------------------------------------------------
# Shared helpers for the probes below: a command here or on a host (key-only
# ssh, NOPASSWD sudo, like cmd_assert), and one HTTP call through curl.
# --------------------------------------------------------------------------
def _local(host):
    return not host or host in ("localhost", "127.0.0.1", "local")


class _Run:
    """What one command returned: rc, out, err, and whether the host was
    reached (False when ssh itself could not get there, which says nothing
    about the goatnet)."""
    __slots__ = ("rc", "out", "err", "reached")

    def __init__(self, rc, out, err, reached):
        self.rc, self.out, self.err, self.reached = rc, out, err, reached


def _host_run(host, cmd, timeout=30):
    """Run `cmd` (a shell string) here, or on `host` under `sudo -n sh -c`."""
    if _local(host):
        full = cmd
    else:
        remote = f"sudo -n sh -c {shlex.quote(cmd)}"
        full = (f"ssh -o BatchMode=yes -o ConnectTimeout=6 {_ssh_jump()}"
                f"-o StrictHostKeyChecking=accept-new {host} {shlex.quote(remote)}")
    try:
        proc = subprocess.run(full, shell=True, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return _Run(124, "", "timed out", True)
    return _Run(proc.returncode, proc.stdout, proc.stderr,
                _local(host) or proc.returncode != 255)



def onboard_runner_profile(params) -> Verdict:
    """Check the default profile materialized by the runner entrypoint, not binary strings.

    Match goat-cli's flat extract_toml_field reader. Do not print endpoint values
    or read portal.token; this proves configuration presence, not a live mint.
    """
    kind = "onboard-runner-profile"
    goatnet = params.get("goatnet")
    if not goatnet:
        return Verdict(UNKNOWN, "no goatnet in params", kind)
    container = shlex.quote(params.get("container", "onboard-runner"))
    command = (f"docker exec {container} sh -c " +
               shlex.quote('test -r "$HOME/.goat/contexts/default/profile.toml" || exit 42; '
                           'cat "$HOME/.goat/contexts/default/profile.toml"'))
    result = _host_run(params.get("host"), command, _timeout(params, 20))
    if result.rc == 42:
        return Verdict(FAIL, "runner default profile is missing or unreadable", kind)
    if not result.reached or result.rc != 0:
        return Verdict(UNKNOWN, "could not read the running container's profile", kind)

    def value(key):
        for line in result.out.splitlines():
            line = line.strip()
            if line.startswith(key):
                rest = line[len(key):].lstrip()
                if rest.startswith("="):
                    return rest[1:].strip().strip('"').strip()
        return ""

    named = value("goatnet")
    if named and named != goatnet:
        return Verdict(FAIL, "runner default profile names another goatnet", kind)
    required = ("portal_endpoint", "router_endpoint", "netbird_mgmt_url",
                "netbird_token_env", "netbird_site_prefix", "ory_auth_url",
                "ory_ssh_host", "ory_ssh_user")
    missing = [key for key in required if not value(key) or "{{" in value(key)]
    if missing:
        return Verdict(FAIL, "runner profile lacks settings: " + ", ".join(missing), kind)
    return Verdict(PASS, "runner profile contains native onboarding settings", kind)


def _curl(url, timeout=8, method="GET", headers=(), data=None, host=None, follow=False):
    """One HTTP call. Returns (status, body, redirect_url) or (None, reason, '')
    when nothing answered. Runs on `host` when given (for an admin port bound to
    the host's loopback), else here."""
    parts = ["curl", "-s", "-o", "-", "-w", "\\n%{http_code} %{redirect_url}",
             "--max-time", str(int(timeout)), "-X", method]
    if follow:
        parts.append("-L")
    for h in headers:
        parts += ["-H", h]
    if data is not None:
        parts += ["--data-binary", data]
    parts.append(url)
    cmd = " ".join(shlex.quote(p) for p in parts)
    r = _host_run(host, cmd, timeout + 6)
    if not r.reached:
        return None, f"{host}: unreachable ({r.err.strip()[:80]})", ""
    body, _, tail = r.out.rpartition("\n")
    code, _, redirect = tail.partition(" ")
    if not code.isdigit() or code == "000":
        return None, f"{url}: no response ({r.err.strip()[:80] or 'HTTP 000'})", ""
    return int(code), body, redirect.strip()


def _json(text):
    import json
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------
# oidc_flow — the identity plane a person signs in through, proven the way a
# browser exercises it, without a person:
#   1. discovery: the issuer publishes its configuration under its own name,
#      and its signing keys (JWKS) are non-empty;
#   2. every named client exists in Hydra (admin API on the host's loopback),
#      and the authorization endpoint STARTS a login for it — a redirect to the
#      login UI carrying a login_challenge — and the login UI answers. This is
#      the step an unregistered fence fails at (`invalid_client` on every load);
#   3. the negative: a client that does not exist is refused, by the admin API
#      and by the authorization endpoint. A check that cannot say no is not one;
#   4. optional, `assert_nonempty` + `config_file`: fields a consumer of the
#      issuer reads (NetBird's HttpConfig AuthIssuer/AuthAudience) are set, and
#      an AuthIssuer equals this issuer;
#   5. optional, `token_client` + `token_secret_env`: a client-credentials token
#      is minted, and a wrong secret is refused.
# `clients_from_containers: true` takes the clients from the running fences
# themselves (each container's *CLIENT_ID env whose issuer is this one), so the
# row follows what is deployed instead of a list that drifts from it.
# Writes nothing durable: steps 2-3 create login requests Hydra and Kratos
# expire unused; the evidence says so.
# --------------------------------------------------------------------------
def _fence_clients(host, issuer):
    fmt = "{{.Name}}{{range .Config.Env}}|{{.}}{{end}}"
    cmd = f"for c in $(docker ps -q); do docker inspect --format '{fmt}' $c; done"
    r = _host_run(host, cmd, 40)
    if not r.reached or r.rc != 0:
        return None, f"could not list containers on {host}: {(r.err or r.out).strip()[:80]}"
    clients = {}
    for line in r.out.splitlines():
        name, *env = line.split("|")
        kv = dict(e.split("=", 1) for e in env if "=" in e)
        iss = next((v for k, v in kv.items() if "ISSUER" in k and v.startswith("http")), "")
        if iss and iss.rstrip("/") != issuer:
            continue  # this fence trusts another issuer
        for k, v in kv.items():
            if k.endswith("CLIENT_ID") and v:
                clients.setdefault(v, []).append(name.lstrip("/"))
    return clients, ""


def _start_login(auth_ep, client, redirect, timeout):
    import secrets
    import urllib.parse
    q = {"client_id": client, "response_type": "code", "scope": "openid",
         "state": secrets.token_hex(8)}
    if redirect:
        q["redirect_uri"] = redirect
    code, body, loc = _curl(f"{auth_ep}?{urllib.parse.urlencode(q)}", timeout)
    return code, body, loc


def oidc_flow(params) -> Verdict:
    import secrets
    import urllib.parse
    issuer = str(params.get("issuer") or "").rstrip("/")
    if not issuer:
        return Verdict(UNKNOWN, "no issuer", "oidc-flow")
    t = _timeout(params, 10)
    host = params.get("host")
    admin = str(params.get("admin_url", "http://127.0.0.1:4445")).rstrip("/")
    fails, unknowns, oks = [], [], []

    # 1. discovery + JWKS
    code, body, _ = _curl(f"{issuer}/.well-known/openid-configuration", t)
    if code is None:
        return Verdict(UNKNOWN, f"discovery unreachable from here: {body}", "oidc-flow")
    disc = _json(body) if code == 200 else None
    if not isinstance(disc, dict):
        return Verdict(FAIL, f"{issuer}/.well-known/openid-configuration -> HTTP {code}", "oidc-flow")
    if str(disc.get("issuer", "")).rstrip("/") != issuer:
        fails.append(f"discovery names issuer {disc.get('issuer')!r}, not {issuer}")
    jcode, jbody, _ = _curl(str(disc.get("jwks_uri", "")), t) if disc.get("jwks_uri") else (None, "no jwks_uri", "")
    keys = (_json(jbody) or {}).get("keys") if jcode == 200 else None
    if jcode is None:
        unknowns.append(f"JWKS: {jbody}")
    elif not keys:
        fails.append(f"JWKS {disc.get('jwks_uri')} -> HTTP {jcode}, no signing keys")
    else:
        oks.append(f"discovery + {len(keys)} key(s)")
    auth_ep = disc.get("authorization_endpoint")

    # 4. fields a consumer reads from its own config
    want = _aslist(params.get("assert_nonempty"))
    if want:
        path, section = params.get("config_file"), params.get("config_section", "HttpConfig")
        if not path or not host:
            unknowns.append("assert_nonempty needs config_file and host")
        else:
            r = _host_run(host, f"cat {shlex.quote(str(path))}", t + 10)
            cfg = _json(r.out) if r.rc == 0 else None
            if not r.reached or cfg is None:
                unknowns.append(f"could not read {path}: {(r.err or r.out).strip()[:60]}")
            else:
                sec = cfg.get(section, cfg) if isinstance(cfg, dict) else {}
                empty = [f for f in want if not str(sec.get(f) or "").strip()]
                if empty:
                    fails.append(f"{path} {section}: empty {', '.join(empty)}")
                elif "AuthIssuer" in want and str(sec["AuthIssuer"]).rstrip("/") != issuer:
                    fails.append(f"{section}.AuthIssuer is {sec['AuthIssuer']!r}, not {issuer}")
                else:
                    oks.append(f"{section} {'/'.join(want)} set")

    # 2. clients exist and a login starts for each
    clients = {c: [] for c in _aslist(params.get("client")) + _aslist(params.get("clients"))}
    if params.get("clients_from_containers"):
        if not host:
            unknowns.append("clients_from_containers needs host")
        else:
            found, why = _fence_clients(host, issuer)
            if found is None:
                unknowns.append(why)
            elif not found:
                fails.append(f"no running container on {host} names a client of {issuer}")
            else:
                for c, users in found.items():
                    clients.setdefault(c, []).extend(users)

    # Hydra's registered clients, read once over the host's loopback admin port.
    registered, admin_err = None, ""
    if host:
        acode, abody, _ = _curl(f"{admin}/admin/clients?page_size=500", t + 10, host=host)
        listed = _json(abody) if acode == 200 else None
        if isinstance(listed, list):
            registered = {c.get("client_id"): c for c in listed if isinstance(c, dict)}
        else:
            admin_err = f"admin API: {abody if acode is None else f'HTTP {acode}'}"

    def check_client(cid):
        """(state, detail) for one client: ok / fail / unknown."""
        redirect = ""
        if host:
            if registered is None:
                return "unknown", admin_err
            if cid not in registered:
                return "fail", "Hydra has no such client"
            redirect = next(iter(registered[cid].get("redirect_uris") or []), "")
        if not auth_ep:
            return "unknown", "discovery has no authorization_endpoint"
        lcode, _, loc = _start_login(auth_ep, cid, redirect, t)
        if lcode is None:
            return "unknown", "authorization endpoint unreachable"
        if "login_challenge=" in loc:
            ucode, _, _ = _curl(loc, t)
            if ucode is None:
                return "unknown", "login UI unreachable"
            if ucode >= 400:
                return "fail", f"login started, but the login UI answered HTTP {ucode}"
            return "ok", "login started"
        err = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query).get("error", [""])[0]
        if err == "invalid_client":
            return "fail", "the issuer refused it: invalid_client"
        if not redirect and err:
            return "unknown", f"no login without its redirect uri ({err}); give host"
        return "fail", f"no login started (HTTP {lcode}{', ' + err if err else ''})"

    for cid, users in sorted(clients.items()):
        state, detail = check_client(cid)
        who = f" (used by {', '.join(sorted(set(users)))})" if users else ""
        line = f"{cid}{who}: {detail}"
        {"ok": oks, "fail": fails, "unknown": unknowns}[state].append(line)

    # 3. the negative: the authorization endpoint itself must refuse a client
    # nobody registered (the admin list saying "absent" proves nothing about
    # what the issuer does with it).
    if auth_ep:
        bogus = f"goat-assay-no-such-client-{secrets.token_hex(4)}"
        lcode, _, loc = _start_login(auth_ep, bogus, "", t)
        if lcode is None:
            unknowns.append("negative: authorization endpoint unreachable")
        elif "login_challenge=" in loc:
            fails.append("the issuer started a login for a client that does not exist: "
                         "it cannot tell a registered client from none")
        else:
            oks.append("an unregistered client is refused")

    # 5. client-credentials mint (optional)
    tc, tenv = params.get("token_client"), params.get("token_secret_env")
    if tc and tenv:
        secret = os.environ.get(str(tenv))
        tok_ep = disc.get("token_endpoint")
        if not secret or not tok_ep:
            unknowns.append(f"token mint needs ${tenv} and a token_endpoint")
        else:
            import base64
            def mint(sec):
                basic = base64.b64encode(f"{tc}:{sec}".encode()).decode()
                return _curl(tok_ep, t, "POST",
                             [f"Authorization: Basic {basic}",
                              "Content-Type: application/x-www-form-urlencoded"],
                             "grant_type=client_credentials")
            mcode, mbody, _ = mint(secret)
            bcode, _, _ = mint(secret + "-wrong")
            if mcode == 200 and (_json(mbody) or {}).get("access_token") and bcode in (400, 401):
                oks.append(f"{tc}: token minted, a wrong secret refused")
            elif mcode is None or bcode is None:
                unknowns.append("token endpoint unreachable")
            else:
                fails.append(f"{tc}: mint HTTP {mcode}, wrong-secret HTTP {bcode}")

    note = " [writes: transient login requests only, expire unused]"
    if fails:
        return Verdict(FAIL, "; ".join(fails)[:400] + note, "oidc-flow")
    if unknowns:
        return Verdict(UNKNOWN, "; ".join(unknowns)[:300] + (f" — ok: {len(oks)}" if oks else ""), "oidc-flow")
    if not oks:
        return Verdict(UNKNOWN, "nothing was checked", "oidc-flow")
    return Verdict(PASS, f"{issuer}: " + "; ".join(oks)[:300] + note, "oidc-flow")


# --------------------------------------------------------------------------
# bus_roundtrip — the fabric carries a sample to a reader, under the key it
# should. Two modes:
#   subscribe: <key>  wait for one sample published under <key> (a site's
#                     health beat, say) and check `expect_field` on its payload;
#   publish: true     publish a fresh nonce under `key` and read it back; the
#                     key should be a volatile one, so nothing is stored.
# Through the operator's `goat` CLI when a context can speak for the goatnet
# (`context`, `via`), else through the router's own REST plugin on `rest_host`
# (`rest_port`, default 8000), on the host's loopback. The evidence names the
# transport used. Nothing heard by the deadline is FAIL: nothing-heard is never
# green. A transport that cannot connect is UNKNOWN.
#
# Payloads: a JSON object is read as is; otherwise the base64 or raw bytes are
# read as protobuf for the EnvHealthV1 string fields (1 domain, 2 scope,
# 4 overall_color), and `site` in expect_field means `scope`.
# --------------------------------------------------------------------------
_ENV_HEALTH_FIELDS = {1: "domain", 2: "scope", 4: "overall_color"}


def _pb_strings(raw):
    """Top-level length-delimited fields of a protobuf message that decode as
    UTF-8, keyed by field number. Enough to read EnvHealthV1's identity."""
    out, i = {}, 0
    try:
        while i < len(raw):
            tag, shift = 0, 0
            while True:
                b = raw[i]; i += 1
                tag |= (b & 0x7F) << shift; shift += 7
                if not b & 0x80:
                    break
            field, wire = tag >> 3, tag & 7
            if wire == 0:
                while raw[i] & 0x80:
                    i += 1
                i += 1
            elif wire == 2:
                n, shift = 0, 0
                while True:
                    b = raw[i]; i += 1
                    n |= (b & 0x7F) << shift; shift += 7
                    if not b & 0x80:
                        break
                chunk = raw[i:i + n]; i += n
                try:
                    out.setdefault(field, chunk.decode())
                except UnicodeDecodeError:
                    pass  # a nested message or bytes field: not a string we read
            elif wire == 1:
                i += 8
            elif wire == 5:
                i += 4
            else:
                break
    except IndexError:
        pass  # a truncated message: keep the fields read so far
    return out


def _payload_fields(value):
    import base64
    if isinstance(value, dict):
        return value
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    else:
        text = str(value)
        obj = _json(text)
        if isinstance(obj, dict):
            return obj
        try:
            # `goat sub` prints a payload that is not UTF-8 as `hex:<bytes>`
            # (the protobuf health envelopes); the REST plugin gives base64.
            raw = (bytes.fromhex(text[4:].strip()) if text.startswith("hex:")
                   else base64.b64decode(text, validate=True))
        except ValueError:
            raw = text.encode()
    try:
        obj = _json(raw.decode())
    except UnicodeDecodeError:
        obj = None
    if isinstance(obj, dict):
        return obj
    pb = _pb_strings(raw)
    fields = {_ENV_HEALTH_FIELDS[k]: v for k, v in pb.items() if k in _ENV_HEALTH_FIELDS}
    if "scope" in fields:
        fields.setdefault("site", fields["scope"])
    return fields


def _check_fields(key, value, expect):
    got = _payload_fields(value)
    bad = [f"{k}={got.get(k)!r} (want {v!r})" for k, v in (expect or {}).items()
           if str(got.get(k)) != str(v)]
    return bad


def _sub_via_goat(params, key, secs, publish_nonce=None):
    """(state, samples|reason) through `goat sub`. state is 'ok' with a list
    of (key, payload) lines, or 'locus' when goat cannot speak for the goatnet,
    or 'fail' with the reason."""
    import time
    ctx, via = params.get("context"), params.get("via")
    if not ctx:
        return "locus", "no goat context"
    remote = bool(via) and not _local(via)
    if not remote and not shutil.which("goat"):
        return "locus", "`goat` is not on PATH here"
    sub = (f"goat --context {shlex.quote(str(ctx))} sub {shlex.quote(key)} --literal "
           f"--take 1 --for {int(secs)}s")
    pub = (f"goat --context {shlex.quote(str(ctx))} pub {shlex.quote(key)} "
           f"--payload {shlex.quote(publish_nonce)}") if publish_nonce else None

    def wrap(c):
        if remote:
            return (f"ssh -o BatchMode=yes -o ConnectTimeout=6 {_ssh_jump()}-o StrictHostKeyChecking=accept-new "
                    f"{via} {shlex.quote('cd /tmp && ' + c)}")
        return c
    env = dict(os.environ, NO_COLOR="1", GOAT_NO_FUN="1", RUST_LOG="error")
    proc = subprocess.Popen(wrap(sub), shell=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, env=env)
    if pub:
        time.sleep(float(params.get("settle_s", 2)))
        subprocess.run(wrap(pub), shell=True, capture_output=True, text=True,
                       timeout=secs + 10, env=env)
    try:
        out, err = proc.communicate(timeout=secs + 15)
    except subprocess.TimeoutExpired:
        proc.kill()
        return "fail", f"`goat sub {key}` did not return"
    lines = [l.split(" ", 1) for l in out.splitlines() if l.strip()]
    if lines:
        return "ok", [(l[0], l[1] if len(l) > 1 else "") for l in lines]
    if remote and proc.returncode == 255:
        return "locus", f"{via}: unreachable"
    if proc.returncode == 127 or "command not found" in err:
        return "locus", "`goat` is not installed"
    if "unexpected argument" in err or "unrecognized subcommand" in err:
        return "locus", "the goat here predates `sub --for`"
    import re
    m = re.search(r"\bcode: ((?:E|GB|X)[-_][A-Z0-9_-]+)", err)
    if m and m.group(1) in LOCUS_CODES:
        return "locus", m.group(1)
    return "fail", (f"nothing heard on {key} in {int(secs)}s"
                    + (f" ({m.group(1)})" if m else ""))


def _sub_via_rest(params, key, secs, publish_nonce=None):
    """Same contract as _sub_via_goat, through the router's REST plugin
    (server-sent events) on the host's loopback."""
    host = params.get("rest_host")
    if not host:
        return "locus", "no rest_host"
    url = f"http://127.0.0.1:{int(params.get('rest_port', 8000))}/{key}"
    s = int(secs)
    sub = (f"curl -s -N --max-time {s} -H 'Accept: text/event-stream' {shlex.quote(url)}")
    if publish_nonce:
        cmd = (f"f=$(mktemp); ({sub} > \"$f\" 2>/dev/null &); "
               f"sleep {float(params.get('settle_s', 2))}; "
               f"curl -s -o /dev/null -X PUT -H 'Content-Type: text/plain' "
               f"--data-binary {shlex.quote(publish_nonce)} {shlex.quote(url)}; "
               f"sleep 3; cat \"$f\"; rm -f \"$f\"")
    else:
        cmd = f"{sub} | grep -m1 '^data:'"
    r = _host_run(host, cmd, s + 20)
    if not r.reached:
        return "locus", f"{host}: unreachable"
    samples = []
    for line in r.out.splitlines():
        if line.startswith("data:"):
            obj = _json(line[5:])
            if isinstance(obj, dict):
                samples.append((str(obj.get("key", "")), obj.get("value", "")))
    if samples:
        return "ok", samples
    probe = _host_run(host, f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 4 "
                      f"http://127.0.0.1:{int(params.get('rest_port', 8000))}/@/*/router", 10)
    if probe.out.strip() in ("", "000"):
        return "locus", f"no router REST on {host}"
    return "fail", f"nothing heard on {key} in {s}s"


def bus_roundtrip(params) -> Verdict:
    import secrets
    secs = _timeout(params, 30)
    publish = bool(params.get("publish"))
    key = params.get("key") if publish else params.get("subscribe")
    if not key:
        return Verdict(UNKNOWN, "no key (subscribe: <key> or publish: true + key)", "bus-roundtrip")
    if publish:
        key = f"{str(key).rstrip('/')}/{secrets.token_hex(4)}"
    nonce = f"goat-assay-{secrets.token_hex(8)}" if publish else None
    reasons = []
    for name, fn in (("goat", _sub_via_goat), ("router REST", _sub_via_rest)):
        state, got = fn(params, key, secs, nonce)
        if state == "locus":
            reasons.append(f"{name}: {got}")
            continue
        if state == "fail":
            return Verdict(FAIL, f"via {name}: {got}", "bus-roundtrip")
        if publish:
            if any(nonce in str(v) for _, v in got):
                return Verdict(PASS, f"via {name}: {key} published and read back "
                               "[writes: one sample on a volatile key, not stored]", "bus-roundtrip")
            return Verdict(FAIL, f"via {name}: published on {key}, read back "
                           f"{[str(v)[:30] for _, v in got][:3]} without the nonce", "bus-roundtrip")
        k, v = got[0]
        if k and k != key and not k.startswith(key.rstrip("*").rstrip("/") + "/"):
            return Verdict(FAIL, f"via {name}: a sample arrived under {k}, not {key}", "bus-roundtrip")
        bad = _check_fields(k, v, params.get("expect_field"))
        if bad:
            return Verdict(FAIL, f"via {name}: {k}: " + "; ".join(bad), "bus-roundtrip")
        shown = {kk: vv for kk, vv in _payload_fields(v).items() if kk in ("scope", "overall_color", "site")}
        return Verdict(PASS, f"via {name}: {k} {shown or ''}".strip(), "bus-roundtrip")
    return Verdict(UNKNOWN, "no transport could speak for the goatnet — " + "; ".join(reasons),
                   "bus-roundtrip")


# --------------------------------------------------------------------------
# enroll_probe — a factory-fresh peer enrols with a setup key and reaches the
# management host across the mesh, then is removed. The Gate 1 claim
# (fresh-peer-probe.sh, F-188): every component "up" says nothing about
# whether a new peer can join.
#
# It writes, so it runs only when asked: `opt_in` truthy (the assay's
# `--var enroll_probe=1`), a docker host to run the throwaway peer on
# (`peer_host`; user@host or local), the NetBird admin API token in
# `$<token_env>` (it mints the key and removes the peer — without the means to
# clean up, it does not start). One session serves both parts:
#   1. mint an ephemeral one-off setup key (one use, one hour);
#   2. negative: a peer with a made-up key must NOT get a mesh address;
#   3. a fresh netbird client container enrols with the real key (part
#      `enroll`: management connected, a mesh address assigned);
#   4. from inside it, `reach_ip` answers on `reach_port` (part `mesh-reach`);
#   5. always: remove the containers, delete the peer and the key, and confirm
#      the peer is gone. A cleanup that fails is a FAIL naming what was left.
# --------------------------------------------------------------------------
_ENROLL_SESSIONS = {}


def _nb_api(mgmt, token, method, path, data=None, timeout=15):
    import json
    hdrs = [f"Authorization: Token {token}", "Accept: application/json"]
    if data is not None:
        hdrs.append("Content-Type: application/json")
    code, body, _ = _curl(f"{mgmt}{path}", timeout, method, hdrs,
                          json.dumps(data) if data is not None else None)
    return code, _json(body) if code is not None else body


def _enroll_session(params):
    import secrets
    import time
    mgmt = str(params.get("mgmt_url", "")).rstrip("/")
    host, image = params.get("peer_host"), params.get("image")
    token = os.environ.get(str(params.get("token_env", "")))
    t = _timeout(params, 120)
    res = {"enroll": None, "mesh-reach": None, "wrote": []}

    def verdict(part, status, ev):
        res[part] = Verdict(status, ev, "enroll-probe")

    name = f"goat-assay-{secrets.token_hex(4)}"
    key_id = peer_id = None
    containers = []
    docker = "docker"
    try:
        code, body = _nb_api(mgmt, token, "POST", "/api/setup-keys", {
            "name": name, "type": "one-off", "expires_in": 3600, "usage_limit": 1,
            "ephemeral": True, "auto_groups": [], "revoked": False})
        if code is None:
            verdict("enroll", UNKNOWN, f"management API unreachable: {body}")
            return res
        if code not in (200, 201) or not isinstance(body, dict) or not body.get("key"):
            verdict("enroll", FAIL if code not in (401, 403) else UNKNOWN,
                    f"could not mint a setup key: HTTP {code}")
            return res
        key_id = body.get("id")
        res["wrote"].append(f"setup key {name}")

        def run_peer(cname, setup_key):
            containers.append(cname)
            cmd = (f"{docker} run -d --name {cname} --hostname {name} --cap-add NET_ADMIN "
                   f"--cap-add SYS_ADMIN --cap-add SYS_RESOURCE --device /dev/net/tun "
                   f"-e NB_SETUP_KEY={shlex.quote(setup_key)} "
                   f"-e NB_MANAGEMENT_URL={shlex.quote(mgmt)} -e NB_HOSTNAME={name} "
                   f"{shlex.quote(str(image))}")
            return _host_run(host, cmd, 120)

        def status(cname):
            r = _host_run(host, f"{docker} exec {cname} netbird status --json", 20)
            st = _json(r.out) if r.rc == 0 else None
            return st if isinstance(st, dict) else {}

        # negative: a made-up key gets no address
        bad = f"{name}-neg"
        r = run_peer(bad, "00000000-0000-0000-0000-000000000000")
        if not r.reached or r.rc != 0:
            verdict("enroll", UNKNOWN, f"could not start a peer on {host}: {(r.err or r.out).strip()[:100]}")
            return res
        time.sleep(float(params.get("negative_wait_s", 20)))
        neg = status(bad)
        neg_ip = neg.get("netbirdIp") or ""
        _host_run(host, f"{docker} rm -f {bad}", 30)
        containers.remove(bad)

        # positive
        r = run_peer(name, body["key"])
        if r.rc != 0:
            verdict("enroll", UNKNOWN, f"could not start the peer: {(r.err or r.out).strip()[:100]}")
            return res
        res["wrote"].append(f"peer {name}")
        deadline, st = time.time() + t, {}
        while time.time() < deadline:
            st = status(name)
            if (st.get("management") or {}).get("connected") and st.get("netbirdIp"):
                break
            time.sleep(3)
        ip = st.get("netbirdIp") or ""
        connected = (st.get("management") or {}).get("connected")
        if neg_ip:
            verdict("enroll", FAIL, f"a peer with a made-up setup key got {neg_ip}")
        elif connected and ip:
            verdict("enroll", PASS, f"{name} enrolled at {ip} via {mgmt}; a made-up key got no address")
        else:
            verdict("enroll", FAIL, f"{name} did not enrol in {int(t)}s "
                    f"(management connected={connected}, ip={ip or 'none'})")
        if res["enroll"].status == PASS and params.get("reach_ip"):
            rip, rport = params["reach_ip"], int(params.get("reach_port", 443))
            r = _host_run(host, f"{docker} exec {name} sh -c "
                                    f"{shlex.quote(f'nc -z -w 8 {rip} {rport} || ping -c 2 -W 4 {rip}')}", 40)
            verdict("mesh-reach", PASS if r.rc == 0 else FAIL,
                    f"{name} -> {rip}:{rport} " + ("answered across the mesh" if r.rc == 0
                                                  else f"did not answer ({(r.err or r.out).strip()[:60]})"))
        elif res["enroll"].status == PASS:
            verdict("mesh-reach", UNKNOWN, "no reach_ip")
        else:
            verdict("mesh-reach", SKIPPED, "the peer did not enrol")
        return res
    finally:
        left = []
        for c in containers:
            _host_run(host, f"{docker} rm -f {c}", 30)
        if any(w.startswith("peer") for w in res["wrote"]):
            code, peers = _nb_api(mgmt, token, "GET", "/api/peers")
            for p in peers if isinstance(peers, list) else []:
                if name in (p.get("hostname"), p.get("name")) or str(p.get("name", "")).startswith(name):
                    peer_id = p.get("id")
                    dcode, _ = _nb_api(mgmt, token, "DELETE", f"/api/peers/{peer_id}")
                    if dcode not in (200, 204):
                        left.append(f"peer {peer_id} (DELETE HTTP {dcode})")
            code, peers = _nb_api(mgmt, token, "GET", "/api/peers")
            if isinstance(peers, list) and any(name in (p.get("hostname"), p.get("name")) for p in peers):
                left.append(f"peer {name} still listed")
        if key_id:
            dcode, _ = _nb_api(mgmt, token, "DELETE", f"/api/setup-keys/{key_id}")
            if dcode not in (200, 204):
                rcode, _ = _nb_api(mgmt, token, "PUT", f"/api/setup-keys/{key_id}",
                                   {"name": name, "revoked": True, "auto_groups": []})
                if rcode not in (200, 204):
                    left.append(f"setup key {key_id}")
        if left:
            for part in ("enroll", "mesh-reach"):
                prior = res[part].evidence if res[part] else ""
                res[part] = Verdict(FAIL, f"cleanup incomplete, left on the goatnet: "
                                    f"{', '.join(left)}. {prior}"[:300], "enroll-probe")
        else:
            for part in ("enroll", "mesh-reach"):
                v = res[part]
                if v is not None and res["wrote"]:
                    v.evidence += f" [wrote and removed: {', '.join(res['wrote'])}]"


def enroll_probe(params) -> Verdict:
    part = params.get("part", "enroll")
    if part not in ("enroll", "mesh-reach"):
        return Verdict(UNKNOWN, f"unknown part {part!r}", "enroll-probe")
    opt = str(params.get("opt_in", "")).strip().lower()
    if opt in ("", "0", "false", "no"):
        return Verdict(SKIPPED, "opt-in: enrols a throwaway peer and removes it; run with "
                       "--var enroll_probe=1 --var enroll_peer_host=<docker host> and the "
                       "NetBird admin token in the environment", "enroll-probe")
    for need in ("mgmt_url", "peer_host", "image", "token_env"):
        if not params.get(need):
            return Verdict(UNKNOWN, f"needs {need}", "enroll-probe")
    if not os.environ.get(str(params["token_env"])):
        return Verdict(UNKNOWN, f"needs ${params['token_env']} (the NetBird admin token): "
                       "without it the probe could not remove what it creates, so it "
                       "does not start", "enroll-probe")
    sk = (params["mgmt_url"], params["peer_host"])
    if sk not in _ENROLL_SESSIONS:
        _ENROLL_SESSIONS[sk] = _enroll_session(params)
    v = _ENROLL_SESSIONS[sk].get(part)
    return v or Verdict(UNKNOWN, "the session did not reach this part", "enroll-probe")


# --------------------------------------------------------------------------
# safe_browsing — is a PUBLIC enrollment/login FQDN flagged by Google Safe
# Browsing? A fresh public login/consent domain gets flagged as social
# engineering (it is not a TLS fault); a flagged apex means every enrolling
# user hits a full-page red browser interstitial and cannot reach the portal.
# Catching it at the finish gate is the point — before real users see it.
# Needs SAFE_BROWSING_API_KEY (a Google Cloud key with the Safe Browsing API
# enabled); without it the row is UNKNOWN with the procedure, never a false
# pass. A match is FAIL with the threat type; no match is PASS.
# --------------------------------------------------------------------------
def safe_browsing(params) -> Verdict:
    import json
    import os
    url = params.get("url") or params.get("name")
    if not url:
        return Verdict(UNKNOWN, "no url/name in params", "safe-browsing")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    key = os.environ.get("SAFE_BROWSING_API_KEY")
    if not key:
        return Verdict(UNKNOWN, "SAFE_BROWSING_API_KEY not set — cannot query "
                       "Safe Browsing; re-run the gate with the key (a Google "
                       "Cloud key with the Safe Browsing API enabled) to grade "
                       "this row", "safe-browsing")
    if not shutil.which("curl"):
        return Verdict(UNKNOWN, "curl not on PATH — probe kit incomplete", "safe-browsing")
    body = json.dumps({
        "client": {"clientId": "goat-acceptance-gate", "clientVersion": "1"},
        "threatInfo": {
            "threatTypes": ["SOCIAL_ENGINEERING", "MALWARE",
                            "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    })
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + key
    cmd = ["curl", "-s", "--max-time", str(int(_timeout(params))),
           "-H", "Content-Type: application/json", "-X", "POST", "-d", body, endpoint]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=_timeout(params) + 4)
    except subprocess.TimeoutExpired:
        return Verdict(UNKNOWN, f"{url}: Safe Browsing query timed out", "safe-browsing")
    resp = out.stdout.strip()
    if not resp:
        return Verdict(UNKNOWN, f"{url}: no response from Safe Browsing API "
                       "(unreachable from here) — not proof of clean", "safe-browsing")
    try:
        data = json.loads(resp)
    except ValueError:
        return Verdict(UNKNOWN, f"{url}: unparseable Safe Browsing response: "
                       f"{resp[:120]}", "safe-browsing")
    if isinstance(data, dict) and data.get("error"):
        msg = str(data["error"].get("message", ""))[:120]
        return Verdict(UNKNOWN, f"{url}: Safe Browsing API error: {msg}", "safe-browsing")
    matches = (data or {}).get("matches") or []
    if matches:
        types = ",".join(sorted({m.get("threatType", "?") for m in matches}))
        return Verdict(FAIL, f"{url}: FLAGGED by Safe Browsing as {types} — public "
                       "enrollers hit a browser interstitial; file a review request "
                       "in Google Search Console for the zone", "safe-browsing")
    return Verdict(PASS, f"{url}: not flagged by Safe Browsing", "safe-browsing")


# --------------------------------------------------------------------------
# container_health — a container on a host is running, and healthy when it
# declares a healthcheck. Running alone is the weakest signal in this file
# (the suite exists because running != functional); a row uses it only where
# the container's own healthcheck is the functional probe.
# --------------------------------------------------------------------------
def container_health(params) -> Verdict:
    name, host = params.get("container"), params.get("host")
    if not name or not host:
        return Verdict(UNKNOWN, "need container and host", "container-health")
    fmt = "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}"
    v = cmd_assert({"host": host, "cmd": f"docker inspect -f '{fmt}' {shlex.quote(name)}",
                    "timeout": params.get("timeout", 20)})
    if v.status != PASS:
        return Verdict(v.status, f"{name}: {v.evidence}", "container-health")
    state = v.evidence.removeprefix("ok: ").split()
    if state[:1] != ["running"]:
        return Verdict(FAIL, f"{name}: {' '.join(state)}", "container-health")
    if state[1:2] not in (["healthy"], ["no-healthcheck"]):
        return Verdict(FAIL, f"{name}: running but {state[1]}", "container-health")
    return Verdict(PASS, f"{name}: {' '.join(state)}", "container-health")


# --------------------------------------------------------------------------
# goat_cli — run a `goat` (or `goatbuilder`) verb and grade its JSON. The
# operator's own CLI is the preferred probe: it carries the honesty grading
# and the error codes a raw curl or docker exec does not. Runs locally, or on
# `via` (user@host, plain ssh, no sudo: a goat context belongs to its user).
#
# The probe's locus is graded apart from the goatnet. A probe that cannot
# speak for the goatnet is UNKNOWN with the reason: no profile or identity, off
# the mesh, an expired probe cert, a clock the probe's own host got wrong, a
# transport that never reached the router or the portal, or a goat older than
# the row's `min_goat` (default GOAT_MIN). Only an answer FROM the goatnet is
# FAIL: the portal answered 404/429/5xx (exit 7/8/9) or refused, a topic
# conflict, an assertion that does not hold. A clean exit is graded by
# `expect_jq` on stdout. goat's codes and exits are crates/goat-cli/src/errors.rs
# and exit_codes.rs (#2111); an older goat prints no code, so its exit decides:
# 3, 4, 5, 6 say the probe could not speak; 7, 8, 9 say the goatnet answered.
# --------------------------------------------------------------------------
LOCUS_CODES = ("E_PROFILE_MISSING", "E_PROFILE_DENIED", "E_OFF_MESH",
               "E_CERT_EXPIRED", "E_TOKEN_INVALID", "E_BUNDLE_INVALID",
               "E_CLOCK_SKEW", "E_ROUTER_UNREACHABLE", "E_PORTAL_UNREACHABLE",
               "E_DOCTOR_INCONCLUSIVE", "E_NOT_ADMIN")
ANSWER_CODES = ("E_PORTAL_NOT_FOUND", "E_PORTAL_RATE_LIMITED", "E_PORTAL_SERVER_ERROR",
                "E_PORTAL_REFUSED", "E_PORTAL_FORBIDDEN", "E_PORTAL_BAD_RESPONSE",
                "E_TOPIC_CONFLICT", "E_DOES_NOT_EXIST")
LOCUS_EXITS = (3, 4, 5, 6)
ANSWER_EXITS = (7, 8, 9)
# The oldest goat whose fabric session reaches today's routers: 0.5.4 is the
# release whose fabric path works on a slot-pool goatnet (#1071). A row can
# raise it with `min_goat` for a verb or flag added later.
GOAT_MIN = "0.5.4"
_CODE = None
_VERSIONS = {}


def _ver(s):
    import re
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", s or "")
    return tuple(int(x) for x in m.groups()) if m else None


def _goat_version(binary, via, remote):
    """`<binary> --version` on the probe's host, cached per host."""
    key = (binary, via if remote else "")
    if key not in _VERSIONS:
        cmd = f"{binary} --version"
        if remote:
            cmd = (f"ssh -o BatchMode=yes -o ConnectTimeout=6 {_ssh_jump()}-o StrictHostKeyChecking=accept-new "
                   f"{via} {shlex.quote(cmd)}")
        try:
            out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=20)
            _VERSIONS[key] = _ver(out.stdout) if out.returncode == 0 else None
        except subprocess.TimeoutExpired:
            _VERSIONS[key] = None
    return _VERSIONS[key]


def goat_cli(params) -> Verdict:
    import re
    global _CODE
    _CODE = _CODE or re.compile(r"\bcode: ((?:E|GB|X)[-_][A-Z0-9_-]+)")
    verb = params.get("verb")
    if not verb:
        return Verdict(UNKNOWN, "no verb", "goat-cli")
    binary = params.get("bin", "goat")
    ctx = params.get("context")
    if binary == "goat" and not ctx:
        return Verdict(UNKNOWN, "no goat context named (set probe_context or goat_context)", "goat-cli")
    cmd = f"{binary} --context {shlex.quote(str(ctx))} {verb}" if binary == "goat" else f"{binary} {verb}"
    via = params.get("via")
    remote = bool(via) and via not in ("localhost", "127.0.0.1")
    if remote:
        cmd = (f"ssh -o BatchMode=yes -o ConnectTimeout=6 {_ssh_jump()}-o StrictHostKeyChecking=accept-new "
               f"{via} {shlex.quote('cd /tmp && ' + cmd)}")
    elif not shutil.which(binary):
        return Verdict(UNKNOWN, f"`{binary}` is not on PATH here", "goat-cli")
    where = f" on {via}" if remote else ""
    if binary == "goat":
        floor = str(params.get("min_goat") or GOAT_MIN)
        have = _goat_version(binary, via, remote)
        if have is not None and have < _ver(floor):
            return Verdict(UNKNOWN, f"goat {'.'.join(map(str, have))}{where} is older than {floor}, "
                           f"which `{verb.split()[0]}` needs here; run `goat update`", "goat-cli")
    env = dict(os.environ, NO_COLOR="1", GOAT_NO_FUN="1", RUST_LOG="error")
    try:
        out = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                             timeout=_timeout(params, 60), env=env)
    except subprocess.TimeoutExpired:
        return Verdict(UNKNOWN, f"`{binary} {verb}` timed out", "goat-cli")
    err = out.stderr.strip()
    if remote and out.returncode == 255:
        return Verdict(UNKNOWN, f"{via}: unreachable ({err[:80]})", "goat-cli")
    if out.returncode == 127 or "command not found" in err:
        return Verdict(UNKNOWN, f"`{binary}` is not installed{where}", "goat-cli")
    if "unexpected argument" in err or "unrecognized subcommand" in err:
        return Verdict(UNKNOWN, f"the {binary}{where} predates `{verb}` "
                       f"({err.splitlines()[0][:80]}); update it", "goat-cli")
    m = _CODE.search(err)
    code = m.group(1) if m else ""
    # expect_rc: "graded-by-json" — the verb's exit code summarises the very
    # legs the row's expect_jq grades one by one (`goat status` exits 1 when
    # any leg is not ok, including a leg the row deliberately does not grade),
    # so the JSON decides. A non-zero exit with no JSON on stdout still fails.
    rc_by_json = params.get("expect_rc") == "graded-by-json"
    want_rc = 0 if rc_by_json else int(params.get("expect_rc", 0))
    if out.returncode != want_rc and not (rc_by_json and out.stdout.strip().startswith("{")):
        locus = code in LOCUS_CODES or (not code and binary == "goat"
                                         and out.returncode in LOCUS_EXITS)
        if locus:
            return Verdict(UNKNOWN, f"{code or 'rc=' + str(out.returncode)}{where}: the probe cannot "
                           f"speak for the goatnet — {err.splitlines()[-1][:90] if err else ''}", "goat-cli")
        last = next((l for l in reversed(err.splitlines()) if l.startswith("error")), err[-120:])
        return Verdict(FAIL, f"rc={out.returncode}{' ' + code if code else ''}{where}: "
                       f"{last[:110] or out.stdout.strip()[:110]}", "goat-cli")
    stdout = out.stdout.strip()
    # unknown_jq: an answer that cannot tell the goatnet's state either way
    # (an empty presence set is an idle goatnet or a silently denied query,
    # F-177) is UNKNOWN with the row's reason, never a FAIL and never a PASS.
    if "unknown_jq" in params and shutil.which("jq"):
        uq = subprocess.run(["jq", "-e", params["unknown_jq"]], input=stdout,
                            capture_output=True, text=True)
        if uq.returncode == 0:
            return Verdict(UNKNOWN, f"{params.get('unknown_reason', 'the answer cannot grade this row')}{where}",
                           "goat-cli")
    if "expect_jq" in params:
        if not shutil.which("jq"):
            return Verdict(UNKNOWN, "expect_jq needs jq on PATH", "goat-cli")
        jq = subprocess.run(["jq", "-e", params["expect_jq"]], input=stdout,
                            capture_output=True, text=True)
        if jq.returncode != 0:
            return Verdict(FAIL, f"{params['expect_jq']} is false on: {stdout[:110]}", "goat-cli")
    return Verdict(PASS, f"ok{where}: {stdout[:110]}", "goat-cli")


def _aslist(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


REGISTRY = {
    "http-ok": http_ok,
    "dns-resolve": dns_resolve,
    "tls-identity": tls_identity,
    "tls-alpn": tls_alpn,
    "cmd-assert": cmd_assert,
    "safe-browsing": safe_browsing,
    "bus-roundtrip": bus_roundtrip,
    "bus-liveliness": bus_roundtrip,
    "oidc-flow": oidc_flow,
    "enroll-probe": enroll_probe,
    "goat-cli": goat_cli,
    "container-health": container_health,
    "onboard-runner-profile": onboard_runner_profile,
}
