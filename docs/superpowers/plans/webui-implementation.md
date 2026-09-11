# Implementation plan — replacement WebUI

Spec: `docs/WEBUI-PLAN.md` (binding authority; this plan argues from it).

## Context

CSF's built-in WebUI is 5,071 lines running as root: `lfd.pl sub ui()` is 853
lines of hand-written HTTP parsing, `DisplayUI.pm` 2,935, `cseUI.pm` 1,042,
`DisplayResellerUI.pm` 241. `lfd.pl` never drops privilege. Passwords are
compared with `eq` against a plaintext value in `csf.conf` (`lfd.pl:9788`) and
there is no CSRF protection anywhere (`grep -ci 'csrf|nonce'` returns 0).

This plan builds the replacement. Nothing in it deletes the old UI until the
last task.

## Global Constraints

**G1 — no new runtime dependencies.** Perl 5.14-compatible (raised from 5.10 by
Ruling R14: `Socket::inet_pton` and `SO_PEERCRED` need Socket >= 1.94, which ships
with 5.14). Core modules only,
plus what CSF already vendors under `/usr/local/csf/lib` (`JSON::Tiny` is
vendored and is the wire format). `IO::Socket::SSL` is optional and must fail
closed when absent — never downgrade to plain HTTP. Verified available on the
target: `Socket`, `IO::Socket::UNIX`, `Digest::SHA`, `MIME::Base64`,
`Time::HiRes`, `Test::More`.

**G2 — no shell, ever.** Every external command runs via `system`/`exec` with an
argv LIST. No string interpolation into a command, no backticks, no `qx`, no
`open` with a pipe to a string. This is absolute at every layer.

**G3 — fail closed.** Missing dependency, unverifiable input, unknown state: refuse
and say why. Never degrade to a less safe path.

**G4 — copyright.** Every new file starts with the CSF GPL header, keeping
`Copyright (C) 2006-2025 Jonathan Michaelson`, plus a line
`# Added <YYYY-MM-DD> in https://github.com/nkyo/csf — see CHANGES.md.`
Never remove or alter an existing copyright notice in a file you modify.

**G5 — tests.** Tests live in `t/`, run with `prove -I. t/`. Every task that adds
code adds tests for it. Tests must pass without root, without network, and
without `IO::Socket::SSL`. Tests that need root are skipped with a clear
`skip` reason, never silently passed.

**G6 — CHANGES.md.** Every task appends its entry under `### Unreleased` with a
date, per GPLv3 §5(a). Never rewrite prior entries.

**G7 — installed paths.**

> **Ruling R11.** Nothing belonging to the UI lives under `/etc/csf`,
> `/var/lib/csf` or `/usr/local/csf`. `lfd.pl:1187-1196` sits inside the `while (1)`
> at `lfd.pl:1173` and resets all three to `0600` on every main-loop pass, logging
> each reset — an unprivileged process can never traverse them, and permissions we
> set are undone within seconds. `/usr/local/csf` being on that list also means
> systemd could not exec a binary there as `csfui`, since exec happens after
> credentials are dropped.

| Thing | Path |
|---|---|
| helper (root) | `/usr/local/csf-ui/bin/csf-ui-helper` |
| web app (user `csfui`) | `/usr/local/csf-ui/bin/csf-ui` |
| password CLI | `/usr/local/csf-ui/bin/csf-ui-passwd` |
| setup wizard | `/usr/local/csf-ui/bin/csf-ui-setup` |
| modules | `/usr/local/csf-ui/lib/ConfigServer/UI/*.pm` |
| helper socket | `/var/run/csf-ui/helper.sock` (0660 `root:csfui`) |
| users file | `/etc/csf-ui/users` (0600 root — the helper reads it, the web tier never does) |
| UI config | `/etc/csf-ui/ui.conf` (dir 0750 `root:csfui`, file 0640 `root:csfui`) |
| runtime state | `/var/lib/csf-ui/` — `sessions/`, `rl/`, `helper/authfail.state` |
| audit log (root) | `/var/log/csf-ui-audit.log` (0640 root) |
| access log (web) | `/var/log/csf-ui-access.log` (0640 `csfui`) |

In-repo sources live at `ui-src/` (`ui-src/csf-ui`, `ui-src/csf-ui-helper`,
`ui-src/lib/ConfigServer/UI/*.pm`, `ui-src/web/*`). Installers copy from there.

**G8 — the helper never trusts the web tier for identity.** It authenticates its
peer with `SO_PEERCRED` and serves only the frozen allowlist; it does not accept a
role from a message, because it cannot verify one.

The OS boundary here is **unprivileged-vs-root, not admin-vs-support**. There is
one web process, running as `csfui`; whichever role a session carries, that process
can reach every allowlisted operation. Support-role enforcement is therefore
application-level, and an attacker who owns `csf-ui` reaches every operation
regardless of session role. Say this plainly wherever the design is described —
claiming a boundary that does not exist is worse than not having one.

**G9 — no secrets in logs or URLs.** Tokens never appear in a URL, a log line, or
an error message.

---

## Task 1: Threat model and frozen RPC contract

**Deliverable:** `docs/WEBUI-RPC.md`. No code.

Write, in this order:

1. **Trust boundaries** — a table of the four zones (network, `csf-ui`,
   `csf-ui-helper`, system) and for each: what it trusts, what it must validate,
   what an attacker who owns it can reach.
2. **The frozen operation allowlist.** Exactly these 13, no more, taken from the
   spec §5. For each: name, arguments with types and validation rules, return
   shape, which socket it is served on (admin / read-only), and whether it
   mutates state.

   `status` · `counts` · `deny(ip,note)` · `undeny(ip)` · `allow(ip,note)` ·
   `unallow(ip)` · `tempdeny(ip,ttl,ports)` · `temprm(ip)` ·
   `list(which,offset,limit,filter)` · `grep(ip)` · `reconcile` ·
   `reconcile_fix(ids)` · `restart` · `authenticate(user,pass)`

   Ruling R6 added `authenticate`: password hashes stay root-only and the web tier
   never reads them. The helper keeps its own per-user failure counter, independent
   of the web tier's rate limiter.

   All 13 are served on the single helper socket. Do not design a second
   read-only socket: with one web process it separates nothing (see G8).
   Record which operations mutate state — the audit log and the screens depend
   on that distinction, not the transport.
3. **Wire format.** One JSON object per line, UTF-8, `\n`-terminated. Request
   `{"op":"...","args":{...},"id":"<uuid>"}`. Response
   `{"id":"...","ok":true,"data":{...}}` or
   `{"id":"...","ok":false,"error":"<code>","message":"..."}`. Maximum 65536
   bytes per line; a longer line is a protocol error that closes the connection.
   Error codes are an enumerated list — define it.
4. **Validation rules per argument type**: `ip` (IPv4, IPv6, or CIDR, via
   `Socket::inet_pton`; reject anything else), `ttl` (integer 60..604800),
   `ports` (comma list of 1..65535 or ranges, max 20 entries), `note` (max 200
   bytes, control characters and newlines rejected), `which`
   (`deny`|`temp`|`allow`), `offset`/`limit` (integers, limit max 500),
   `filter` (max 100 bytes, treated as a literal substring, never a regex),
   `ids` (list of opaque ids from a preceding `reconcile`, max 500).
5. **What is deliberately absent and why** — no file paths, no command strings,
   no config writes, no log reads over RPC.
6. **The `ui.conf` keys**, frozen here because Task 5 reads them and Task 9
   writes them and neither may invent its own names:
   `UI_MODE` (`a` or `b`) · `UI_LISTEN` (address, Mode B only) · `UI_PORT` ·
   `UI_ALLOW` (comma-separated CIDRs; empty means refuse to start) ·
   `UI_CRYPT_ROUNDS` · `UI_SESSION_IDLE` · `UI_SESSION_MAX`. Give each a type,
   a default and a validation rule.

**Acceptance:** the document answers, for each of the 13 operations, what an
attacker sending a hostile value for every argument gets. If any answer is "it
depends on the caller", the boundary is wrong — fix the design, not the prose.

---

## Task 2: `csf-ui-helper` — the privileged half

**Files:** `ui-src/csf-ui-helper`, `ui-src/lib/ConfigServer/UI/Proto.pm`, `t/10-proto.t`,
`t/11-helper-validate.t`

Implement the contract frozen in Task 1.

**`ConfigServer/UI/Proto.pm`** — shared by both halves:
- `encode($hashref)` → one JSON line, dies if > 65536 bytes
- `decode($line)` → hashref, dies on malformed JSON or oversize
- `read_message($fh)` → reads one `\n`-terminated line with a byte cap, returns
  hashref or undef on EOF; never reads unbounded
- `validate_ip($s)`, `validate_ttl($n)`, `validate_ports($s)`,
  `validate_note($s)`, `validate_which($s)`, `validate_filter($s)` — each returns
  the normalised value or `undef`. `validate_ip` uses `Socket::inet_pton` for
  both families and handles `addr/len` CIDR.

**`csf-ui-helper`** — runs as root:
- Listens on one socket. Creates `/var/run/csf-ui` mode 0755 root, socket 0660
  group `csfui`. **If the `csfui` group does not exist yet** — Task 9 creates it —
  the socket is created 0600 root-only and every connection is refused with a clear
  error. Never fall back to a permissive mode (G3).
- **On every accepted connection**, reads peer credentials with
  `getsockopt($sock, SOL_SOCKET, SO_PEERCRED)` and `unpack("iii")` → pid, uid,
  gid. Verified working on this platform: `Socket::SO_PEERCRED()` is 17.
  Rejects and logs any peer whose uid is not the expected `csfui` uid — and
  rejects uid 0 as well, because root has no reason to come through this door.
- Dispatches only names in the allowlist; an unknown `op` is an error response,
  never an exception that kills the daemon.
- Every csf invocation is `system('/usr/sbin/csf', '-d', $ip, $note)` style —
  an argv list (G2). Assert this in tests by grepping the source for backticks,
  `qx`, and `system` with a single string argument.
- Serves each connection in a forked child; parent reaps. Hard cap of 16
  concurrent children; over the cap, respond with an error and close.
- Audit: every mutating op appends one line to `/var/log/csf-ui-audit.log` as
  JSON with time, op, args (note truncated), peer pid/uid, outcome. Control
  characters escaped by the JSON encoder (G9, log injection).

**Tests** (must pass without root): `Proto.pm` round-trips; oversize line
rejected; malformed JSON rejected; every validator accepts a table of good
values and rejects a table of hostile ones — including `1.2.3.4; rm -rf /`,
`$(id)`, newline injection, `::ffff:127.0.0.1`, `999.1.1.1`, `10.0.0.0/33`,
overlong notes, and a note containing `\n` and `\r`. Helper dispatch logic is
tested by calling the dispatch function directly with a fake peer-credential
provider, so no root and no real socket are needed.

---

## Task 3: authentication store

**Files:** `ui-src/lib/ConfigServer/UI/Auth.pm`, `ui-src/csf-ui-passwd`, `t/20-auth.t`

> **Ruling R6 — read this before writing a line.** `Auth.pm` runs **inside the root
> helper**, not in the web tier. `csf-ui` never opens the users file; it calls the
> `authenticate` operation. Writing this module on the assumption that the web tier
> loads it would silently undo the boundary R6 exists to create.

- Password hashing: `crypt()` with a `$6$` SHA-512 salt, 16 random salt bytes
  from `/dev/urandom`, rounds from `ui.conf` (`UI_CRYPT_ROUNDS`, default 100000,
  minimum 5000). **Ruling R13: `$6$` SHA-512 is the only implemented algorithm.**
  `Crypt::Argon2` is neither core nor vendored, so G1 forbids it, and a branch that
  cannot run implies a strength the deployment does not have. Keep the `algo` field
  in the record format so a future migration is possible; reject any record whose
  `algo` is not `6`. Never store plaintext.
- Record format, one user per line:
  `username:algo:hash:role:created_epoch` — `role` is `admin` or `support`.
  Username `[a-z0-9_-]{1,32}`. Reject anything else on write.
- `verify($user,$pass)` compares in constant time (compare every byte of a
  fixed-length digest of both sides; never `eq` on the raw hash).
- Writes are atomic: write `users.tmp` in the same directory with mode 0600,
  `fsync`, `rename`. Refuse to operate if `users` is a symlink or not owned by
  uid 0.
- `csf-ui-passwd` CLI: `add <user> <role>`, `passwd <user>`, `delete <user>`,
  `list`. Reads the password from a prompt with echo off, or from stdin when not
  a tty. **No default account and no default password** — until an admin is
  created, the UI has no way in.

**Tests:** hash/verify round-trip; wrong password fails; constant-time compare
does not short-circuit (assert by comparing timings is flaky — instead assert
the implementation consumes both inputs fully via a mocked digest); malformed
records rejected; symlink target refused; atomic replace leaves no partial file;
role values validated.

---

## Task 4: `csf-ui` core

**Files:** `ui-src/lib/ConfigServer/UI/Session.pm`, `ui-src/lib/ConfigServer/UI/Client.pm`,
`ui-src/lib/ConfigServer/UI/RateLimit.pm`, `ui-src/csf-ui`, `t/30-session.t`,
`t/31-ratelimit.t`, `t/32-client.t`

- **`Client.pm`** — connects to the helper socket, sends a request, reads one
  response, enforces a 10-second timeout, and never retries a mutating op.
- **`Session.pm`** — 32 bytes from `/dev/urandom`, base64url. Stored server-side
  in `/var/lib/csf-ui/sessions/<id>` mode 0600 with the username, role, CSRF
  nonce, creation and last-use epochs. Idle timeout 1800s, absolute 43200s.
  Cookie attributes `HttpOnly; Secure; SameSite=Strict; Path=/`.
  `csrf_ok($session,$submitted)` compares in constant time.
- **`RateLimit.pm`** — token bucket per source address AND per username, state
  under `/var/lib/csf-ui/rl/`. Defaults: 5 failed logins per 15 min per address,
  10 per 15 min per username. **Never writes to `csf.deny`** — a login failure
  must not be able to add a firewall entry (spec §7).
- **`csf-ui`** — the request handler. Given a normalised request (method, path,
  headers, body, peer address) it routes, checks session and CSRF on every
  state-changing request, calls the helper, and returns status, headers and
  body. It does not parse HTTP and does not touch sockets: that is Task 5 or the
  front web server. This separation is what lets Mode A exist at all.

**Tests:** session create/load/expire/idle; CSRF accept and reject; tampered
session id rejected; rate limiter opens and closes; client timeout path; router
returns 405 for unknown method, 404 for unknown path, 403 without CSRF.

---

## Task 5: minimal HTTP and TLS core (Mode B)

**Files:** `ui-src/lib/ConfigServer/UI/HTTP.pm`, `ui-src/lib/ConfigServer/UI/Server.pm`,
`t/40-http-parse.t`, `t/41-http-hostile.t`

`HTTP.pm` parses a request from a filehandle into the normalised structure Task 4
consumes. Deliberately small and deliberately strict:

- **GET and POST only.** Any other method → 405 without reading a body.
- Request line max 8192 bytes; max 64 headers; each header max 8192 bytes;
  body max 65536 bytes; `Content-Length` required for POST and must match.
- **No keep-alive** (`Connection: close` always), **no chunked transfer
  encoding** (`Transfer-Encoding` present → 400), **no multipart**, **no ranges**.
- Body content type must be `application/x-www-form-urlencoded`; anything else
  → 415.
- Percent-decoding rejects invalid escapes rather than guessing. `%00` in a path
  or parameter → 400.
- Read timeout 15s for headers, 15s for body; a slow client is dropped.
- Duplicate `Content-Length` or `Host` → 400 (request smuggling).

`Server.pm` accepts connections and hands them to `HTTP.pm`. TLS via
`IO::Socket::SSL`; if it does not load, `Server.pm` **refuses to start** with a
message naming the package to install (G3). Binds only addresses from
`ui.conf`; an empty IP allowlist refuses to start.

**Tests** — `t/41-hostile.t` is the point of this task. Feed the parser, from
in-memory filehandles: oversize request line; 200 headers; header with no colon;
duplicate `Content-Length`; `Transfer-Encoding: chunked`; `Content-Length`
larger than the body; `%zz` and `%0` and `%00`; a NUL byte; CR without LF; LF
without CR; absolute-form URI; `..%2f..%2f` traversal; a 70000-byte body. Every
one must produce a 4xx and must not hang, die uncaught, or allocate the declared
length before reading it.

---

## Task 6: templates, CSS, accessibility

**Files:** `ui-src/web/layout.html`, `ui-src/web/app.css`,
`ui-src/lib/ConfigServer/UI/Render.pm`, `t/50-render.t`

- `Render.pm`: substitutes `{{key}}` in a template. **HTML-escapes by default**;
  a raw insert requires an explicitly different marker so that forgetting is safe
  rather than dangerous. Escapes `& < > " '`.
- One stylesheet, plain CSS, served from disk. No CDN, no framework, no jQuery,
  no Chosen.
- One breakpoint at 768px; tables become stacked cards below it; touch targets
  ≥44px; `input` types matched to content so mobile keyboards are right.
- Accessibility: every control labelled, visible focus outline that is not
  `outline:none`, contrast ≥4.5:1 for body text, usable at 200% zoom, skip link,
  landmark elements.

**Tests:** escaping (including `<script>` in every substitution position);
missing key is an error, not a silent blank; raw marker requires opt-in.

---

## Task 7: the five screens

**Files:** `ui-src/web/screens/*.html`, handlers in `ui-src/csf-ui`, `t/60-screens.t`

Overview, Block/Unblock, Lists, IP lookup, Health — exactly as the spec §2
describes, no sixth screen. Every state-changing action is a POST carrying the
CSRF nonce. `support` sees **only IP lookup and read-only Lists** — not Overview,
not Health; the server enforces this per request, because hiding a button is not
enforcement.

Health shows the `reconcile` result and requires a **separate confirmation with
a diff** before `reconcile_fix`; no one-click destructive action (spec §5).

**Tests:** each screen renders with fixture data; a `support` session is refused
every mutating route with 403; CSRF missing or wrong → 403; pagination bounds.

---

## Task 8: setup wizard

**Files:** `ui-src/csf-ui-setup`, `ui-src/lib/ConfigServer/UI/Firewall.pm`,
`ui-src/lib/ConfigServer/UI/Rollback.pm`, `t/70-firewall-detect.t`, `t/71-rollback.t`

- `Firewall.pm` — detect the backend actually in use: `iptables-legacy`,
  `iptables-nft`, `nftables`, `firewalld`, `ufw`, or **unknown**. Detection is by
  probing the binaries and their behaviour, not by guessing from the distribution.
  On `unknown`, every mutating path declines.
- Opening the temporary port: allowed only when the backend is known AND a single
  operator address is known. The rule is added, then **read back** and stored in
  its canonical form; removal uses the stored spec. On `unknown` backend, or no
  operator address, the wizard binds `127.0.0.1` only and prints the `ssh -L`
  command.
- The token is set by a POST and carried in a cookie. **Never in a URL** (G9).
- Lifetimes: 30 min absolute, 10 min idle, and cleanup on `EXIT`/`INT`/`TERM`.
  `csf-ui-setup --cleanup` removes leftovers from a session that died badly.
- `Rollback.pm` — snapshot the current ruleset and `csf.conf` before applying;
  install a **systemd timer independent of csf and lfd** that restores the
  snapshot unless the operator confirms; confirmation cancels the timer. Apply is
  atomic: build the new config in a temp file, validate, then rename.
- The wizard writes an answers file and calls `csf-setup --answers FILE --yes`;
  it never edits `csf.conf` directly (spec §6).

**Tests:** backend detection against fixture command outputs for all six cases;
`unknown` declines; canonical spec round-trip; rollback timer unit is written and
removed; answers file round-trips through the CLI path.

---

## Task 9: Mode A integration, packaging, installer choice

**Files:** `ui-src/dist/nginx.conf.tpl`, `ui-src/dist/apache.conf.tpl`,
`ui-src/dist/litespeed.conf.tpl`, `ui-src/dist/csf-ui.service`,
`ui-src/dist/csf-ui-helper.service`, installer changes in all seven
`install.*.sh`, `t/80-templates.t`

- Templates for nginx, Apache and LiteSpeed proxying to the `csf-ui` unix socket,
  terminating TLS and enforcing body/header limits at the front.
- systemd units: `csf-ui` runs as `csfui` with `NoNewPrivileges=yes`,
  `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`,
  `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`,
  `CapabilityBoundingSet=` (empty), `ReadWritePaths=/var/lib/csf-ui`.
  `csf-ui-helper` runs as root with the narrowest set that still works.
- Installer: create the `csfui` system account (no login shell, no home); detect
  nginx/Apache/LiteSpeed; offer Mode A (default when found) or Mode B; write
  `ui.conf` using the keys frozen in Task 1. Non-interactive installs default to
  **neither** — the UI is not enabled by an unattended install.
- Do not enumerate individual asset filenames in installer copy lists; copy
  directories. Task 11 deletes assets, and a hardcoded filename list would break.
- Installers must remain `sh -n` clean and must not fail the install if the UI
  cannot be set up: print and continue (the firewall matters more than its UI).

**Tests:** templates render with substituted values and contain no placeholder
left over; systemd units parse with `systemd-analyze verify` when available,
skipped with a reason when not; installer snippets are `sh -n` clean.

---

## Task 10: hostile-input and integration test pass

**Files:** `t/90-fuzz-http.t`, `t/91-fuzz-rpc.t`, `t/92-integration.t`, `ci/gates.sh`

- HTTP fuzz: generate malformed requests (truncated, oversize, random bytes,
  header floods, encoding abuse) and assert the parser always returns a 4xx or
  closes, never hangs and never dies uncaught.
- RPC fuzz: malformed JSON, oversize lines, unknown ops, valid ops with hostile
  arguments, mutating ops on the read-only socket.
- Integration (skipped without root, with a stated reason): helper and web halves
  over real sockets; peer-credential rejection from a wrong uid.
- `ci/gates.sh`: `perl -I. -c` on every `.pl`/`.pm` touched by this branch,
  `sh -n` on every shell script, `prove -I. t/`, and a grep gate that fails on
  backticks, `qx`, `system` with a single string, and `eval` on a string in any
  file under `ui-src/`.

---

## Task 11: retire the old UI

**Files:** `lfd.pl`, `ConfigServer/DisplayUI.pm`, `ConfigServer/cseUI.pm`,
`ConfigServer/DisplayResellerUI.pm`, `csf.conf` and the six panel configs,
`CHANGES.md`

Only after Tasks 1-10 are complete and reviewed.

- Remove `sub ui()` from `lfd.pl` and the call sites that start it.
- Delete `DisplayUI.pm`, `cseUI.pm`, `DisplayResellerUI.pm` and the front-end
  assets they used (`jquery.min.js`, `chosen.min.js`, `bootstrap-chosen.css`,
  `configserver.css`) from every copy in `ui/`, `csf/`, `da/`, `interworx/`,
  `webmin/csf/`. Delete the Fugue Icons images **and their `LICENSE.txt`
  together** — the attribution file is meaningless once the icons are gone, and
  removing one without the other is wrong in both directions.
- `UI`, `UI_USER`, `UI_PASS` and the other `UI_*` keys: leave them in the config
  with a comment saying the integrated UI is gone and pointing at the new one.
  Do not silently drop keys from a config file people have edited.
- Panel integrations (cPanel, DirectAdmin, InterWorx, Webmin) reach the UI their
  own way: enumerate each, state what breaks, and update or remove it explicitly.
  A panel that silently 404s is not an acceptable outcome.

**Acceptance:** `grep -rn 'DisplayUI\|cseUI\|DisplayResellerUI\|sub ui'` returns
only historical mentions in `CHANGES.md`; `perl -I. -c lfd.pl` passes; the
install scripts still run `sh -n` clean.
