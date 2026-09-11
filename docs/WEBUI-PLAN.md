# Plan: replacing the built-in WebUI

Status: approved to start, 2026-09-11. Nothing here is built yet.

## 1. Why

Measured in this tree, not estimated:

| Component | Lines | Runs as |
|---|---|---|
| `lfd.pl` `sub ui()` — hand-written HTTP server | **853** | root |
| `ConfigServer/DisplayUI.pm` | 2,935 | root |
| `ConfigServer/cseUI.pm` | 1,042 | root |
| `ConfigServer/DisplayResellerUI.pm` | 241 | root |
| **Total** | **5,071** | **root, never dropped** |

`grep -n 'setuid\|setgid\|\$>' lfd.pl` returns nothing: the process that parses
HTTP from the network is the process that owns the firewall.

Authentication, as it stands:

- `lfd.pl:9788` — `$FORM{csfpassword} eq $config{UI_PASS}`. The password is stored
  in plaintext in `csf.conf` and compared with `eq`, which is not constant time.
- `grep -ci 'csrf\|nonce'` over `lfd.pl` and `DisplayUI.pm`: **0**. There is no
  CSRF protection on any state-changing request.
- Front-end ships jQuery 1.12.4 (2016) and Chosen 1.8.2.

A private key shipped in the tarball until 2026-09-11; see CHANGES.md.

## 2. Scope — five screens, and no more

Every feature is an attack surface on a root-adjacent service. The replacement
does what the firewall actually needs day to day and nothing else.

| Screen | Contents |
|---|---|
| Overview | firewall state; counts of denied / temp-denied / allowed; reconcile warnings |
| Block / Unblock | block an IP with a note, unblock, allow |
| Lists | `csf.deny`, temp bans, `csf.ignore` — search, paginate, delete a row |
| IP lookup | `csf -g <ip>` |
| Health | iptables vs `csf.deny` reconciliation: ORPHAN / GHOST / DUP, with cleanup |

Dropped on purpose: RBL checks, ServerCheck, lfd statistics, the reseller UI,
the cse UI. Roughly 5,071 lines become roughly 900.

## 3. Architecture

Three layers. The boundary between them is the point of the design.

```
   TLS + HTTP parsing + request limits
        │
        ▼
   csf-ui          unprivileged, user `csfui`
        │          unix socket, SO_PEERCRED checked on both ends
        ▼
   csf-ui-helper   root, ~200 lines, fixed operation allowlist
        │
        ▼
   csf / iptables
```

**The helper never trusts the web tier.** A role sent in a message is not a
permission. `csf-ui-helper` authenticates its peer with `SO_PEERCRED`, the socket
is `0660 root:csfui`, and privilege differences between roles are expressed as
**two sockets with different ownership**, never as a flag inside a message.

Every operation takes typed arguments, validated in the helper: addresses through
`inet_pton`, TTLs and ports range-checked, notes length-capped and escaped.
Commands are run with `exec` and an argv list. No shell, ever, at any layer.

> Splitting privilege limits an RCE in the web tier to the helper's allowlist. It
> does not make one harmless: an attacker who reaches the socket can still allow
> or deny addresses and restart the firewall. That is why the allowlist is fixed
> up front (§5) and why the web tier is not exposed directly (§4).

## 4. Two deployment modes, chosen during install

The installer detects what is available and asks. Both are supported; they are
not equally safe, and the installer says so.

### Mode A — behind the web server already on the host (default when found)

`csf-ui` listens on a unix socket only. An existing nginx, Apache or LiteSpeed
terminates TLS, parses HTTP, and enforces body and header limits. Shipped vhost
templates for all three, on a dedicated port.

This is the recommended mode because it deletes the most dangerous component
entirely: no HTTP parser of ours is exposed to the network. Machines running CSF
are usually hosting machines, so a maintained web server is normally already
present — the dependency is close to free.

### Mode B — standalone

`csf-ui` serves TLS itself. Chosen when no web server is found, or when the
administrator does not want csf touching the web server's configuration.

This mode means we parse HTTP from the network again, which is the risk Mode A
removes. It is bounded rather than pretended away:

- one HTTP core, shared with the setup wizard, deliberately small: **GET and POST
  only**; no keep-alive, no chunked transfer, no multipart, no ranges; hard caps
  on request line, header count, header size and body size; fixed read timeouts
- it is fuzzed as a release gate (§9), not only unit-tested
- TLS is mandatory and fails closed. Without `IO::Socket::SSL` the ops daemon
  refuses to start and says what to install — it never falls back to plain HTTP
- an IP allowlist is **required**, not optional; an empty allowlist refuses to start
- runs as `csfui` under systemd hardening: `NoNewPrivileges`, `ProtectSystem=strict`,
  `PrivateTmp`, `RestrictAddressFamilies`, no capabilities, minimal writable paths

## 5. The RPC contract, fixed before any code

The helper's allowlist is decided in phase 0 and does not grow to suit a screen.
Writing the screens first and adding calls as they are needed is how a narrow
interface becomes a wide one.

| Operation | Arguments | Used by |
|---|---|---|
| `status` | — | Overview |
| `counts` | — | Overview |
| `deny` | ip, note | Block |
| `undeny` | ip | Block, Lists |
| `allow` | ip, note | Block |
| `unallow` | ip | Lists |
| `tempdeny` | ip, ttl, ports | Block |
| `temprm` | ip | Lists |
| `list` | which, offset, limit, filter | Lists |
| `grep` | ip | IP lookup |
| `reconcile` | — | Health |
| `reconcile_fix` | entry-id list | Health |
| `restart` | — | Overview |

`reconcile_fix` takes explicit entry ids returned by a preceding `reconcile`, so
cleanup can only remove things the operator was shown. Destructive actions
present a diff and a separate confirmation; there is no one-click cleanup.

## 6. Setup

Setup is available from the CLI or from a browser. Both drive the same code path:
the UI writes an answers file and calls the CLI, so a browser session can always
be reproduced non-interactively, and a failure in the web tier cannot corrupt
`csf.conf`.

```
csf-setup                 # interactive CLI
csf-setup --web           # same wizard in a browser
csf-setup --answers FILE --yes   # unattended, reproducible across machines
```

**Reaching the setup UI.** The wizard binds `127.0.0.1` and prints an SSH tunnel
command. If it can identify the operator's address from `$SSH_CLIENT`, it also
offers to open a temporary port restricted to that single address — and to do
that it must detect the **actual** firewall backend in use (iptables, iptables-nft,
nftables, firewalld, ufw). Where it cannot determine the backend with certainty,
it declines and falls back to the tunnel rather than writing a rule it may not be
able to remove. Any rule it does add is removed using the canonical spec read
back from the backend, not a string rebuilt from memory.

The session token is never placed in a URL: URLs reach shell history, proxy logs
and `Referer` headers. It is set once via a POST and carried in a cookie.

The wizard exits on its own: 30 minutes absolute, 10 minutes idle, and on
`EXIT`/`INT`/`TERM`. `csf-setup --web --cleanup` removes anything left behind by
a session that died badly.

**Not locking yourself out.** Applying a configuration goes through
`TESTING=1` / `TESTING_INTERVAL=300`, plus an **independent** rollback: a systemd
timer, owned by neither csf nor lfd, restores the last known-good snapshot unless
the operator confirms. CSF's own `TESTING` is not sufficient on its own — it
assumes csf's timer is still running, and flushing rules can disturb rules that
did not come from csf. Configuration is committed atomically, and the loss of
SSH, a reboot mid-apply, and an nftables backend are all test cases (§9).

## 7. Authentication

| Item | Approach |
|---|---|
| Password storage | `crypt()` SHA-512 (`$6$`) with a high round count; Argon2id used instead when `Crypt::Argon2` is present |
| Where | `/etc/csf/ui/users`, mode `0600` — **not** in `csf.conf` |
| Comparison | constant time |
| First account | created by the CLI during setup. No default password, and no account exists until one is made |
| Session | random token, cookie `HttpOnly; Secure; SameSite=Strict`, 30 minutes idle |
| CSRF | per-session nonce required on every state-changing request |
| Brute force | local rate limit per address **and** per account, plus connection and body limits |
| Roles | `admin` — everything. `support` — **lookup only**: IP lookup, read the lists. No block, no unblock, no allow, no configuration |
| Audit | `/var/log/csf-ui-audit.log`: time, user, source address, action, target, outcome, request id. Control characters and newlines escaped on write |

Login failures are rate-limited **locally**. They are deliberately not written to
`csf.deny`: letting unauthenticated traffic add firewall entries lets an attacker
get a chosen address blocked — a victim's, or a shared NAT egress used by an
entire office.

`support` is read-only because allowing an address is a security decision, not a
support action.

## 8. Interface

- Server-rendered HTML. JavaScript is a convenience; every primary action works
  without it.
- Plain CSS, no framework, nothing from a CDN. Production servers frequently have
  no outbound Internet access, and a tightened `TCP_OUT` blocks it anyway.
- No jQuery, no Chosen. Neither is replaced.
- One breakpoint at 768px; tables become stacked cards on narrow screens; touch
  targets at least 44px; correct `input` types so mobile keyboards match.
- Accessibility is a requirement, not a side effect of the breakpoint: keyboard
  paths for every action, visible focus, contrast checked, usable at 200% zoom,
  labelled controls. Verified on real phones and tablets, not only by resizing.

## 9. Phases

| # | Work | Estimate |
|---|---|---|
| 0 | Threat model, privilege boundary, **freeze the RPC schema** | 5h |
| 1 | `csf-ui-helper`: root, `SO_PEERCRED`, allowlist, argument validation | 8h |
| 2 | `csf-ui` core: unix socket, sessions, CSRF, rate limiting | 6h |
| 3 | Minimal HTTP/TLS core for Mode B, shared with the wizard | 6h |
| 4 | Mode A integration: nginx, Apache, LiteSpeed templates; systemd hardening; installer detection and the choice | 8h |
| 5 | Layout, responsive CSS, accessibility | 5h |
| 6 | Setup: wizard, tunnel and temporary-port paths, firewall backend detection, independent rollback, snapshots | 12h |
| 7 | The five screens | 8h |
| 8 | Authentication: hashing, CLI bootstrap, two roles, audit log | 6h |
| 9 | Testing: HTTP and RPC fuzzing; auth, CSRF, session fixation; malformed IPv4/IPv6/CIDR; concurrent writes with csf and lfd; install, upgrade, reinstall, uninstall; firewall rollback; iptables and nftables; four distributions; phones and tablets | 14h |
| 10 | Remove `DisplayUI.pm`, `cseUI.pm`, `DisplayResellerUI.pm`, `sub ui()`; migration and a way back | 5h |
| | **Total** | **83h** |

Excludes an independent security review, and excludes fixing what such a review
would find.

## 10. Risks

| Risk | Level | Handling |
|---|---|---|
| Mode B means we parse HTTP from the network again | **High** | Mode A is the default where possible; the core is small, strictly limited, and fuzzed as a release gate; it runs unprivileged behind the privilege split |
| Reaching the helper socket is enough to disable the firewall | **High** | fixed allowlist, `SO_PEERCRED`, socket ownership, no shell; the web tier is never directly exposed |
| Locking the operator out of the machine | **High** | tunnel by default; temporary rules removed by canonical spec; independent rollback timer; explicitly tested |
| `IO::Socket::SSL` absent | Medium | ops daemon refuses to start with instructions; never downgrades to http |
| Removing the old UI breaks panel integration | Medium | phase 10 last, behind a release with a documented way back; cPanel and DirectAdmin reach the UI their own way and are tested before removal |
| Firewall backend is not what we assumed | Medium | detect before writing; decline and fall back rather than write a rule we cannot reliably remove |
| Two deployment modes doubles the test matrix | Medium | one HTTP core shared by both modes and the wizard; phase 9 covers both |

## 11. Decisions on the record

- **Perl, not Go.** Not because Perl is better, but because it adds no runtime,
  `IO::Socket::SSL` is already a dependency of the existing UI, and it keeps the
  reproducible source-tarball release model intact. A compiled binary would break
  byte-identical rebuilds from a tag, or force an architecture matrix.
- **Both deployment modes, chosen at install.** Mode A removes the largest single
  risk, but requires a web server the administrator may not have or may not want
  csf to touch. The installer detects, recommends, and lets the operator decide.
- **`crypt()` SHA-512 as the default, Argon2id when available.** `Crypt::Argon2`
  is an XS module needing a compiler on the target host; making a firewall depend
  on that trades one risk for another. SHA-512 crypt is in glibc everywhere.
- **`support` is lookup only.**
- **Setup is reachable from CLI and browser**, because setup being easy is the
  point; it is not an SSH-tunnel-only tool.
