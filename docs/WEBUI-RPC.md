# WebUI RPC contract and threat model

**Status: frozen 2026-09-11.** Binding spec: `docs/WEBUI-PLAN.md`. Implementation
plan: `docs/superpowers/plans/webui-implementation.md`.

This document is the interface between the unprivileged web tier (`csf-ui`, user
`csfui`) and the privileged helper (`csf-ui-helper`, root). Every later task
implements against it; none of them may extend it.

**What "frozen" means here.** The operation list, the argument grammars, the
error codes and the `ui.conf` key names do not change to suit a screen. Adding an
operation, an argument, an error code or a config key is an amendment to this
document, reviewed on its own, before the code that needs it is written. Writing
the screens first and adding calls as they are needed is how a narrow interface
becomes a wide one.

| I want to… | Read |
|---|---|
| know what the privilege split does and does not buy | §1 |
| implement the socket and the peer check | §2 |
| implement the framing and errors | §3 |
| implement a validator | §4 |
| implement or call an operation | §5 |
| answer "what does a hostile value do" | §6 |
| implement the helper's self-imposed limits | §7 |
| implement the audit logs | §8 |
| argue for a new operation | §9 |
| read or write `ui.conf` | §10 |
| know where this contract departs from the plan | §11 |
| know what a later task owes this document | §12 |
| know why the UI does not live under /etc/csf | §13 |

---

## 1. Trust boundaries

### 1.1 The four zones

| Zone | Runs as | Trusts | Must validate | An attacker who owns this zone reaches |
|---|---|---|---|---|
| **Network** — browsers, scanners, anyone who can open the port | nobody | — | — | The TLS endpoint only: the front web server (Mode A) or `csf-ui`'s own listener (Mode B). Without credentials: the login form, the rate limiter, and the static assets. Nothing else. |
| **`csf-ui`** — HTTP routing, sessions, CSRF, rendering | `csfui`, no shell, no capabilities | the kernel; `ui.conf` (root-written, read-only to it); helper responses | **everything from the network**: HTTP framing, method, `Content-Type`, all size limits, session cookie, CSRF nonce, role→route mapping, and every RPC argument before it is sent | **All 14 operations, whatever role the session carries** (see §1.2), at the rates in §7. Its own session store and access log. It can ask the helper to test a password guess, five times per username per five minutes (§5.14). It does **not** reach root, `csf.conf`, `csf.deny` directly, **the password hashes in `/etc/csf-ui/users`** (§11.1), the helper's audit log, or any command not on the allowlist. |
| **`csf-ui-helper`** — the allowlist | `root` | the kernel, and `SO_PEERCRED` on the connected socket | **every byte of every request**, including arguments `csf-ui` claims to have already checked; peer uid on every connection; its own startup preconditions | Everything. It is root. This is why it is ~200 lines with a fixed operation list and no argument that names a file, a command or a flag. |
| **System** — `csf`, `iptables`/`ip6tables`, `/etc/csf`, `/var/lib/csf` | `root` | its own files | — | The machine. |

### 1.2 The boundary is unprivileged-vs-root, not admin-vs-support

There is **one** web process. It runs as `csfui`. Whichever role a session
carries — `admin` or `support` — that process can reach every operation on this
list, because it is the same process with the same uid holding the same socket.

Therefore:

- **Support-role enforcement is application-level**, inside `csf-ui`, per
  request, on the server side (Task 7). It is a correctness control, not a
  privilege boundary.
- **An attacker who owns `csf-ui` reaches every operation in §5 regardless of
  the session's role**, and regardless of whether they ever authenticate.
- One thing they do **not** get is the password *store*. `authenticate` (§5.14) is
  the only path to it and it answers one guess at a time, so a compromised web tier
  cannot take the file away and attack every account offline at its own pace. What
  it holds instead is an oracle bounded at **5 guesses per username per 5 minutes**,
  counted by the helper in its own state.
- **It does still get the plaintext of anyone who logs in while it is
  compromised.** The login form posts a password to `csf-ui`, and `csf-ui` forwards
  it as `pass`; a tier under someone else's control reads it on the way through.
  For reuse against another service that is better for the attacker than a hash
  would have been. What the split buys here is bounded in scope — the accounts that
  authenticate during the compromise — rather than every account in the file,
  forever, at leisure. Saying more than that would be claiming a boundary that is
  not there.
- There is **no second, read-only socket**. Two sockets separate privilege only
  when two processes with different uids hold them. One process holding both
  separates nothing while implying that it does, and a claimed boundary that does
  not exist is worse than an absent one: it gets relied on.

The column "which socket is this served on" is therefore constant for all 14
operations: **the helper socket, the only one**. What varies, and what the audit
log and the screens key off, is whether an operation **mutates state** (§5).

### 1.3 What the split actually buys

Stated exactly, because the design is worth only what is on this list:

1. A remote-code-execution bug in the HTTP tier gets `csfui`, not root. It cannot
   read `/etc/csf/csf.conf` (which still contains `UI_PASS` in plaintext until
   Task 11), cannot write `csf.deny` directly, cannot load a kernel module,
   cannot read `/etc/shadow`, cannot alter the helper's audit log, and **cannot
   read the WebUI's own password hashes** — `/etc/csf-ui/users` is `0600 root`
   and only the helper opens it (§5.14, §11.1).
2. The set of privileged actions reachable from the web tier is **finite,
   enumerated, and reviewable** — this document — instead of "whatever the
   process can be made to exec".
3. **No argument ever names a file, a command, a flag or a chain.** Those are
   fixed tables in the helper (§9), so path traversal, argument injection and
   command injection have no argument to travel in.
   The same discipline is why **the three operations that pass a comment to `csf`
   — `deny`, `allow` and `tempdeny` — never pass an empty one** (§5.3, §5.5,
   §5.7): an argument list that looks harmless can still reach a branch that does
   something we excluded, in that case root resolving an attacker-chosen hostname.
   The other eleven operations send no comment and cannot reach that branch at
   all.
4. The helper's audit log (§8) is written by root and is not writable by the web
   tier. An attacker who owns `csf-ui` can forge *who asked*; they cannot forge
   or erase *what was executed*.

And what it does not buy: an attacker who reaches the socket can still block or
unblock any address the grammar allows, restart the firewall, and test passwords
one guess at a time, at the rates in §7. That is the allowlist working as
designed. It is bounded, not harmless.

One cost is worth naming because it is new. Verifying a password means running
`crypt()` with `UI_CRYPT_ROUNDS` rounds — deliberately expensive — and after §5.14
that expense is spent **in the root process**. A caller who can reach the socket
can therefore make root burn CPU. So the failure counter in §5.14 is two controls
in one: it stops password guessing, and together with the concurrency and rate
caps in §7 it stops `authenticate` from being a way to load the machine the
firewall is protecting.

### 1.4 Why validation in the helper is load-bearing, not defence in depth

`csf` is not a hardened callee, and our validators are the only barrier in front
of it. Verified in this tree:

| Fact | Evidence | Consequence for this contract |
|---|---|---|
| `csf` joins all its arguments into **one space-separated string** and re-splits it | `csf.pl:340-343` (`$input{argument} .= $ARGV[$x] . " "`) | argv separation buys nothing downstream. A value containing whitespace is re-parsed by `csf` as several arguments. |
| `csf -td` extracts `-p <ports>` and `-d <direction>` **out of the comment text** by regex | `csf.pl:4311-4313` | a free-text note can silently change which ports and which direction are blocked — argument injection with no shell involved. §4 forbids option-looking notes. |
| `csf` interpolates values into a **command string** and runs it through `IPC::Open3` | `csf.pl:5697`, `csf.pl:3900-3905` (`open3(..., $command)` where `$command` is one scalar containing `;`) | a single scalar with metacharacters reaches `/bin/sh`. Our arguments must never contain one, whatever `csf`'s own regexes happen to filter today. |
| `csf` writes the note verbatim into `csf.deny` as `"$ip # $comment - <date>"` | `csf.pl:1688` | a newline in a note appends an arbitrary line to `csf.deny` — including `Include /some/file`, which `csf` then follows (`csf.pl:4322-4326`). §4 rejects control bytes. |
| `csf` **exits 0 after refusing an operation** — it prints `deny failed: …` and returns | `csf.pl:1541-1551`, single `exit 0` at `csf.pl:190` | exit status is not a success signal. The helper decides success from the **state delta**, not from the exit code and not from message text (§5.0). |
| `ConfigServer::CheckIP::checkip` accepts prefix `/0` — the `if ($cidr)` guard is false for `"0"`, so the range check is skipped | `ConfigServer/CheckIP.pm:60-61` | `csf -d 0.0.0.0/0` would be accepted by `csf` and would drop everything. §4 rejects `/0` and enforces a prefix floor. |

None of these are bugs we are fixing in this task. They are the reason the
validators in §4 are strict, positive-match grammars and not blocklists.

---

## 2. Transport and peer authentication

| Property | Value |
|---|---|
| Socket path | `/var/run/csf-ui/helper.sock` |
| Type | `AF_UNIX`, `SOCK_STREAM`, listen backlog 32 |
| Directory | `/var/run/csf-ui`, mode `0755`, owner `root:root` — **traversable**, because `csfui` has to reach the socket inside it (§2.3) |
| Socket mode, normal | `0660`, owner `root:csfui` |
| Socket mode, **`csfui` group absent** | `0600`, owner `root:root`, and **every connection is answered `E_UNAVAILABLE` and closed** |
| Concurrency | one forked child per connection, hard cap 16 (§7) |
| Requests per connection | exactly one (§3.1) |

### 2.1 Startup preconditions — all fail closed

The helper refuses to start, with a message naming the failure, if any of these
does not hold. It never starts in a degraded mode.

| Precondition | Why |
|---|---|
| Effective uid is 0 | it cannot do its job otherwise, and a non-root helper listening on that path would be a downgrade attack |
| **Perl ≥ 5.14 with `Socket` ≥ 1.94** — checked explicitly, by version, at startup | `inet_pton`, `inet_ntop` and `SO_PEERCRED` entered core `Socket` at 1.94, first bundled with Perl 5.14. Perl 5.10 ships `Socket` 1.82 and has none of them. This **amends G1's "5.10-compatible"** (§11.7) |
| `Socket::inet_pton`, `Socket::inet_ntop`, `Socket::SO_PEERCRED` all resolve | belt and braces on the version check, and no regex fallback for address parsing, ever (G1, G3) |
| `/var/run/csf-ui` is absent, or is a directory owned by uid 0 with no group/other write bit | otherwise another user chooses where our socket lives |
| an existing `/var/run/csf-ui/helper.sock` is a socket owned by uid 0 (then it is unlinked) | never unlink an arbitrary path |
| `/usr/sbin/csf` is a regular file, owned by uid 0, not group- or world-writable | the one program we hand root to |
| `IPTABLES` (and `IP6TABLES` when `IPV6` is on) from `csf.conf` are absolute paths to root-owned, non-world-writable regular files | same |
| `/etc/csf/csf.conf` is readable and parses | `status` and `reconcile` need `TESTING`, `IPV6`, `LF_IPSET`, `IPTABLES`, `IP6TABLES` |

`csf.conf` is read with a strict line grammar over a **fixed key set** —
`^\s*(TESTING|IPV6|LF_IPSET|LFDSTART|IPTABLES|IP6TABLES)\s*=\s*"([^"]*)"\s*$` —
never by evaluating the file and never by loading a config module that does more
than we need.

`/etc/csf-ui/users` is **deliberately not** on that list. No account exists until
an administrator makes one (spec §7), so a missing store is a normal state for a
fresh install, not a reason to refuse to start; `authenticate` checks it per call
and answers `E_UNAVAILABLE` with the remedy (§5.14).

If the group `csfui` does not exist (it is created in Task 9), the helper still
starts — so that the unit is installable in either order — but the socket is
`0600 root:root` and every accepted connection receives
`E_UNAVAILABLE` ("the csfui group does not exist; run the installer") and is
closed. There is no permissive fallback (G3).

### 2.2 The peer check

On **every** accepted connection, **before reading a single byte**:

```
getsockopt($sock, SOL_SOCKET, SO_PEERCRED)   ->   unpack("iii", $data)  ->  (pid, uid, gid)
```

Verified on the target platform: `Socket::SO_PEERCRED()` is `17`,
`Socket::SOL_SOCKET()` is `1`, and the three-integer `"iii"` layout is correct.
This is stated as fact, not as a possibility to hedge around — on a host that meets
§2.1's floor. Below that floor the constant does not exist at all, which is why the
floor is a startup precondition and an install-time check (§11.7) rather than
something discovered at the first login.

| Condition | Action |
|---|---|
| `getsockopt` returns undef, or unpacks to fewer than 3 values | close immediately, log, no response |
| `uid == 0` | **reject** — `E_PEER`, close, log. Root has no reason to come through this door; if root wants to run `csf`, root runs `csf`. |
| `uid != uid_of("csfui")` (resolved once at startup via `getpwnam`) | **reject** — `E_PEER`, close, log |
| `csfui` group absent (§2.1) | `E_UNAVAILABLE`, close |
| otherwise | proceed to §3 |

`gid` is not used for any decision. `pid` is recorded for the audit log only, and
is **informational**: by the time it is logged the pid may have been reused. The
log says so rather than implying the pid identifies anything.

The helper never accepts an identity, a role or a source address from the message
body. It cannot verify any of them, so it does not ask for them. The one exception
proves the rule: `authenticate` (§5.14) carries a username, and the helper does not
believe it — it treats it as a lookup key and answers with a verdict of its own.

### 2.3 Paths this contract depends on

**Nothing here is under `/etc/csf`, `/var/lib/csf` or `/usr/local/csf`.** Those
trees are held at `0600` by `lfd` on every pass of its main loop, forever; §13 is
the measurement and the reasoning. This table is the frozen layout, and it amends
G7.

| Path | Mode / owner | Written by | Read by |
|---|---|---|---|
| `/usr/local/csf-ui/bin/csf-ui`, `csf-ui-helper`, `csf-ui-passwd`, `csf-ui-setup` | `0755` dir `root:root`, binaries `0750 root:csfui` | installer | systemd (`csf-ui` execs as `csfui`) |
| `/usr/local/csf-ui/lib/ConfigServer/UI/*.pm` | `0755` dir, `0644` files, `root:root` | installer | both halves |
| `/etc/csf-ui/` | `0750` `root:csfui` | installer | `csfui` traverses it |
| `/etc/csf-ui/ui.conf` | `0640 root:csfui` | installer, wizard | `csf-ui` (§10) |
| `/etc/csf-ui/users` | **`0600 root:root`** | `csf-ui-passwd` (root, Task 3) | **the helper only** (§5.14) |
| `/var/lib/csf-ui/` | `0755 root:root` | installer | both halves traverse it |
| `/var/lib/csf-ui/helper/` | `0700 root:root` | helper | helper |
| `/var/lib/csf-ui/helper/authfail.state` | `0600 root:root` | helper (failure counter, §5.14) | helper |
| `/var/lib/csf-ui/sessions/`, `/var/lib/csf-ui/rl/` | `0700 csfui:csfui` | `csf-ui` | `csf-ui` |
| `/var/run/csf-ui/` | **`0755 root:root`** — it must be traversable by `csfui` or the socket is unreachable | helper | `csfui` traverses it |
| `/var/run/csf-ui/helper.sock` | `0660 root:csfui` (§2) | helper | `csf-ui` |
| `/var/run/csf-ui/rate.state` | `0600 root:root` | helper (§7) | helper |
| `/var/log/csf-ui-audit.log` | `0640 root:root` | **the helper** — what actually ran | root |
| `/var/log/csf-ui-access.log` | `0640 csfui:csfui` | **`csf-ui`** — who asked for it | root, `csfui` |

Note the pattern each time a directory and its contents both appear: the
**directory** is traversable and the **contents** are not. A `0600` directory is not a stricter version of a
`0600` file — it is a wall in front of every file beneath it, including for its own
owner (§13.2). Getting this backwards is the single easiest way to ship a UI that
cannot start, with no useful error.

The helper also reads, as root, files it does not own: `/etc/csf/csf.conf`,
`/etc/csf/csf.deny`, `/etc/csf/csf.allow`, `/var/lib/csf/csf.tempban` and
`/var/lib/csf/csf.tempallow`. Reading is all it does to them; every write goes
through the `csf` binary (§5.0.1). `0600 root` is no obstacle to a root reader,
which is why the split works at all.

---

## 3. Wire format

### 3.1 Framing

- One JSON object per line, UTF-8, terminated by a single `\n` (0x0A).
- **Maximum 65536 bytes per line, in both directions**, `\n` included.
- **Exactly one request per connection.** The helper reads one line, answers one
  line, and closes. Any byte after the first `\n` is `E_PROTOCOL`. This removes
  pipelining, interleaving and half-read state from the design entirely.
- A line that exceeds 65536 bytes is a protocol error: the helper stops reading,
  answers `E_PROTOCOL` if it can, and closes the connection. It never buffers
  past the cap, so an oversize line costs 64 KiB of memory, not the sender's
  choice of memory.
- A connection that sends no complete line within the read timeout (§7) is
  closed without a response.
- `\r` is not framing. A line ending `\r\n` has a trailing `\r` inside the JSON
  text, which is a JSON parse failure — `E_PROTOCOL`. We do not strip it.

### 3.2 Request

```json
{"op":"deny","args":{"ip":"192.0.2.10","note":"abuse ticket 4471"},"id":"7b9f1c2e4a5d6e8f"}
```

| Field | Type | Rule |
|---|---|---|
| `op` | string | required; must be one of the 14 names in §5, exactly, lowercase. Anything else → `E_UNKNOWN_OP` |
| `args` | object | optional; absent, `null` and `{}` are equivalent. Any other type → `E_ARG`. **Unknown keys are rejected** (`E_ARG`), never ignored |
| `id` | string | required; `^[A-Za-z0-9._:-]{1,64}$`. Opaque to the helper, echoed verbatim. Generated by `csf-ui` (a UUIDv4 or 32 hex bytes) and used to join the two audit logs (§8) |

The top level must be a JSON **object**. An array, a bare string, a number, or
`null` → `E_PROTOCOL`.

### 3.3 Response

```json
{"id":"7b9f1c2e4a5d6e8f","ok":true,"data":{"ip":"192.0.2.10","added":true}}
{"id":"7b9f1c2e4a5d6e8f","ok":false,"error":"E_ARG","message":"ip: host bits set in 192.0.2.10/24"}
```

| Field | Type | Rule |
|---|---|---|
| `id` | string or null | the request's `id`, verbatim; `null` when the request was so malformed that no `id` could be read |
| `ok` | boolean | JSON `true`/`false` |
| `data` | object | present iff `ok` is true; always an object, never an array at the top level |
| `error` | string | present iff `ok` is false; one of §3.5 |
| `message` | string | present iff `ok` is false; **human-readable, never machine-parsed by the caller**; ASCII, ≤512 bytes, sanitised per §3.6 |

No other envelope fields exist. Anything an operation wants to return goes inside
`data`.

### 3.4 Response size

A response line is capped at 65536 bytes like any other. Operations that return
rows (`list`, `grep`, `reconcile`) build their arrays row by row against a byte
budget of `65536 - 512` and stop before the row that would exceed it, setting
`"truncated": true` and reporting how many rows were actually returned. Totals
and counts in those responses are always computed over the **full** data set,
never over the truncated slice — so a truncated `reconcile` still reports the
true number of orphans.

The caller therefore must read `returned`, not assume it got `limit` rows, and
must page with `next_offset`, which is defined as **`offset + returned`** — never
`offset + limit`. Computing it from `limit` would skip exactly the rows truncation
dropped, and the Lists screen would lose entries silently, which is worse than an
error. `next_offset` is `null` when the last row of the set has been returned.

This is the one place where two frozen numbers (`limit` max 500, and 64 KiB lines)
cannot both be honoured at full stretch, and truncation with an honest count is the
resolution.

### 3.5 Error codes

Closed enumeration. New codes are an amendment to this document.

| Code | Meaning | Connection | `csf-ui` should answer |
|---|---|---|---|
| `E_PROTOCOL` | framing or JSON is invalid: oversize line, invalid UTF-8, not an object, bad/missing `id`, bytes after the first newline | closed | 500 (a client bug — the browser never sees this) |
| `E_UNKNOWN_OP` | `op` is not one of the 14 | closed | 500 (a client bug) |
| `E_ARG` | an argument is missing, the wrong JSON type, unknown, or fails its grammar in §4 | closed | 400, with the field name |
| `E_PEER` | `SO_PEERCRED` check failed | closed | — (the web tier never sees this; it means something else connected) |
| `E_UNAVAILABLE` | a structural precondition is unmet and no request can succeed until someone fixes it: the `csfui` group does not exist (§2.1), `LF_IPSET` is on and `reconcile` cannot be computed (§5.11), the password store is missing, unusable or empty so `authenticate` cannot answer, or the user's record carries an `algo` this helper cannot verify (both §5.14 — and that last one leaves the failure counter untouched). **Not** used for `csf` being disabled — that is a state the operator chose, and it is `E_REFUSED` | closed | 503 + the remedy |
| `E_BUSY` | transient: concurrency cap, `csf` lock held, mutation-rate cap, restart interval (§7) | closed | 503 + `Retry-After` |
| `E_REFUSED` | the request was well-formed and the system refused it: the address is one of this server's own, is in `csf.allow`/`csf.ignore`, is marked "do not delete", or `csf` has an unresolved start error | closed | 409, showing `message` |
| `E_BACKEND` | `csf` or `iptables` failed, timed out, was killed, or left the state inconclusive | closed | 502 |
| `E_STALE` | a `reconcile_fix` request whose ids are all absent from a fresh scan (§5.12) | closed | 409 — "the page is out of date, reload" |
| `E_INTERNAL` | an unexpected error in the helper | closed | 500 |

`E_INTERNAL` never carries a stack trace, a file path outside the fixed set, or
any part of the request back to the caller. Those go to the audit log.

### 3.6 Output sanitising

Every string the helper puts in `data` or `message` that came from the system —
a note read back from `csf.deny`, a line of `csf -g` output, an error message
from `csf` — passes one sanitiser before encoding:

| Input byte | Becomes |
|---|---|
| `0x00`–`0x08`, `0x0B`, `0x0C`, `0x0E`–`0x1F`, `0x7F` | `.` |
| `0x09` (tab), `0x0A` (LF), `0x0D` (CR) | one space |
| a byte ≥ `0x80` that is not part of a valid UTF-8 sequence | `?` |

Applied on the way **out**, not only on the way in, because `csf.deny` can be
edited by hand, by `lfd`, or by an older version of this software, and the web
tier renders whatever it is handed. This is also what keeps the JSON encoder from
producing invalid UTF-8 and the audit log from carrying terminal escapes.

---

## 4. Argument types

Every grammar below is a **positive match**: the value is accepted only if it
matches, and there is no "sanitise and continue" path. A failure is always
`E_ARG`, with a `message` naming the field and the reason, and the operation does
not run.

Before any type-specific rule: a value must be the JSON type stated. A string
where a number is expected, an array where a string is expected, `null` where a
value is required — all `E_ARG`. Integer-valued fields (`ttl`, `offset`, `limit`)
additionally accept a decimal **string** of digits, because form bodies carry
numbers as text; nothing else is coerced.

### 4.1 `ip`

| Step | Rule |
|---|---|
| length | 1–49 bytes (`45` for the longest IPv6 text + `/128`) |
| split | at most one `/`. Two or more → `E_ARG` |
| address | `Socket::inet_pton(AF_INET, $a)` if it contains `.` and no `:`; otherwise `Socket::inet_pton(AF_INET6, $a)`. Undef → `E_ARG`. No regex, ever |
| prefix | `^(0|[1-9][0-9]{0,2})$` — no leading zeros, no sign, no whitespace — and ≤32 (v4) or ≤128 (v6) |
| `/0` | **rejected for `deny`, `allow`, `tempdeny` and `grep`** — it means "the Internet". **Accepted for `undeny`, `unallow` and `temprm`**: `checkip` lets `/0` into `csf.deny` from the command line (`ConfigServer/CheckIP.pm:60-61`), and an entry that can exist must be removable through the UI — refusing to remove the one entry capable of blocking everything would be exactly backwards |
| host bits | for a CIDR, the address must already be the network address. `192.0.2.10/24` → `E_ARG` ("did you mean 192.0.2.0/24"). We never silently mask: a UI that turns "block this host" into "block this /24" without saying so is how an operator blocks their own office |
| IPv4-mapped / IPv4-compatible IPv6 | rejected: any v6 address whose first 80 bits are zero and whose next 16 bits are `0x0000` or `0xffff` (`::ffff:127.0.0.1`, `::192.0.2.1`). Send the IPv4 form. **Two literals are carved out of this rule for `undeny`, `unallow` and `temprm` only: `::` and `::1`** — see below |
| `::` and `::1` | **rejected for `deny`, `allow`, `tempdeny` and `grep`; accepted for `undeny`, `unallow` and `temprm`**, and accepted when parsing an entry back out of a file csf wrote. They fall inside the numeric range the rule above uses to catch IPv4-in-IPv6 forms, but they are not aliases of an IPv4 address — they are their own family's unspecified and loopback addresses, and `csf -d ::1` will put one of them into `csf.deny` from a shell. Refusing to read or remove it would leave the UI unable to undo the most self-inflicted block there is. The carve-out is those two literals, not the range: `::2` and `::ffff:127.0.0.1` stay rejected everywhere |
| canonical form | `inet_ntop` of the packed bytes, lowercase, `/len` appended when a prefix was given. **This canonical form — not the caller's text — is what is passed to `csf`, returned in `data`, and written to the audit log** |

Additional rules for the **mutating** operations `deny`, `tempdeny`, `allow`:

| Rule | Value |
|---|---|
| minimum prefix length | `/8` for IPv4, `/32` for IPv6. Broader → `E_ARG` |
| loopback | reject if the range contains `127.0.0.1` or `::1` |

Rationale for the floor: the single largest risk in the plan (§10) is locking the
operator out of the machine, and the largest legitimate block anyone issues from
a firewall UI is far narrower than a `/8`. It is not a security property — a `/8`
of hostile traffic can be blocked from the CLI — it is a guard rail on the most
damaging typo the interface allows. `10.0.0.0/8` remains permitted and remains
capable of locking out a LAN operator; the protection against that is Task 8's
independent rollback, not this grammar, and this document does not pretend
otherwise.

### 4.2 `ttl`

Integer, or a string of 1–6 digits. Range **60 … 604800** seconds (1 minute to 7
days), inclusive. No suffixes: `"1h"`, `"30m"`, `"2d"` are `E_ARG`. The helper
always passes plain seconds, so `csf`'s own suffix parser (`csf.pl:4280-4287`)
never sees anything but digits.

### 4.3 `ports`

Absent, `null`, or `""` means **all ports**, and the helper passes no `-p` at all.

Otherwise: `^[0-9]{1,5}(-[0-9]{1,5})?(,[0-9]{1,5}(-[0-9]{1,5})?){0,19}$` — at
most **20 comma-separated entries**, each a port or a `low-high` range, every
number `1..65535` with no leading zeros, and `low <= high` in a range.

| Then | Rule |
|---|---|
| expansion | every range is expanded to its member ports before use |
| expansion cap | the expanded list must contain **at most 20 ports**; `"1000-2000"` → `E_ARG` ("expands to 1001 ports, maximum 20"). To block more than that, block the address without ports |
| duplicates | rejected (`E_ARG`) — a duplicate is a caller bug, and silently collapsing it hides one |
| forbidden bytes | `;` `*` `:` whitespace and everything else the grammar does not list. They are not merely unwanted: `;` selects the protocol in `csf`'s port parser and `*` means "all ports" |

Why expand rather than pass the range through: `csf -td`'s port regex is
`\-p\s*([\w\,\*\;]+)` (`csf.pl:4313`), whose character class contains neither `-`
nor `:`. A range handed over verbatim is truncated to its lower bound and the
remainder is stored as the ban's **comment** — the operator would be told 1000-2000
was blocked while only port 1000 was. Expansion is the only way to honour a range
without silent partial enforcement.

Consequence to state plainly: temp bans through this interface are **TCP only**
when ports are given, because the protocol suffix (`;udp`) is outside the
grammar. A ban with no ports covers every protocol.

### 4.4 `note`

| Rule | Value |
|---|---|
| type/length | string, 1–200 **bytes** after trimming ASCII spaces from both ends; valid UTF-8 |
| control bytes | any byte `0x00`–`0x1F` or `0x7F` → `E_ARG`. This is what stops `\n` from appending an arbitrary line — including `Include /path` — to `csf.deny` (`csf.pl:1688`, `csf.pl:4322-4326`) |
| `\|` (0x7C) | rejected. The temp-ban store is pipe-delimited (`time\|ip\|port\|inout\|timeout\|comment`, `csf.pl:4400`) and a note containing `\|` corrupts the record |
| option-looking text | rejected if it matches `/(^\|\s)-[A-Za-z]/`. `csf` re-splits its joined argument string (`csf.pl:340-343`) and `csf -td` scans the comment for `-p` and `-d` (`csf.pl:4311-4313`), so a note that looks like an option **is** an option |
| empty | a note consisting only of spaces → `E_ARG`. **There is no "no note" option anywhere in this contract:** `deny` and `allow` require one (§5.3, §5.5) and `tempdeny` sends a fixed literal (§5.7), precisely so that `csf` never reaches the empty-comment branch that resolves the address through root's DNS (`csf.pl:1517`, `:1687`, `:4320`) |

### 4.5 `which`

Exactly one of `deny`, `temp`, `allow` — lowercase, no whitespace, no other
value. It selects a row in a **fixed table inside the helper**:

| `which` | Source | Written by |
|---|---|---|
| `deny` | `/etc/csf/csf.deny` | `deny` / `undeny` |
| `temp` | `/var/lib/csf/csf.tempban` | `tempdeny` / `temprm` |
| `allow` | `/etc/csf/csf.allow` | `allow` / `unallow` |

The value never becomes part of a path. `../../etc/shadow` is not a traversal
attempt that we defeat by sanitising; it is a value that is not in the table, and
the table lookup fails.

`csf.ignore` is **not** listed. The spec's screen description (§2) names it, but
the frozen operations `allow`/`unallow` map to `csf -a`/`csf -ar`, which write
`csf.allow`; `csf.ignore` is `lfd`'s ignore list and no operation on this list
mutates it. Listing it would put a delete button on rows that nothing can delete.
See §11.2.

### 4.6 `offset` and `limit`

| Field | Rule |
|---|---|
| `offset` | integer (or digit string), `0 … 1000000`. Absent → 0 |
| `limit` | integer (or digit string), `1 … 500`. Absent → 100. The response may carry fewer rows than this — read `returned`, and page with `next_offset` (§3.4, §5.9) |

Both are applied to the **filtered** row set, after the filter, so paging is
stable for a given filter. See §3.4: the response may return fewer than `limit`.

### 4.7 `filter`

String, 0–100 bytes, valid UTF-8, no control bytes (§4.4 rule). Matched with
`index()` on an ASCII-lowercased copy of the row's address and note.

**It is never compiled as a pattern.** `.*`, `(a+)+$`, `\x{0}` and every other
metacharacter are literal text that will simply not be found. There is no regex
denial of service here because there is no regex.

### 4.8 `ids`

Array of 1–500 strings, each exactly `^[0-9a-f]{32}$`. Duplicates → `E_ARG`. Not
an array, or an element of any other type → `E_ARG`.

An id is a **content address**, not a capability: it is the first 16 bytes of
`SHA-256(kind \0 family \0 chain \0 canonical-rule-spec)`, computed by the helper
during `reconcile`. It is unguessable only incidentally; what makes it safe is
that `reconcile_fix` re-derives the entire set from a **fresh** scan and acts only
on ids present in that fresh set (§5.12). A forged id names nothing and does
nothing.

### 4.9 `user`

String, `^[a-z0-9_-]{1,32}$` — the same grammar Task 3 enforces when it writes a
record, so a username that could not be created cannot be submitted either.
Anything else → `E_ARG`.

The helper treats it as a **lookup key and nothing else**. It is never used to
build a path: the failure counter is a single file with one record per username
(§5.14), specifically so that no argument in this contract ever names a file. It
carries no authority — a username in a message is not an identity (§2.2, G8).

### 4.10 `pass`

| Rule | Value |
|---|---|
| type/length | string, 1–1024 bytes, valid UTF-8 |
| control bytes | any byte `0x00`–`0x1F` or `0x7F` → `E_ARG` |
| trimming | **none.** Leading and trailing spaces are part of a password |
| normalisation | none. The bytes are compared as sent |

Why 1024: `crypt()` ignores everything past the first few bytes anyway, and an
unbounded password is a way to spend root's CPU (§1.3). The 64 KiB line cap bounds
it too, but not tightly enough to be the only limit.

**`pass` is never written anywhere and never echoed anywhere.** Not in `data`, not
in `message`, not in the audit log, not in a debug line, not truncated, not
hashed, not its length. An `E_ARG` on `pass` says `"pass: contains a control
byte"` and stops there — naming the field and the rule, never quoting the value.
The same applies to any validation failure that could reveal it by inference: the
helper does not report which byte, or where.

This is the one argument in the contract with an output rule attached to its input
rule, and §8 repeats it, because a password that reaches a log file has leaked
whether or not anyone was looking.

---

## 5. The frozen operation allowlist

Fourteen operations. Not thirteen, not fifteen.

| # | Operation | Arguments | Mutates | Socket | Screen | `csf`/system action |
|---|---|---|---|---|---|---|
| 1 | `status` | — | no | helper (the only one) | Overview | reads files, plus one `iptables -S` |
| 2 | `counts` | — | no | helper | Overview | reads files only |
| 3 | `deny` | `ip`, `note` | **yes** | helper | Block | `csf -d <ip> <note>` |
| 4 | `undeny` | `ip` | **yes** | helper | Block, Lists | `csf -dr <ip>` |
| 5 | `allow` | `ip`, `note` | **yes** | helper | Block | `csf -a <ip> <note>` |
| 6 | `unallow` | `ip` | **yes** | helper | Lists | `csf -ar <ip>` |
| 7 | `tempdeny` | `ip`, `ttl`, `ports` | **yes** | helper | Block | `csf -td <ip> <ttl> [-p <ports>] csf-ui` |
| 8 | `temprm` | `ip` | **yes** | helper | Lists | `csf -trd <ip>` |
| 9 | `list` | `which`, `offset`, `limit`, `filter` | no | helper | Lists | reads files only |
| 10 | `grep` | `ip` | no | helper | IP lookup | `csf -g <ip>` |
| 11 | `reconcile` | — | no | helper | Health | `iptables -S`, reads files |
| 12 | `reconcile_fix` | `ids` | **yes** | helper | Health | `iptables -D <chain> <spec>` |
| 13 | `restart` | — | **yes** | helper | Overview | `csf -r` |
| 14 | `authenticate` | `user`, `pass` | no firewall state; writes its own failure counter (§5.14) | helper | Login | reads `/etc/csf-ui/users`, runs `crypt()` |

The "Socket" column is constant by design; §1.2 says why. The "Mutates" column is
what the audit log (§8), the CSRF requirement, the role check and the rate caps
(§7) key off.

**Role mapping, enforced in `csf-ui` (Task 7), not here:** `support` may call
`grep` and `list` only. Every other operation is `admin`, except `authenticate`,
which is **pre-session** — it is how a role is discovered, so it cannot require
one. The helper does not know about roles and will execute any of the 14 for the
web tier — §1.2.

### 5.0 Rules that apply to every operation

1. **Every external command is `system`/`exec`/`open` with an argv LIST** — no
   string form, no backticks, no `qx`, no shell, at any layer (G2). `open(my $fh,
   '-|', $prog, @args)` is the list form and forks without a shell; it is the only
   way the helper reads a child's output.
2. **Exit status is not the outcome.** `csf` exits 0 after refusing (§1.4). Every
   mutating operation therefore: snapshots the relevant store → runs `csf` →
   re-reads the store → decides the outcome from the **delta**. `csf`'s text is
   used for the human-readable `message` only, after §3.6 sanitising.
3. **Timeouts.** Every child is run with a deadline (§7). On expiry it gets
   `SIGKILL` and the operation answers `E_BACKEND`. The helper never waits
   indefinitely on `csf` holding a lock.
4. **Output caps.** At most 64 KiB is read from any child; beyond that the child
   is killed and the operation answers `E_BACKEND`.
5. **`csf` disabled or in error**, with one carve-out that matters.
   - `/etc/csf/csf.disable` present: `csf` refuses everything on this list and
     exits 1 (`csf.pl:90-99`; `-r` is **not** in its exemption list). Every
     operation that shells out answers `E_REFUSED` with that reason, `restart`
     included — re-enabling is `csf -e`, which is deliberately not on this list
     (§9).
   - `/etc/csf/csf.error` present: `csf` refuses most commands and exits 1
     (`csf.pl:104-111`) — but its exemption list at `csf.pl:104` explicitly
     includes `--restart`/`-r`, and its own message is "You need to restart csf
     successfully to remove this warning". **So `restart` is exempt here too.**
     Every other mutating operation answers `E_REFUSED`; `restart` runs.
   Refusing `restart` in the one state it is the remedy for would leave an operator
   whose firewall failed to start looking at a UI where nothing on the list can fix
   it — and nothing else here clears `csf.error`.
   `status` reports both conditions as fields so the Overview can say which one it
   is, and say what to do about it.
6. **Canonical values.** Whatever the caller sent, `data` and the audit log carry
   the canonical form from §4.1.
7. **Idempotence is success, not error.** Blocking an address that is already
   blocked returns `ok:true` with `"added": false`. A user who double-clicks, or
   a retry after a timeout, must not produce an error screen.

### 5.1 `status` — no arguments, read-only

```json
{"ok":true,"data":{
  "enabled":true,"rules_loaded":true,"testing":false,"ipv6":false,
  "lfd_running":true,"version":"15.00","start_error":null,
  "ipset_mode":false,"generated":1757548800}}
```

| Field | Type | Source |
|---|---|---|
| `enabled` | bool | `!-e /etc/csf/csf.disable` |
| `rules_loaded` | bool | chain `DENYIN` exists in the output of `('<IPTABLES>','-S')` — the **one child process** this operation spawns |
| `testing` | bool | `TESTING` in `csf.conf` |
| `ipv6` | bool | `IPV6` in `csf.conf` |
| `lfd_running` | bool | `/var/run/lfd.pid` exists, contains a pid, and `kill(0,$pid)` succeeds |
| `version` | string or null | `/etc/csf/version.txt`, accepted only if it matches `^[0-9.]{1,16}$`; otherwise `null` |
| `start_error` | string or null | first line of `/etc/csf/csf.error`, sanitised, ≤256 bytes |
| `ipset_mode` | bool | `LF_IPSET` in `csf.conf` — when true, `reconcile` is unavailable (§5.11) |
| `generated` | int | epoch seconds when the helper computed this |

`rules_loaded` cannot be answered from a file: only the live ruleset knows whether
the rules are actually loaded, and it is the single most important thing on the
Overview. So `status` **does** spawn one child, with a 10 s deadline and the same
64 KiB output cap as any other (§7).

**If that child fails, times out or is killed, the whole call answers
`E_BACKEND`** — it does not return `rules_loaded:false` alongside the fields it did
manage to read. "The firewall is not loaded" and "I could not find out" are
different answers, and reporting the second as the first is a lie about the state
of a firewall (G3). The Overview shows "cannot determine firewall state", which is
the truth and is actionable.

### 5.2 `counts` — no arguments, read-only

```json
{"ok":true,"data":{"deny":412,"allow":37,"temp_deny":19,"temp_allow":2,
  "deny_includes":0,"allow_includes":1,"generated":1757548800}}
```

Read directly from four fixed paths — `/etc/csf/csf.deny`, `/etc/csf/csf.allow`,
`/var/lib/csf/csf.tempban` and `/var/lib/csf/csf.tempallow` — with no `csf`
invocation and no child process. `csf.tempallow` appears only here: nothing on
this list mutates it (§9 rules out `csf -ta`), but an Overview that counts
temporary bans and stays silent about temporary *allows* hides the more
security-relevant number of the two.

Counts are of **parsable entries**: blank lines, comment lines and `Include`
lines are excluded from the count; the number of `Include` directives is reported
separately so the Overview can say "1 include file, contents not shown" instead of
quietly under-reporting. Temp counts exclude entries whose TTL has already
expired.

### 5.3 `deny(ip, note)` — mutating

`ip` per §4.1 including the mutating-operation floor. `note` per §4.4, required.

Runs `('/usr/sbin/csf','-d',$ip,$note)`. Success is decided by re-reading
`csf.deny`.

| Outcome | Response |
|---|---|
| the address is now in `csf.deny` and was not before | `ok:true`, `{"ip":…,"added":true}` |
| it was already there | `ok:true`, `{"ip":…,"added":false,"already":true}` |
| `csf` refused: the server's own address, in `csf.allow`, in `csf.ignore`, IPv6 while `IPV6=0` | `E_REFUSED` + `csf`'s reason |
| `csf` timed out, was killed, or the file is unchanged with no recognised reason | `E_BACKEND` |

### 5.4 `undeny(ip)` — mutating

Runs `('/usr/sbin/csf','-dr',$ip)`. Returns
`{"ip":…,"removed":N,"protected":M}` where `N` is the drop in matching lines in
`csf.deny` and `M` is the number of matching lines left behind because their note
matches `/do not delete/i` (`csf.pl:1735`). `removed:0, protected:0` is `ok:true`
— removing something that is not there is not an error.

No prefix floor and, alone with `unallow` and `temprm`, **no `/0` rejection and
no `::`/`::1` rejection** (§4.1): removal is not dangerous, and an entry broad
enough — or close enough to home — to have locked the operator out is the one
they most need this operation for. `csf -dr 0.0.0.0/0` removes such a line;
refusing to send it because the value is broad would be perverse. The same
argument decides `::1`, which `csf -d` will happily write from a shell: an entry
that can exist must be removable here.

Both exceptions rest on the same verified fact, and neither would be safe without
it: `csf` deletes by **exact string equality** on the canonicalised address
(`csf.pl:1734`, `:1827`, `:4733`), never by CIDR containment. So an accepted
literal reaches exactly the line that carries that literal and cannot touch any
other entry. If that ever changes, both exceptions have to be revisited together.

### 5.5 `allow(ip, note)` — mutating

Runs `('/usr/sbin/csf','-a',$ip,$note)`. Same shape and same outcome table as
`deny`, against `csf.allow`.

Allowing is a **security decision**, which is why `support` cannot reach it
(§1.2) and why it carries the same prefix floor as `deny`: `allow 0.0.0.0/0`
would exempt the Internet from the firewall.

### 5.6 `unallow(ip)` — mutating

Runs `('/usr/sbin/csf','-ar',$ip)`. Same shape as `undeny`, against `csf.allow`.

### 5.7 `tempdeny(ip, ttl, ports)` — mutating

Runs `('/usr/sbin/csf','-td',$ip,$ttl)` plus `('-p',$ports_expanded)` when ports
were given, and **always** the fixed literal note `csf-ui` as the final argument.

**No caller-supplied note is accepted** — the operation has no `note` argument,
precisely because `csf -td` parses options out of comment text (§1.4). **No
direction is sent**; `csf` defaults to inbound. There is no way to request `out` or
`inout` over this interface.

**Why a fixed note is mandatory, not cosmetic.** `csf -td` strips `-p <ports>` out
of the comment (`csf.pl:4318`) and then, at `csf.pl:4320`:

```perl
if ($comment eq "") {$comment = "Manually added: ".iplookup($ip)}
```

`ConfigServer::LookUpIP::iplookup` is gated on `LF_LOOKUPS`, which ships as `"1"`
(`csf.conf:451`), and on a cache miss runs `host -W 5 <ip>` as root
(`LookUpIP.pm:87`, inside `alarm(10)` at `LookUpIP.pm:85`). So a `tempdeny` with no
note makes **root perform a reverse-DNS lookup of an address the caller chose** —
a covert egress channel to a nameserver the caller controls, which is exactly the
primitive §9 excludes when it rules out `csf -i`, arriving through the back door of
operation 7 on every call. It would also write to `/var/lib/csf/csf.dnscache` and
could spend up to 10 of the 20 seconds this operation is allowed (§7).

`csf-ui` is a deliberate choice of literal: it passes §4.4's grammar (the `-u` is
not preceded by whitespace or start-of-string, so it is not option-looking), it
contains no `-p` or `-d` token for `csf.pl:4311-4313` to find, and it makes the
origin of the entry obvious in `csf -t` output.

The same branch exists for permanent entries — `csf.pl:1687` for `deny` and
`csf.pl:1517` for `allow` — which is the second reason `note` is **required** on
both (§5.3, §5.5) rather than optional. Across all fourteen operations, no `csf`
invocation this contract makes can reach an empty-comment branch.

```json
{"ok":true,"data":{"ip":"192.0.2.10","added":true,"ttl":3600,
  "ports":"80,443","dir":"in","note":"csf-ui","expires":1757552400}}
```

| Outcome | Response |
|---|---|
| a matching unexpired row now exists in `csf.tempban` and did not before | `ok:true`, `added:true` |
| it already existed | `ok:true`, `added:false, already:true` |
| the address is already **permanently** blocked (`csf.pl:4331`) | `E_REFUSED`, "already permanently blocked" |
| server's own address, invalid for the configured IP version | `E_REFUSED` |
| no change and no recognised reason | `E_BACKEND` |

### 5.8 `temprm(ip)` — mutating

Runs `('/usr/sbin/csf','-trd',$ip)` — **`-trd`, not `-tr`**. `-tr` removes the
address from the temporary ban list *and* the temporary allow list
(`csf.pl:4537`); an operator deleting a row from the temp-ban screen must not
silently delete a temporary allow they cannot see. Returns
`{"ip":…,"removed":N}` from the delta in `csf.tempban`.

### 5.9 `list(which, offset, limit, filter)` — read-only

Reads the file named by the `which` table (§4.5) directly — no `csf` invocation.
`Include` lines are counted, never followed: rows from an included file could not
be deleted by `csf -dr`, which rewrites only the main file.

```json
{"ok":true,"data":{"which":"deny","total":412,"offset":0,"returned":100,
  "next_offset":100,"truncated":false,"includes":0,
  "rows":[{"ip":"192.0.2.10","note":"abuse ticket 4471","protected":false,"line":37}]}}
```

| Row field | `deny` / `allow` | `temp` |
|---|---|---|
| `ip` | canonical address or CIDR | same |
| `note` | text after the address, with a leading `#` and surrounding spaces stripped; sanitised, ≤200 bytes | the record's comment field, same treatment |
| `protected` | note matches `/do not delete/i` | — |
| `line` | 1-based line number in the file | — |
| `ports` | — | `"*"` or the stored list |
| `dir` | — | `in` / `out` / `inout` |
| `expires` | — | epoch |
| `ttl_left` | — | seconds, ≥0 |

`next_offset` is `offset + returned` — never `offset + limit` (§3.4) — and `null`
once the last row has been returned. `total` is the count **after** filtering. A line that does not parse is skipped
and counted in `unparsable` (an integer field, present when non-zero) rather than
being rendered as a half-row. Expired temp rows are omitted.

### 5.10 `grep(ip)` — read-only

Runs `('/usr/sbin/csf','-g',$ip)` and returns its output as lines:

```json
{"ok":true,"data":{"ip":"192.0.2.10","lines":["filter DENYIN  …"],
  "count":14,"truncated":false}}
```

At most 200 lines, each at most 512 bytes, and the §3.4 byte budget on top;
every line sanitised per §3.6. `csf -g` also accepts a port number or a bare
CIDR; **this operation accepts only `ip`** (§4.1), which is a deliberate
narrowing.

`csf -g` builds a shell pipeline internally (`csf.pl:3900-3905`) — but the
searched address is not interpolated into it; it is used in-process via
`quotemeta`. An address that passed §4.1 cannot reach that shell. This is stated
because "it goes through a shell somewhere" is exactly the kind of thing a
reviewer must be able to check rather than take on trust.

### 5.11 `reconcile` — no arguments, read-only

Compares the live ruleset against the configured one.

**Scope, fixed:** chains `DENYIN` and `DENYOUT` only, in the `filter` table,
IPv4 always and IPv6 when `status.ipv6` is true. Rules anywhere else are out of
scope and are never reported, which is what makes §5.12 safe.

| Kind | Meaning | Fixable here |
|---|---|---|
| `ORPHAN` | a rule in a scoped chain whose address is in neither `csf.deny` nor the unexpired temp-ban store | **yes** — delete the rule |
| `DUP` | the same canonical rule spec appears more than once in one chain | **yes** — delete the extra copies, keep one |
| `GHOST` | an entry in `csf.deny` with no matching rule loaded | **no** — the remedy is `restart`, which rebuilds the ruleset from config |

```json
{"ok":true,"data":{"totals":{"orphan":3,"ghost":1,"dup":0},
  "returned":4,"truncated":false,"generated":1757548800,
  "entries":[{"id":"9f1c…","kind":"ORPHAN","family":4,"chain":"DENYIN",
              "ip":"198.51.100.7","spec":"-s 198.51.100.7/32 -j DROP",
              "fixable":true,"reason":null}]}}
```

`totals` is always exact even when `entries` is truncated (§3.4).

**`E_UNAVAILABLE` when `LF_IPSET` is enabled.** With ipsets, blocked addresses
are set members rather than individual rules, so a per-rule comparison would
report every deny entry as a `GHOST` — thousands of false findings leading to a
destructive button. Refusing with a stated reason is the fail-closed answer (G3).

A rule whose `iptables -S` line does not tokenise under the strict grammar
`^[A-Za-z0-9_.:/,=+-]+$` per token — a quoted `--comment`, for instance — is
reported with `fixable:false` and `reason:"unparsable"`. It is never
approximately parsed, because §5.12 turns tokens back into a delete command.

**It takes `kind:"ORPHAN"` and counts in `totals.orphan`.** The kind set is
closed at three, and this is the only one of the three that is not a claim the
helper would be making falsely: its address could not be read, so it cannot be
matched to a configured entry, which is what `ORPHAN` says. `GHOST` would be
wrong — the rule is loaded — and inventing a fourth kind would widen a frozen
enumeration for a row nothing can act on. Screens must therefore key the fix
button off `fixable`, never off `kind`: an `ORPHAN` is not necessarily
deletable, and this is the case that proves it.

**A rule spec loaded more than once in one chain is one `DUP` finding, not one
per copy**, and `totals.dup` counts findings. The id is a content address over
`kind`, `family`, `chain` and the canonical rule spec (§4.8), so identical copies
would otherwise produce identical ids — and a request carrying the same id twice
is `E_ARG`, which would make the duplicate unfixable through the very operation
that exists to fix it. Fixing one `DUP` finding deletes copies until one remains.
The same address orphaned in both `DENYIN` and `DENYOUT` is two findings, because
those are two different rules in two different chains.

### 5.12 `reconcile_fix(ids)` — mutating

The only destructive operation whose target is chosen by the caller, so its
safety is structural rather than advisory:

1. It **re-runs the full `reconcile` scan**. Nothing is cached between calls.
2. It computes the ids of that fresh result.
3. It acts **only** on ids present in the fresh result **and** marked
   `fixable:true`.
4. Its only verb is `iptables -D <chain> <spec-tokens>` / `ip6tables -D …`,
   built as an argv list from tokens that `iptables -S` itself produced, with the
   chain name taken from the helper's own two-entry table — never from the
   request.

```json
{"ok":true,"data":{"fixed":3,"stale":1,"unfixable":0,
  "results":[{"id":"9f1c…","outcome":"deleted"},
             {"id":"0000…","outcome":"stale"}]}}
```

| Situation | Result |
|---|---|
| id is not 32 lowercase hex, or `ids` is not an array of strings, or >500 entries, or duplicated | `E_ARG`, **nothing is executed** |
| id is well-formed but absent from the fresh scan (forged, or the page is stale) | per-id `"outcome":"stale"`, no action |
| id names a `GHOST` or an unparsable entry | per-id `"outcome":"unfixable"`, no action |
| every id came back `stale` | `E_STALE` for the whole request — the caller is looking at a dead page |
| `iptables -D` fails | per-id `"outcome":"failed"`, the rest still processed, `ok:true` |

So the answer to "what does an attacker get by sending 500 fabricated ids" is:
500 `stale` outcomes and an `E_STALE`. They cannot name a rule outside `DENYIN`
and `DENYOUT`, and they cannot name a rule that is not divergent right now —
because they do not name rules at all; they name findings the helper just made
itself.

The UI requirement from spec §5 stands on top of this: Health shows the diff and
requires a separate confirmation. There is no one-click cleanup.

### 5.13 `restart` — no arguments, mutating

Runs `('/usr/sbin/csf','-r')`, deadline 120 s.

```json
{"ok":true,"data":{"restarted":true,"duration_ms":8412,
  "testing":true,"warnings":["*WARNING* TESTING mode is enabled …"]}}
```

| Situation | Result |
|---|---|
| fewer than 10 seconds since the last successful restart (§7) | `E_BUSY` |
| `csf` is disabled (`/etc/csf/csf.disable`) | `E_REFUSED` — `-r` is not exempt from that check (`csf.pl:93`), and `csf -e` is not on this list |
| `csf` has an unresolved start error (`/etc/csf/csf.error`) | **runs** — `csf.pl:104` exempts `-r`, and this operation is how that state is cleared (§5.0.5) |
| the csf lock is held ("csf is being restarted, try again in a moment") | `E_BUSY` |
| exceeds the deadline | `E_BACKEND`, and the child is killed — **note that the restart may still have taken effect**; the message says so rather than claiming failure |

This is the most dangerous operation on the list and it takes no arguments, which
is the point: there is nothing hostile to send. What an attacker who owns
`csf-ui` gets is firewall flapping at most once per 10 seconds, logged every
time by root.

### 5.14 `authenticate(user, pass)` — no firewall state, own counter

The web tier does not read the password store. It asks.

```
request   {"op":"authenticate","args":{"user":"alice","pass":"…"},"id":"…"}
response  {"id":"…","ok":true,"data":{"ok":true,"role":"admin"}}
```

The envelope's `ok` means *the helper answered the question*. `data.ok` means *the
credentials are valid*. A wrong password is **not** an RPC error: it is a
successful call with a negative verdict. Confusing the two is how a web tier ends
up treating a backend failure as a login.

| Response | `data` |
|---|---|
| valid credentials | `{"ok":true,"role":"admin"}` — `role` is `admin` or `support`, from the record |
| wrong password, **or no such user** | `{"ok":false,"role":null,"locked":false,"retry_after":0}` |
| the username is locked out | `{"ok":false,"role":null,"locked":true,"retry_after":287}` |
| the store is missing, unreadable, not a regular file, a symlink, not owned by uid 0, group/other-readable, or contains no accounts | `E_UNAVAILABLE` with the remedy |
| the user's record carries an `algo` this helper cannot verify | `E_UNAVAILABLE` naming the algorithm and the remedy — **and the failure counter is not incremented** |
| `user` or `pass` fails §4.9 / §4.10 | `E_ARG`, naming the field and the rule only |

**Why the hashes stay put.** `/etc/csf-ui/users` is `0600 root:root` and is opened
by the helper and by `csf-ui-passwd` (root) and by nothing else. A compromise of
`csf-ui` therefore yields **no hash file**: nothing to carry away and grind through
offline, and no record of the accounts that never log in. What it yields is this
operation, with the bounds set out below.

It does **not** make a compromised web tier harmless to credentials. Every password
typed into the login form passes through `csf-ui` in cleartext on its way here, so
an attacker holding that tier captures the credentials of everyone who logs in
while they hold it — and cleartext is more useful to them than a hash. The
guarantee is about *scale and duration*, not secrecy: the accounts exposed are the
ones that authenticate during the compromise, not all of them for as long as the
hashes hold out. §1.2 says the same thing in the threat model, and neither
statement should ever be trimmed into the shorter, false one.

**Verification.** The helper runs Task 3's `Auth::verify()` **in its own process**:
`crypt()` with the record's own `$6$` salt and round count, compared in constant
time.

**One hash algorithm, and it is `$6$` SHA-512 crypt.** The record keeps its `algo`
field so a future migration has somewhere to go, but the only value this contract
implements is **`6`** — the record format is `username:algo:hash:role:created_epoch`
and Task 3 rejects any other `algo` on write. `Crypt::Argon2` is neither a core module nor vendored in
this tree — `Crypt/` holds `Blowfish_PP.pm` and `CBC.pm` and nothing else — so
under G1 it cannot be a dependency, and a branch that cannot run would advertise a
strength the deployment does not have. The plan's "Argon2id when present"
(`docs/WEBUI-PLAN.md:178`) is amended accordingly (§11.8).

A record whose `algo` is anything other than `6` — a store copied from a
machine that had something else, or a future format met by an older helper — is
**unverifiable, not wrong**. `authenticate` answers `E_UNAVAILABLE` naming the
username's algorithm and the remedy (`csf-ui-passwd passwd <user>`), and
**does not count it as a failure**: a store the helper cannot read must not lock
out the administrator who would fix it. `data.ok:false` would be the wrong answer
twice over — indistinguishable from a wrong password, and it would burn the
counter. Wrong password and unknown username must be
indistinguishable, in the response **and in the time taken**, so when the username
is not in the store the helper still runs one `crypt()` against a fixed dummy
`$6$` record before answering. Skipping that turns response latency into a user
enumeration oracle.

**The failure counter — the helper's own, not the web tier's.**

| Property | Value |
|---|---|
| Keyed by | the submitted `user` string, whether or not it exists |
| Threshold | **5 consecutive failures → the username is locked for 300 s** |
| Reset | a successful verification clears the record |
| While locked | the helper answers `locked` **without running `crypt()`** — that is what makes the counter a CPU control as well as an anti-guessing one |
| State | `/var/lib/csf-ui/helper/authfail.state`, `0600 root:root`, one record per username, rewritten atomically (temp file + `rename`) under `flock` |
| Capacity | 256 usernames |
| Eviction | **only records whose lockout has expired.** If all 256 are actively locked, a new username is answered `locked` with `retry_after` set to the earliest expiry — it is never admitted by evicting someone else's lockout |
| Survives reboot | yes, deliberately — `/var/run` is tmpfs, and a lockout that a reboot clears is not a lockout |

The capacity rule exists because the key comes from the caller: without it, an
attacker cycling usernames grows the file without bound, and with naive eviction
they flush a real account's lockout by submitting 256 invented names. Expired-only
eviction closes both.

This counter is **independent of `RateLimit.pm`** in the web tier (Task 4). That
one protects the login form; this one holds even when the web tier is the
attacker. `csf-ui` must not treat its own limiter as sufficient, and must not try
to reset this one — it cannot: the state is `0600 root`.

**Audit.** Every attempt is logged by the helper: `user`, the outcome
(`ok` / `bad` / `locked`), the peer, the request id. **Never `pass`** — see §4.10
and §8.

**What this costs.** `crypt()` at `UI_CRYPT_ROUNDS` now runs as root. §7 caps
`authenticate` at 2 concurrent children and 30 calls per rolling 60 s across all
callers, so the worst a caller can spend is two cores' worth of hashing. The
per-username lockout bounds the guessing itself at 5 attempts per 5 minutes,
which is what a stolen web tier is reduced to.

---

## 6. Hostile-input matrix

The acceptance question for this document: **for each operation, what does an
attacker sending a hostile value for every argument get?** Not "it depends on the
caller" — the helper validates everything itself, so the answer is the same
whether the sender is the login page, a compromised web tier, or a process that
somehow acquired the socket.

### 6.1 Answers that hold for every argument of every operation

| Hostile input | Result |
|---|---|
| any shell metacharacter — `; & \| $ ( ) \` < > \n` | `E_ARG` from the type grammar (§4). And if a grammar were ever wrong, the value still reaches `execve` as one argv element: there is no shell in the helper (G2) |
| NUL byte (`%00`, or a JSON `\u0000` escape) inside any string | `E_ARG` (control byte, §3.6/§4.4) — and it cannot be part of an argv element in any case |
| wrong JSON type (array/object/number/bool/null where a string is required) | `E_ARG` |
| an argument the operation does not define | `E_ARG` — unknown keys are rejected, never ignored (§3.2) |
| a required argument omitted | `E_ARG` |
| a value longer than its cap | `E_ARG`; if the whole line exceeds 64 KiB, `E_PROTOCOL` and the connection closes after 64 KiB is read |
| unicode confusables, RTL overrides, combining marks | accepted only where valid UTF-8 is allowed (`note`, `filter`); rendered escaped by Task 6's default-escaping template layer; sanitised out of anything echoed back (§3.6) |
| 10⁶ requests | `E_BUSY` past the caps in §7; each connection costs one forked child, capped at 16 |
| a hostile value in `pass`, of any kind | rejected or verified, and **never echoed**: no argument value from `pass` appears in any response, message or log line (§4.10) |
| a request replayed verbatim | executed again. There is no nonce at this layer — replay protection is CSRF and session state in `csf-ui`. A caller that can replay on this socket can also compose the request from scratch; a nonce here would protect nothing (§1.2) |

### 6.2 Per operation

`status`, `counts`, `reconcile`, `restart` take **no arguments**, so the only
hostile input is an `args` object with keys in it (→ `E_ARG`) or request volume
(→ `E_BUSY`, §7). Their entries below record what a caller gets when the
arguments are valid, because that is the remaining question.

| Op | Argument | Hostile value | Result |
|---|---|---|---|
| `status` | — | `{"args":{"x":1}}` | `E_ARG` |
| | | flood | `E_BUSY`; one `iptables -S` per call, 10 s deadline (§7), so a flood is bounded by the concurrency cap like any other child |
| `counts` | — | as above | as above |
| `deny` | `ip` | `1.2.3.4; rm -rf /`, `$(id)`, `` `id` `` | `E_ARG` — `inet_pton` fails |
| | | `0.0.0.0/0`, `::/0` | `E_ARG` — `/0` rejected |
| | | `1.0.0.0/4` | `E_ARG` — below the `/8` floor |
| | | `192.0.2.10/24` | `E_ARG` — host bits set |
| | | `127.0.0.1`, `127.0.0.0/8`, `::1` | `E_ARG` — loopback (and `csf` rejects it too) |
| | | `::ffff:127.0.0.1` | `E_ARG` — IPv4-mapped |
| | | `999.1.1.1`, `10.0.0.0/33`, `1.2.3.04`, `0x7f000001` | `E_ARG` |
| | | `<the server's own address>` | `E_REFUSED` — `csf` refuses (`csf.pl:1541`); the helper reports the refusal rather than reporting success |
| | | 100 000-byte string | `E_PROTOCOL` (line cap) |
| | `note` | `"x\nInclude /etc/shadow"` | `E_ARG` — control byte; this is the injection the rule exists for |
| | | `"-p 22 -d out"` | `E_ARG` — option-looking note |
| | | `"a\|b"` | `E_ARG` — pipe |
| | | 201 bytes | `E_ARG` |
| | | `"<script>alert(1)</script>"` | **accepted** — it is a legal note. It is stored as text, sanitised on the way out (§3.6), and HTML-escaped by default when rendered (Task 6). The helper is not an HTML encoder and does not pretend to be |
| | valid everything | worst case | one address or CIDR (≥ `/8`) is blocked. That is the operation |
| `undeny` | `ip` | all `ip` cases above except the prefix floor, the loopback rule and the `/0` rejection, none of which apply to removal (§4.1) | `E_ARG` |
| | | an address that is not blocked | `ok:true, removed:0` — not an error |
| | | an entry noted "do not delete" | `ok:true, removed:0, protected:1` — `csf` keeps it |
| | valid | worst case | one address is unblocked. Bounded by the caps in §7, an attacker who owns `csf-ui` can unblock addresses one at a time — there is no bulk flush on this list (§9) |
| `allow` | `ip` | as `deny`, including the floor | `E_ARG` |
| | `note` | as `deny` | `E_ARG` |
| | valid | worst case | one address or CIDR is exempted from the firewall. This is the most security-relevant *successful* call on the list, which is why `support` cannot reach it and why every call is logged by root |
| `unallow` | `ip` | as `undeny`, including `/0` being accepted here | `E_ARG` / `removed:0` |
| `tempdeny` | `ip` | as `deny` | `E_ARG` / `E_REFUSED` |
| | `ttl` | `59`, `604801`, `-1`, `0`, `1e9`, `"1h"`, `"30m"`, `"\n3600"`, `null` | `E_ARG` |
| | | `"3600"` (digit string) | accepted — normalised to integer 3600 |
| | `ports` | `"80;udp"`, `"*"`, `"22 -d out"`, `"80,"`, `"0"`, `"65536"`, `"08"` | `E_ARG` |
| | | `"1000-2000"` | `E_ARG` — expands to 1001 ports, cap 20 |
| | | `"1-20"` | accepted — 20 ports |
| | | 21 comma entries | `E_ARG` |
| | valid everything | worst case | one address blocked inbound, ≤20 TCP ports, ≤7 days; it expires on its own. **No DNS is emitted**: the fixed `csf-ui` note keeps `csf` out of its `iplookup` branch (§5.7). Had the note been empty, every call would have made root resolve an address of the caller's choosing |
| `temprm` | `ip` | as `undeny` | `E_ARG` / `removed:0` |
| | valid | worst case | one temporary ban is lifted. It cannot touch a temporary **allow** — that is why `-trd` and not `-tr` (§5.8) |
| `list` | `which` | `"ignore"`, `"DENY"`, `"../../etc/shadow"`, `"deny\0"`, `["deny"]` | `E_ARG` — table lookup, not path construction |
| | `offset` | `-1`, `1000001`, `"1e9"`, `1.5` | `E_ARG` |
| | `limit` | `0`, `501`, `-5` | `E_ARG` |
| | | `500` on a 100 000-line file | `ok:true` with `returned` < 500 and `truncated:true` when the 64 KiB budget binds (§3.4) |
| | `filter` | `".*"`, `"(a+)+$"`, `"\\x{0}"` | accepted and matched **literally** — no regex is compiled, so no pattern can be pathological |
| | | 101 bytes, or a control byte | `E_ARG` |
| | valid everything | worst case | the caller reads the block lists — which the `support` role is allowed to do by design. Notes may contain anything an admin or `lfd` wrote; §3.6 sanitises and Task 6 escapes |
| `grep` | `ip` | as `deny` for `/0` (rejected — searching for "everything" is not a lookup), as `undeny` for the floor and loopback (not applied) | `E_ARG` |
| | | `"80"`, `"tcp"` — things `csf -g` would accept | `E_ARG` — this operation takes an address, deliberately |
| | valid | worst case | one `iptables -L` scan per call, ~1 s of CPU; capped by §7, and by 200 lines / 64 KiB of output |
| `reconcile` | — | `{"args":{"chain":"INPUT"}}` | `E_ARG` — the chain set is not an argument |
| | | flood | `E_BUSY`; it is the most expensive read (two `iptables -S` calls), so it counts against the same caps |
| | | `LF_IPSET` enabled | `E_UNAVAILABLE` with the reason, rather than thousands of false ghosts |
| `reconcile_fix` | `ids` | `["../../x"]`, `["9F1C…"]` (uppercase), `[1,2]`, `"9f1c…"` (not an array) | `E_ARG`, nothing executed |
| | | 501 ids, or a duplicate id | `E_ARG`, nothing executed |
| | | 500 well-formed but fabricated ids | 500 × `stale`, then `E_STALE`. No rule is touched |
| | | an id from a `reconcile` five minutes ago whose rule is gone | `stale` — the scan is fresh every time |
| | | an id naming a `GHOST` | `unfixable` — `reconcile_fix` only ever deletes live rules |
| | valid | worst case | orphan and duplicate rules **in `DENYIN`/`DENYOUT` only** are deleted. An orphan by definition has no config entry, so a restart does not bring it back — this is real deletion, which is why the UI requires a diff and a second confirmation |
| `restart` | — | `{"args":{"force":true}}` | `E_ARG` |
| | | called in a loop | first call runs; the rest get `E_BUSY` for 10 s (§7) |
| | valid | worst case | the firewall is rebuilt. Brief window during the rebuild; every call logged by root with its request id |
| `authenticate` | `user` | `"../../etc/shadow"`, `"Alice"`, `"a"*33`, `"root\u0000"`, `["alice"]`, `""` | `E_ARG` — `^[a-z0-9_-]{1,32}$`, and the value never names a file (§4.9) |
| | | a username that does not exist | `data.ok:false`, **identical shape and identical timing** to a wrong password — one dummy `crypt()` is run (§5.14). No enumeration |
| | | 256 invented usernames, to flush a victim's lockout | fails — only expired records are evicted; when the table is full a new username is answered `locked` (§5.14) |
| | `pass` | a control byte, invalid UTF-8, 1025 bytes | `E_ARG` naming the field and the rule, **never quoting or measuring the value** (§4.10) |
| | | a 60 KiB password, to burn root CPU | `E_ARG` at 1024 bytes, before any hashing |
| | | the right password, guessed | 5 tries per username per 5 minutes, then `locked` for 300 s with no `crypt()` run at all |
| | | any value at all, seeking the hash | nothing — no hash appears in `data`, in `message` or in either log, and `/etc/csf-ui/users` is `0600 root` where `csf-ui` cannot open it. This bounds *offline* attack on the store; it does not protect a password typed into a login form the attacker already controls (§1.2, §5.14) |
| | | an automated flood | `E_BUSY` past 2 concurrent / 30 per 60 s (§7) |
| | valid everything | worst case | a caller who already knows a valid password learns the role that goes with it. That is the operation. The web tier still has to mint a session, and the helper never sees it |

### 6.3 The three answers that are not "the request is rejected"

Stated separately so they are not lost in the table:

1. **A caller who reaches the socket can block and unblock addresses and restart
   the firewall.** Every value is validated, but valid values have effects. The
   allowlist bounds *what kind* of effect, §7 bounds *how fast*, §8 records *that
   it happened*. Nothing here bounds *how many* over a long period.
2. **`support` is not enforced at this boundary.** A compromised `csf-ui`
   executes admin operations with a support session, or with no session at all
   (§1.2).
3. **A caller who reaches the socket can test passwords** — five per username per
   five minutes, and each success tells them a role. What they cannot do is take
   the hash file away and work on it offline. And a caller that *is* a compromised
   `csf-ui` need not guess at all for anyone who logs in while it is compromised:
   it reads those passwords in cleartext as they pass through (§1.2, §5.14). The
   store is protected; a live login is not.

---

## 7. Helper-side limits

These are enforced by the helper, on its own state, independent of anything the
caller says — so they hold for a hostile caller.

| Limit | Value | Exceeded → |
|---|---|---|
| Concurrent connection children | 16 | `E_BUSY`, close |
| Requests per connection | 1 | `E_PROTOCOL` on trailing bytes |
| Line size, each direction | 65536 bytes | `E_PROTOCOL`, close |
| Time from accept to a complete request line | 5 s | close, no response |
| Time to write one response line | 5 s | close, and log that the response could not be written |
| Child deadline — `status` (one `iptables -S`) | 10 s | `SIGKILL`, `E_BACKEND` for the whole call (§5.1) |
| Child deadline — read ops (`grep`, `reconcile`) | 30 s | `SIGKILL`, `E_BACKEND` |
| Child deadline — mutating ops except `restart` | 20 s | `SIGKILL`, `E_BACKEND` |
| Child deadline — `restart` | 120 s | `SIGKILL`, `E_BACKEND` (with the caveat in §5.13) |
| Bytes read from any child | 65536 | kill, `E_BACKEND` |
| Mutating operations, all callers combined | 120 per rolling 60 s | `E_BUSY` |
| Minimum interval between successful `restart`s | 10 s | `E_BUSY` |
| Concurrent `authenticate` children | 2 | `E_BUSY` |
| `authenticate` calls, all callers combined | 30 per rolling 60 s | `E_BUSY` |
| Consecutive `authenticate` failures per username | 5, then locked 300 s | `data.locked:true`, no `crypt()` run (§5.14) |
| Wall-clock deadline — `authenticate` (hashing runs in the connection child, not a `csf` child) | 10 s | `E_BACKEND` |

Rate-counter state is `/var/run/csf-ui/rate.state` and the per-username failure
counter is `/var/lib/csf-ui/helper/authfail.state` (§5.14). **Both files are
`0600 root:root`; the directories holding them are traversable** (`0755` and
`0700` respectively, §2.3) — a `0600` directory would wall off the socket and the
helper's own state (§13.2). The web tier cannot read or reset either counter. The
failure counter is on `/var/lib` rather than `/var/run` on purpose: a lockout that
a reboot clears is not a lockout.

The `authenticate` caps are CPU caps as much as security caps. `crypt()` at
`UI_CRYPT_ROUNDS` is deliberately slow, and after §5.14 it runs as root, so
without a ceiling the login form is a way to load the machine (§1.3).

These caps are not a rate limiter for users — that is `RateLimit.pm` in the web
tier, with different thresholds and a different purpose. These exist so that a
compromised web tier cannot turn the helper into a firewall-flapping engine or a
fork bomb.

---

## 8. Audit

Two logs, because the two halves know different things and neither can write the
other's file.

| Log | Written by | Mode | Records |
|---|---|---|---|
| `/var/log/csf-ui-audit.log` | `csf-ui-helper` (root) | `0640 root:root` | what was **executed** |
| `/var/log/csf-ui-access.log` | `csf-ui` (`csfui`) | `0640 csfui:csfui` | who **asked** |

Helper line — one JSON object per line, for every **mutating** operation, every
`authenticate` attempt whatever its outcome, and every rejected request:

```json
{"ts":1757548800,"id":"7b9f…","op":"deny","args":{"ip":"192.0.2.10","note":"abuse ticket 4471"},
 "peer":{"uid":998,"pid":31337},"ok":true,"error":null,"detail":"added"}
```

- `note` is truncated to 64 bytes in the log.
- **`pass` is never logged.** Not the value, not a truncation, not a hash of it,
  not its length. The helper's log line for `authenticate` carries `user`, the
  outcome (`ok` / `bad` / `locked`), the peer and the id — and `args` is written
  with `pass` **removed**, not blanked, so there is no field for a future change to
  start filling in. The same applies to the web tier's access log: a login POST is
  logged as a path and a status, never as a body (§4.10, G9).
- All strings pass §3.6 first, and JSON encoding escapes what remains: there is
  no way to write a newline or a terminal escape into this file through an
  argument. That is the whole point of rejecting control bytes twice.
- `peer.pid` is informational (§2.2).

Web line: `ts`, `id`, `user`, `role`, `source address`, `method`, `path`,
`status`. No token, no cookie, no password, ever (G9).

**The join is `id`, and an incident needs both files.** Neither alone answers
"who blocked 192.0.2.10": the helper knows what ran but cannot know the user
(§1.2, G8), and the access log knows the user but is written by the process most
likely to have been compromised. Correlate by request id, and read the pair with
that asymmetry in mind — an attacker who owns `csf-ui` can forge or truncate
`/var/log/csf-ui-access.log`; they cannot touch `/var/log/csf-ui-audit.log`,
because it is `0640 root:root` and they are not root. Say this in the operator
documentation rather than presenting the pair as one tamper-proof trail.

A worked example: `csf-ui-audit.log` shows `op:"authenticate"`, `user:"alice"`,
`ok:true`, id `7b9f…`, then `op:"allow"` with the same id family; the access log
shows which source address and session presented itself as alice for those ids. If
the second file is missing the entries, the first still proves an address was
allowed, and when — which is the half you cannot afford to lose.

---

## 9. What is deliberately absent

| Not on the list | Why |
|---|---|
| **File paths as arguments** | every path in this design is a constant in the helper. `which` selects a table row (§4.5); `reconcile_fix` names findings, not files. There is no argument a traversal could travel in |
| **Command strings, flags, or a "raw csf command" operation** | the moment one exists, the allowlist is the set of everything `csf` can do, and the review value of this document is zero |
| **Chain or table names as arguments** | `reconcile` is fixed to `DENYIN`/`DENYOUT` in `filter`. Otherwise `reconcile_fix` becomes "delete any iptables rule", including the ones that let you back in |
| **Config writes — `csf.conf`, `ui.conf`, `csf.*` files** | spec §6: setup writes an answers file and calls the CLI, so a failure in the web tier cannot corrupt `csf.conf`. Config editing was also the largest single screen in the old UI |
| **Log reads (`lfd.log`, `/var/log/messages`, `csf-ui-audit.log`)** | a log-read operation is a file-read operation with a filter argument, which is a file-read primitive with extra steps. Logs are read over SSH by someone who is already root |
| **Bulk flush: `csf -df`, `csf -tf`, `csf -f`** | one call empties the block list or stops the firewall. The screens have no need; an operator who does has a shell |
| **`csf -x` / `csf -e` (disable/enable)** | disabling the firewall from a web form, on a machine the form is protecting |
| **`csf -u` (update)** | downloads and installs code as root |
| **Cluster operations (`-cd`, `-cg`, `-ca`, …)** | one call reaches every machine in the cluster; the blast radius of a web-tier compromise stops being one host |
| **`csf -i` (iplookup)** | outbound DNS and geolocation lookups initiated by root, driven by an attacker-chosen argument. Excluding the operation is not sufficient on its own: `csf` reaches the same code from `-d`, `-a` and `-td` whenever the comment ends up empty (`csf.pl:1517`, `:1687`, `:4320`), so the contract requires a note on the first two and sends a fixed one on the third (§5.7) |
| **`lfd` control** | not needed by any of the five screens |
| **Temporary *allow* (`csf -ta`)** | exempting an address from the firewall, temporarily, with no record in `csf.allow`. If it is worth allowing, it is worth allowing visibly |
| **Direction and protocol on `tempdeny`** | `csf -td` parses `-p`/`-d` out of free text (§1.4); keeping them out of the grammar keeps that parser out of reach |
| **A `note` on `tempdeny`** | same reason |
| **`csf.ignore` — reading it, editing it, or a Lists tab for it** | **not an oversight; ruled out deliberately.** `csf.ignore` is `lfd`'s ignore list, not a firewall list. No operation here mutates it, so showing it would put a delete button on rows nothing can delete, and giving it its own read and removal operations would widen the allowlist for a tuning file that administrators already edit by hand over SSH. Spec §2's screen description is amended accordingly (§11.2). Before re-adding it, read this row |
| **Reading the password store — a `get_user` or "return the hash" operation** | `authenticate` (§5.14) returns a **verdict**, never a record. A hash that crosses the socket is a hash the web tier can lose. The store is `0600 root` and stays there |
| **A second, read-only socket** | §1.2 |
| **Any argument carrying a role, a username, or a source address** | the helper cannot verify them, so it does not accept them (G8) |

---

## 10. `ui.conf`

`/etc/csf-ui/ui.conf`, mode `0640 root:csfui`. Written by the installer (Task 9)
and the setup wizard (Task 8); read by `csf-ui` and `Server.pm` (Task 5). Root
writes; the web tier only reads.

**File grammar:** `#` comment lines, blank lines, and
`^\s*([A-Z][A-Z0-9_]*)\s*=\s*"([^"]*)"\s*$` — the same shape as `csf.conf`, so
nobody has to learn a second format. It is **parsed, never evaluated**.

| Key | Type | Default | Validation | Refuses to start when |
|---|---|---|---|---|
| `UI_MODE` | enum `a` \| `b` | *(none)* | exactly `a` or `b`, lowercase | missing, or any other value. Absent means the UI was never configured, which is not the same as mode A |
| `UI_LISTEN` | IPv4/IPv6 **address literal** | `127.0.0.1` | `Socket::inet_pton`; a literal only, never a hostname — no DNS at startup (G3) | mode B and the value is unparsable; **mode A and it is present** (in mode A `csf-ui` listens on a unix socket and a listen address means the config contradicts itself) |
| `UI_PORT` | integer | `8443` | `1024 … 65535`, **in both modes** | out of range, in either mode. In mode B it is the port `csf-ui` binds; in mode A `csf-ui` binds nothing and the value is the port Task 9 renders into the front-server template — it still has to be right, and it is still the answer to "where is the UI". Below 1024 is rejected at config time rather than failing to bind at runtime: `csf-ui` runs as `csfui` and can never bind one, and a front server that already binds 443 does not need this key |
| `UI_ALLOW` | comma-separated list of addresses/CIDRs | *(empty)* | 1–64 entries, each per §4.1 (prefix floor does **not** apply; `/0` still rejected); no spaces except around commas | **empty or missing, in both modes** |
| `UI_CRYPT_ROUNDS` | integer | `100000` | `5000 … 2000000` | out of range. It is the `$6$` round count used when a **new** hash is made; existing records carry their own, so lowering it never weakens a hash already stored |
| `UI_SESSION_IDLE` | integer seconds | `1800` | `60 … 86400`, and `<= UI_SESSION_MAX` | out of range or greater than `UI_SESSION_MAX` |
| `UI_SESSION_MAX` | integer seconds | `43200` | `300 … 604800`, and `>= UI_SESSION_IDLE` | out of range |

Rules that bind both readers and writers:

- **An unknown key is a startup failure**, naming the key. A typo'd `UI_ALOW`
  would otherwise silently mean "no allowlist" — and `UI_ALLOW` empty is itself a
  refusal to start, so the typo must not be able to hide. Adding a key means
  amending this table first.
- **A duplicate key is a startup failure.** Last-one-wins is how a reviewer and a
  program come to different conclusions about the same file.
- **`UI_CRYPT_ROUNDS`'s ceiling is set by `authenticate`'s deadline, not by
  taste.** `$6$` at 100,000 rounds costs roughly 0.1 s on 2026 hardware, so
  2,000,000 is of the order of 1–2 s — comfortably inside the 10 s deadline in §7,
  with room for slower machines. A larger value would be legal configuration that
  makes every login burn root CPU and then return `E_BACKEND`, which is a
  self-inflicted lockout with no diagnostic. `csf-ui-passwd` refuses to create a
  hash outside the same range, so the file and the config cannot disagree.
- **`UI_ALLOW` in mode A** is not enforced by `csf-ui` — in mode A `csf-ui`
  listens on a unix socket and the peer address it sees is the front web server.
  It does **not** trust `X-Forwarded-For` for access control; that header is
  recorded in the web log, annotated as untrusted, and used for nothing else. In
  mode A the value is what Task 9 renders into the nginx/Apache/LiteSpeed
  template, and it must still be non-empty so that no template is ever generated
  wide open.
- Defaults apply **only** to keys that are absent. An empty string is a value,
  and for `UI_ALLOW` it is the value that refuses to start.

**Where this file lives, and why not in `/etc/csf`.** `lfd` resets `/etc/csf` to
`0600` on every pass of its main loop, so a `ui.conf` under that tree would become
unreadable to `csfui` within seconds of the installer setting it — permanently, and
with the reset written to the log each time. Hence `/etc/csf-ui/`. §13 is the
measurement and the full reasoning; §2.3 is the frozen layout.

---

## 11. Where this contract departs from the plan, and why

Each of these is a change to a document that was written before the details were
known. They are listed rather than quietly implemented.

### 11.1 A 14th operation, `authenticate` — the users file stays `0600 root`

G7 gives `/etc/csf-ui/users` mode `0600 root`, and Task 4's login handler runs as
`csfui`. Taken together those cannot both hold: with `0600 root` the web tier
cannot read the store, and nobody can ever log in.

Two ways out. Relax the mode to `0640 root:csfui` and let the web tier read the
hashes, or add an operation and let it ask. **The ruling is the operation**, and
it is the right one: the split exists so that taking over the web tier yields as
little as possible, and a copy of every password hash — offline-crackable at
leisure, for every account including the ones that never log in — is not "as little
as possible". The operation does not make credentials safe in a compromised web
tier, and §5.14 says so plainly: passwords typed during the compromise are read in
cleartext on their way through. It removes the bulk-offline attack on the store,
which is the part that outlives the intrusion. So the allowlist is **fourteen** operations, `authenticate` is §5.14,
and the store stays `0600 root:root`, opened by the helper and by
`csf-ui-passwd` and by nothing else.

What that costs, recorded so nobody has to rediscover it:

- **`crypt()` now runs as root.** Verifying a password is deliberately expensive,
  and that expense has moved into the privileged process. §7 caps `authenticate`
  at 2 concurrent and 30 per minute, and §5.14's lockout skips hashing entirely
  for a locked username, so the login form cannot be used to load the machine.
- **The helper is an authentication oracle**, bounded at 5 guesses per username
  per 5 minutes by a counter it keeps itself (§5.14) — deliberately not the web
  tier's rate limiter, which is useless precisely when the web tier is the
  attacker.
- **Task 3's `Auth.pm` is consumed by the helper, not by `csf-ui`.** That moves
  `crypt()` and the constant-time compare inside the root process and
  adds to the helper's line count; the "~200 lines" figure in the plan should be
  read as a goal for the dispatch and validation core, not a budget the auth path
  must fit inside.

**This changes Task 3 (writes the store, and its verify() is now called by the
helper), Task 4 (calls `authenticate` instead of reading the store) and Task 9
(installs the store `0600 root` — see §13).** It amends G7 only by making the
mode achievable rather than contradictory.

### 11.2 The Lists screen shows `csf.allow`, not `csf.ignore` — spec §2 amended

Spec §2 describes the Lists screen as "`csf.deny`, temp bans, `csf.ignore`". The
frozen operations `allow`/`unallow` run `csf -a`/`csf -ar`, which write
`csf.allow`; `csf.ignore` is `lfd`'s ignore list and no operation on this list
touches it.

**Ruled: `csf.ignore` is out of scope, and `which` stays `deny|temp|allow`.**
Giving the ignore file its own read and removal operations would widen the
allowlist — the one thing this whole design is arranged to prevent — for a tuning
file administrators already edit by hand on a machine they have root on. This
**amends spec §2**: the Lists screen shows `csf.deny`, temp bans and `csf.allow`.

§9 carries the same decision in the "deliberately absent" table, with the reason,
so that a later reader who notices the gap finds a decision rather than what looks
like an omission.

### 11.3 Additions to the argument grammars

Three rules are stricter than the brief's text. Each fails closed and each is
justified by something verified in this tree (§1.4):

| Addition | Applies to | Reason |
|---|---|---|
| `note` also rejects `\|` and option-looking text | §4.4 | the temp-ban store is pipe-delimited; `csf` re-splits its joined argument string and scans comments for `-p`/`-d` |
| `ip` rejects `/0`, rejects host bits set, and has a `/8`(v4) / `/32`(v6) floor for mutating operations | §4.1 | `checkip` accepts `/0` (`ConfigServer/CheckIP.pm:60`), and self-lockout is the plan's own top risk |
| `ports` ranges are expanded and the expansion is capped at 20 ports | §4.3 | `csf -td`'s port regex accepts neither `-` nor `:`, so a range passed through is silently truncated to its lower bound |

### 11.4 `temprm` uses `csf -trd`, not `csf -tr`

`-tr` removes from the temporary ban list *and* the temporary allow list. The
screen shows only bans. §5.8.

### 11.5 Two audit logs, not one — confirmed

Spec §7 describes one audit log containing both the user and the action. The
process that knows the user cannot write root's log, and the process that executes
the action cannot know the user (G8). One shared file would mean one side writing
where the other can tamper, which is worse than two honest files.

**Ruled: keep both.** `/var/log/csf-ui-audit.log` (root, written by the helper,
what actually ran) and `/var/log/csf-ui-access.log` (`csfui`, written by the web
tier, who asked for it), joined by request id. Correlating an incident needs both,
and §8 says which half survives a compromise of the other.

### 11.6 Every UI path moves out of the csf trees — G7 replaced

G7 places the UI under `/usr/local/csf/bin`, `/etc/csf/ui` and (by implication)
`/var/lib/csf`. None of those can work: `lfd` resets `/etc/csf`, `/var/lib/csf` and
`/usr/local/csf` to `0600` on every pass of `while (1)` (`lfd.pl:1173`,
`lfd.pl:1187-1201`), so `csfui` can traverse none of them, and a `0600`
`/usr/local/csf` also means systemd cannot `exec` a binary from there after
dropping to `csfui`.

**Ruled: the UI lives in sibling trees** — `/usr/local/csf-ui/`, `/etc/csf-ui/`,
`/var/lib/csf-ui/`, with the socket already under `/var/run/csf-ui/` and the logs
already in `/var/log/`. §2.3 is the frozen layout and **replaces G7's table**.
`lfd`'s hardening is not touched: it is correct, and the alternative — patching
`lfd.pl` to carve out a subtree and relaxing `/etc/csf` to `0711` — would weaken a
years-old control in the daemon this project exists to keep trustworthy, and would
have to be re-applied to every future csf release (§13.4).

**This changes Tasks 2, 3, 4, 5, 8 and 9**, all of which name paths.

### 11.7 The Perl floor is 5.14, not 5.10 — G1 amended

G1 says "Perl 5.10-compatible". `Socket::inet_pton`, `Socket::inet_ntop` and
`SO_PEERCRED` — which §2.1 and §4.1 require and forbid working around — entered
core `Socket` at **1.94**, first bundled with **Perl 5.14**. Perl 5.10 ships Socket
1.82 and has none of them, and CSF's own code carries the scars of that era
(`ConfigServer/LookUpIP.pm:114` does `eval('use Socket6;')` right before calling
`inet_pton`).

**Ruled: the floor is Perl ≥ 5.14 with Socket ≥ 1.94**, checked by version at
helper startup (§2.1) **and** at install time by Task 9, so the failure is a clear
message during installation rather than a UI that will not start. The behaviour was
already fail-closed; what was missing was saying so. A regex fallback for address
parsing remains forbidden — that is not a compatibility measure, it is a way to
accept addresses `inet_pton` would reject.

### 11.8 One password hash algorithm — the Argon2id branch is dropped

The plan offers "Argon2id used instead when `Crypt::Argon2` is present"
(`docs/WEBUI-PLAN.md:178`). `Crypt::Argon2` is not core and is not vendored here —
`Crypt/` contains `Blowfish_PP.pm` and `CBC.pm` — so under G1 it cannot be a
dependency, and an optional branch nobody can exercise advertises a strength the
deployment does not have.

**Ruled: `$6$` SHA-512 `crypt()` is the only implemented algorithm.** The record
keeps its `algo` field so a later migration has somewhere to go; `6` is the
only value this contract accepts, `UI_CRYPT_ROUNDS` (§10) is its cost, and a record
carrying any other `algo` is answered `E_UNAVAILABLE` **without** touching the
failure counter (§5.14) — a store the helper cannot read must not lock out the
administrator who would fix it.

**This changes Task 3**, whose brief names Argon2id.

### 11.9 Three amendments made while Task 2 implemented this document

Recorded here because the rest of §11 is departures from the *plan*, and these
are changes to *this document* — each found by writing the code the document
describes, and each ruled on before it was implemented.

| Amendment | Section | Why it was needed |
|---|---|---|
| `::` and `::1` are accepted by `undeny`, `unallow`, `temprm` and by file parsing | §4.1, §5.4 | the IPv4-mapped rule as written also catches them, which made an entry `csf -d ::1` can create unreadable and unremovable through the UI |
| An unparsable scoped rule is `kind:"ORPHAN"`, and a repeated rule spec is one `DUP` finding | §5.11 | the document said what to report but not under which kind, and content-addressed ids collide for identical copies. Two tasks reading the gap would have filled it two different ways |
| Every response write carries a 5 s deadline | §7 | a peer that opens a connection and never reads must not be able to stall the accept loop of a root daemon, however unlikely filling a socket buffer with a few hundred bytes is |

Two things reviewed at the same time were **left exactly as they are**, and are
written down so that a later reader does not "simplify" them back:

- **Bytes after the first newline are detected within one read.** §3.1 makes them
  `E_PROTOCOL`, and a single read window catches every pipelined sender. A line
  that arrives after the response cannot be acted on, because the connection is
  closed — so a second read with its own timeout would buy nothing.
- **A trailing `\r` is rejected explicitly, not by the JSON parser.** §3.1 states
  the outcome, and the vendored `JSON::Tiny` happens to treat `\r` as trailing
  whitespace and would accept it. What binds is the stated behaviour, so the
  helper refuses the line itself. Deleting that check on the grounds that "the
  parser handles it" would silently re-open the case.

---

## 12. Checklist for the tasks that implement this

| Task | Owes this document |
|---|---|
| 2 — helper | §2 startup preconditions (including the Perl/Socket floor) and peer check, §3 framing and codes, §4 validators, §5 all 14 operations, §5.7's fixed `csf-ui` note, §5.14 failure counter, §7 limits, §8 helper log, §2.3 paths |
| 3 — auth store | `/etc/csf-ui/users` `0600 root:root` (§2.3); `verify()` is called **by the helper**, not by `csf-ui` (§11.1); `$6$` only, `algo` field retained (§11.8); `UI_CRYPT_ROUNDS` range from §10; the dummy-`crypt()` path for unknown usernames (§5.14) |
| 4 — `csf-ui` core | §3 client side, §5 role mapping, **login calls `authenticate` and never opens the users file** (§5.14), §8 access log, error→HTTP table in §3.5 |
| 5 — HTTP/TLS core | §10 keys `UI_MODE`, `UI_LISTEN`, `UI_PORT`, `UI_ALLOW` and their refusals; `ui.conf` is at `/etc/csf-ui/ui.conf` (§2.3) |
| 7 — screens | §5 mutating column (CSRF + role), §5.12 diff and second confirmation, §5.1's "cannot determine firewall state" case |
| 8 — setup wizard | §10 — it writes `ui.conf` too, with these key names and these refusals |
| 9 — installer | **§2.3 is the path layout and §13 is why**; creates `csfui`, the socket directory and the three `csf-ui` trees; writes every §10 key with these names; checks the Perl/Socket floor at install time (§11.7); the two post-install assertions in §13.5 |
| 10 — fuzzing | §6 is the test table: every row is a case |

---

## 13. Deployment constraint: the UI lives outside every csf-managed tree

This is not a design preference. It is the only arrangement that survives contact
with the software already on the machine, and it was found by measurement.

### 13.1 What the installers do

Every installer re-permissions the csf trees near its end:

| Installer | `chmod -R 600 /etc/csf` | `chmod -R 600 /var/lib/csf` |
|---|---|---|
| `install.cpanel.sh` | 424 | 425 |
| `install.cwp.sh` | 450 | 451 |
| `install.cyberpanel.sh` | 427 | 428 |
| `install.directadmin.sh` | 412 | 413 |
| `install.generic.sh` | 430 | 431 |
| `install.interworx.sh` | 431 | 432 |
| `install.vesta.sh` | 430 | 431 |

`-R` sweeps the directories too, the top of each tree included.

### 13.2 What a `0600` directory does

A directory at mode `0600` has no execute bit, and without it the path through it
cannot be walked — by anyone subject to discretionary access control, *including
the directory's own owner*. Reproduced here as an unprivileged user (uid 1000):

```
$ mkdir -p d/ui && echo 'UI_MODE = "b"' > d/ui/ui.conf && chmod 600 d/ui
$ ls -ld d/ui
drw------- 2 coder coder 4096 … d/ui
$ cat d/ui/ui.conf
cat: d/ui/ui.conf: Permission denied        # EACCES — the file's own mode is irrelevant
$ chmod 750 d/ui && cat d/ui/ui.conf
UI_MODE = "b"
```

Root holds `CAP_DAC_OVERRIDE` and walks through such a directory without
complaint, which is why nothing has ever noticed: the installer, `csf` and `lfd`
all run as root. `csfui` is the only account that would ever be stopped, and it
does not exist yet.

### 13.3 Why fixing the installers is not enough — `lfd` re-applies it forever

The install-time sweep is the smaller half. `lfd` **enforces** `0600` on those
trees continuously. `lfd.pl:1173` is `while (1) {`, and inside that loop, at
`lfd.pl:1187-1201`:

```perl
my $perms = sprintf "%04o", (stat("/etc/csf"))[2] & oct("07777");
if ($perms != "0600") {
        chmod (0600,"/etc/csf");
        logfile("*Permissions* on /etc/csf reset to 0600 [currently: $perms]");
}
$perms = sprintf "%04o", (stat("/var/lib/csf"))[2] & oct("07777");
if ($perms != "0600") { … "/var/lib/csf" … }
$perms = sprintf "%04o", (stat("/usr/local/csf"))[2] & oct("07777");
if ($perms != "0600") { … "/usr/local/csf" … }
```

Three trees, every pass of the main loop, with each reset written to the log.
Anything an installer sets is undone within seconds and stays undone. This cannot
be ordered around by Task 9, because it is not an ordering problem: it is a root
daemon actively restoring a mode we would need it not to.

`/usr/local/csf` being on that list matters too. systemd drops credentials
**before** `exec`, so a unit running as `csfui` could not execute a binary under a
`0600` directory — the WebUI could not start at all from there.

### 13.4 The constraint

**No part of the WebUI — binary, library, configuration, state or log — may live
under `/etc/csf`, `/var/lib/csf` or `/usr/local/csf`.** Those trees belong to `csf`
and `lfd`, whose hardening is correct and stays exactly as it is. The UI uses
sibling paths, frozen in §2.3, and touches the csf trees only by *reading* the
files `csf` owns (`csf.deny`, `csf.allow`, `csf.tempban`, `csf.tempallow`,
`csf.conf`) — as root, in the helper, where `0600` is no obstacle.

Rejected alternative, recorded so it is not revisited: patching `lfd.pl` to exempt
a `ui` subtree and relaxing `/etc/csf` to `0711`. It weakens a control that has
been in place for years, in the daemon this project exists to keep trustworthy,
to save a path rename — and every future csf release would have to carry the
patch.

### 13.5 Requirement on Task 9

Create the paths in §2.3 with the modes given there. They are outside the swept
trees, so no ordering relative to `chmod -R 600` is needed and none should be
introduced. Two assertions belong in the installer tests, because both failures are
silent:

1. after a full install **and one minute of `lfd` running**, `sudo -u csfui test -r
   /etc/csf-ui/ui.conf` succeeds — this catches any future drift back under a
   managed tree;
2. `/etc/csf`, `/var/lib/csf` and `/usr/local/csf` are still `0600` — the UI's
   install must not have weakened csf's own hardening anywhere.

---

*Added 2026-09-11 in https://github.com/nkyo/csf — see CHANGES.md. Part of
ConfigServer Security & Firewall, Copyright (C) 2006-2025 Jonathan Michaelson,
released under GPLv3.*
