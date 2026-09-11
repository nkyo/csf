# Changes in this repository

Modifications made in **[nkyo/csf](https://github.com/nkyo/csf)** relative to the
base it was imported from.

This file exists to satisfy **GPLv3 §5(a)** — a modified work must carry prominent
notices stating that it was changed, and the date of each change. Git history is
convenient but is not a substitute for this file.

## Base

```
ConfigServer Security & Firewall v15.00
Copyright (C) 2006-2025 Jonathan Michaelson
Released under GPLv3 by its author, August 2025

csf.tgz   sha256 99ef3f6e63c0f8b4509b1e72...   2,297,087 bytes
```

Imported unmodified as the first commit of this repository. The archive was
verified byte-for-byte identical from two independent sources, since the original
repository no longer exists:

1. `github.com/centminmod/configserver-scripts` — a fork of the original
   `waytotheweb/scripts`, preserving the unaltered `.tgz` files
2. `github.com/Black-HOST/csf` commit `2923c43` "GPL v3 Release" (2025-08-28) —
   that project's own import of the same archive

No code from any downstream fork is included in this repository.

## Rule

**Copyright notices are never removed or replaced.** Where a file is modified, a
line is added below the original notice; the original stays intact.

## Modifications

### Unreleased

#### Replacing the WebUI — the privilege boundary, written down before any code

- **2026-09-11** — Added `docs/WEBUI-RPC.md`: the threat model and the frozen RPC
  contract between the unprivileged web tier and the root helper that will replace
  the built-in WebUI. It fixes, before anything is implemented, the thirteen
  operations the root helper will ever perform, the grammar and limits of every
  argument, the wire format and its ten error codes, the peer-credential check on
  the socket, and the `ui.conf` keys. Nothing in it changes behaviour yet; its
  purpose is that the privileged surface is decided once, in one reviewable place,
  rather than growing one call at a time as screens are written.

  It also records what the split does **not** buy, because the alternative is a
  boundary people rely on that is not there: there is one web process, so the
  operating-system boundary is unprivileged-vs-root, not admin-vs-support. The
  `support` role is enforced inside the web tier, and anyone who takes over that
  tier reaches every one of the thirteen operations whatever role their session
  carries. (`docs/WEBUI-RPC.md` — new file)

- **2026-09-11** — Amended the same day, on review, before anything was built on
  it. The allowlist is **fourteen** operations, not thirteen: `authenticate` was
  added so that the web tier never opens the password file. `/etc/csf/ui/users`
  stays `0600 root` and the web tier asks the root helper to check a guess instead
  of reading the hashes itself, so taking over the unprivileged half yields no
  hashes to crack offline or replay elsewhere — only an oracle the helper limits
  to five guesses per username per five minutes, with its own counter that the web
  tier cannot reach or reset. Password verification therefore now runs as root, so
  those limits are also what stops the login form being used to spend the
  machine's CPU.

  Recorded at the same time: `csf.ignore` is deliberately not reachable from the
  UI, with the reason, so it is not mistaken later for an oversight; and a
  deployment constraint measured rather than assumed — every installer runs
  `chmod -R 600 /etc/csf` and `chmod -R 600 /var/lib/csf`, and a directory at mode
  `0600` has no execute bit, so it cannot be traversed at all. Root passes through
  it regardless, which is why nothing has ever noticed; the unprivileged UI account
  would not. The exact modes and the ordering the installers must follow are now
  part of the document. (`docs/WEBUI-RPC.md`)

- **2026-09-11** — Reviewed, and two things in it were wrong. **The WebUI now
  lives outside every csf-managed tree** — `/usr/local/csf-ui/`, `/etc/csf-ui/`,
  `/var/lib/csf-ui/` — because `lfd` resets `/etc/csf`, `/var/lib/csf` and
  `/usr/local/csf` to mode `0600` on **every pass of its main loop**
  (`lfd.pl:1173`, `lfd.pl:1187-1201`), logging each reset. A directory at `0600`
  has no execute bit and cannot be entered at all, so an unprivileged UI account
  could never read its own configuration, and systemd could not even execute a
  binary stored there. That enforcement is correct and stays exactly as it is; the
  UI moves instead.

  **Temporarily blocking an address no longer makes root look it up in DNS.**
  `csf -td` with an empty comment falls into `iplookup()` (`csf.pl:4320`), which
  with the shipped default `LF_LOOKUPS = "1"` runs `host` against the address as
  root (`ConfigServer/LookUpIP.pm:87`) — so every temporary block would have sent a
  query to a nameserver chosen by whoever requested the block. The contract now
  sends a fixed note on that call, and requires one on the permanent-block and
  allow calls, so no path reaches that branch.

  Also corrected: the minimum supported Perl is **5.14** (Socket 1.94), because
  `inet_pton` and `SO_PEERCRED` do not exist before it; the optional Argon2id hash
  branch is dropped, since the module is neither core nor vendored and a branch
  that cannot run implies a strength that is not there; and the security claim
  about password hashing now says what it actually buys — an attacker holding the
  web tier cannot take the hash file away and attack every account offline, but
  does read the password of anyone who logs in while they are there.
  (`docs/WEBUI-RPC.md`)

- **2026-09-11** — Added `csf-ui-helper`, the privileged half of the replacement
  WebUI and the only part of it that will run as root, together with the wire
  format and argument grammars both halves share. It listens on one unix socket,
  authenticates its peer with `SO_PEERCRED` rather than believing anything a
  message says about who is calling, and serves exactly the fourteen operations
  frozen in `docs/WEBUI-RPC.md`. No argument names a file, a command, a flag or a
  chain: `which` selects a row in a table, `reconcile_fix` names findings the
  helper itself just made, and every other path and program is a constant in the
  source. That is what makes the privileged surface reviewable, which the 5,071
  line WebUI it replaces was not.

  Three things in it are worth knowing about before reading the code. **csf exits
  0 after refusing an operation** (`csf.pl:1541-1551`), so no mutating operation
  decides its outcome from an exit status: each one snapshots the store, runs
  `csf`, re-reads the store and reports the delta. **Every child is exec'd with
  an argv list** through the block form, which cannot reach a shell even for a
  one-element list — there is no backquote, no `qx` and no piped open in either
  file, and the tests assert that about the source rather than trusting it.
  **`tempdeny` always sends the fixed note `csf-ui`**, because an empty comment
  sends `csf` into `iplookup` (`csf.pl:4320`), which runs `host -W 5 <ip>` as
  root against an address the caller chose.

  Everything fails closed. The helper refuses to start — naming each failure —
  if it is not root, if Perl is older than 5.14 or `Socket` older than 1.94, if
  the socket directory is not root-owned, or if `csf` or `iptables` is not a
  root-owned regular file. When the `csfui` group does not exist yet the socket
  is created `0600 root:root` and every connection is answered `E_UNAVAILABLE`;
  there is no permissive fallback. Root is refused at the door as well: if root
  wants to run `csf`, root runs `csf`.

  `authenticate` is implemented except for the credential check itself, which is
  the next task. Argument validation, the per-username failure counter (5 tries,
  then locked for 300 s, with hashing skipped entirely while locked), the store's
  own preconditions, the audit behaviour and the response shape are all here; the
  verifier is called through a module interface that currently answers
  `E_UNAVAILABLE` and **does not touch the failure counter**, because a store the
  helper cannot verify must not lock out the administrator who would fix it.
  (`ui-src/bin/csf-ui-helper`, `ui-src/lib/ConfigServer/UI/Proto.pm`,
  `t/10-proto.t`, `t/11-helper-validate.t` — new files)

- **2026-09-11** — Three amendments to the frozen contract, found by implementing
  it and ruled on before the code changed. **`::` and `::1` are now accepted by
  `undeny`, `unallow` and `temprm`**, and when reading entries back out of the
  files `csf` wrote: the IPv4-mapped rule as written also caught them, so an
  entry `csf -d ::1` creates from a shell was invisible to the Lists screen and
  impossible to remove — leaving the UI unable to undo the most self-inflicted
  block there is. Adding them is still refused, and every genuine mapped or
  compatible form stays refused everywhere. **An `iptables -S` rule that does not
  tokenise is reported as `ORPHAN` with `fixable:false`**, and **a rule spec
  loaded more than once is one `DUP` finding**, because content-addressed ids
  would otherwise collide into a duplicate that `reconcile_fix` must reject. Both
  were gaps the document left open; two later tasks would have filled them two
  different ways. **Every response write now carries a five second deadline**, so
  that a peer which opens a connection and never reads cannot stall the accept
  loop of a root daemon. (`docs/WEBUI-RPC.md`, `ui-src/bin/csf-ui-helper`,
  `ui-src/lib/ConfigServer/UI/Proto.pm`, `t/10-proto.t`,
  `t/11-helper-validate.t`)

#### The update mechanism — moved to GitHub, and made verifiable

The original update path fetched a tarball and ran `sh install.sh` from it **as
root, with no integrity check of any kind**. It has been rebuilt to fetch from
this repository and to refuse anything it cannot verify.

- **2026-08-14** — Update channel moved to GitHub. Version checks read
  `raw.githubusercontent.com/nkyo/csf/main/version.txt`; upgrades download
  `csf.tgz` and `csf.tgz.asc` from the GitHub release matching that version.
  The previous host, `download.configserver.com`, stopped resolving when the
  original project closed on 2025-08-31.
  (`ConfigServer/Release.pm` — new file, `csf.pl`, `ConfigServer/DisplayUI.pm`)

- **2026-08-14** — **Upgrades now require a valid GPG signature.** The package
  is verified against a release key that ships with the source, in a throwaway
  keyring so root's own keyring is neither read nor written, and the signing
  key's fingerprint is **pinned in code** — a good signature from some other key
  is rejected. If gpg is missing, if the key is missing, if the fingerprint does
  not match: no upgrade. (`ConfigServer/Release.pm`, `csf.pl`)

- **2026-08-14** — **Removed the silent downgrade to plain HTTP.** With
  `URLGET = "1"` (HTTP::Tiny) both the version check and the package download
  rewrote `https://` to `http://`, because HTTP::Tiny cannot do TLS without
  `IO::Socket::SSL`. On a server missing that module, the update path fetched
  root-privileged code over an unencrypted connection. It now refuses to
  upgrade and says what to install. (`csf.pl`, `ConfigServer/DisplayUI.pm`)

- **2026-08-14** — **Removed `-k` (`--insecure`) from every curl invocation.**
  `csget.pl` used `curl -skLf` and `ConfigServer/URLGet.pm` used `-skLf`/`-kLf`,
  which accept *any* certificate — including one an attacker on the path
  presents. This affected every `https://` fetch csf makes, not only upgrades.
  (`csget.pl`, `ConfigServer/URLGet.pm`)

- **2026-08-14** — Fixed a guard that never guarded. The upgrade downloaded to
  `/usr/src/csf.tgz` but tested `/usr/src/csf/csf.tgz` — a different path. In
  Perl `! -z` on a missing file is true, so a failed or partial download still
  reached `tar -xzf` and `sh install.sh`. Downloads are now checked for the file
  they actually wrote, and unpacking must produce `install.sh` before anything
  runs. (`csf.pl`)

- **2026-08-14** — `AUTO_UPDATES` now defaults to `"0"` in all seven shipped
  configs. It was `"1"`: a fresh install silently enabled automatic root-level
  upgrades. It stays off until a signed release exists to verify against.

- **2026-08-14** — `csget.pl` now looks up only csf. It also polled for cxs,
  cmm, cse, cmq, cmc, osm and msfe — ConfigServer products with no server left
  to answer. It also now discards a response that is not a version number,
  rather than storing an error page and showing it in the UI as "the latest
  version".

- **2026-08-14** — Added `tools/setup-signing-key.sh` and `tools/release.sh`.
  Releases are built with `git archive` from the tag and gzipped with `-n`, so
  the tarball is **reproducible**: anyone can rebuild it from the tag and get a
  byte-identical file, then check that against the published signature.

#### The WebUI shipped a private key that everyone had

- **2026-09-11** — **Removed `ui/server.key` and `ui/server.crt` from the source.**
  Up to and including v15.00 a working private key was shipped inside the
  tarball, and every installer copied the whole `ui/` directory to `/etc/csf/ui/`
  (`install.generic.sh:305`), which is exactly where `lfd.pl:9466` reads
  `SSL_key_file` from. Every server with `UI = "1"` therefore served https with
  a key that anyone who downloaded csf already had, so that traffic could be read
  or altered by anyone positioned to see it. The certificate had also expired on
  **2020-07-17**, which trained administrators to click past the browser warning
  — the same warning a real interception would raise.

  Verified present with the same key in Black-HOST v15.03 as well, so this
  affected the wider fork ecosystem, not one distribution of it.

  Mitigating factor: `UI` ships as `"0"`, so only installations that deliberately
  enabled the built-in WebUI were exposed.

- **2026-09-11** — Added `ui-cert.sh`, installed as
  `/usr/local/csf/bin/csf-ui-cert.sh`. It generates a 2048-bit RSA certificate
  for the host it runs on, with the hostname and local addresses in
  `subjectAltName` (browsers ignore CN), key mode `0600`, valid ten years. It
  regenerates when the certificate is missing, expired, mismatched with its key,
  or **is the leaked one** — recognised by SHA-256 fingerprint
  `2EAB8C4A…119BB29A` — and is otherwise silent, so re-running it is safe.
  `sh /usr/local/csf/bin/csf-ui-cert.sh --force` rotates on demand.

  All seven installers call it **unconditionally**, not only on a fresh install,
  so a server upgrading from an affected version stops using the public key as
  part of the upgrade. If openssl is absent it says so and leaves the install
  alone rather than failing.

#### Dead links and advice for software that no longer exists

- **2026-08-14** — `ConfigServer/DisplayUI.pm`: removed three promotional panels
  offering cxs, osm and msfe. All three were discontinued with the company on
  2025-08-31 and the pages they linked to are gone, so the UI was advertising
  software nobody can obtain.

- **2026-08-14** — `ConfigServer/ServerCheck.pm`: removed the two server-check
  rows recommending the purchase of cxs and osm, for the same reason. Reworked
  the `AUTO_UPDATES` advice: it linked to a blog that no longer resolves, and it
  told administrators to enable a setting that does nothing on an installation
  where release signing is not configured — `csf -u` refuses to install an
  unverifiable package. The check now reports that state instead.

- **2026-08-14** — `lfd.pl`: only rewrite blocklist URLs when a mirror is
  actually configured. `DOWNLOADSERVER` comes from `/etc/csf/downloadservers`,
  whose entries ConfigServer had already commented out in v15.00, so it is
  normally empty — and substituting an empty host turned a URL into
  `https:///path`, failing in a way that looks like a network fault rather than
  a configuration one.

> Copyright notices that link to `configserver.com` are **left exactly as they
> are**, dead link and all. They are attribution, not advertising, and GPLv3
> §5(c) requires keeping them.

#### Documentation

- **2026-08-14** — `install.txt`: replaced the documented install command, which
  fetched from the host that no longer resolves. Now clones this repository.
- **2026-08-14** — Added `README.md` and this file. No functional change.

## Known issues inherited from v15.00

- **`ConfigServer::Config::getdownloadserver` returns nothing.** It reads
  `/etc/csf/downloadservers`, whose two entries ConfigServer commented out before
  release, so `DOWNLOADSERVER` is undefined. Nothing depends on it any more —
  its last consumer, the blocklist rewrite in `lfd.pl`, now checks before using
  it — so it is left in place rather than removed, in case anyone points it at a
  mirror of their own.

<!--
Format for entries:

- **YYYY-MM-DD** — <what changed, and why> (`path/to/file`)

Newest first. Every functional change belongs here.
-->
