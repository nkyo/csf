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
