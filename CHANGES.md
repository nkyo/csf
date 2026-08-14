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

- **2026-08-14** — `install.txt`: replaced the documented install command. It
  fetched `https://download.configserver.com/csf.tgz`, a host that shut down with
  the original project on 2025-08-31, so the documented install could not work.
  Now clones this repository instead.
- **2026-08-14** — Added `README.md` and this file. No functional change.

## Known issues inherited from v15.00

- **Dead `configserver.com` endpoints throughout the tree.** 19 files still point
  at hosts that no longer resolve — including `csget.pl` (the downloader),
  `csf.conf` defaults, `ConfigServer/Config.pm`, `ConfigServer/ServerCheck.pm`
  and `ConfigServer/DisplayUI.pm`. This affects the update check, the RBL/server
  security check and parts of the UI. Only `install.txt` has been corrected so
  far; the rest needs deciding on a replacement update channel before it is
  touched, since it changes behaviour in a firewall.
  Meanwhile, keep `AUTO_UPDATES = "0"` in `csf.conf`.

<!--
Format for entries:

- **YYYY-MM-DD** — <what changed, and why> (`path/to/file`)

Newest first. Every functional change belongs here.
-->
