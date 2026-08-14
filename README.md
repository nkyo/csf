# ConfigServer Security & Firewall (CSF)

A Stateful Packet Inspection (SPI) firewall, login/intrusion detection and
security application for Linux servers.

> [!IMPORTANT]
> **This is a modified version of CSF, maintained by [@nkyo](https://github.com/nkyo).**
> It is an independent continuation — not affiliated with, nor endorsed by, the
> original authors.
>
> Copyright in the CSF source belongs to **Jonathan Michaelson**. This project
> adds to his notices; it never removes or replaces them. Every change made here
> is listed with a date in [CHANGES.md](CHANGES.md), as GPLv3 §5(a) requires.

## Where this comes from

ConfigServer / Way to the Web Ltd. shut down on **31 August 2025** after ~20
years, and relicensed the final release — **CSF v15.00** — under the GPLv3. Their
repository at `github.com/waytotheweb/scripts` is gone, and
`download.configserver.com` no longer resolves.

This repository starts from that v15.00 release, imported unmodified as its first
commit. The archive was verified byte-for-byte from two independent mirrors:

```
csf.tgz   sha256 99ef3f6e63c0f8b4509b1e72...   2,297,087 bytes
```

Everything after the first commit is a modification, and is listed in
[CHANGES.md](CHANGES.md).

## Install

```bash
git clone https://github.com/nkyo/csf.git
cd csf
sh install.sh
```

The installer detects the control panel in use (cPanel, DirectAdmin, CyberPanel,
CWP, InterWorx, VestaCP) and falls back to a generic install otherwise.

Requires `perl`, `iptables`, and root. **`firewalld` must be stopped and disabled**
— CSF refuses to start alongside it.

To remove:

```bash
sh uninstall.sh
```

## Documentation

The upstream manual ships with the source and is still accurate:

| File | Contents |
|---|---|
| [readme.txt](readme.txt) | full manual — every configuration option explained |
| [install.txt](install.txt) | installation notes per platform |
| [upgrade.txt](upgrade.txt) | upgrade notes |
| [changelog.txt](changelog.txt) | upstream changelog up to v15.00 |
| [CHANGES.md](CHANGES.md) | changes made in *this* repository |

## License

GPLv3 — see [license.txt](license.txt).

CSF is Copyright (C) 2006-2025 Jonathan Michaelson, released under the GNU General
Public License v3 by its author. This repository is distributed under the same
licence. It comes with **absolutely no warranty**.

Please report issues with *this* repository here. The original authors are no
longer contactable and are not responsible for anything in this fork.
