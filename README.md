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

## Updates

`csf -c` checks the published version. `csf -u` upgrades.

An upgrade installs and runs code as root, so it will not proceed unless the
downloaded package carries a valid GPG signature from the release key pinned in
`ConfigServer/Release.pm`. Missing gpg, missing signature, wrong key, or a
package altered after signing — any of these stop the upgrade rather than
proceed on trust.

`AUTO_UPDATES` ships as `"0"`. Turn it on once you have decided you trust this
repository's releases.

Every release can be checked by hand, and rebuilt from scratch:

```bash
gpg --import ConfigServer/release-key.asc
gpg --verify csf.tgz.asc csf.tgz
sha256sum -c csf.tgz.sha256

# rebuild the tarball yourself and compare — it is byte-for-byte reproducible
git archive --format=tar --prefix=csf/ v<version> | gzip -n -9 | sha256sum
```

> The original update path fetched a tarball over the network and ran
> `sh install.sh` from it as root with **no integrity check at all**, falling
> back to plain `http://` on servers without `IO::Socket::SSL`. That is fixed
> here; see [CHANGES.md](CHANGES.md).

## The built-in WebUI

`UI = "0"` by default, and that is the right setting unless you need it.

If you enable it, note what was fixed here: up to v15.00 a **private key shipped
inside the tarball** and every installer copied it into `/etc/csf/ui/`, so every
server running the WebUI used a key anyone who downloaded csf already had. Its
certificate had also expired in 2020. Both are gone from this source; the
installers now generate a certificate belonging to your host alone.

To rotate it, or if you are unsure what your server is serving:

```bash
sh /usr/local/csf/bin/csf-ui-cert.sh --force
openssl x509 -in /etc/csf/ui/server.crt -noout -fingerprint -sha256 -dates
```

If that fingerprint is `2E:AB:8C:4A:...:11:9B:B2:9A`, the server is still using
the leaked certificate — rotate it now.

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
