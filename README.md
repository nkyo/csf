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

## The WebUI

The interface that used to be built into `lfd` has been **removed**. It was
5,071 lines that parsed HTTP from the network as root, stored its password in
plaintext in `csf.conf` and had no CSRF protection. `lfd` no longer listens on
`UI_PORT` in any configuration; leaving `UI = "1"` set now only produces a line
in `/var/log/lfd.log` saying so.

Its replacement is **csf-ui**, installed by the csf installer. The web tier runs
as an unprivileged user (`csfui`) behind your own web server and reaches root
only through a small helper over a unix socket, which takes a fixed list of
operations and validates every argument itself. See
[docs/WEBUI-RPC.md](docs/WEBUI-RPC.md) for the interface and the threat model,
and [docs/WEBUI-PLAN.md](docs/WEBUI-PLAN.md) for the plan it was built to.

To set it up, as root:

```bash
csf-ui-setup
```

(`csf-ui-setup` and `csf-ui-passwd` are symlinked into `/usr/sbin` by the
installer, next to `csf` itself; the files are
`/usr/local/csf-ui/bin/csf-ui-setup` and `/usr/local/csf-ui/bin/csf-ui-passwd`.)

It asks which addresses may reach it, creates the first account and prints the
address to browse to. It is configured in `/etc/csf-ui/ui.conf`, not in
`csf.conf`. Accounts are managed with `csf-ui-passwd`; each has an `admin` or
`support` role and a `$6$` hash in `/etc/csf-ui/users`, readable by root only.

The control panel plugins (cPanel, DirectAdmin, Webmin, InterWorx, CWP, VestaCP,
CyberPanel) are all still installed and registered. Their pages now say the
interface was retired and point at csf-ui, rather than 404ing.

> **If you ran the old WebUI, change `UI_PASS` wherever else you used it.** The
> `UI_*` keys are deliberately left in `csf.conf` - dropping a key from a config
> file silently deletes the operator's setting - but `UI_PASS` is a plaintext
> password that is still in the file, still in every backup of it, and carried
> forward by upgrades. Nothing reads it any more; that does not make it secret.
>
> Also gone with the old UI: the private key that shipped inside the tarball up
> to v15.00, which every installer copied into `/etc/csf/ui/`, so every server
> running the WebUI used a key anyone who downloaded csf already had. Its
> certificate had expired in 2020. `/etc/csf/ui/` is left in place on an
> upgraded server rather than deleted, but nothing reads it now.

Upgrading **does** remove the retired interface's own code and bundled assets,
so that an upgraded server and a fresh one agree about what is installed:
`ConfigServer/{DisplayUI,cseUI,DisplayResellerUI}.pm`, `csf.div`,
`restricted.txt`, `csfajaxtail.js`, `/var/lib/csf/ui/`, and the jQuery /
Bootstrap / Chosen / Fugue files from every `images/` directory an earlier
release copied them into — `/etc/csf/ui/images` included, though `/etc/csf/ui`
itself is kept. Nothing at this release loads any of them, so nothing changes
behaviour.

Uninstalling csf (`csf -u`) now removes csf-ui too: both units are stopped and
disabled first, then `/usr/local/csf-ui`, `/etc/csf-ui`, `/var/lib/csf-ui`, the
Mode A vhost and the `csfui` account. **`/etc/csf-ui` holds the account hashes
and the TLS private key, and it is removed** — the same way `csf -u` already
removes `/etc/csf`. The audit and access logs are kept.

> **If you ran `csf-ui-setup` at commit `f83b5e2` or earlier, check `/etc/crontab`.**
> The wizard's `TESTING_INTERVAL` was written as `300` on the mistaken belief it
> shared a unit with the rollback window; the key is actually **minutes**, and
> `csf.pl` renders it into the minute field of a line in `/etc/crontab` — a file
> shared with every other system cron job on the host. On Debian/Ubuntu cron this
> is not rejected, it is silently clamped to minute 0: the flush sold as every
> five minutes runs once an hour, so a locked-out operator waits up to sixty
> minutes instead of five. If `/etc/crontab` has a line ending `/usr/sbin/csf -f`
> with `*/300` in the minute field, correct it by hand to `*/5` (or `*/N` for
> whatever `TESTING_INTERVAL`, 1–60, you want). On a cron that is not the
> Debian/Ubuntu family, also confirm the rest of `/etc/crontab` is still being
> honoured — some implementations reject a line like that outright instead of
> clamping it, taking every other job in that shared file down too. New installs
> and new applies already write `5`; see [CHANGES.md](CHANGES.md), "Task 8 fix
> round 5", for how this was measured.

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
