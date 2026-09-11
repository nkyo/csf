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

#### Task 8 fix round 1 — a gate that ran as the wrong user, and a confirmation route the apply destroyed

**2026-09-11** — Six findings, two of which mean the feature did not work at all.

- **C1 — `ui.conf` was written `root:root`, so `csf-ui` could not read its own
  configuration.** `rename` leaves the new file owned by root's group; `csf-ui` execs as
  `csfui`. The previous round's evidence that the file was good was that `csf-ui`'s own
  startup gate accepted it — but that gate ran **as root** in the test, and root reads a
  `root:root` file perfectly well. It proved nothing whatever about the process that will
  actually run. `write_atomic` now takes a `group`, resolves it, and chowns the **temp
  file** before the rename (so the file is never visible at its real path owned wrongly);
  `chmod`'s result is checked, which it was not; and mode and owner are now asserted as
  **values** read back off the filesystem and as recorded `chown` arguments. A missing
  `csfui` group is a refusal, not a file written with whatever ownership it happened to get.

- **C2 — the confirmation route was destroyed by the apply it exists to confirm.** `csf -r`
  is `dostop;dostart` (`csf.pl:125`) and `dostop` flushes — including the wizard's own
  `INPUT 1` rule. With no keep-alive, `POST /confirm` is a new connection to a port that is
  no longer open, so the rollback fired every time and setup over the temporary port could
  never succeed. The rule is now re-asserted after `csf -r`, in the child that ran it, via
  the state file the two processes share. It **asks before it acts** — a rule still present
  is left alone rather than duplicated — stores the new read-back rather than the old
  string, and takes the rule straight back out if it cannot be recorded. `t/71` walks the
  operator's whole journey and ends on the only question that matters: after the apply, can
  they still get back in?

- **C3/C4 (R66) — two more discarded results, on the two mechanisms that exist to be
  trustworthy.** `save_state`'s result was thrown away, so a failed write left the port open
  with nothing on the system that knew it existed; recording is now part of opening the
  port, and a failure closes it again and falls back to the tunnel. `Rollback::confirm`
  returned `cancelled => 1` regardless of what `stop`, `disable` and the unlinks did; it now
  checks every one of them, re-tests `armed()` afterwards, and reports `cancelled` only when
  that is true. An operator who believes "the timer has been cancelled" and walks away comes
  back to a machine that reverted itself.

  The sweep this prompted found three more in the same family: `waitpid`'s result was
  unread, so a child reaped by anything else would have had some **other** process's exit
  status read out of `$?` as its own; the best-effort undo after a failed read-back had its
  result discarded, which is the difference between "added something and took it back out"
  and "a rule is installed that nothing is tracking"; and a failed timer-unit write left the
  service unit behind unnoticed. All three now checked. Every remaining ignored return in
  these files is enumerated and justified in the task report.

- **C5 — `firewall-cmd --state` failing for any reason was read as "not running".** So a
  host where firewalld could not be reached was answered `iptables-nft` with
  `certain => 1` — a confident wrong answer, which is worse than `unknown` because
  `unknown` is the safe path and this one writes a rule. Only exit 252 (firewall-cmd's own
  NOT_RUNNING) or an explicit "not running" now counts; everything else is `unknown`. And
  when firewall-cmd says stopped while `systemctl` says active, the two witnesses disagree
  and this code declines rather than picking one.

- **C6 — directories were created at the leaf's mode all the way down**, so
  `/var/lib/csf-ui` could become `0700` and a wall in front of `csfui`'s own session store.
  `make_path` now takes a separate `parent_mode` (default `0755`), chmods what it creates,
  and leaves directories it did not create alone. `/etc/csf-ui/ui.conf` is written `0640
  root:csfui` and `/var/lib/csf-ui` left `0755`, which is what `docs/WEBUI-RPC.md` §2.3
  freezes and what Task 9 installs against.

- **C10 — the pre-check proved content, not writability.** A read-only `/etc`, a full
  filesystem or a missing `csfui` group are all foreseeable, and finding out about any of
  them after `csf.conf` had been committed put a predictable failure inside the one window
  this design cannot close. Both targets are now probed by actually creating and renaming a
  file, and the ui.conf dry run is written with the same mode and group the real file gets,
  so the gid lookup and the chown are exercised too — all before anything is committed.

`t/70-firewall-detect.t`: 177 → 206. `t/71-rollback.t`: 272 → 361. Whole suite: **2408
tests** (was 2290), `prove -I. t/`.

#### Task 8 — the setup wizard, and the two independent ways it refuses to lock you out

**2026-09-11** — The setup wizard: `ui-src/bin/csf-ui-setup`, plus
`ConfigServer::UI::Firewall` (backend detection and the temporary port) and
`ConfigServer::UI::Rollback` (the snapshot, the atomic commit, and the independent
rollback timer). `docs/WEBUI-PLAN.md` §6 is the design; `docs/WEBUI-RPC.md` §2.3 and §10
are the frozen paths and the frozen `ui.conf` keys, neither of which this task adds to.

Every other part of this UI fails by refusing to work. This one can leave an operator
locked out of a machine they are holding a support ticket about, so the notable thing
about all three files is what they decline to do.

- **The backend is detected, never inferred from the distribution.** `Firewall.pm` probes
  the binaries and reads what they say about themselves — `iptables --version`'s
  parenthetical (`(nf_tables)` / `(legacy)` / absent, meaning pre-1.8 legacy),
  `firewall-cmd --state`, `ufw status`, `nft list ruleset` — and produces one of six
  answers: `iptables-legacy`, `iptables-nft`, `nftables`, `firewalld`, `ufw`, `unknown`.
  Managers are asked before the raw layer, because a rule written straight into the
  ruleset a running firewalld or ufw manages is a rule that manager rewrites away. On
  `unknown`, every mutating path declines and the wizard falls back to the SSH tunnel.

  Three hosts that are *not* nothing and are still `unknown`: firewalld running with no
  `firewall-cmd` installed (a rule could go in but could never come out); an iptables
  present whose ruleset will not read back; and — the one worth stating — **both
  `iptables-legacy` and `iptables-nft` holding live rules at once**, however confidently
  `/sbin/iptables` identified itself, because a permit added to one can be overruled by a
  drop in the other and "which is in force" then has two answers.

  `nftables` is detected and then deliberately never written to, with its own refusal code
  (`E_NO_SAFE_RULE`) rather than being folded into `unknown`. In nftables an `accept` in a
  base chain does not end evaluation of the other base chains at the same hook, so a permit
  rule in a table of our own would not reliably open anything while reporting that it had;
  and csf drives `$config{IPTABLES}` for everything, so a host with no iptables binary is a
  host where the thing being configured will not start. "We know exactly what this is and
  will not write to it" is different information from "we have no idea what this is", and
  the operator gets the difference.

- **A rule that is added is read back, and it is the backend's rendering that is stored.**
  Removal matches that stored text against a *fresh* read-back and deletes the line the
  backend is showing right now. Nothing rebuilds a rule string from the port and address it
  remembers: iptables turns `-s 203.0.113.5` into `-s 203.0.113.5/32`, inserts an `-m tcp`
  nobody typed, and orders the match modules its own way, so a `-D` built from memory
  matches nothing — and a `-D` that matches nothing leaves the port open forever with this
  code certain it had closed it. ufw gets the same treatment from the other direction: its
  indices renumber on every change, so the index used to delete is read at removal time,
  never the one the rule had when it was added. firewalld's rule is added to the **runtime**
  configuration only, never `--permanent`, so the worst case for a session that dies badly
  is a hole that closes itself on the next reload or reboot.

- **The temporary port additionally requires TLS material to already exist**, and this is
  a deviation from the plan text, made deliberately and flagged here rather than buried.
  The loopback default is reached through the operator's own SSH tunnel and is encrypted by
  that tunnel; a temporary port is not, and serving a firewall's configuration interface
  and its session cookie in cleartext to the Internet to save someone an `ssh -L` is not a
  trade this code makes on the operator's behalf. Provisioning TLS is Task 9's job and this
  task does not do it — it only declines to use a port when the material is absent. The
  tunnel is always available and is strictly safer.

  The listener follows the offer rather than being decided separately, because the two ways
  of getting that wrong are both silent: a port opened in the firewall while the process
  still binds `127.0.0.1` is a hole that leads nowhere, and a listener bound to a public
  address while the process still speaks cleartext defeats the condition above one layer
  further down. So the bind address, the TLS flag and the one peer the listener will talk
  to all come out of the same decision at once, and the listener enforces the operator's
  address itself as well — two independent walls, so the inner one still stands if the rule
  is removed out from under it or was never as narrow as intended.

- **Applying goes through csf's `TESTING=1` / `TESTING_INTERVAL=300` *and* an independent
  systemd timer that belongs to neither csf nor lfd.** csf's own TESTING is a cron job csf
  installs, so it assumes csf's timer is still running — and the configurations most likely
  to lock somebody out are the ones most likely to stop lfd or leave csf unable to start. It
  also *flushes* rather than *restores*, which takes out rules csf never created (a Docker
  NAT chain, the hosting provider's own rules) and hands back SSH at the price of something
  else, silently. So `Rollback.pm` snapshots `csf.conf`, `ui.conf` and the live ruleset
  first, then installs `csf-ui-rollback.{service,timer}` naming no csf or lfd unit in any
  dependency directive — being ordered after `csf.service` would mean csf failing to start
  stopped the rollback, which is the case it exists for. The timer is **enabled**, not
  merely started, and carries `OnBootSec=` as well as `OnActiveSec=`, so a power cycle
  mid-apply does not quietly disarm it. Confirming cancels and deletes it; the restore path
  disarms itself so it cannot fire twice.

  **On a host without systemd, `arm()` refuses and the apply does not happen.** There is no
  cron, `at`, or forked-sleeper fallback: a forked sleeper dies with the session, which is
  the event the rollback is for, and an approximation of this net is worse than none because
  the operator would be told they had one. The refusal names the reason and says to apply
  from a shell instead, with a second session already open.

- **Configuration is committed atomically, and both candidates are judged before either is
  renamed.** Build in a temp file in the same directory, fsync, validate the finished file
  *off the disk*, rename, fsync the directory. ui.conf's validator is `Server.pm`'s own
  `read_ui_conf()` — the actual startup gate, not a second opinion about it — and it runs
  as a dry run before `csf.conf` is touched at all, because `UI_SESSION_IDLE` and
  `UI_SESSION_MAX` are each valid alone and invalid as a pair, so ui.conf can only be judged
  whole. csf.conf's validator re-reads the candidate with `ConfigServer::Config`'s own rules
  and additionally asserts that every setting asked for **reads back with the value asked
  for** — which catches the interesting failure: a perfectly valid file that does not
  contain the change.

- **The token is never in a URL.** It is printed on the terminal, pasted into a password
  field, and POSTed; the reply mints a *different* value as the session id and sets that in
  the cookie, so the printed secret is used once and never stored by the browser. Enforced
  rather than avoided: the wizard refuses **any** request carrying **any** query string, on
  every route, because it has no route that takes one — so there is no shape of URL in which
  a secret could arrive and be acted on, and none in which one could reach shell history, a
  proxy log, or a `Referer` header. Comparisons use `Session.pm`'s constant-time compare
  rather than a second implementation. Sessions last 30 minutes absolute and 10 minutes
  idle, and both limits end the **process**, not merely the session — an expired session
  with the listener still up is a port still bound and a firewall rule still installed.

- **The wizard writes an answers file and re-invokes the CLI**; it never edits `csf.conf`
  itself. That is what makes a browser session reproducible from a shell
  (`csf-ui-setup --answers FILE --yes`) and what keeps a fault in the web tier from being a
  fault in the firewall's configuration. The answers grammar is the same `KEY="VALUE"` shape
  as `csf.conf` and `ui.conf`, parsed and never evaluated, with an allowlisted key table: an
  unknown key and a duplicate key are both refusals, for the reasons §10 already gives.
  `TESTING` may be mentioned only with the value it is going to have anyway —
  `TESTING="0"` is **refused**, not quietly overridden, because somebody wrote that on
  purpose and is entitled to be told it is not on offer.

- `csf-ui-setup --cleanup` closes a port left open by a session that died badly, using the
  same read-back removal path; the record of the rule is **kept** when the port could not be
  closed, since deleting it would delete the only thing that knows a hole is open.
  `EXIT`, `INT` and `TERM` all run the same idempotent cleanup.

No shell anywhere (G2): the only `exec` in the new code is the block form with an argv list,
in `Firewall.pm`, and `argv[0]` is always an absolute path resolved from a fixed directory
list rather than the inherited `$PATH` — which matters most here, because the values
reaching those argv lists came out of a form submitted over the network and the program on
the other end is the firewall. No new runtime dependency; no new `ui.conf` key; no new
helper operation.

Note on naming: `docs/WEBUI-PLAN.md` §6 calls the CLI `csf-setup` while
`docs/WEBUI-RPC.md` §2.3 — the frozen layout, which wins over plan prose — installs exactly
one setup binary, `csf-ui-setup`. They are the same program.

New: `t/70-firewall-detect.t` (177 assertions, detection against fixture command output for
all six cases plus the ambiguous and unusable hosts, and the canonical-spec round trip) and
`t/71-rollback.t` (272 assertions). Whole suite: **2290 tests** (was 1841), `prove -I. t/`.

#### Task 7 fix round 2 — the R58 accessibility fix hid the one message Health exists to show

**2026-09-11** — One finding. R55, R56, R57 and the destructive-control half of R58 all
confirmed addressed by independent review of the shipped code and its behaviour, not the
report describing it - including re-sweeping every `/ui/*` route with a fresh `support`
session and a valid CSRF token and getting the same 13-refused/4-allowed split as the
first pass.

- **R59 — the R58 fix put `.fully-hidden` on the wrong element.** `health.html` wrapped
  BOTH the reconciliation summary message ("No reconciliation issues found." on the clean
  path, or the finding count otherwise) AND the findings table+form in one
  `findings_class` div. R58 correctly hid that div's table+form when there is nothing to
  act on - but hiding the *whole* div with `display: none` took the summary message with
  it, so the one clean-path success message vanished along with the (correctly) empty
  table. An operator who opens Health specifically to ask "are we clean?" got a blank
  panel, indistinguishable from the page being broken - on the one screen where that
  ambiguity is exactly wrong, since doubt is the reason to visit it. The reviewer found
  this by dispatching a real request with an empty reconcile result and reading the
  response, not by reading the template.

  Fixed by moving the summary paragraph outside the `findings_class` wrapper in
  `ui-src/web/screens/health.html`, so it renders unconditionally while `findings_class`
  now hides only the table+form - the thing that genuinely has nothing to show on that
  path. No Perl changes: `_route_ui_health()`'s `summary_text`/`findings_class` values
  were already correct: the class was on the wrong element, not computed from the wrong
  condition. Checked every other toggle in both Health templates for the same shape (a
  class wrapping sibling content that must survive being hidden) - `health-review.html`'s
  `apply_class` wraps `count_text` alongside its form too, but `count_text` is already ''
  in exactly the branch that hides it, so no second instance exists.

  New test in `t/60-screens.t` dispatches `/ui/health` with an empty reconcile result in
  isolation (findings-bearing tests elsewhere would not have caught this - "ORPHAN"/"GHOST"
  text on the page would still have passed even with the summary line gone) and asserts
  the message is present in the response body, specifically outside the `fully-hidden`
  wrapper. Guard-removal: reverted the template to the regressed shape (summary paragraph
  back inside `findings_class`) and re-ran - both new assertions failed, showing the exact
  literal markup the review flagged (`<div class="fully-hidden">` immediately followed by
  the "No reconciliation issues found." paragraph); reverted back, confirmed byte-identical,
  full suite green.

`t/60-screens.t`: 143 → 147 assertions. Whole suite: **1841 tests** (was 1837),
`prove -I. t/`.

#### Task 7 fix round 1 — a test bound to nothing, a role check by memory, a class fixed but not closed, focusable-while-invisible on the one screen that can't afford it

**2026-09-11** — Two independent reviews came back PASS with no Critical and the role
boundary confirmed by measurement (every `/ui/*` route swept with a fresh `support`
session and a valid CSRF token: 200 on exactly `/ui/lists` and `/ui/lookup`, 403 on the
other fourteen). Four findings, all in tests or one CSS rule, not in the security
properties themselves.

- **R55 — `t/60-screens.t`'s GHOST-exclusion test was bound to nothing.** The review-step
  test submitted only the fixable id and asserted the GHOST finding did not appear on the
  confirmation page - true, but for the wrong reason: GHOST was never selected, so nothing
  about the `fixable` cross-check was exercised. The reviewer proved it by removing the
  cross-check entirely and watching this exact test stay green; only the stale-count
  assertion noticed. The fifth test-passing-for-the-wrong-reason in this project, and the
  first one found *inside* the guard-removal table meant to catch exactly that - the table
  had credited a guarantee the removal did not actually exercise. Fixed by submitting
  **both** ids (`fix_id_0` the fixable ORPHAN, `fix_id_1` the unfixable GHOST, as a tampered
  client would) and asserting GHOST is excluded *despite* being submitted, with a `stale`
  count assertion pinning that exactly 1 of 2 was rejected. Re-verified against the real
  code (all green) and against the code with the cross-check removed (three exactly-named
  assertions red).
- **R56 — the read-only role check rested on hand-written lists in two files.**
  `t/60-screens.t` swept mutating `/ui/*` routes mechanically from `@ROUTES` but checked
  the five GET routes against a hand-written three-element admin-only list and a
  hand-written two-element allowed list - nothing forced either to stay in sync with new
  screens. `t/33-app.t`'s own mechanical binding (the R27 table) only ever matches a route
  that names an `op`; every `/ui/*` row is a `handler` row, so none of Task 7's routes were
  bound by it at all. Both fixed: `t/60-screens.t` now enumerates every non-anonymous GET
  `/ui/*` route from `@ROUTES` and checks each one's `support` flag against an independent
  table keyed from `docs/WEBUI-RPC.md` S5 (not against the route's own flag - an earlier
  draft of this exact fix did that, which is a tautology that can never go red no matter
  which way a flag is wrong, caught before it shipped by re-running the removal proof and
  watching nothing turn red). `t/33-app.t` gets a new `%HANDLER_SPEC` table binding all
  22 handler rows (3 pre-existing `/api/*` + 19 from Task 7) by path, plus a converse check
  that every table entry names a route that still exists. Guard-removal re-run against both
  independently: a `support => 1` added to `/ui/health` turns red in both files.
- **R57 — the `layout.html` comment bug was fixed as one instance; the class was still
  open.** The prior fix round respelled `layout.html`'s own comment and added
  `_strip_leading_comments()` - but that function ran *after* `render()`, stripping only
  the rendered output's leading block. The reviewer showed this mitigates nothing: `render()`
  substitutes a template's entire text in one pass, comments included, so by the time an
  output-side strip runs, any comment that happened to spell a real var's name has already
  been substituted, and for a RAW marker whose value contains a comment-closing sequence,
  the strip regex itself truncates early at that *embedded* sequence rather than the
  comment's real end - not "mitigates nothing" by accident, but demonstrably: reverting to
  the old shape and feeding it a synthetic template reproduces a live `<script>` leaking
  into rendered output. Fixed structurally: `_render_template()` (replacing
  `_render_screen()`'s/`_render_nav()`'s/`_authed_page()`'s direct `render_file()` calls)
  now reads a template's raw bytes off disk and strips every HTML comment - leading or
  mid-file - with `_strip_comments()` *before* handing the result to
  `ConfigServer::UI::Render::render()`. Nothing inside any comment, anywhere, in any
  template, is a substitution candidate any more, regardless of what brace syntax it
  contains - closing the class the first fix only closed one instance of. Three new direct
  tests against `_strip_comments()`/`_render_template()`, including a synthetic on-disk
  template reproducing the exact truncation shape (a raw marker substituted with content
  containing `--><script>evil</script>`), plus an end-to-end assertion that no template's
  GPL header or any HTML comment survives into a real dispatched response. Guard-removal:
  reverting `_render_template()` to the old post-render-strip shape reproduces the live
  `<script>` leak in the new tests, confirmed, then reverted back.
- **R58 — `.visually-hidden` on a destructive form left it keyboard-focusable while
  invisible.** `app.css`'s own `.visually-hidden` comment says plainly what it is for -
  content that stays reachable by keyboard and screen reader (a control's label) - which
  is the opposite of what "there is nothing here to reach" needs. Health's "Review selected
  fixes" button (when nothing is fixable) and, worse, `health-review.html`'s "Yes, delete
  these rules" form (when nothing survived a fresh re-check) were both hidden with it, so a
  keyboard user tabbing through the page could land on - and activate - a destructive
  control they never saw. Added `.fully-hidden { display: none; }` to `app.css` (removes
  from layout, the accessibility tree, AND the tab order) and switched `findings_class`,
  `review_form_class` and `apply_class`'s hidden values to it in `ui-src/bin/csf-ui`; left
  `.visually-hidden` in place everywhere else it wraps non-interactive status text, which is
  exactly what it is for. Four new tests pin the exact class on the exact form in both
  states (hidden with nothing to apply, visible with a survivor); guard-removal (reverting
  `apply_class` to `visually-hidden`) turns both red.
- Two small corrections: `_route_ui_health_apply`'s own comment now states explicitly that
  the function does not itself re-derive or re-validate submitted ids - the safety of an id
  it did not check is entirely `reconcile_fix`'s own re-scan per S5.12, not anything in this
  tier, and the comment said so imprecisely enough to read otherwise. And `t/50-render.t`'s
  scanner failure message no longer cites a `task-7-report.md` heading that does not exist;
  it points at `lists.html`'s own header comment, where the R51 worked example actually
  lives.

`t/33-app.t`: 140 → 207 assertions. `t/60-screens.t`: 120 → 143 assertions. Whole suite:
**1837 tests** (was 1747), `prove -I. t/`.

#### Task 7 — the five screens: Overview, Block/Unblock, Lists, IP lookup, Health

**2026-09-11** — Added the server-rendered screens people actually use, built entirely on
top of the frozen contract (`docs/WEBUI-RPC.md`), the root helper (Task 2), the auth store
(Task 3), the unprivileged web tier and its router (Task 4), the HTTP/TLS core (Task 5),
and the rendering layer (Task 6). No JavaScript anywhere: every primary action is a plain
HTML `<form>`, and every state-changing one carries the session's CSRF nonce. Twenty-one
new template files under `ui-src/web/screens/` plus `ui-src/web/nav-admin.html` /
`ui-src/web/nav-support.html`, wired to nineteen new routes in `ui-src/bin/csf-ui`'s
`@ROUTES` (`ui-src/bin/csf-ui`, `ui-src/web/screens/*.html`, `ui-src/web/nav-*.html`,
`t/60-screens.t`).

- **Role enforcement is server-side, per request, in the same `_gate()` every `/api/*`
  route already goes through** — `support => 1` on `GET /ui/lists` and `GET /ui/lookup`
  only; every other `/ui/*` route defaults to admin-only, exactly `docs/WEBUI-RPC.md` S5's
  role mapping. A logged-in support session that navigates straight to `/ui/overview`,
  `/ui/block` or `/ui/health` by URL is refused with 403 before any handler runs, not
  merely kept off a nav link.
- **Health's destructive flow is two POSTs, never one**: `GET /ui/health` shows the
  reconcile diff and posts to `POST /ui/health/review` (never a mutation itself — it only
  re-runs the read-only `reconcile`), which shows exactly what a FRESH scan says is still
  present and fixable and posts to `POST /ui/health/apply`, the only route in this whole
  tier that ever calls `reconcile_fix`. Selection is via independently-named `fix_id_N` /
  `apply_id_N` hidden fields rather than a shared `name="ids"`, because neither this
  contract's query-string folding (S14.1) nor `csf-ui`'s own form-body parser promises to
  preserve repeated same-named values as a list.
- **Lists paginates and switches lists with GET `<form>`s carrying hidden fields, never a
  query string spliced into `href=`** — see "R51" below.
- A pre-existing bug in `layout.html` (Task 6) is fixed as part of this task:
  `Render.pm`'s `render()` processes a template's ENTIRE text as one substitution pass,
  comments included. `layout.html`'s own documentation comment spelled out its five
  variables using the literal brace syntax it was explaining (`{{title}}`, `{{{nav}}}`,
  `{{{content}}}`, ...) — every one of those got substituted too, silently duplicating the
  real values into the comment and, for the two RAW markers, truncating the comment at the
  first place the substituted HTML happened to close a comment of its own. Never caught
  before this task because nothing before it actually rendered `layout.html` with real
  `nav`/`content` HTML end to end. Fixed by respelling every mention in that comment
  without brace syntax; the functional markers are unchanged. The same class of problem
  (a partial's own header comment being spliced, verbatim, into a page that composes many
  small partials) is why `ui-src/bin/csf-ui`'s new `_strip_leading_comments()` strips each
  template's leading GPL/doc comments from rendered output before it is used — GPLv3 S5(a)
  requires the notice in the source tree, not in every HTTP response a Lists page's
  twenty-five rows would otherwise have repeated it in.
- **Every screen author hits the URL-parameter question on the first screen with
  pagination — the remedy is written down twice, per the review's own instruction**: in
  `t/50-render.t`'s scanner failure message, and in `ui-src/web/screens/lists.html`'s own
  header comment (the worked example, since Lists is the screen that needed it): a GET
  `<form>` whose parameters are hidden `name=`/`value=` inputs, never a query string
  spliced into `href=`/`src=`/`action=` (those three are flagged unconditionally the
  moment any `{{ }}` lands in them — see Task 6 fix round 5's R47 below — there is no
  allowlist rescue for them the way there is for `value=`).

**R50 (review carry-over from Task 6, closed by this task)** — the escaping-context
scanner's entire premise (an inert-attribute allowlist that lets `title="{{v}}"` and
`data-ip="{{id}}"` through unescaped-for-JS) rests on this UI shipping no JavaScript at
all. Nothing enforced that premise: `<script src="/app.js">` and a static, un-templated
`onclick="showDetail(this)"` both scanned clean while being live script/XSS the moment
anything else on the page carried attacker text. Closed in `t/50-render.t` by
`_find_script_or_event_handlers()`, which reuses the same tag/attribute tokenizer as the
placeholder-safety scan (rather than a fresh regex — that is the whole lesson of Task 6's
five fix rounds) to flag any `<script>` element or `on*=` attribute NAME anywhere under
`ui-src/web/`, unconditionally of whether a `{{ }}` placeholder is anywhere near it. This
guard was written and verified BEFORE any screen template was authored, per the review's
own instruction, and the real enforcement loop at the bottom of `t/50-render.t` runs it
against every `.html` file automatically.

**Guard-removal verification** (the method this project has used since Task 5): every
guarantee added by this task was removed, the specific test(s) that go red were recorded,
and the guard was restored and re-verified byte-identical before moving to the next. Full
table with the exact tests in `.superpowers/sdd/webui-implementation/task-7-report.md`.

#### Task 6 fix round 5 — invert the attribute rule, model the script-data escape states, correct a comment that lied about its own guard

- **2026-09-11** — Re-review of fix round 4 verdicted the rewrite sound and both R45 and R46
  ADDRESSED, re-running all 87 corpus rows plus every earlier review's inputs with no regression,
  and checking performance (200k `<`, 200k `<!--`, a 20k-attribute tag, a 200KB script body: all
  under 0.1s). Three findings remained.

  **R47 — the `href`/`src`/`action` enumeration, the last regex-era artifact in the file, is
  reachable by ordinary markup.** `<button formaction="/api/unblock?ip={{id}}">` is simply how the
  Block/Unblock screen's two-submit form gets written, and a guarded `action=` two lines above it
  teaches exactly the wrong lesson. Widening the list invites the next omission — `xlink:href`,
  `<object data>`, `poster`, `srcset`, `ping`, `background` were all already known, `style=` was
  forbidden by `Render.pm`'s own header comment yet went unflagged, and `srcdoc=` is worse than all
  of them, since an `<iframe srcdoc="{{v}}">` re-parses the escaped markup as a document. So the
  rule was **inverted**, exactly as R42 inverted the raw marker: a quoted attribute value holding
  `{{` is reported unless the attribute's name is on a closed allowlist of provably inert names
  (`alt`, `class`, `for`, `id`, `label`, `name`, `placeholder`, `title`, `value`, plus the `aria-`
  and `data-` prefixes — the hyphen matters, since bare `data` is a URL on `<object>`). The test for
  admission is stated in the file: the value must never be read as a URL, as CSS, as JavaScript or
  as markup **in any element**, not merely in the element a screen happens to use it on. `on*` and
  `href`/`src`/`action` keep their own finding text for the diagnostic, not for the decision.

  **R48 — `<script>`'s escaped and double-escaped tokenizer states were not modelled.**
  `<script><!--<script>x</script>{{v}}</script>` leaves `{{v}}` as live JavaScript source: `<!--`
  enters SCRIPT DATA ESCAPED, a following `<script` enters SCRIPT DATA DOUBLE ESCAPED, and in that
  state `</script>` does not end the element — it only drops back to escaped. The
  `document.write("<!--<script")` form reaches the same machine. This is a missing *state* rather
  than a missing name in a list, so R47 does not reach it. `_scan_script_data()` now walks all
  three states; `<style>` is RAWTEXT, which has no escape states, and keeps the simpler scan.

  **R49 — a comment that misdescribed its own guard,** the fourth time this project has hit one.
  The note on RCDATA elements (`<title>`, `<textarea>`) claimed the blindness over-reports and so
  fails closed. It does both: `<textarea><div title="</textarea><button onclick='{{v}}'>">…` is
  **not** flagged, because a browser ends the textarea at the `</textarea>` inside that quoted
  value — RCDATA has no notion of attributes — while the scanner is inside an inert `title=` at that
  point. Verified against the real `render()`, which emits the live `onclick`. Per the round-5
  brief the behaviour is unchanged and only the sentence is corrected; both directions are now
  described and both are pinned by tests so the description cannot drift again. The unclosed-tag
  over-report was judged the right trade by the reviewer and is kept.

  No change to `Render.pm`'s escaping behaviour, to the screens, or to the raw-marker allowlist's
  contents. All 113 corpus inputs re-run through the real scanner and the real `render()`;
  the 94 rows inherited from round 4 reproduced identically except for two additive findings on
  inputs that were already flagged. Performance re-checked including the new script states (12k
  nested `<script>` pairs, 50k `<!--` inside one body): worst case 0.12s. `t/50-render.t`:
  153 → 202 assertions. Whole suite: **1609 tests** (was 1560), `prove -I. t/`.

#### Task 6 fix round 4 — the context scanner is no longer built out of regular expressions

- **2026-09-11** — Re-review of fix round 3 found R43's fix unsound: scoping every attribute check
  to a tag region captured by `<[a-zA-Z][a-zA-Z0-9-]*([^>]*)>` meant `[^>]*` stopped at the *first*
  `>` in the tag, including one inside an earlier **quoted** attribute value. Confirmed live:
  `<div title="Count > 5" onclick="{{v}}">` produced no findings while `render()` emitted a real
  `onclick="alert(1)"` — ordinary business text (a `>` comparison in a label) beside a dynamic
  handler in the same tag, exactly the shape a screen author writes. That was a regression from
  round 2, whose unscoped regex would have caught it.

  Rather than patch the regex again (the recommended round-4 patch, alternating
  `"[^"]*"|'[^']*'|[^>]` inside the repetition, is only the next approximation — it still cannot
  tell a comment from markup, nor see that a `<` inside an attribute value is not a new tag), the
  scanner was **replaced with an explicit single-pass scan that tracks context**: element content,
  inside a tag, inside a quoted or unquoted attribute value, inside a comment or other markup
  declaration, inside a `<script>`/`<style>` raw-text body. It follows the HTML5 tokenizer's own
  state transitions for the subset that decides those boundaries. The reason is structural, not
  stylistic: each of rounds 1–3 introduced its bypass inside the fix for the previous bypass,
  because HTML is not a regular language and "where am I in this document" is not a question a
  regular expression can answer — there is no patch sequence that converges, only the next
  construction nobody thought of.

  Closed by the replacement, each verified against both the scanner and the real `render()`: the
  truncating `>` in any earlier quoted value (R45, all quote styles); a `<` inside an attribute
  value; two attributes with no whitespace between them (`<a href="{{v}}"onclick="{{v}}">`, live to
  a browser, invisible to every earlier round's `\s`-anchored patterns); a stray `/` where that
  whitespace would be (`<div/onclick="{{v}}">`, same); `</scriptx` not ending a script body; a tag
  whose attribute value contains a whole fake `<script>`.

  **R46, found while probing the new scan and fixed in the same round** — a placeholder in
  **tag-name position**: `<{{v}}`, `</{{v}}` or `<d{{v}}`. `escape_html()` escapes `<` and `>` in a
  *value*, so a value can never invent a tag; but where the *template* wrote the `<` itself, the
  value supplies the tag name and every attribute after it, because `escape_html()` escapes neither
  space nor `=` nor `/`. Confirmed live: `<p>5 <{{v}}> 6</p>` with `v = "img src=x
  onerror=alert(1)"` renders exactly that `img`. Missed by every earlier round — the question it
  asks is about the *output's* structure, not the template's. `< {{v}}` with whitespace between is
  not this and is not flagged: an HTML tokenizer emits that `<` as a character token.

  Also resolved naturally rather than by a special case: round 3's known false positive on a
  commented-out `<!-- <button onclick=...> -->`. Comment content is now skipped, and soundly — every
  way HTML5 ends a comment (`-->`, `--!>`, the abrupt `<!-->`/`<!--->` forms, EOF) needs a literal
  `>`, `escape_html()` turns `>` into `&gt;`, and entities are not decoded inside a comment, so a
  substituted value cannot close the comment it sits in. That argument covers the escaped marker
  only, which is why `_find_unauthorized_raw_markers()` stays context-free and still reports a
  `{{{key}}}` inside a comment.

  No change to `Render.pm`'s escaping behaviour, to the screens, or to the raw-marker allowlist's
  contents. `t/50-render.t`: 115 → 153 assertions. Whole suite: **1560 tests** (was 1522),
  `prove -I. t/`.

#### Task 6 fix round 3 — the fix for R40 itself had two more holes, plus a false positive that would have gotten it disabled

- **2026-09-11** — Re-review of fix round 2's scanner confirmed R40 (`<a href={{evil}}>` now flags,
  name-agnostic, quoted forms not double-counted) and the "split-brace is unreachable" claim
  (re-run against the real `render()`), then attacked the guard rather than reading it and found
  two more live holes plus a false positive urgent enough to fix in the same round, because a
  guard that blocks correct work is a guard someone disables - and the moment it is disabled, R40
  and this round's own holes stop being theoretical.

  **R41 — a placeholder used as the attribute NAME, not its value.** `<div {{attr}}="{{val}}">`
  passed every round-1/round-2 check; `render()` with `attr=>'onclick', val=>'alert(1)'` was
  confirmed to actually emit `<div onclick="alert(1)">`. `escape_html()` only ever escapes a
  *value* - nothing it does can make an attacker-influenced attribute *name* safe. Fixed by adding
  a check for a placeholder-shaped token (`{{key}}` or `{{{key}}}`) sitting immediately before `=`
  within a tag's attribute region, checked before the value-position checks since a name-position
  placeholder is dangerous independent of whatever the value turns out to be. Verified against
  both the scanner and the real `render()` for a quoted value, an unquoted value, and the raw
  marker used as the name - all three confirmed live before the fix, all three confirmed caught
  after it.

  **R42 — the raw marker after a `</script>` embedded inside a JS string. Fixed by allowlisting
  call sites instead of enumerating unsafe contexts, per explicit direction.** A JS string
  literal's embedded `</script>` ends the `<script>` element from the *browser's* tokenizer's point
  of view regardless of JS-string context - confirmed live: `{{{v}}}` placed after one renders
  `<img src=x onerror=alert(1)>` as real, live markup, while the escaped `{{v}}` form in the
  identical position stays inert text (`escape_html()` already makes a value safe as ordinary
  element content, which is exactly what it becomes there - confirmed, not assumed, by running both
  through `render()`). The instruction was explicit and is recorded here because it is the more
  important fix than the regex: **do not enumerate contexts where the raw marker is unsafe - that
  set is unbounded, and this hole is the proof. Allowlist the call sites instead.** Added
  `%RAW_MARKER_ALLOWLIST` and `_find_unauthorized_raw_markers()`: every `{{{key}}}` anywhere under
  `ui-src/web/` is flagged unless the exact `(file, key)` pair is on the list, regardless of
  surrounding context. Today's allowlist has exactly two entries, both on `layout.html`: `nav` and
  `content` - the two slots that file's own header comment already documents as its raw-marker
  contract with Task 7.

  **R43 — the round-2 unquoted-attribute rule fired on ordinary element text with no tag involved
  at all** (the reviewer's own examples: `<p>Max attempts = {{max}}</p>`,
  `<div class="stat">Blocked count = {{count}}</div>` - precisely the shape Task 7's Overview
  screen needs to write), because it matched against the whole document text with no requirement
  that it actually sit inside a tag. Fixed by requiring real tag context: every attribute-level
  check (R41's new name check, `on*`, `href`/`src`/`action`, and R40's unquoted-any) now runs only
  against the region a `<tagname ...>` opening captures between the tag's name and its own closing
  `>`, never against text between tags. Confirmed both examples now produce zero findings, and
  re-ran every prior positive control (R38, R40, R41, all five round-2 evasion candidates) against
  the amended scanner to confirm the tag-scoping introduced no regressions - all still flag
  correctly.

  **R44 — the file-traversal regex (`/\.html\z/`) had no `/i`**, so a screen saved as `SCREEN.HTML`
  (any case) was silently never scanned - the one guard standing between Task 7 and this whole
  class of mistake, skipping files without a word. Fixed (`/\.html\z/i`); the traversal was also
  factored into `_html_files_under()` so this has a direct regression test against a synthetic
  tempdir rather than only exercising it indirectly through whatever currently exists under
  `ui-src/web` (none of which is uppercase today - exactly how this went unnoticed the first time).

  Method used for all four, per explicit instruction: construct the input, run it through the real
  scanner *and* the real `render()`, confirm the scanner flags it and that no legitimate case
  broke - then re-run the full evasion list (including the ones previously found unreachable, since
  a change to the matcher can make a previously-unreachable pattern reachable) against the amended
  matcher. Also live-verified against the actual `layout.html`: injected the R41 and R42 examples,
  watched the real-file enforcement test go red naming the file; injected the R43 examples,
  confirmed the suite stayed green; reverted all three, confirmed clean again.

  `t/50-render.t`: 97 → 115 assertions. Whole suite: 1522 tests (was 1504), `prove -I. t/`.
  (`t/50-render.t`)

#### Task 6 fix round 2 — the fix for R38 itself had a hole: unquoted attributes bypassed it entirely

- **2026-09-11** — Re-review of fix round 1's context-boundary scanner (R38) verified it by doing
  real work rather than reading the diff: created a temp file under `ui-src/web/screens/` to
  confirm the `File::Find` walk actually reaches a directory that does not exist yet, checked that
  the positive/negative controls call the real `_find_unsafe_placeholders()` rather than a
  reimplemented copy of its regexes (the failure mode that would have made the whole thing
  theatre), and confirmed 44px is genuine total height under `box-sizing: border-box`. It then
  found R40: both the event-handler and the URL-bearing-attribute regexes required a captured
  quote character (`(["'])(.*?)\2`), so an unquoted value - `<a href={{evil}}>`, legal HTML5 -
  bypassed detection completely. Confirmed live: took a violation the scanner correctly caught,
  removed the quotes, watched 81/82 become 82/82. This was not merely a scanner gap:
  `escape_html()` does not escape spaces, so an unquoted value containing one does not just break
  out of the attribute, it injects a whole new one - `onmouseover` is one space away.

  Enumerating "the dangerous attributes" was the wrong shape for the unquoted case, because
  without quotes *every* attribute is injectable, not only `on*`/`href`/`src`/`action`. Fixed by
  adding a fifth check to `_find_unsafe_placeholders()` (`t/50-render.t`) that flags `{{` in an
  unquoted attribute value regardless of the attribute's name, as an addition alongside the
  existing quoted checks, not a replacement for them - a negative lookahead right after `=\s*`
  keeps it from double-counting a value the quoted checks already caught.

  The same review named five other evasion candidates to check individually rather than assume:
  single-quoted attributes, uppercase `ONCLICK`/`HREF`, a `<script>` tag carrying its own
  attributes or a `type`, a `<script>` body split across lines, and whitespace around an
  attribute's `=`. All five were already handled by the existing regexes (quote-character
  backreference, the `/i` flag, `[^>]*` before a script tag's `>`, `/s` dotall on the script-body
  capture, and `\s*=\s*` respectively) - now proven with explicit tests rather than left as an
  unverified claim. One further candidate, `{{` itself split by a newline (a `{` then a line break
  then `{key}}`), turned out not to be reachable at all: `ConfigServer::UI::Render`'s own
  `$PLACEHOLDER_RE` requires the two braces strictly adjacent, so that text is not a placeholder
  to `render()` either - proven directly by running it through the real module rather than only
  reasoning about the regex, rather than silently leaving it uncovered.

  A guard written specifically to protect the next task, shipped with a hole that task could walk
  through unknowingly, is worse than no guard, because it would be trusted - which is why this
  was a round rather than a deferred minor.

  `t/50-render.t`: 82 → 97 assertions. Whole suite: 1504 tests (was 1489), `prove -I. t/`.
  (`t/50-render.t`)

#### Task 6 fix round 1 — the escaping-context boundary was a comment, not a guard; a stated touch-target guarantee was 8px short

- **2026-09-11** — Spec review (R38) found that `Render.pm`'s and
  `layout.html`'s header comments correctly document that HTML-escaping
  covers element content and quoted attributes but not a `<script>`/
  `<style>` body, an event-handler attribute, or a URL-bearing attribute
  (`href`/`src`/`action`) — and that nothing besides those comments
  stopped Task 7's five screens, added directly on top of this file,
  from putting `{{value}}` in one of those positions anyway. The
  reviewer also named the specific way the "entities happen to survive
  inside `<script>` anyway" fallback comfort fails: a value ending in an
  unescaped backslash still corrupts a `<script>` string literal there,
  escaped or not, so the undefended boundary is also less forgiving than
  it looks. This is the third landmine of the same shape in the project
  — an `@ROUTES` table nothing bound to the contract, a read sized by a
  literal that happened to equal its cap, now an escaping-context
  boundary enforced only by prose — each ruled into a test rather than
  left as description.

  Added a text scan (`t/50-render.t`) that walks every `.html` file
  under `ui-src/web/` — recursively, so `ui-src/web/screens/*.html`
  (Task 7, not yet written) is covered automatically with no second
  place to remember to add it — and fails if `{{` appears inside a
  `<script>` body, a `<style>` body (beyond what R38 asked for, added
  for consistency with `Render.pm`'s own documented scope), an
  `on*="..."` attribute, or an `href=`/`src=`/`action=` attribute. It
  bars both the escaped and the raw marker in all four positions alike,
  since neither is safe there. Proved against six synthetic positive
  controls (one per danger category) and four negative controls
  (ordinary safe placeholder usage, plus `data-action=`/`data-onload=`
  to confirm the attribute-name match requires a real attribute
  boundary rather than a hyphenated substring), then run for real
  against `ui-src/web/layout.html` — which passes clean, having never
  put a substitution in any of those four positions — with a companion
  assertion that at least one `.html` file was actually found, so the
  enforcement test cannot pass vacuously from a wrong path the way a
  prior task's traversal test once did from an accident in its fixture.
  Confirmed live: injecting `<a href="{{evil}}">` into `layout.html` and
  re-running turns the enforcement test red; reverting turns it green
  again.

  Separately (R39), `app.css`'s `.btn-small` set `min-height:
  calc(var(--touch-min) - 8px)` — 36px against the file's own stated
  "every interactive element ... has a minimum 44x44px hit area" — on
  exactly the row actions (`.row-actions`, a Lists table's
  undeny/unallow buttons) where a mis-tap has real consequences. Fixed
  to the full 44px floor; "small" is now visual density only (padding,
  font-size), never a shorter hit area than the guarantee promises.

  `t/50-render.t` grew from 70 to 82 assertions; the whole suite is now
  1489 tests (was 1477), `prove -I. t/`.
  (`t/50-render.t`, `ui-src/web/app.css`)

#### Task 6 — the rendering layer and stylesheet the five screens will use

- **2026-09-11** — Added `ConfigServer::UI::Render` (`ui-src/lib/ConfigServer/UI/Render.pm`),
  a template substitutor for the replacement WebUI's server-rendered HTML
  (docs/WEBUI-PLAN.md S8). It replaces `{{key}}` with the HTML-escaped
  value of `$vars{key}` — escaping `& < > " '`, in that order, so the `&`
  the other four introduce is never re-escaped — and never with anything
  else: the default is escaped, and a raw, byte-for-byte insert requires
  the visibly different `{{{key}}}` marker, so a screen that forgets to
  think about escaping still gets it. A key absent from the vars
  hashref, or present with an `undef` or reference value, is a `die()`
  naming the key, on both the escaped and the raw path — never a blank
  landing silently in the page, which is the specific failure mode
  task-6-brief.md calls out as how a broken template ships unnoticed.
  Substitution runs as a single `s///ge` pass, so a substituted value
  that is itself the literal text `{{key}}` (an IP-block note that
  happens to contain double braces, say) is inserted as inert text and
  never re-scanned for placeholders of its own — proved rather than
  assumed: an earlier draft that looped substitution until no
  placeholder matched (the naive way to write a template expander) does
  not merely mis-render a value shaped like `{{a}}` sitting inside its
  own substitution, it never terminates, which is a strictly worse
  failure for a request-handling process to hit than a wrong render. A
  thin `render_file()` wrapper reads a template from disk as raw bytes —
  no `:encoding` layer, so Perl's internal UTF-8 flag is never set on
  the result, matching the byte-in/byte-out convention
  docs/WEBUI-RPC.md S14.2 already states for the request/response
  structures this sits inside; escape_html()'s byte-level scan for the
  five ASCII characters it looks for cannot misfire on a multi-byte
  UTF-8 sequence, because every continuation and lead byte of one is
  `>= 0x80`.

  `escape_html()` covers both element content and quoted attribute
  values with the same five characters — every attribute in every
  template in this tree is quoted, and `"`/`'` are exactly what keep a
  quoted value from being broken out of. It does **not** cover
  `<script>` bodies, inline event-handler attributes, `javascript:`
  URLs, or `<style>`/CSS values: an HTML tokenizer ends a `<script>`
  element on a literal `</script` byte sequence without decoding
  entities first, so an escaped `<` does not stop it, and none of
  `&<>"'` is what JavaScript or CSS syntax needs escaped in the first
  place. No template in this tree places a substitution in any of those
  four positions; a future one that needs to will need a different
  escaping function, not a misuse of this one. Written down in
  `Render.pm`'s own header comment so Task 7 reads it before adding a
  screen, not after.

  Added `ui-src/web/layout.html`, the authenticated app shell all five
  screens (Task 7) load via `render_file()`: a skip link, and `<header>`/
  `<nav>`/`<main>`/`<footer>` as native HTML5 landmarks rather than added
  `role=""` attributes. Its five-variable contract (`title`, `user`,
  `role`, the raw `{{{nav}}}`, the raw `{{{content}}}`) is documented at
  the top of the file itself, including why `{{{nav}}}`, not this file,
  is where a logout action belongs: which screens exist and which link
  is "current" is route-table knowledge, and logout is itself the
  mutating `POST /api/logout` `ui-src/bin/csf-ui` already defines —
  both are Task 7's, not this task's, and Task 6 does not add routes.

  Added `ui-src/web/app.css`: one plain stylesheet, no build step, no
  framework, nothing from a CDN — served from disk exactly as written,
  because a production firewall host frequently has no outbound Internet
  access and a tightened `TCP_OUT` blocks it anyway. One breakpoint at
  768px, below which any table wrapped in `.table-responsive` becomes
  one stacked card per row (the `<thead>` stays in the DOM, moved
  offscreen with the same clip-rect technique as the `.visually-hidden`
  utility, rather than removed, so a screen reader still gets it once;
  a sighted narrow-viewport reader gets the column name from each
  `<td>`'s own `data-label` attribute instead, a markup contract
  documented at the top of the file for Task 7). Every interactive
  element (`.btn`, nav links, pagination, form controls) keeps a 44px
  minimum hit area. `:focus-visible` (with a plain `:focus` fallback for
  browsers without it) draws a visible, high-contrast outline on every
  focusable element and is never suppressed anywhere in the file. Status
  badges, alerts and the diff view pair color with text or a leading
  glyph, never color alone. The full palette was checked against the
  WCAG 2 relative-luminance formula rather than eyeballed: body and
  muted text both clear 7:1 on every background in the palette (AAA,
  not merely the 4.5:1 this task requires), tinted status text clears
  7.4:1 on its own tint, and the one color that conveys a form control's
  boundary on its own clears the separate 3:1 WCAG 1.4.11 non-text
  threshold — recorded as measurements in the file's own header comment,
  since a Perl test suite with no headless browser cannot assert what a
  human eye perceives as contrast.

  **Verification.** `t/50-render.t` (70 assertions) tests the escaping
  like an adversary rather than a formality: a `<script>` payload
  substituted into seven distinct positions (start, middle and end of a
  template, inside both attribute-quoting styles, two placeholders back
  to back, and as the whole template); double- and single-quote
  attribute-breakout payloads compared byte-for-byte against a
  hand-computed expected string, plus a combined quote+tag breakout; a
  value that is itself `{{a}}`, a raw value containing `{{{b}}}` for a
  `b` that is not in `%vars` at all (proving the substitution pass never
  revisits what it just inserted, since a recursive implementation could
  only be caught missing `b` by trying), and a value spelling another
  real key's raw marker, proving that other key's value is never pulled
  in; every fail-closed path (missing key on both markers, present-but-
  undef, present-but-reference on both the escaped path and the raw
  path, non-hashref vars, non-string template); and `render_file()`'s
  byte-safety, including `utf8::is_utf8()` asserted false on its result
  and a multi-byte UTF-8 sequence surviving both a pure disk round-trip
  and escaping of adjacent ASCII unchanged. Every one of the ten
  escaping guards in `Render.pm` (each of the five characters
  individually; the default marker's call to `escape_html()`; the
  missing-key check, distinct from the separate undef check it would
  otherwise be mistaken for; the undef check; the reference check on the
  raw path, which `escape_html()`'s own reference check cannot cover
  since raw output never reaches `escape_html()` at all; and the
  single-pass substitution itself) was removed one at a time, against
  the running suite, and confirmed to turn a specific named test red
  before being restored — the single-pass guard's removal (looping the
  substitution until stable, the naive way to write this) made the
  suite hang rather than fail, which is the point made concrete: that
  guard's absence is not a wrong render, it is a request that never
  completes. Full mapping in
  `.superpowers/sdd/webui-implementation/task-6-report.md`. The whole
  suite is 1477 tests (was 1407), `prove -I. t/`.
  (`ui-src/lib/ConfigServer/UI/Render.pm`, `ui-src/web/layout.html`,
  `ui-src/web/app.css`, `t/50-render.t`)

#### Task 5 fix round 3 — the R36 handshake alarm leaked past a `tls_wrap` that dies

- **2026-09-11** — Fixed `Server.pm`'s `_serve_accepted()` leaving the
  handshake watchdog armed when `tls_wrap` dies outright, rather than
  returning or returning false (found in the scoped re-review of fix round
  2's own R36 change). The cancellation (`Time::HiRes::alarm(0)`) sat on
  the line textually after the `tls_wrap` call with no `eval` around it, so
  a die skipped that line along with everything else in the function,
  leaving the handshake's alarm pending. Harmless today only because
  `run()` has no `eval` around `_serve_accepted()`, so an uncaught die
  takes the whole forked child with it and there is no second phase left
  for the leaked alarm to misfire into - the same "correct only by
  coincidence" shape R34's flat-8192 read had, where the cap happened to
  equal the read size. The coincidence here has a name: Task 9's mode-B
  daemon entry point is the obvious place to wrap this call in an `eval` so
  one bad connection does not kill the whole process, and the day that
  lands this stops being inert. The module's own comment, and fix round
  2's commit message, both also claimed the alarm was "cancelled on
  success or failure" - true of the code as it read, false of what it did
  on a die; fixed to match reality rather than left standing.

  `tls_wrap` is now called inside an `eval`; the handshake alarm is
  cancelled unconditionally immediately afterward regardless of how the
  `eval` ended, and if it died, the original error is re-raised unchanged
  - the same fate an uncaught die always had here, just with the alarm
  already off before it propagates. Verified with a new
  `t/40-http-parse.t` case: a `tls_wrap` that dies, driven through
  `_serve_accepted()` from outside its own `eval`, followed immediately by
  `Time::HiRes::alarm(0)` to both cancel and read back whatever is still
  pending - a direct, deterministic check (the builtin and
  `Time::HiRes::alarm()` both return the remaining seconds of any
  previously scheduled alarm, 0 if none is pending), not an inference from
  timing. Confirmed by reverting to the unconditional, un-eval'd
  cancellation and watching the new case fail with the full
  `handshake_timeout` (5s, chosen long enough that a leak is unmistakable)
  still reading as pending.
  (`ui-src/lib/ConfigServer/UI/Server.pm`; `t/40-http-parse.t`)

#### Task 5 fix round 2 — the fix for R31 could itself kill a slow-but-honest client

- **2026-09-11** — Fixed `Server.pm`'s `_serve_accepted()` charging the TLS
  handshake against the same watchdog budget the request phase needs
  (found in the scoped re-review of fix round 1's own R31 change, below).
  R31 armed one `Time::HiRes::alarm()`, sized to `header_timeout +
  body_timeout + write_timeout`, *before* `tls_wrap` ran, so a legitimate
  client with non-trivial handshake latency who then went on to use close
  to its own real allowance for headers, body and the response write could
  be killed having violated no single per-phase deadline — a failure mode
  that did not exist before R31, since before it there was no deadline
  here at all. `_serve_accepted()` now arms two alarms in sequence: a new
  `handshake_timeout` (constructor option, default
  `$DEFAULT_HANDSHAKE_TIMEOUT` = 10s) covers only `tls_wrap`, is cancelled
  the instant it returns, and only then — if the wrap produced real TLS —
  is a fresh alarm armed for `header_timeout + body_timeout +
  write_timeout`, the same sum as before but now starting from zero rather
  than continuing to run down a clock the handshake already spent from. A
  peer stuck in either phase is still killed, promptly, by that phase's
  own budget alone.

  The 10s handshake figure has no precedent in `docs/WEBUI-RPC.md` (§14.4
  is explicit that Mode B's TLS layer is entirely this task's own problem)
  and is reasoned from first principles: a TLS handshake is a
  machine-to-machine negotiation with no human typing or reading in the
  loop, unlike `HEADER_TIMEOUT`'s 15s, which has to leave room for a
  client formulating a request — so it does not need that much slack. What
  it does need is margin for a genuinely slow or lossy network path (a
  congested mobile link, a slow VPN, a retransmit or two); a real
  handshake, even a bad one, completes in low single-digit seconds. 10s is
  an order of magnitude above that normal case while staying under
  `HEADER_TIMEOUT`, and it is a strict improvement over fix round 1's own
  number for the attack R31 exists to stop: a child stuck in a silent
  handshake is now reaped in at most 10s rather than holding its slot for
  the full combined (header+body+write) budget as it did immediately after
  R31 first shipped.

  Tested both ends, in `t/40-http-parse.t`: the R31 "silent peer" case now
  sets `handshake_timeout` explicitly and short, so it is proven by the
  handshake's own budget rather than (as fix round 1 left it) by
  coincidentally matching the 10s default against a 10s simulated stall. A
  new case stages a `tls_wrap` that spends most of a short
  `handshake_timeout`, then a request that is already fully buffered
  (so the request phase itself takes negligible time) — total elapsed
  exceeds what the *removed* single combined budget would ever have
  allowed, and the connection still succeeds, because each phase now has
  its own budget. Verified by reverting to the single-budget shape and
  confirming both cases go red — the R31 case for the wrong reason (killed
  by the request-phase sum instead of the handshake budget) and the new
  case for the R36 bug itself (watchdog fires on an honest, merely slow
  client).
  (`ui-src/lib/ConfigServer/UI/Server.pm`; `t/40-http-parse.t`)

#### Task 5 fix round 1 — the TLS handshake had no deadline, the accept loop could spin, and three fixes had code but no test proving any of it

This round finishes work a previous session started and could not complete:
`f3fb785` left `HTTP.pm`/`Server.pm` already carrying code for R31, R32 and
R34 below, but the test count was unchanged, so none of it was proven. Each
inherited change was verified against `task-5-review.md`'s own description
before being trusted, by disabling it and confirming a specific test goes
red, then restoring it — the same requirement this round's own new guards
are held to.

- **2026-09-11** — Fixed `Server.pm` running the TLS handshake on a
  blocking socket with no deadline of its own (`task-5-review.md` Critical
  C1/R31). `HTTP.pm`'s two 15s read deadlines sit *after* `start_SSL()`
  returns, so a peer that completes the TCP handshake and then sends
  nothing — or dribbles one handshake byte a minute — parked the forked
  child inside `SSL_accept` forever; 32 such connections, no more, denied
  the admin UI with zero attacker bytes ever reaching `HTTP.pm`'s own
  defences. `_serve_accepted()` now installs a `Time::HiRes::alarm()`
  watchdog, sized to the handshake *plus* the header, body and write
  budgets combined, immediately after fork and before `tls_wrap` runs;
  `$SIG{ALRM}` is injectable (`watchdog_exit`, default `POSIX::_exit(1)`)
  so a test can observe it firing instead of being killed by it.
  `Time::HiRes::alarm()`, not the builtin, because the builtin truncates to
  whole seconds and would round a test's short injected budget down to
  "cancel the alarm" rather than "fire almost at once". Verified by
  disabling the alarm call and confirming a `tls_wrap` that never returns
  hangs the full 10s a test staged for it, rather than being cut off inside
  the configured budget — this is inherited code; this round supplied the
  test and the confirmation, not the fix itself.

- **2026-09-11** — Fixed `tls_wrap` (and `listener`) being un-gated
  constructor-injection seams that could run the whole request pipeline —
  parse, dispatch, response — over a raw, unencrypted socket, past every
  preflight refusal including the `IO::Socket::SSL` one (`task-5-review.md`
  Important I3/R32). `_serve_accepted()` now asserts
  `UNIVERSAL::isa($tls_socket, 'IO::Socket::SSL')` before handing the
  socket to `HTTP.pm`, and closes both handles without a byte served
  otherwise. `UNIVERSAL::isa`'s function form, not a method call, because a
  failed handshake can hand back something that is not a blessed reference
  at all, and a method call on that would die instead of simply failing the
  check. Verified the same way: disabling the `isa()` check and confirming
  a plaintext pass-through `tls_wrap` gets a real request answered over the
  unverified socket — again inherited code, newly proven here.

- **2026-09-11** — Fixed `run()`'s `accept()`-failure handling treating
  every error identically to `EINTR` (`task-5-review.md` Important I2): on
  a persistent condition — `EMFILE`/`ENFILE` from descriptor exhaustion,
  which the stuck-handshake bug above made directly reachable —
  `accept()` returned immediately and forever, spinning the loop as fast
  as the CPU allowed with no log line anywhere to say why the admin UI had
  gone unresponsive. The policy is now `_accept_backoff($self, $is_eintr,
  $errno_text)`, extracted out of `run()`'s loop specifically so it is
  testable without a real listening socket or fork — `run()` itself sits
  behind `preflight()`, which always refuses in this workspace because
  `IO::Socket::SSL` is not installed, so nothing inside `run()`'s own loop
  can be driven from a test at all. `EINTR` returns at once, with nothing
  written and no delay; anything else logs one line to `STDERR` naming the
  errno and backs off (`select(undef,undef,undef,$self->{accept_backoff})`,
  configurable, default 0.1s, a new constructor option). Verified in three
  directions: `EINTR` alone produces no log line and near-zero elapsed
  time; a non-`EINTR` error alone produces the log line and the backoff;
  and collapsing the two branches back into one (always backing off, or
  never) turns each of those assertions red in turn.

- **2026-09-11** — Added the actual regression test for the bug fixed
  during Task 5's own verification pass and described in
  `task-5-report.md` (`task-5-review.md` Minor M5/R34): `_await_first_byte()`'s
  first read is sized from `$max - length($$bufref)` rather than a flat
  `8192`, which was already correct in the inherited tree but was, as the
  review notes, "inert only because that cap happened to equal 8192
  today" — nothing in the suite lowered `$MAX_REQUEST_LINE` to make the two
  numbers diverge, so nothing proved the fix does anything. The existing
  "oversize request line" case in `t/41-http-hostile.t` cannot be that
  test either: at `$MAX_REQUEST_LINE + 100` bytes against the real
  8192-byte cap, it is too large to ever arrive in a single `sysread()` and
  never touches `_await_first_byte()`'s own read size at all. The new case
  lowers `$MAX_REQUEST_LINE` to 20 and sends a line short enough (about 100
  bytes) to arrive whole, terminator included, in one read from a
  `File::Temp`-backed handle — exactly the shape that let an over-cap line
  slip past the length check before this task's original build fixed it.
  Verified by reverting the read size to a flat `8192` and confirming the
  new case goes red — the line is accepted whole, with no fault at all,
  once the first read is no longer bounded to the (lowered) cap.

- **2026-09-11** — Closed the two parts of R33 (Important, entirely
  untouched by the previous session), both in `t/41-http-hostile.t`:

  First, the percent-escape hex-validity guard (`HTTP.pm:486`) was not
  isolated by any test. `%zz` and `%0` both still return `400` with that
  guard deleted, but not because of it — Perl's `hex()` stops at the first
  non-hex character rather than failing, so `hex('zz')` and `hex('')` are
  both `0`, and both inputs decode to a NUL byte and are caught by the
  *next* guard down instead. `%4z` is the one input that tells the two
  guards apart, verified by hand in the previous round and never turned
  into a test: `'4z'` still fails the two-hex-digit check (refused, guard
  present), but `hex('4z')` is `4`, not `0`, so with only the hex-validity
  guard gone it decodes to byte `0x04` and passes with **no fault at all**.
  Added for both the path and a query value, confirmed by disabling the
  hex-validity guard and watching `%zz`/`%0` stay green (400, wrong
  message) while `%4z` goes red (no fault raised, not merely the wrong
  one).

  Second, the general form: no case in this file asserted *which* guard
  refused an input, only that some 4xx did, leaving thirteen distinct `400`
  guards (and, found during this pass, the two distinct `431` guards —
  header count versus a single header line too long) mutually
  indistinguishable — any one is deletable and another guard, or luck,
  catches the input with the suite still green. Every `400`-status case in
  the file, plus the `431` pair, now also asserts the specific fault
  message the guard that is supposed to fire actually produces. This is
  not decorative: verified by disabling the request-line/header-line
  bare-`\n` guard (`_clean_line`'s `\r\n\z` check) and confirming the
  *header-line* case goes red with no fault at all (the guard this row
  actually isolates, matching `task-5-report.md`'s own note), while the
  *request-line* case's message assertion goes red for a **different**
  reason — it is still refused, just via the version-allowlist guard
  further down, with a different message — proving that row was never a
  clean isolation of the CRLF guard and would not have caught its removal
  before this change. Also verified by disabling the header-count guard
  alone and confirming only the "200 headers" case goes red, leaving the
  unrelated "oversize header line" case (a different guard, same `431`)
  untouched.
  (`ui-src/lib/ConfigServer/UI/HTTP.pm`, `ui-src/lib/ConfigServer/UI/Server.pm`;
  `t/40-http-parse.t`, `t/41-http-hostile.t`)

#### Task 5 — the minimal HTTP/TLS core that faces the network (Mode B)

- **2026-09-11** — Added `ui-src/lib/ConfigServer/UI/HTTP.pm`: the only HTTP
  parser in this project that ever reads bytes a network peer chose. It is
  deliberately small and deliberately strict, because the design's preferred
  deployment (a front web server in Mode A) has no HTTP parser of ours facing
  the network at all — this module exists for the other mode, standalone,
  which reintroduces exactly the risk Mode A removes.

  What it accepts: `GET` and `POST` only, origin-form targets, `HTTP/1.0` and
  `HTTP/1.1`, a request line of at most 8192 bytes, at most 64 headers of at
  most 8192 bytes each, and a body of at most 65536 bytes that is
  `application/x-www-form-urlencoded` (or has no `Content-Type` at all — the
  shape a plain `<form>` without `enctype=""` POSTs as) when one is sent.
  Every other method is refused with a `405` before the request line's
  target, version or headers are even parsed — not merely before the body is
  read. There is no keep-alive: every response carries `Connection: close`
  and this module answers exactly one request per filehandle it is given.
  There is no chunked transfer encoding — `Transfer-Encoding`'s mere
  presence, any value, is a `400` — no multipart, and no byte-range support.

  Percent-decoding (`docs/WEBUI-RPC.md` §14.2, for the path and the query
  string this module is the one that decodes) refuses rather than guesses: a
  `%` not followed by two hex digits is a `400`, and so is any escape —
  valid or not — that names a NUL byte, in a path or a query key/value. The
  decoded query hash is raw bytes with no UTF-8 flag set, matching exactly
  what `ui-src/bin/csf-ui`'s own `_url_decode()` produces for a form body, so
  a value from either source reaches `Proto::as_chars` the same way. A
  `..%2f..%2f` traversal path is deliberately *not* rejected here — §14.1 is
  explicit that routing is exact-string match one layer up, so this decodes
  it and lets the router's `404` be the `4xx` for that case.

  Every read is bounded by a deadline (15s for the request line and headers
  together, 15s more for the body) and every cap is enforced by bounding
  what is read *before* it is trusted: a declared `Content-Length` is
  checked against the 65536-byte cap and refused with `413` before a single
  body byte is read, so a peer cannot make this process allocate a buffer
  sized by a number it chose. A single header or request line that runs
  past its own cap with no newline in it is refused at exactly that many
  bytes, never more — fixed during this task's own verification pass after
  a test proved a line arriving in one large chunk (its newline included)
  could still slip a few hundred bytes past the 8192-byte cap, because the
  per-read chunk size was a flat 8192 rather than bounded to the cap's
  remaining headroom; reads are now sized to never let the buffer exceed the
  cap in the first place. A `Content-Length` larger than what the peer
  actually sends is refused immediately on a clean close, or after the body
  deadline on an idle connection that never closes — the fault in the idle
  case is marked `silent`, so the connection is dropped rather than
  answered, the same "a slow client is dropped" reading `docs/WEBUI-RPC.md`
  §7 already gives the helper side. Two lines are never accepted as framing:
  a bare `\n` with no preceding `\r` (LF without CR), and any other `\r` not
  immediately followed by `\n` (CR without LF, whether malformed or an
  attempt to fold a second header into one line) — checked identically for
  the request line and every header line. Duplicate `Content-Length` or
  `Host` headers are refused outright rather than folded, because folding is
  exactly the ambiguity a request-smuggling payload needs from those two
  headers specifically; every other repeated header folds last-value-wins,
  which §14.1 leaves to the producer's choice. `write_response()` puts
  §14.3's response structure on the wire, computing `Content-Length` from
  the body's own byte length rather than trusting anything csf-ui supplies,
  and refuses to let a response header carry a literal CR/LF or override
  `Connection`/`Content-Length` — csf-ui's own responses never try to, but
  this tier does not take that on faith either.
  (`ui-src/lib/ConfigServer/UI/HTTP.pm` — new file; `t/40-http-parse.t`,
  `t/41-http-hostile.t` — new files)

- **2026-09-11** — Added `ui-src/lib/ConfigServer/UI/Server.pm`: TLS
  termination, the `ui.conf` startup gate, the IP allowlist, and the
  accept/fork loop for Mode B. Three refusals, fail closed, each named
  rather than silent:

  **No `IO::Socket::SSL`, no start.** Checked for real at `preflight()` time
  (`require IO::Socket::SSL`) and never assumed — this module never falls
  back to plain HTTP, because a firewall admin interface served unencrypted
  is worse than one that will not start. `IO::Socket::SSL` is not installed
  in this workspace by design (G1), which is what lets this refusal be
  tested for real rather than only through a mock.

  **An empty or missing `UI_ALLOW`, no start.** `read_ui_conf()` is the
  strict gate for all six `ui.conf` keys (`docs/WEBUI-RPC.md` §10), not only
  the four (`UI_MODE`, `UI_LISTEN`, `UI_PORT`, `UI_ALLOW`) this task's own
  checklist row names — `ui-src/bin/csf-ui`'s own `ConfigServer::UI::App`
  already documents that its own lenient two-key reading of `ui.conf` is not
  a substitute for "the long-running process" owning the full contract, and
  this is that process. An unknown key, a duplicate key, or a line that
  matches none of comment/blank/`KEY="VALUE"` refuses the whole file, naming
  the key or line rather than silently ignoring it — the same reasoning §10
  itself gives for why a typo'd `UI_ALOW` must not be able to hide as "no
  allowlist". `UI_ALLOW` itself is validated per §4.1 with neither the
  removal carve-out nor the mutating prefix floor (`Proto::ip_info($entry)`
  with no options is exactly that), 1–64 entries, `/0` still rejected.

  **`UI_MODE` other than `"b"`, no start** — Server.pm's own addition, not
  named in §10 (which only requires the value be `"a"` or `"b"`): this
  binary is specifically the Mode-B listener, and a syntactically valid
  `"a"` still means it has nothing to bind and should not be running.

  The allowlist itself (`peer_allowed()`) is checked on the connecting
  address *before* TLS ever begins — the cheapest possible rejection for a
  peer with no business here, spending neither a handshake nor a parse on an
  address the administrator never listed — using the same packed-address
  CIDR-containment arithmetic `ConfigServer::UI::Proto::ip_info()` already
  computes, not a second implementation of it. `handle_connection()` is the
  full per-request pipeline (parse via `ConfigServer::UI::HTTP`, add `peer`,
  dispatch to `ConfigServer::UI::App`, write the response) and never lets a
  die — a parse fault, or a bug in whatever `App` turns out to be — escape
  to its caller, which in production is a forked child of the accept loop:
  every failure becomes a well-formed HTTP response, or, for a fault marked
  silent, a closed connection with nothing written at all.

  The accept/fork loop (`run()`) mirrors `csf-ui-helper`'s own accept loop —
  a per-connection fork, a concurrency cap, `SO_REUSEADDR`, signals reset in
  the child — and, like that loop, is not itself exercised by this task's
  tests: it needs a real listening socket, a real fork, and, in production,
  a real TLS library this workspace does not have installed. Everything up
  to and including one connection's handling is a plain function or takes
  its socket as an argument instead, so `t/40` and `t/41` exercise all of it
  directly over `socketpair()`s and a fake `App`. The TLS certificate/key
  path (`/etc/csf-ui/ssl/{cert,key}.pem`) is this module's own placement
  inside the already-frozen `/etc/csf-ui/` tree — `docs/WEBUI-RPC.md` names
  no path for Mode B's TLS material, and this task adds no new `ui.conf`
  key to name one, so this is not yet confirmed against whichever task
  provisions the certificate.
  (`ui-src/lib/ConfigServer/UI/Server.pm` — new file; `t/40-http-parse.t` —
  new file)

#### Task 4 fix round 1 — a rate limiter that stopped enforcing for the third time, connect() outside its own timeout, and a route table with no floor

- **2026-09-11** — Fixed `RateLimit.pm` failing OPEN under exactly the
  failure mode `docs/WEBUI-RPC.md` §7 exists to name — *"a limit that cannot
  be counted is not a limit"* — and that this project has now shipped twice
  before: once in the helper's own rate limiter (Task 2), and now here,
  arriving by a different door. `_write_state()` did not check `print`'s or
  `close`'s return value, so a short write under `ENOSPC` still reached
  `rename()` and landed a truncated file on top of good state; `_read_state()`
  then read anything it could not parse as `{}` — indistinguishable from "no
  failures yet". Chained together: fill the disk, then guess a password
  freely. Both are fixed at the source — a write is never renamed into place
  unless every byte of it is confirmed written, and unparseable content is
  now `undef` (fail closed) rather than `{}` (fail open) — and cited to §7 in
  the code so the next state-file module in this tree does not have to
  re-derive the lesson a third time.

  Also fixed in the same module: `record_failure()` pruned only the bucket
  it was touching, so a key that failed once and was never seen again sat in
  the file forever — the remote-triggerable route to the `ENOSPC` above, from
  an unauthenticated caller with a large address range. Every write now
  prunes every key, and a new `max_keys` cap (default 4096) refuses to admit
  a brand-new key once the table is full, rather than growing without limit.
  (`ui-src/lib/ConfigServer/UI/RateLimit.pm`; `t/31-ratelimit.t` — a corrupt
  state file, a genuinely short write staged with the same FIFO technique
  `t/11-helper-validate.t` uses for the helper's audit log, unbounded growth,
  and the key cap, each verified by reverting the fix and watching the
  specific test fail)

- **2026-09-11** — Fixed `Client.pm`'s 10-second budget not covering
  `connect()`. Measured: a blocking `AF_UNIX` `connect()` to a listener whose
  backlog is full does not return until the listener accepts, with no
  timeout of its own — and "16 children busy, 32 queued" (`csf-ui-helper`'s
  own limits) is a reachable state, not a contrived one. `IO::Socket::UNIX`'s
  `Timeout` constructor option does not reliably detect this for `AF_UNIX`
  either — measured returning a "connected" socket for every attempt against
  a saturated listener. `Client.pm` now performs its own non-blocking
  `connect()`, waits on the same deadline as everything else in the call, and
  reads `SO_ERROR` once the descriptor is writable, rather than trusting that
  writability alone means success. (`ui-src/lib/ConfigServer/UI/Client.pm`;
  `t/32-client.t` — reproduced directly against a saturated listener, and
  confirmed by reverting to the old blocking connect and watching the test
  hang until an external timeout killed it)

- **2026-09-11** — Fixed `csf-ui`'s `@ROUTES` extension shape defaulting to
  *unenforced*: a `handler` row ran with no session check, no role check and
  no CSRF check unless it re-implemented all three itself, which is exactly
  backwards for an interface Task 7 is about to build five screens on top
  of. Every route — `op` or `handler` alike — now runs through one shared
  gate (`_gate()`) before anything route-specific executes; the only way to
  skip it is the explicit, visible `anonymous => 1` that `/api/login` alone
  carries, matching `docs/WEBUI-RPC.md` §5.14's "pre-session" reading. A new
  `t/33-app.t` test pushes a synthetic mutating `handler` route and confirms
  it is refused with no session, refused with no CSRF token, and only then
  reaches its own body — the same route shape Task 7 will actually use.

  A second, mechanical test now binds `@ROUTES` itself to `docs/WEBUI-RPC.md`
  §5's Mutates and role columns — for each of the thirteen non-authenticate
  operations, that a route exists, that its `mutates` flag matches the
  contract, that `support` is set on `list` and `grep` and nowhere else, and
  that no mutating operation is reachable by `GET` — the same reasoning
  `t/12-contract-enum.t` already applies to the error enumeration, so a
  future row that forgets `mutates => 1` fails a test instead of shipping
  silently.

  `/api/logout` moved onto the same shared gate as a consequence rather than
  as a separate fix, which also closed a smaller gap noted in review: logout
  with no session at all used to answer `200` with no check performed; it now
  requires a session like anything else on this gate (a new `any_role => 1`
  flag, since either role may end its own session).

  Also added: the CSRF nonce this tier mints was previously delivered
  nowhere a client could read it back, leaving the `X-CSRF-Token` header path
  this tier already accepted with no way to ever be populated. A successful
  login's response now includes it, and a new `GET /api/session` route (no
  RPC call, the same standing as `/api/logout`) returns it for any later page
  load that did not itself just log in. A server-rendered template has a
  third path needing no route at all: `_gate()` hands every non-anonymous
  `handler` the session object directly, and `$session->{csrf}` is that
  page's copy — documented in `@ROUTES`'s own header comment, so Task 6/7 do
  not have to rediscover it by reading `_gate()`'s source.
  (`ui-src/bin/csf-ui`; `t/33-app.t`)

- **2026-09-11** — Fixed `csf-ui` silently degrading protection when the
  request structure's `peer` field was missing or empty — `RateLimit.pm`
  treats an unkeyed address as "not blocked" by design (it must never refuse
  to persist a failure just because it was handed nothing to key on), so a
  request with no `peer` got username-only protection with nothing anywhere
  saying so, and the access log recorded who asked as an empty string.
  `csf-ui` now refuses any request with a missing or empty `peer` outright,
  before routing or session lookup runs. A second, related gap — no size
  limit was ever stated for the request body — is closed the same way: a
  body over 65536 bytes (the same figure as the wire line cap, for
  consistency rather than derivation) is refused before any parsing is
  attempted, as a backstop behind whatever limit Task 5 imposes earlier.
  (`ui-src/bin/csf-ui`; `t/33-app.t`)

- **2026-09-11** — Added `docs/WEBUI-RPC.md` §14: the normalised request and
  response structure between `csf-ui` and Task 5, written into the frozen
  contract rather than left living only in `csf-ui`'s own header comment and
  a task report — the same reasoning an earlier amendment in §11.9 already
  used for two interpretations a review found living in one task's report
  instead of the document every task reads. Closes three gaps a review found
  the shape "implementable but not guess-free" over: `peer` is now mandatory
  and explicitly required to be per-connecting-client, never a constant, and
  never taken from a client-supplied header; a body over 65536 bytes is
  refused (§14.1, enforced in the same commit); and the byte-versus-character
  question after URL-decoding is answered directly, from measurement rather
  than assumption — `JSON::Tiny` decodes a JSON body's string values into
  proper UTF-8-flagged Perl characters, while this tier's own form-body
  decoder produces raw, unflagged UTF-8 bytes for the identical logical
  input, and both are correct: `Proto::as_chars()` already normalises either
  shape, and §14.2 tells Task 5's query-string decoder to produce the same
  raw-byte shape `_url_decode()` does, so the three paths (JSON body, form
  body, query string) cannot disagree about what a value means.

  Found and fixed in the same pass: `t/12-contract-enum.t`'s token scan
  matched `E_NAME` inside the unrelated identifier `COOKIE_NAME`, because
  nothing required a word boundary before `E_` — a false positive that
  would have fired on any future document mention of that constant, not only
  this one. The scan now requires `\bE_`, which excludes a match with no
  non-word character before it while changing nothing about which real `E_*`
  tokens it finds. (`docs/WEBUI-RPC.md`, `t/12-contract-enum.t`)

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

- **2026-09-11** — Fixed a fail-open in the helper found by review: **when a state
  file could not be rewritten, every rate cap and the password lockout silently
  stopped applying.** `_with_state` discarded the return value of the atomic
  rewrite, so under a full disk, a read-only remount or a wrong mode on the state
  directory the counters went on answering as though they were still counting —
  measured, twelve wrong passwords never locked and two hundred mutating calls
  produced no refusal. A counter that did not persist has not been applied, so
  every caller now refuses with `E_UNAVAILABLE` and the helper writes one line to
  its audit log and one to stderr, because the condition was otherwise invisible:
  an operator saw a working login form with no lockout and no diagnostic. The
  restart interval is now claimed before `csf -r` runs rather than recorded after
  it succeeds, since a mark written afterwards cannot refuse anything.

  Also fixed: **a caller could make a rejected request leave no audit record at
  all**, by padding it with thousands of short keys until the entry that logs it
  exceeded the line cap — §8 says every rejected request is logged, and the loss
  is the record of what an attacker tried. Logged argument keys are now capped in
  number and length and sanitised like values, an entry that still will not fit is
  replaced by a minimal line rather than dropped, and the append is looped so a
  short write cannot leave a truncated line for the next entry to run into.
  **§7's ten second deadline on `authenticate` is now implemented** — it was
  declared and never applied, which mattered because password records carry their
  own round count, so a store copied from another machine could make root hash
  without a ceiling. Three smaller ones: descriptors are marked close-on-exec
  explicitly rather than relying on Perl's `$^F` default, so nothing exec'd as
  root inherits the peer's socket; the files the helper slurps are capped at 16
  MiB, the one resource it had with no ceiling; and §5.13, §5.14 and §7 record the
  refusals above. (`ui-src/bin/csf-ui-helper`, `docs/WEBUI-RPC.md`,
  `t/11-helper-validate.t`)

- **2026-09-11** — `docs/WEBUI-RPC.md` §3.5 is the closed enumeration of error
  codes, and two changes had added reasons to it in other sections without
  amending the table — so the document answered differently depending on which
  section you opened. The `E_UNAVAILABLE` and `E_BACKEND` rows now carry the
  triggers added with the counter fixes above. Because this was the second time
  the same staleness occurred, and nine tasks remain that could each add a
  trigger, `t/12-contract-enum.t` now checks the mechanical half of it: every
  `E_*` token used anywhere in the contract must appear as a row of that table.
  It says plainly what it does not check — that an enumerated code is still
  reachable, and that a row's *description* covers every reason the code is
  returned, which is the defect it was written after and which no token-level
  check can see. Also added a test that stages a real short write, through a FIFO
  with a shrunk buffer and a reader that leaves mid-write, replacing an assertion
  that could only observe the property indirectly. (`docs/WEBUI-RPC.md`,
  `t/12-contract-enum.t` — new file, `t/11-helper-validate.t`)

- **2026-09-11** — Added `ConfigServer::UI::Auth` and `csf-ui-passwd`: the
  credential store the root helper's `authenticate` operation calls into, and
  the only way an account for it is ever created. This is what replaces
  `lfd.pl:9788`'s `$FORM{csfpassword} eq $config{UI_PASS}` — a plaintext
  password kept in `csf.conf` and compared with `eq`, which returns on the
  first differing byte and is a plain string anyone with a copy of `csf.conf`
  already has. Per Ruling R6, this module is loaded and called only by
  `csf-ui-helper`, in the root process; `csf-ui` never requires it and never
  opens `/etc/csf-ui/users`.

  Passwords are hashed with `crypt()` using a `$6$` SHA-512 salt — 16 bytes
  from `/dev/urandom` mapped onto crypt's 64-character alphabet, at a round
  count read from `ui.conf`'s `UI_CRYPT_ROUNDS` (default 100000, clamped to
  5000–2000000; `csf-ui-passwd` falls back to the default rather than refuse
  to run when `ui.conf` does not exist yet or the key is missing or
  out of range, since a password tool failing closed on a config problem
  would be one more way to lock an administrator out of the one store nothing
  else can open). Per Ruling R13, `$6$` is the only algorithm this module can
  produce or verify; the record format's `algo` field is kept for a future
  migration, but a record carrying any other value is refused on write and
  reported, not silently trusted, on read.

  `verify($hash, $pass)` — the exact seam `csf-ui-helper`'s `auth_verify()`
  already called through a placeholder — never compares the hash with `eq`.
  Both sides are reduced to a fixed-length digest first and every byte of
  both digests is visited in a loop that accumulates an OR of the
  differences rather than returning on the first one, so the comparison's
  cost never depends on where, or whether, the two inputs differ. It also
  never dies on a wrong password or a malformed stored hash: a die here is
  read by the helper as "the verifier could not run", which must never be
  how an ordinary wrong guess is answered, since that path leaves the
  per-username failure counter untouched — an unmetered guess is exactly
  what that counter exists to prevent.

  Writes to `/etc/csf-ui/users` are temp-file-and-`rename`: a new file is
  created `O_EXCL` at mode 0600 in the same directory, written, `fsync`'d,
  then renamed over the target — `rename(2)` replaces whatever directory
  entry is there without ever following it as a symlink, so the failure mode
  that matters is refusing beforehand, not racing during the replace. Both
  the reader and the writer refuse outright, before touching the file
  further, if the target is a symlink, is not a regular file, or (once it
  exists) is not owned by the process running this code — root, in
  production; a store already readable or writable by group or other is
  refused too, naming the mode it requires. There is no default account and
  no default password: a store that does not exist yet reads back as empty,
  not as an error, and nothing anywhere seeds one — `csf-ui-passwd add` is
  the only line of code that ever writes the first record.

  `csf-ui-passwd add <user> <role>`, `passwd <user>`, `delete <user>` and
  `list` read the password from a prompt with echo disabled (via
  `POSIX::Termios`, not a spawned `stty`) when run at a terminal, or a single
  line from standard input otherwise; it is never echoed, written to a
  command-line argument `ps` could show another user, or included in any
  error message. (`ui-src/lib/ConfigServer/UI/Auth.pm`,
  `ui-src/bin/csf-ui-passwd`, `t/20-auth.t` — new files; `t/11-helper-validate.t`
  — the placeholder-seam case in section 5.14 now exercises the real module
  instead of its absence)

- **2026-09-11** — Review round 1 on the credential store found four
  Important-severity defects, all measured against the tree rather than
  argued, and fixed here. **A correct non-ASCII password could never
  authenticate, and burned the S5.14 lockout counter trying**:
  `Proto::validate_pass` hands the helper a utf8-flagged *character* string
  for anything outside ASCII, `csf-ui-passwd` hashes raw *bytes* read from
  stdin with no such flag, and `crypt()` croaks on the flagged form rather
  than hashing the bytes underneath it — so a right password looked exactly
  like a wrong one, five times, and locked the account. `Auth.pm` now
  encodes both sides to the same UTF-8 octets before every `crypt()` call.

  **A line this module could not parse was silently deleted by the next
  write** — `read_store()` already dropped anything unparsable from its
  result, but nothing read the count it kept, so `write_store()` rewrote the
  file minus those lines on the very next `add`, `passwd` or `delete`,
  taking any comment and any record with it — including a four-field record
  the helper's own, looser reader still authenticates against. Every
  write-side operation now refuses outright, naming the line numbers,
  before touching the file; `list` (read-only, so safe to be more lenient)
  warns instead.

  **A record with an algorithm this module cannot verify made almost every
  other command die uncaught.** `parse_record()` deliberately admits such a
  row on read, so an operator can still be told to fix it with
  `csf-ui-passwd passwd <user>` — but `write_store()` re-serialised every
  record through the mint-time "only algo 6" gate, so the very next
  unrelated write crashed with exit 255, including the one command that was
  supposed to fix the row. Foreign-algo records are now carried through a
  write verbatim, unchanged, unless they are the one actually being reset —
  the mint-time gate still refuses to *originate* anything but algo 6.

  **The R17 placeholder's fail-closed branch lost its only test** when the
  previous commit replaced the block asserting its absence: the branch
  itself — a verifier that cannot answer gets `E_UNAVAILABLE` with the
  failure counter untouched (`csf-ui-helper:1863-1866`) — was never touched,
  but every remaining mock in the suite returns a defined verdict or dies,
  which is the neighbouring branch. Three lines restore it.

  Also fixed: the store's ownership check now compares against uid 0 when
  this process is actually root, rather than always against its own euid —
  identical in production, where the difference only mattered for a store
  deliberately owned by someone else; and `csf-ui-passwd`'s echo-off prompt
  now refuses to read a password at all if it cannot first confirm echo is
  disabled, rather than falling back to reading it with echo silently still
  on. (`ui-src/lib/ConfigServer/UI/Auth.pm`, `ui-src/bin/csf-ui-passwd`,
  `t/20-auth.t`, `t/11-helper-validate.t`)

- **2026-09-11** — Added the unprivileged web tier's request handler: the
  part of the replacement WebUI that terminates HTTP-level concerns and
  talks to `csf-ui-helper` over the socket Task 2 built, running as `csfui`
  with no shell and no capabilities. Four pieces.

  `Client.pm` connects to the helper's socket, sends one request, reads one
  response and enforces a 10-second wall-clock budget across the whole
  exchange. It never retries — not once, for any operation, mutating or
  not — which is the simplest way to guarantee a mutating call is never
  retried by accident: a client with no retry logic anywhere in it cannot
  retry selectively. A failure that never reached the wire (the socket is
  missing, the helper never answers, it answers something unparseable or
  with the wrong request id) is reported back shaped exactly like a real
  wire response, reusing `E_UNAVAILABLE`/`E_BACKEND` from the closed
  enumeration in `docs/WEBUI-RPC.md` §3.5 rather than inventing a second
  vocabulary for "the same kind of failure, but local".

  `Session.pm` implements the server-side sessions the brief calls for: a
  32-byte `/dev/urandom` identifier, base64url, naming a file under
  `/var/lib/csf-ui/sessions/` (mode 0600) that carries the username, role,
  a CSRF nonce and both timestamps — never a self-contained token the
  server cannot revoke. A tampered, expired or never-issued identifier is
  refused identically in every case, which is what stops a bad guess from
  learning anything about which case it hit. `csrf_ok()` compares the
  submitted token against the session's in constant time, visiting every
  byte regardless of where — or whether — a difference is found, the same
  discipline `Auth.pm` already applies to password verification.

  `RateLimit.pm` is the web tier's own login rate limiter — two rolling
  15-minute windows, one keyed by source address (cap 5) and one by the
  submitted username (cap 10), counting failed attempts only, state under
  `/var/lib/csf-ui/rl/`. It is independent of, and no substitute for, the
  helper's own per-username lockout (§5.14): that one holds even when this
  web tier is the attacker; this one acts earlier, before a guess ever
  reaches the socket. It has no dependency on `Client.pm` at all and cannot
  reach `csf.deny` — letting unauthenticated traffic add a firewall entry
  would let an attacker get a chosen address blocked, a victim's or a
  shared office egress. Every counter here fails *closed*: a state file
  that cannot be opened or rewritten is reported as "blocked", never as
  "not blocked, so proceed unmetered" — the specific failure mode this
  project's own helper was found to have during Task 2's review, silently,
  while its test suite kept passing.

  `csf-ui` is the request handler: given a normalised request (method,
  path, headers, body, peer address — the structure is defined and
  documented in this file's header comment, for Task 5 to produce), it
  routes, resolves the session, enforces role (`support` reaches `grep` and
  `list` only, admin reaches all fourteen — application-level, because the
  helper authenticates the process, not the session, so this is the only
  place it can happen), requires and constant-time-checks a CSRF token on
  every one of the eight mutating operations, calls the helper through
  `Client.pm`, and maps the closed error enumeration onto HTTP status per
  §3.5. It never parses HTTP and never touches a listening socket itself.
  Login calls the helper's `authenticate` and never opens the users file;
  every request, whatever its outcome, is written to
  `/var/log/csf-ui-access.log` (ts, request id, user, role, source address,
  method, path, status) joined to the helper's own audit log by the same
  request id — and never carries a header, a cookie value, a CSRF token or
  a request body, so there is no field in it a password could leak into.

  Several security-relevant behaviours were verified the hard way — the
  guard was reverted, the specific test that should fail was confirmed to
  fail, and the guard was restored — and two of those reverts found the
  test suite itself did not yet prove what it looked like it proved. A
  short-circuiting `eq` in place of `csrf_ok`'s XOR loop passed every
  existing assertion, because every one of them checked the boolean
  outcome and none checked that the comparison actually ran to completion;
  a `$COMPARE_VISITS` counter (the same test-only introspection `Auth.pm`
  already uses for password verification) was added so the loop's
  completeness is asserted directly rather than inferred from a result
  a short-circuit would also have produced. Separately, the id grammar
  check in `Session.pm`'s path-building was found to be provably
  unexercised by the existing "path-traversal-shaped id is refused"
  assertion — it passed only because `/etc/passwd` does not happen to
  parse as a five-field session record on the machine running the test,
  not because the guard caught it; a decoy file placed one directory above
  a session store, containing something that *would* parse as a valid
  session, is what actually exercises the guard. (`ui-src/lib/ConfigServer/UI/Client.pm`,
  `ui-src/lib/ConfigServer/UI/Session.pm`, `ui-src/lib/ConfigServer/UI/RateLimit.pm`,
  `ui-src/bin/csf-ui`, `t/30-session.t`, `t/31-ratelimit.t`, `t/32-client.t`,
  `t/33-app.t` — new files)

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
