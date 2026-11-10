# ROOTBACK

> A local-only instrument for the post-AI era: find a public kernel path back to root on the machine you already own, then reset your password.
>
> **Authorized machines only. Personal research project. No warranty.**

`rootback.dev` · [source](https://github.com/pysio2007/rootback)

---

## Why this exists

In the post-AI era, exploit research is abundant and cheap. Proof of ownership is not.

A model can summarize a CVE. It cannot prove that the computer in front of you is yours, that its kernel is the one you think it is, or that you can still recover it without a vendor account, a cloud console, or a rescue USB.

ROOTBACK is a gift to that gap. It reads the kernel actually running, matches it against a curated snapshot of public root-escalation and KVM/container-escape research, and — only after explicit consent — runs a narrow set of public PoCs. When one succeeds, it uses the root context to reset a local password and verifies the reset with a root-owned marker.

It does not phone home, persist, harvest credentials, or accept a remote target. There is no `--host`. The blast radius is the machine you are sitting at.

## Warning

- Use only on machines you own or have written authorization to test.
- Kernel exploits can crash or corrupt the machine. Page-cache exploits can leave a poisoned `/usr/bin/su` until caches are dropped or the machine reboots.
- Public PoCs are third-party code. They are fetched from upstream, not audited here. Pin or audit them with `--poc-dir` if that matters.
- Resetting a password can lock you out if you mistype the account. The tool validates the account and prints the new password once.
- No warranty. See [LICENSE](LICENSE).

## What it detects

Catalog snapshot: **2026-11-10**. 27 entries: 8 kernel LPEs, 5 KVM escapes, 7 container-runtime escapes, 1 userspace entry, and 6 legacy entries (2 of which have auto recipes).

The tables below are generated from [`catalog/cves.tsv`](catalog/cves.tsv), the single source of truth.

`auto` means the tool detects the CVE and can run a public recipe after explicit consent. `manual` means the tool detects it and prints the research link, but does not execute it: the prerequisite is host-side control of a VM/container, a kernel-specific offset profile, a second terminal, or the public PoC is a panic/DoS rather than a recovery path.

### Kernel local privilege escalation

| CVE | Name | Class | Affected (upstream) | Fixed (upstream) | Mode |
|---|---|---|---|---|---|
| CVE-2026-31431 | Copy Fail | kernel | Linux 4.14 - 6.18.21, 6.19.0 - 6.19.11 | 6.18.22, 6.19.12, 7.0+ | auto |
| CVE-2026-43284 | Dirty Frag (ESP) | kernel | Linux 4.11 - 6.18.27, 7.0.0 - 7.0.4 | 6.18.28, 7.0.5, 7.1+ | auto |
| CVE-2026-43500 | Dirty Frag (RxRPC) | kernel | Linux 5.3 - 6.18.28, 7.0.0 - 7.0.5 | 6.18.29, 7.0.6, 7.1+ | manual |
| CVE-2026-46300 | Fragnesia | kernel | Linux 3.9 - 6.18.32, 7.0.0 - 7.0.9 | 6.18.33, 7.0.10, 7.1+ | auto |
| CVE-2026-46331 | pedit COW | kernel | Linux 5.18 - 7.1-rc6 (vendor backports vary) | 5.10.260, 5.15.211, 6.1.177, 6.6.144, 6.12.94, 6.18.36, 7.0.13, 7.1-rc7 | auto |
| CVE-2026-43494 | PinTheft | kernel | Linux 4.17 - 6.18.32, 7.0.0 - 7.0.9 (CONFIG_RDS) | 6.18.33, 7.0.10, 6.12.91, 6.6.141 | auto |
| CVE-2026-46333 | ptrace fd theft | kernel | Linux 4.10 - 6.18.30, 7.0.0 - 7.0.7 | 6.18.31, 7.0.8, 7.1+ | manual |
| CVE-2026-46243 | CIFSwitch | kernel | Linux 2.6.24 - 6.18.33, 7.0.0 - 7.0.10 | 6.18.34, 7.0.11, 7.1+ | manual |

### KVM guest-to-host

| CVE | Name | Class | Affected (upstream) | Fixed (upstream) | Mode |
|---|---|---|---|---|---|
| CVE-2026-53359 | Januscape | kvm | Linux 2.6.36 - 7.1.2 (KVM/x86) | 7.1.3+ | manual |
| CVE-2026-64561 | Zapscape | kvm | Linux 5.9 - 7.1.5 (KVM/x86) | 7.1.6+ | manual |
| CVE-2026-89775 | KVM arm64 VNCR | kvm | Linux 6.16 - 6.18.50, 7.2.0 - 7.2.4 (KVM/arm64) | 6.18.51, 7.2.5, 7.3+ | manual |
| CVE-2025-40026 | KVM x86 I/O intercept | kvm | Linux 3.0 - 6.17.1 (KVM/x86) | 6.17.2, 6.18+ | manual |
| CVE-2026-46316 | ITScape | kvm | Linux 6.10 - 6.12.92, 6.18.0 - 6.18.34, 7.0.0 - 7.0.11 (KVM/arm64) | 6.12.93, 6.18.35, 7.0.12, 7.1+ | manual |

### Container runtime

These require control over container creation, a malicious image, or shared mounts. A version match alone is not an escape.

| CVE | Name | Class | Affected (upstream) | Fixed (upstream) | Mode |
|---|---|---|---|---|---|
| CVE-2025-31133 | runc masked /dev/null | container | runc <= 1.2.7; 1.3.0-rc.1 - 1.3.1; 1.4.0-rc.1 - rc.2 | 1.2.8, 1.3.2, 1.4.0-rc.3 | manual |
| CVE-2025-52565 | runc /dev/console | container | runc 1.0.0-rc3 - 1.2.7; 1.3.0-rc.1 - 1.3.2; 1.4.0-rc.1 - rc.2 | 1.2.8, 1.3.3, 1.4.0-rc.3 | manual |
| CVE-2025-52881 | runc procfs write | container | runc <= 1.2.7; 1.3.0 - 1.3.2; 1.4.0-rc.1 - rc.2 | 1.2.8, 1.3.3, 1.4.0-rc.3 | manual |
| CVE-2026-41579 | runc /dev symlink | container | runc < 1.3.6; 1.4.0-rc.1 - < 1.4.3; 1.5.0-rc.1 - < 1.5.0-rc.3 | 1.3.6, 1.4.3, 1.5.0-rc.3 | manual |
| CVE-2026-57231 | Podman image escape | container | Podman 1.8.1 - 5.8.3 | 5.8.4 | manual |
| CVE-2024-21626 | Leaky Vessels | container | runc <= 1.1.11 | 1.1.12+ | manual |
| CVE-2026-17106 | CopyEscape | container | Docker Engine/CLI < 29.7.0; Docker Desktop < 4.86.0; Compose < 5.4.0; go-archive < 0.3.0 | 29.7.0, 4.86.0, 5.4.0, 0.3.0 | manual |

### Userspace

| CVE | Name | Class | Affected (upstream) | Fixed (upstream) | Mode |
|---|---|---|---|---|---|
| CVE-2025-32463 | sudo chroot | userspace | sudo 1.9.14 - 1.9.17 | 1.9.17p1+ | auto |

### Legacy kernel LPEs

Kept for long-lived LTS/embedded machines. Most are detection-only here because their public PoCs need kernel-specific offsets, a second terminal, or deliberately panic the host.

| CVE | Name | Class | Affected (upstream) | Fixed (upstream) | Mode |
|---|---|---|---|---|---|
| CVE-2021-4034 | PwnKit | legacy | pkexec <= 0.120 | 0.121+ / vendor backport | auto |
| CVE-2024-1086 | nf_tables UAF | legacy | Linux 5.14 - 6.6 (unpatched branches) | 5.15.149, 6.1.76, 6.6.15, 6.7.3, 6.8+ | manual |
| CVE-2022-0847 | Dirty Pipe | legacy | Linux 5.8 - 5.16.10, 5.15.24, 5.10.101 | 5.16.11, 5.15.25, 5.10.102 | manual |
| CVE-2023-4911 | Looney Tunables | legacy | glibc 2.34 - 2.38 | 2.38-4+ / vendor backport | manual |
| CVE-2023-0386 | OverlayFS | legacy | Linux 5.11 - 6.2.1 | 6.2.2, 6.3+ | manual |
| CVE-2023-32233 | nf_tables UAF | legacy | Linux 5.0 - 6.3.1 | 6.3.2, 6.4+ | manual |

## How it works

```text
uname / config / modules / sysctls
              │
              ▼
   catalog match (stable fix matrix + feature gates)
              │
              ▼
   explicit authorization gate (--authorized + typed phrase)
              │
              ▼
   fetch public PoC → build → feed reset payload
              │
              ▼
   root-owned marker (uid 0, nonce) → password reset verified
```

Detection is a triage, not an attestation. The version matrices are upstream stable fix thresholds taken from the CVE records; distribution kernels backport fixes without changing their base version. A `VULNERABLE` result on a vendor kernel is therefore a hypothesis. `--include-medium` is required for non-interactive auto-runs of such candidates.

Feature gates matter: `algif_aead`, `esp4`/`esp6`, `act_pedit`, `rds`, `cifs.upcall`, unprivileged user namespaces, `ptrace_scope`, `/dev/kvm`, and nested virtualization. If the feature is absent, the exploit path is not reachable even when the kernel version is in range.

## Quick start

```bash
git clone https://github.com/pysio2007/rootback
cd rootback
./rootback.sh deps
./rootback.sh scan
./rootback.sh scan --json | jq .
```

Exploitation:

```bash
./rootback.sh exploit auto --authorized
```

Then type `I OWN THIS MACHINE` when prompted. An SSH session additionally requires `--allow-ssh`.

Explicit candidate, or a dry run:

```bash
./rootback.sh exploit CVE-2026-31431 --authorized --dry-run
./rootback.sh exploit CVE-2026-31431 --authorized
```

A dry run prints the recipe, source, tools, and target without fetching, building, or executing anything.

To fetch and build a recipe without executing it (useful for auditing the third-party code first):

```bash
./rootback.sh exploit CVE-2026-46331 --authorized --build-only
```

Reset without exploitation (already root, for example single-user mode):

```bash
sudo ./rootback.sh reset --authorized
```

Password handling:

```bash
./rootback.sh exploit auto --authorized --user root
./rootback.sh exploit auto --authorized --password-file /run/secrets/pw
./rootback.sh reset --authorized --save-password /root/rootback.pw
```

A generated password is printed once and is never written to the audit log. `--password` is supported but leaks through `ps`; prefer `--password-file`.

## Automatic paths

Only recipes with a public, reasonably deterministic PoC are marked `auto`:

| CVE | Recipe | Execution model |
|---|---|---|
| CVE-2025-32463 | sudo chroot | Direct command execution as root |
| CVE-2021-4034 | PwnKit | Direct command execution as root |
| CVE-2026-31431 | Copy Fail | Page-cache write, then `su` → root shell; payload on stdin |
| CVE-2026-43284 | Dirty Frag (ESP) | Page-cache write, then `su` → root shell; payload on stdin |
| CVE-2026-46300 | Fragnesia | Page-cache write, then `su` → root shell; payload on stdin |
| CVE-2026-46331 | pedit COW | Page-cache write, then `su` → root shell; payload on stdin |
| CVE-2026-43494 | PinTheft | Page-cache write, then `su` → root shell; payload on stdin |

Notes:

- PinTheft needs `CONFIG_RDS`; among common distributions RDS is enabled by default only on Arch.
- pedit COW uses `--ubuntu` on Ubuntu to attempt the AppArmor user-namespace bypass; Ubuntu 26.04 is expected to fail.
- Page-cache recipes can transiently corrupt the cached image of `su`. The payload drops caches after resetting the password. If an attempt fails before the payload runs, reboot or drop caches manually.
- Copy Fail, Dirty Frag, Fragnesia, pedit COW, and PinTheft are deterministic rather than race-based, but they still depend on the upstream PoC matching your kernel layout.

Manual entries are detection plus research links. They are not auto-run because they need host-side control of a VM/container, kernel-specific offsets, a second terminal, or because the public PoC is a panic/DoS rather than a password-recovery path.

## KVM and container escapes

These are detection-only by design:

- A KVM guest-to-host escape requires a malicious guest. The public Januscape PoC panics the host; the full escape is withheld. Zapscape and the arm64 VNCR bug need nested virtualization. ITScape has a public full-chain PoC for arm64, but it needs an arm64 KVM host, nested virtualization, and guest root.
- runc/Podman escapes require control over container creation, a malicious image, or shared mounts. If you are already inside a container without those, a version match is not enough.
- Copy Fail is the exception: the same page-cache primitive can cross a shared base image in some Kubernetes setups. A public Kubernetes PoC is linked from the Copy Fail entry.

## Safety model

1. **Local only.** No target argument, no network scanning, no lateral movement.
2. **Explicit consent.** `--authorized` plus a typed phrase, unless `--yes`; SSH requires `--allow-ssh`.
3. **Least persistence.** No cron, no systemd unit, no shell-profile changes. The only writes are the PoC workdir and the password change.
4. **Verification.** Success requires a root-owned marker containing a random nonce, written by the payload after `chpasswd` and a shadow-hash check. A user-namespace "root" cannot forge the file ownership.
5. **Cleanup.** Page-cache recipes drop caches in the root payload. The workdir is deleted on success; on failure it is kept for inspection with the payload removed.
6. **Audit.** `~/.local/state/rootback/audit.log` records time, uid, CVE, result, and kernel. No passwords.

## Requirements

- Linux, bash 4+, coreutils.
- Detection needs no build tools.
- Auto exploitation needs `git`, `gcc`, `make`, `python3` as appropriate, plus `chpasswd` and `base64`.
- A normal user account that can run the PoC. Running the tool as root is unnecessary for exploitation and makes it pointless.
- For container entries: `runc` or `podman` installed on the host being inspected.

`./rootback.sh deps` prints what is present.

## Verification status

The recipes come from upstream, and upstream lists the targets it tested. This repository does **not** claim that every recipe works on every kernel in range.

| Recipe | Upstream-tested targets |
|---|---|
| Copy Fail | Ubuntu 24.04, Amazon Linux 2023, RHEL 10.1, SUSE 16 |
| Dirty Frag | Ubuntu 24.04, RHEL 10.1, openSUSE Tumbleweed, CentOS Stream 10, AlmaLinux 10, Fedora 44 |
| Fragnesia | Ubuntu 6.8.0-111-generic |
| pedit COW | RHEL 10.0, Debian 13, Ubuntu 24.04; Ubuntu 26.04 fails under AppArmor |
| PinTheft | Arch (RDS default) |
| sudo chroot | Ubuntu 24.04 with sudo 1.9.16p2 |
| PwnKit | Ubuntu, Debian, Fedora, CentOS era |

Dry-run first, and keep a recovery path (console, rescue media) before changing a password.

## CI

Five workflows, with deliberately different claims:

| Workflow | Proves | Runs the exploit? |
|---|---|---|
| `ci.yml` | shell syntax, catalog/site consistency, smoke tests | no |
| `cve-matrix.yml` | one detection job per CVE (vulnerable + patched fixtures), one build-only job per `auto` recipe | no |
| `qemu-vulnerable.yml` | builds a known-vulnerable kernel and boots it under QEMU TCG on a hosted runner | no |
| `vulnerable-kernel.yml` | real detection/exploit on a self-hosted runner that already boots a vulnerable kernel | yes, manual and gated |
| `e2e-self-hosted.yml` | real exploit + root reset on a disposable self-hosted VM | yes, manual and gated |

The 27 detection jobs read `tests/cases.tsv` and drive `rootback.sh` through fixture overrides (`ROOTBACK_KERNEL`, `ROOTBACK_CONFIG`, `ROOTBACK_MODULES`, `ROOTBACK_USERNS`, `ROOTBACK_KVM`, `ROOTBACK_NESTED`, tool-version binaries in `PATH`). Each job asserts both a vulnerable fixture and a patched fixture, so a detector cannot pass by always saying "vulnerable".

The 7 build jobs run `tests/cve_matrix.sh --cve CVE-... --build-only`. They fetch and compile the upstream PoC but never execute it.

### Can a hosted runner use a vulnerable kernel?

Not by swapping its own kernel. A GitHub-hosted runner cannot reboot into a custom kernel, and a container always shares the host kernel. The supported path is a QEMU TCG guest:

- `qemu-vulnerable.yml` builds Linux 6.12.80 from `tests/kernel/build_vuln_kernel.sh` with the features the recipes need (`algif_aead`, ESP/ESPINTCP, `act_pedit`, RDS, io_uring, nf_tables, overlayfs, user/net namespaces), then boots it with `tests/qemu_probe.sh` and verifies `uname -r` inside the guest.
- QEMU TCG needs no `/dev/kvm` and does not touch the runner kernel. This is a **vulnerable-kernel boot probe**, not a claim that every exploit succeeds inside it.
- For real root/password-reset E2E, use `vulnerable-kernel.yml` on a disposable self-hosted runner that already boots the target kernel, or `e2e-self-hosted.yml` with the full `rootback.sh` flow.

`vulnerable-kernel.yml` requires `/etc/rootback-vulnerable-kernel`, an exact `uname -r` match, the `vulnerable-kernel` environment approval, and passwordless sudo for the post-check. `e2e-self-hosted.yml` additionally requires `/etc/rootback-e2e-disposable` and the typed input `DISPOSABLE`. Do not point either at a machine you care about.

## Repository layout

```text
rootback.sh              CLI, authorization gate, commands
lib/common.sh            logging, version math, introspection + test fixtures
lib/catalog.sh           TSV loader + Markdown/HTML renderers
lib/detect.sh            per-class detection
lib/exploit.sh           fetch / build / run / verify
lib/reset.sh             payload construction + chpasswd
catalog/cves.tsv         single source of truth (27 rows)
index.html               pure-HTML text site for rootback.dev
CNAME                    rootback.dev
tests/smoke.sh           detection, version, and payload tests
tests/cases.tsv          per-CVE vulnerable/patched fixtures
tests/cve_matrix.sh      fixture runner + optional build-only
tests/qemu_probe.sh      QEMU TCG vulnerable-kernel boot probe
tests/kernel/            deterministic vulnerable-kernel build
.github/workflows/       ci, cve-matrix, qemu-vulnerable, vulnerable-kernel, e2e
```

## Updating the catalog

Add a row to `catalog/cves.tsv`; keep 18 `|`-separated fields. `kfix` is a space-separated stable matrix; `X.Y.Z+` is a floor. Then render the tables:

```bash
./rootback.sh list --markdown --class kernel
./rootback.sh list --html
```

A new `auto` recipe also needs a branch in `lib/exploit.sh`. Do not mark a CVE `auto` without a public PoC and a tested build path.

## Design notes

- **Why shell?** It is inspectable, runs before you trust anything, and keeps the safety gate visible.
- **Why version heuristics?** There is no local, offline oracle for distribution backports. The tool shows its uncertainty instead of hiding it.
- **Why public PoCs?** Reimplementing kernel exploits would be worse for review and worse for safety. The value is selection, preconditions, orchestration, verification, and cleanup.
- **Why a text-only site?** No JavaScript, no analytics, no build step, no third-party supply chain.

## Credits

CVE research and PoCs belong to their authors:

- **Xint** — Copy Fail (CVE-2026-31431).
- **Hyunwoo Kim / @v4bel** — Dirty Frag (CVE-2026-43284, CVE-2026-43500), Januscape (CVE-2026-53359), Zapscape (CVE-2026-64561).
- **William Bowling / V12 Security** — Fragnesia (CVE-2026-46300), PinTheft (CVE-2026-43494).
- **Rich Mirch / Stratascale** — sudo chroot (CVE-2025-32463).
- **Qualys** — PwnKit (CVE-2021-4034), Looney Tunables (CVE-2023-4911).
- **Notselwyn, ly4k, leesh3288, xkaneiki, Liuk3r, Arinerron** — public PoCs used by the legacy recipes.
- **runc and Podman maintainers** — container-runtime advisories.

See the links in the catalog for each entry.

## License

MIT. See [LICENSE](LICENSE).

---

> The post-AI era will produce more exploits than any one person can read. The scarce thing will be the ability to prove that a machine is yours, that you understand what it runs, and that you can still get back in. This is a small attempt at that.
