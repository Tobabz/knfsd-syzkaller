# knfsd-syzkaller

A tool that builds **customized syzkaller fuzzing environments for fuzzing the NFS subsystem of the Linux kernel (knfsd)**.
It reflects a **remote KCOV coverage model** — collecting NFS server-side coverage remotely — on a KCOV + memory-sanitizer (KASAN or KCSAN) instrumented
kernel, and automates the whole pipeline from base image to a bootable fuzz VM (instrumented kernel + syzkaller binaries +
baked protocol image).

The checked-in customization series — **12 kernel patches + 17 syzkaller patches** (`bundle/patches/`) — is re-applied and
rebuilt against each new kernel/syzkaller RC by the forward-port pipeline (P0..P7). Environment validity is machine-checked
against the functional design-contract gates **R1,R2,R4,R5** (`tools/fport-design-gate.sh`; R3/R6 retired).

## Design highlights

| Aspect | Description |
|---|---|
| Instrumentation | KCOV + KASAN/KCSAN boot kernel |
| Coverage model | **Remote KCOV** — knfsd server-side coverage collected remotely (`remote_cover`, `cover_edges`); fs/nfsd and net/sunrpc PCs are attributed through this path |
| A/B causal check | A fuzzing experiment with remote coverage **ON/OFF as the only variable** — OFF: 0 fs/nfsd PCs, ON: 1,748 (gate R2) |
| Fuzz lanes | Fixed 34-call NFS lane workload · mount-namespace clients 0/1 (`/nfs-lane`) |
| NFS version | `--minor 1\|2` selects the NFS minor version (recorded in the manifest) |
| Boot model | Kernel is injected **outside the image** (`-kernel`), so the base image is kernel-agnostic; each new RC only needs a rebake |

## Host requirements

Build prerequisites are exactly those of the upstream components — this repo adds nothing to them:

- **Linux kernel**: toolchain and libraries per `Documentation/process/changes.rst` in the kernel tree
  (mirror: <https://www.kernel.org/doc/html/latest/process/changes.html>).
- **syzkaller**: Go, gcc, and VM prerequisites per [docs/linux/setup.md](https://github.com/google/syzkaller/blob/master/docs/linux/setup.md).

On top of that, this repo needs network access to `git.kernel.org` and `github.com` for the pinned source clones, and ~30 GiB of working space.

## Usage — commands, inputs, outputs

### 1. Create the base image (once per site)

```sh
sudo bash tools/make-base-image.sh --out artifacts
```

- **Input**: host root (sudo) + debootstrap + network (runs `create-image.sh -d bookworm` from the pinned syzkaller tree)
- **Output**: `artifacts/bookworm-base.img` (2 GiB raw ext4, kernel not included) and `artifacts/bookworm.id_rsa[.pub]` (SSH keypair, `.id_rsa` mode 0600)

### 2. Provision the fuzzing environment (build + bake)

```sh
python3 tools/bootstrap-kcov-env.py env \
  --base-image artifacts/bookworm-base.img \
  --ssh-key artifacts/bookworm.id_rsa \
  --deps-tar bundle/src/guest-deps.tar.gz \
  --minor 1
```

| Input | Description |
|---|---|
| `--base-image`, `--ssh-key`, `--deps-tar` (required) | Stage-1 outputs + guest dependencies |
| `--minor 1\|2` (required) | NFS minor version |
| kernel/syzkaller sources (default) | Cloned at pinned refs — kernel `v7.3-rc4` (git.kernel.org), syzkaller `801f09666` (github.com/google/syzkaller) |
| `--kernel-repo` / `--syz-repo` (optional) | Override clone URLs |
| `--kernel-tarball` / `--syz-tarball` (optional) | Offline source archives instead of clones |
| `--jobs N` (optional) | Parallel build jobs |

- **Behavior**: clone upstream → apply the series (12+17) → build `bzImage`/`vmlinux` and the syzkaller binaries → bake the bootable VM image (`bookworm-kcov-fresh-v1.raw`) → verify lane status
- **Output**: `env/` — `env/linux/arch/x86/boot/bzImage`, `env/linux/vmlinux`, `env/syzkaller/bin/...`, `env/bookworm-kcov-fresh-v1.raw`, and **`env/manifest.json`** (records all sources, pins, and build state)

### 3. A/B fuzzing · evidence collection

```sh
KOOV_SSH_KEY=artifacts/bookworm.id_rsa bash tools/run-ab.sh
bash tools/analyze-ab.sh
```

- **Input**: the provisioned `env/` (bzImage, image, vmlinux) and `KOOV_SSH_KEY` (default `bundle/src/bookworm.id_rsa`)
- **Behavior**: run the fixed 34-call lane workload on fresh `-snapshot` VMs with remote coverage **OFF/ON x 2 trials x 30 executions** (evidence T1..T6). The analysis stage symbolizes raw PCs, checks the per-NFS-operation handler gate, and reports throughput metrics (T7, T9)
- **Output**: `evidence/` — OFF/ON coverage, symbolized results, handler gates, exec/RPC throughput

### 4. Design-gate verdict

```sh
bash tools/fport-design-gate.sh -v
```

- **Input**: `env/manifest.json` + `evidence/` analysis
- **Output**: R1..R6 verdict (R3 retired) — **exit 0 = DESIGN HOLDS** (1 = gate failure, 2 = precondition violation)

### 5. Forward-port a new RC (kernel/syzkaller)

```sh
bash tools/fport-pipeline.sh --mode full --kind kernel \
  --target <fresh clone path> --new-base <new RC commit hash>
```

- **Input**: the new RC ref (commit hash) · **Output**: `runs/port-kernel-<stamp>/` run manifest + `port-run.md` (P0..P7 end-to-end: apply → build → gates → AB evidence → report)

## Command summary

| Stage | Command | Input → Output |
|---|---|---|
| Re-verify | `bash tools/fport-pipeline.sh --mode reuse` | existing evidence → gates re-run (fast, deterministic) |
| Base image | `sudo bash tools/make-base-image.sh --out artifacts` | sudo + debootstrap → `artifacts/bookworm-base.img` + keypair |
| Bootstrap | `python3 tools/bootstrap-kcov-env.py env --base-image ... --ssh-key ... --deps-tar ... --minor 1` | base · key · deps + upstream → `env/` (bzImage, binaries, image, manifest) |
| A/B | `KOOV_SSH_KEY=... bash tools/run-ab.sh && bash tools/analyze-ab.sh` | `env/` → `evidence/` (OFF/ON coverage, metrics) |
| Gates | `bash tools/fport-design-gate.sh -v` | manifest + evidence → R1,R2,R4,R5 (R3/R6 retired) (0 = HOLDS) |
| RC port | `bash tools/fport-pipeline.sh --mode full --kind kernel --target ... --new-base <hash>` | new RC → `runs/port-*` report |


## Repository layout

| Path | Contents |
|---|---|
| `tools/` | Pipeline P0..P7 · gates R1..R6 · A/B harness · base-image generation (usage: `tools/README.md`) |
| `bundle/` | Immutable inputs — patch series · guest deps · kernel config · manifests (`bundle/README-HANDOFF.md`) |
| `report/` | Design contract · verification results |
| `LICENSE` · `THIRD-PARTY-LICENSES.md` | MIT + vendor component attribution |

## License

MIT (`LICENSE`) — the kernel series is GPL-2.0 (derivative work); the syzkaller series is Apache-2.0; other vendor
attributions are listed in `THIRD-PARTY-LICENSES.md`.
