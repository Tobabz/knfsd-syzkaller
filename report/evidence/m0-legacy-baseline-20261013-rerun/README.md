# M0 legacy baseline rebuild rerun (2026-10-13)

이 디렉터리는 issue #20의 최신 결정에 따라 `--skip-build` 없이 환경을
재빌드하고 L1–L8/R1–R5를 다시 실행한 증거다. 실행 에이전트는
**OpenAI Codex (GPT-5 기반)**다. 이는 작성 에이전트의 자체 실행이며 독립
review라고 부르지 않는다. 별도 reviewer의 판정은 issue/PR comment에 있다.

기존 [`m0-legacy-baseline-20261013/`](../m0-legacy-baseline-20261013/) 실행은
guest kernel이 3-patch `7.3.0-rc5-00003-g7f1a35fcc0e5`였으므로 이 실행으로
대체된다. 과거 디렉터리는 이력 보존을 위해 삭제하지 않았다.

## Rebuild and pretest gate

검증 대상 저장소 코드는
`f51d8fee2d49308e14d8c8b0b86f483046abad25`다. 이 호스트에는 `uv`
실행 파일이 없어 같은 Python entry point를 직접 실행했다.

```sh
python3 tools/bootstrap-kcov-env.py env \
  --base-image artifacts/bookworm-base.img \
  --ssh-key artifacts/bookworm.id_rsa \
  --deps-tar /tmp/m0-issue19-rerun/guest-deps-lane.tar.gz \
  --version 4.2 --variant kasan --update
```

| Gate | Actual | Expected | Result |
| --- | --- | --- | --- |
| Kernel commits after base `72d3fcf8…` | 4, tip `7bd83d51f06a0a47a9135d3330eb72392795e4b7` | 4 | PASS |
| Kernel series fingerprint | `bb2b3d825e86c0a99607835ca9a8838f211590822b5fd21e129dbd2e0ded51f1` | `bb2b3d825e86…` | PASS |
| syzkaller commits after base `801f0966…` | 21, tip `51df18e17ade097520080f812f57fff257021451` | 21 | PASS |
| syzkaller series fingerprint | `ef819dd8f3c4a46df9bc67a827ec09c32634a357aba88b052e73500a305b8271` | `ef819dd8f3c4…` | PASS |
| Pretest guest identity | `x86_64`, `7.3.0-rc5-00004-g7bd83d51f06a` | `-00004-g…` | PASS |

`env-manifest.json`, `kernel-commits.txt`, `syzkaller-commits.txt`와
`pretest-guest/`가 위 gate의 원문이다. bootstrap은 새 kernel/syzkaller를
clone하고 새 deps를 넣은 qcow2를 bake한 뒤 4개 lane verification boot까지
통과했다.

## Artifact identity

| Artifact | SHA-256 |
| --- | --- |
| KASAN `bzImage` | `3a6264281e5ac88f15b4bfb2de7eb90a2c5e90a9e4df04d1538f6f5fdd12293b` |
| KASAN `vmlinux` | `13148ddd18a154cf83ee911ad1bb5a6715606b5adbded47e7805060aab51c98c` |
| baked qcow2 | `c7f7870d2185af70cb01b656b6f04ee05026dee97611656e80a50e4c99629b9c` |
| converted raw image | `82e8232325a0db512abd2f3f36eae96f318163210292d461a6507373755a98e3` |
| guest relay | `1013d4456a86ede71310f8d4f305e814806ac7e4e78b4932fbb2f3c7e48b5d38` |
| guest replay probe | `612059336553c16b6f937a6285de77233aeb660074c27435bb7fcff413d82c0c` |
| bootstrap deps tar | `3ab67120ef4b8093184577bb0db22cea6da03965e8e3b85688c287512899f302` |
| per-run deps tar | `d0e000c71484ec3910cfeab2319d54876e577602281d02c74bbdce67a05151be` |
| `syz-executor` | `117bfcef05d604432595ddee94f95511e75331c18dab08a1fd5a6a31015307f6` |
| `syz-execprog` | `1542fe8b632a17c3423dab304d3f53e81318edefa69b787a04157834afbca3bf` |

relay와 replay probe는 같은 Debian 12.15 `linux/amd64` 컨테이너에서
빌드했다. `guest-build.provenance.txt`는 두 파일 모두 `ELF64 x86-64`, 최대
요구 버전 `GLIBC_2.34`, compiler/binutils와 소스·바이너리 해시를 기록한다.
두 deps tar의 gzip 컨테이너 해시는 다르지만 동일 relay를 포함하며 각 실행의
`result.json`이 실제 주입된 deps와 relay 해시를 고정한다.

## Commands and matrix

```sh
OUT=~/prune-evidence/m0-issue20-rerun-live \
IMAGE=~/prune-env-image.raw PROCS=4 \
docs/handoff/proxy-variable-length-edits/run-verify.sh \
  env kasan direct proxy raw

OUT=~/prune-evidence/m0-issue20-rerun-legacy \
IMAGE=~/prune-env-image.raw \
REPLAY_PROBE=/tmp/m0-issue19-rerun/guest-delta-replay \
docs/handoff/proxy-variable-length-edits/run-verify.sh \
  env kasan legacy-v1 legacy-v2 legacy-v2-refusal
```

L6와 L7은 각각 `guest-syzkaller-v2-append.prog`와
`guest-syzkaller-v2-append-raw.prog`를 `WORKLOAD`로 지정하고
`EXECUTIONS=1 PROCS=1`로 실행했다.

| Arm | Oracle | Result |
| --- | --- | --- |
| L1 direct | 4 proc × 30, `.extra` 30/30, `fs/nfsd` PC 1955 | PASS |
| L2 no-edit proxy | 4 proc × 30, `.extra` 30/30, `fs/nfsd` PC 1956, 4 lane proxy 오류 0 | PASS |
| L3 raw 4-route | 4 proc × 30, `.extra` 30/30, 4 lane route와 proxy 오류 0 | PASS |
| L4 v1 mutation | `armed=2 expired=2 applied=2 refused_orig=0` | PASS |
| L5 v2 replace | `edit_applied=1 edit_refused_orig=0` | PASS |
| L6 v2 struct append | `edit_applied=3`, proxy 오류 0, `.extra` 1/1 | PASS |
| L7 v2 raw append | `edit_applied=3`, proxy 오류 0, `.extra` 1/1 | PASS |
| L8 v2 wrong original | `edit_applied=0 edit_refused_orig=1` | PASS |

| Replay | Oracle | Result |
| --- | --- | --- |
| R1 v1 C2S exact | `expected=1 applied=1 refused_orig=0` | probe 0, relay 0 |
| R2 v1 S2C exact | `expected=1 applied=1 refused_orig=0` | probe 0, relay 0 |
| R3 v1 unmatched count | `expected=1 applied=0 refused_orig=0` | probe 0, relay 1 |
| R4 v1 original mismatch | `expected=1 applied=0 refused_orig=1` | probe 0, relay 1 |
| R5 v2 resize exact | `edit=1 expected=1 applied=1 refused_orig=0` | probe 0, relay 0 |

모든 성공 arm의 `guest_inventory`는
`7.3.0-rc5-00004-g7bd83d51f06a`를 기록하고 `execprog_rc=rc=0`, fatal
dmesg 0이다. v1/v2의 변조한 `applied_count` mismatch와 v2 original
mismatch도 relay `rc=1`로 거부됐다.

`negative-execprog/`는 의도적으로 invalid workload를 넣은 진단 경로
테스트다. wrapper는 예상대로 `rc=1`이었고 `executor.log`의
`parsed 0 programs`와 함께 `result.json`, `dmesg.txt`가 모두 남았다.
이는 L1–L8 실패가 아니다.

각 arm 디렉터리에는 `result.json`, phase1 command index,
executor/proxy/dmesg/serial log와 legacy delta/replay log가 있다. 대용량 KCOV
원시 파일과 `cov.tgz`는 저장소 크기를 제한하기 위해 포함하지 않았으며,
그 수·nonempty 여부와 symbolized counts는 `result.json`에 남겼다.
