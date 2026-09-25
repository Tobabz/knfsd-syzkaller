# tools/ — knfsd-fuzz 포워드포트 도구

핸드오프 패치 시리즈(`bundle/patches/`: kernel 11패치 + syzkaller 15패치)를 **신규
커널/syzkaller rc로 전진 이식**하는 자동화 파이프라인입니다.
설계 계약(`report/design-spec.md` R1..R6, 기계 판정 `fport-design-gate.sh`)이 **최종 권위**이며,
패치 적용은 그 계약을 가시화하는 구현 단계일 뿐입니다. 사람의 손이 필요한 단계는
신규 rc 충돌 시 의도 인덱스(`patch-forward-compat.md §3`)를 보고 패치를 재생성하는 것 하나뿐입니다.

## 진입점

```sh
# 로컬 재검증 (빠름, 결정적 — 기본 모드)
bash tools/fport-pipeline.sh --mode reuse

# 신규 rc 포팅 (다시간; 신선 환경 필요)
bash tools/fport-pipeline.sh --mode full --kind kernel \
    --target <신선 클론> --new-base <해시>
```

| 옵션 | 값 | 기본 |
|---|---|---|
| `--mode` | `reuse` \| `full` | reuse |
| `--kind` | `kernel` \| `syzkaller` | kernel |
| `--target` | 대상 저장소 경로 | `<root>/env/linux` |
| `--new-base` | 신규 rc 커밋 해시 | "" |
| `--phases` | 실행할 페이즈 `a,b,..` | all |
| `--no-checkpoint` | sentinel 건너뜀 | off |
| `--help` | 사용법 출력 | - |

**종료코드**: `0`=DESIGN HOLDS · `1`=게이트 실패 · `2`=전제조건 위반 ·
`10`=적용 실패(인간 체크포인트 — bundle 갱신 후 재실행 시 P3부터 재개) · `20`=환경 실패

## 페이즈 P0..P7

| 페이즈 | 역할 |
|---|---|
| P0 provision | 도구 점검(git/python3/sha256sum/qemu-img) + WORK_ROOT 유도 |
| P1 detect | sentinel 파일로 이미-적용 판정 — kernel: `net/sunrpc/fuzz.c`, syzkaller: `sys/linux/fs_nfs_fuzz.txt` |
| P2 variant | `fport-variant.sh`로 rc 변형 기록 (스크래치 워크트리, target 불변) |
| P3 apply | `fport-apply.sh` 자체 적용 — base 일치/불일치 모두 sha 검증 + `git am -3`, drift 시 rerere+변형 fallback |
| P4 build-check | 빌드 검증 |
| P5 gates | `fport-design-gate.sh` R1..R6 판정 (DESIGN HOLDS?) |
| P6 evidence | 일반 코퍼스 AB 증거 (reuse: 기존 증거 재사용) |
| P7 report | `runs/port-<kind>-<stamp>/` 런 매니페스트 + `port-run.md` |

## 설계 게이트 R1..R6

```sh
bash tools/fport-design-gate.sh -v     # exit 0 = DESIGN HOLDS
```

| 게이트 | 계약 | 실측 (reuse 본체) |
|---|---|---|
| R1 build-integrity | 부트스트랩 `status: pass` | PASS |
| R2 remote-contribution | OFF fs/nfsd=0 vs ON>0, converged | PASS (0 vs 1,748) |
| R3 throughput-bound | ON/OFF exec·RPC/s ≥ 0.90 | PASS (0.9605) |
| R4 coverage-depth-general | `on_only ≥ 100` + 핸들러 랭킹 + `nfsd4_proc_compound` | PASS (1,748) |
| R5 evidence-chain-general | status/integrity/지분 ≥ 95%, 셋 6종 | PASS (100%, 6/6) |
| R6 apply-audit | 번들 2종 SHA256SUMS 자기 일치 + 핀 11/15 | PASS (2/2 · 11/11 · 15/15) |

## 경로 이식성 (전제: `~` 구조 배치·fetch·부트스트랩 산출물)

스크립트는 **자기 위치에서 WORK_ROOT를 유도**하며, 필요 시 환경변수로 오버라이드합니다:

| 변수 | 의미 |
|---|---|
| `KOOV_WORK_ROOT` | 작업 루트 (기본: `tools/..`) |
| `KOOV_BUNDLE` | 시리즈 경로 (기본: `<root>/bundle/patches`) |
| `KOOV_MANIFEST` | 부트스트랩 매니페스트 (기본: `<root>/env/manifest.json`) |
| `PORT_RUNS` | 런 기록 위치 (기본: `<root>/runs`) |
| `KOOV_PATCH_VARIANTS` | rc 변형 보관 위치 (기본: `<root>/tools/patch-variants`) |

## 도구 목록

| 도구 | 용도 |
|---|---|
| `fport-pipeline.sh` | 오케스트레이터 P0..P7 |
| `fport-apply.sh` | 자체 시리즈 적용 — `fport-apply.sh [--dry-run] [--variant-dir DIR] <kind> <target>` |
| `fport-variant.sh` | rc 변형 기록 — `fport-variant.sh <kind> <target> <new-base> [이름]` |
| `fport-design-gate.sh` | R1..R6 기계 판정 — `-v` |
| `fport-evidence.sh` | 증거 해시 기록 → `report/evidence-forward-port.sha256` |
| `fport-patch-hygiene.py` | 패치 위생 진단 |
| `fport-patch-risk.py` | 패치 리스크 진단 |
| `portability-check.sh` | 이식성 검증(/tmp 이동 실행 + 게이트) |
| `rename-scripts.py`·`check-rename-leftovers.sh` | 명칭 개명 대장·잔여 검증 |
| `README-tests.md` | T1–T7 검증 배터리 체크리스트 |
| `bootstrap-kcov-env.py` | env 부트스트랩 — 시리즈 적용은 `fport-apply.sh` 연동 |
| `run-ab.sh`·`analyze-ab.sh`·`run_ab_adapted.py` | 일반 코퍼스 AB 하네스 (관례 절대경로 — `<root>` 구조만 준비하면 됨) |
| `release-assembly.sh` | 배포 아카이브 조립 (SHA256SUMS 6항목 기반, raw 제외 — `--minimal`은 정확히 6항목만) |
| `tool-requirements.txt` | 팀메이트 호스트 의존성 정형화 (README-HANDOFF 'Reproduce' 전제) |

## 검증·증거 규율

```sh
bash tools/portability-check.sh          # 구문 + /tmp 실행 + 게이트 일괄
bash tools/fport-pipeline.sh --mode reuse
bash tools/fport-evidence.sh             # 도구·문서 수정 후 해시 재기록 필수
```

- 증거 해시는 `report/evidence-forward-port.sha256` — 수정하면 반드시 재기록.
- 번들(`bundle/patches/` 2종 시리즈)은 검증 기준 — 시리즈 수정 시 게이트 R6 재확인.

## 문서 맵

| 문서 | 내용 |
|---|---|
| `report/patch-forward-compat.md` | 해석·§3 의도 인덱스·§7 파이프라인 표/환경 이식/디렉토리 배치 |
| `report/design-spec.md` | Ψ/R1..R6 설계 계약 + 재구현 지침 |
| `report/script-rename-map.md` | 개명·삭제 대장 |
| `report/T1-T10-results.md` | T1–T7 검증 결과 + 증거 해시 |


## 환경 변수 (`KOOV_*`)

파이프라인·AB 하네스의 절대경로는 자기 위치에서 유도한다(이식 가능 트리).
`KOOV_WORK_ROOT`로 작업 루트를 잡으면 아래 파생 경로가 함께 따라간다.

| 변수 | 기본값 | 용도 |
|---|---|---|
| `KOOV_WORK_ROOT` | 스크립트 위치의 부모 | 작업 루트(파생 경로 기준) |
| `KOOV_ENV_DIR` | `$WORK_ROOT/env` | 커널·이미지·syzkaller 빌드 환경 |
| `KOOV_BUNDLE_DIR` | `$WORK_ROOT/bundle` | 불변 번들 루트 |
| `KOOV_EVIDENCE_DIR` | `$WORK_ROOT/evidence` | AB 증거 출력 |
| `KOOV_ABRUNNER_DIR` | `$WORK_ROOT/bundle/ab-runner` | phase 런너 소재지 |
| `KOOV_SYZ_ROOT` | `/home/fuzzer/tools/syzkaller-frozen-attribution` | syzkaller 바이너리 기본 경로(원본 핸드오프 호스트 폴백) |
| `KOOV_SYZ_BIN` | (미설정) | 외부 syzkaller 빌드 루트(`bin/linux_amd64/` 포함) — `run-ab.sh`가 `--syz-bin`으로 전달 |
| `KOOV_OUT` | `$TOOLS/ab-lane-fixture.sh` | lane fixture 생성 목적지 |

- `bundle/` 원본(`ab-runner/`·`corpus/`·`baker/`)의 내부 `/home/fuzzer` 기본값은 불변 정책상 유지 — 런타임 오버라이드(`KOOV_SYZ_ROOT` 등)로 대체.
- syzkaller 바이너리 외부화: `run_ab_adapted.py --syz-bin <빌드 루트>`(또는 `run-ab.sh`의 `KOOV_SYZ_BIN`)로 env/ 기본 빌드 대신 외부 빌드를 소비. 소비 바이너리 경로·sha256은 `evidence/experiment_manifest.json`의 `inputs.syz_executor`/`inputs.syz_execprog`에 기록된다.

## 배포

- 배포 정의는 `bundle/SHA256SUMS`(고정 **6항목, 프로젝트 생성물만**) — 커널·syzkaller
  소스는 **배포하지 않는다** (bootstrap이 핀 ref에서 클론; 오프라인 약속 철회 2026-09-26).
  raw 베이스 이미지(`src/bookworm-base.img`)는 로컬 작업 파일로 **배포에 포함되지
  않는다**; 배포 아티팩트는 `src/bookworm-base.img.gz` (조립 시점 배제 · raw 유출 시
  어보트 자체 점검은 `release-assembly.sh`가 수행).
- 사용법: `bash tools/release-assembly.sh` (기본: 6항목 + 패치 시리즈 + 라이선스 문서),
  `bash tools/release-assembly.sh --minimal` (정확히 6항목만).
  산출물: `dist/knfsd-fuzz-forward-port-<날짜>[-minimal].tar.gz` + `dist/SHA256SUMS`.

## 경계

- **번들 독립 구조** (2026-09-25): `repo/` 트리·`apply_patch_series.sh` 의존 제거.
  `bundle/` = `src/`(원천) · `patches/`(독립 시리즈) · `ab-runner/`(AB 런처) ·
  `baker/`(프로비저닝) · `corpus/`(코퍼스 전처리),
  원본 `knfsd-fuzz-HEAD.tar.gz`는 해시를 `README-HANDOFF.md`에 기록 후 삭제.
- **파이프라인 스코프**: `--kind`는 `kernel|syzkaller`만. R6는 번들 2종 검증(2/2).
  상세는 `design-spec.md §6`·`script-rename-map.md`.
- **env/ 빌드 산출물**은 부트스트랩이 만든 일반 코퍼스 AB 오라클 — `--mode full` 포팅 시 신선 환경으로 교체.

## 라이선스

- `tools/`·`bundle/`(`ab-runner/`·`baker/`·`corpus/`)·`report/` 문서: **MIT** (`LICENSE`, 작업 루트)
- 커널 시리즈: **GPL-2.0**(파생), syzkaller 시리즈: **MIT**(상류 소유)
  — 세부 귀속·고지는 `THIRD-PARTY-LICENSES.md`