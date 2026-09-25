# tools/ 스크립트 개명 기록 (2026-09-23)

넘버링 단계 코드(prefix) 대신 **설명적 이름**을 사용합니다. forward-port 패밀리는 `fport-` 접두사로 묶습니다. 불변 번들 `repo/`는 건드리지 않았습니다.

| 구 (넘버링) | 신규 (설명적) | 계열 |
|---|---|---|
| `70-make-ab-lane-fixture.sh` | `make-ab-lane-fixture.sh` | core/other |
| `80-parse-executor-log.py` | *삭제됨* (2026-09-25, 일회성 진단 도구 제거) | core/other |
| `90-fix-workload-tail.py` | *삭제됨* (2026-09-25, 일회성 진단 도구 제거) | core/other |
| `95-summarize-numeric.py` | `summarize-numeric.py` | core/other |
| `131-probe-diag-tools.sh` | *삭제됨* (2026-09-25, 다이어그램 툴체인 제거 — SVG 제거와 동일 조치) | core/other |
| `132-gen-architecture.py` | *삭제됨* (2026-09-25, SVG 다이어그램 제거) | core/other |
| `00-convert-ab-image.sh` | `convert-ab-image.sh` | core/other |
| `106-evidence-hashes.sh` | `evidence-hashes.sh` | core/other |
| `134-inspect-handoff.sh` | *삭제됨* (2026-09-25, 번들 재구성 — repo 트리 제거) | core/other |
| `103-phase-counters.py` | `phase-counters.py` | core/other |
| `113-run-cocci-demo.sh` | *삭제됨* (2026-09-23 의도 기반 재생성 전환) | forward-port |
| `110-patch-hygiene.py` | `fport-patch-hygiene.py` | forward-port |
| `130-port-pipeline.sh` | `fport-pipeline.sh` | forward-port |
| `91-check-bind-re.py` | *삭제됨* (2026-09-25, 일회성 진단 도구 제거) | core/other |
| `112-apply-robust.sh` | `fport-apply.sh` | forward-port |
| `133-validate-svg.sh` | *삭제됨* (2026-09-25, SVG 다이어그램 제거) | core/other |
| `60-diag-fixture.py` | *삭제됨* (2026-09-25, 일회성 진단 도구 제거) | core/other |
| `93-summarize-ab.py` | `summarize-ab.py` | core/other |
| `114-add-variant.sh` | `fport-variant.sh` | forward-port |
| `120-design-gate.sh` | `fport-design-gate.sh` | forward-port |
| `111-patch-risk.py` | `fport-patch-risk.py` | forward-port |
| `20-analyze-ab.sh` | `analyze-ab.sh` | core/other |
| `92-check-args.py` | *삭제됨* (2026-09-25, 일회성 진단 도구 제거) | core/other |
| `94-dump-trial.py` | `dump-trial.py` | core/other |
| `96-list-keys.py` | *삭제됨* (2026-09-25, 일회성 진단 도구 제거) | core/other |
| `115-evidence.sh` | `fport-evidence.sh` | forward-port |
| `113-cocci-demo` | *삭제됨* (2026-09-23, `cocci-demo/` 제거) | core/other |
| `10-run-ab.sh` | `run-ab.sh` | core/other |

파일 이동 + 내부 참조 치환 + 증거 해시 재기록까지 이 문서로 감사 가능합니다.

## 디렉토리 개명 (2026-09-25 — 명칭 개편)

경로 관례 제거 작업의 일환으로 작업 루트 하위 디렉토리를 기능 명칭으로 재명명했습니다 (`tools/rename-dirs.sh`·`/tmp/fport-migrate.py` 기록, 42개 텍스트 파일 치환 + SVG 재생성 + 증거 해시 재기록).

| 구 | 신규 | 근거 |
|---|---|---|
| `prep/` | `tools/` | 실행 도구의 소재지 ("준비"라는 절차적 의미 제거) |
| `handoff/` | `bundle/` | 불변 번들 + 부트스트랩 입력 (절차적 "핸드오프" → 구조적 명칭) |
| `kcov/` | `env/` | 검증 실험 환경 전체 (도구명 → 환경명) |
| `ab-results/` | `evidence/` | 생성 증거·게이트 oracle (하이픈 제거) |
| `port-runs/` | `runs/` | 런 매니페스트 (하이픈 제거) |
| `report/` | (유지) | 명확성 유지 |

- `manifest.json` 경로 필드(`target`, `repo`)도 신규 명칭으로 갱신 (핀·verify 값 불변).
- `handoff.zip`·루트 로그(`bootstrap*.log`, `ab-run.log`, `ab-analyze.log`)·`check_syz_makefile.sh`는 시점 기록/일회성 진단으로 **삭제** (2026-09-25 — 출처 증명은 bundle/SHA256SUMS·증거 해시가 담당).
- 역사적 런 기록(`runs/port-*`)은 시점 기록으로 **명칭 유지**.
- **번들 독립화 재구성** (2026-09-25): `bundle/repo/` 트리(68M — workdir/크래시 597·artifacts·checkpoints·corpus·nfs_seeds·docs·reproducers·config 잔여) 전면 제거. `bundle/` = `src/`(원천 7종) · `patches/`(kernel 11 + syzkaller 15 + kernel.config) · `ab-runner/`(AB 런처 32개) 독립 배치. `apply_patch_series.sh` 의존 제거 — `fport-apply.sh` 자체 적용(단일 경로). 원본 `knfsd-fuzz-HEAD.tar.gz`(sha256 `42f2789ce0d…`)는 `bundle/README-HANDOFF.md`에 해시 영구 기록 후 삭제. `bootstrap_kcov_env.py` → `tools/bootstrap-kcov-env.py` 이동 + `fport-apply.sh` 연동. `inspect-handoff.sh` 제거. `run-ab.sh` 자산 경로 `src/` 반영. `bundle/SHA256SUMS` 재생성(8항목).
- **일회성 진단 도구 6종 제거** (2026-09-25): `diag-fixture.py`·`parse-executor-log.py`·`fix-workload-tail.py`·`check-bind-re.py`·`check-args.py`·`list-keys.py` — 유지 도구/하네스 참조 없음(grep 확인). 증거 해시 목록에 미포함이라 해시 변동은 없으나, 개명 맵(`rename-scripts.py`·본 문서) 갱신으로 증거 재기록. `tools/__pycache__/`도 제거. (루트 `rename-dirs.sh`는 개명 배치 잔여 — 별도 판단 대기)
- 파이프라인 경로는 이제 스크립트 위치에서 유도(`KOOV_WORK_ROOT` 오버라이드) — `patch-forward-compat.md §7 환경 이식` 참조.
- **번들 내부 관심사 분리** (2026-09-26): `bundle/ab-runner/`(32개) → `bake_nfs_protocol_image.py`는 `bundle/baker/`, `audit_*`·`build_*` 4종은 `bundle/corpus/`로 이동, 나머지(런너 9종·frozen fixture·workload·check_port·monitor)는 `ab-runner/` 유지. 내용물 불변(경로만 이동). `tools/bootstrap-kcov-env.py`에 `BAKER` 경로 추가 + bake 호출 시 `--lane-script/--boot-fixture/--service`를 `ab-runner/` 경로로 명시 전달 (기본 경로 drift 해소). 증거 해시·`bundle/SHA256SUMS` 재기록.
- **하드코딩 경로 변수화 (P1, 2026-09-26)**: `tools/` 13개 파일의 `/home/idealinsane/work`·`/home/fuzzer` 하드코딩을 자기 위치 유도 + `KOOV_*` 오버라이드로 치환 (`run-ab.sh`·`analyze-ab.sh`·`convert-ab-image.sh`·`make-ab-lane-fixture.sh`· `summarize-ab.py`·`summarize-numeric.py`·`phase-counters.py`·`dump-trial.py`· `rename-scripts.py`·`check-rename-leftovers.sh`·`evidence-hashes.sh`·`portability-check.sh`·`run_ab_adapted.py`). `make-ab-lane-fixture.sh`의 `$REPO/scripts/…` drift(2026-09-25 재구성 이전 레이아웃)를 `$ABRUN/frozen_phase9_lane.sh`로 수정·`REPO` 변수 제거. `KOOV_SYZ_ROOT` 기본값은 원본 `/home/fuzzer/tools/syzkaller-frozen-attribution` 유지(오버라이드 전용). `bundle/` 원본의 `/home/fuzzer` 기본값은 불변 정책상 유지(런타임 오버라이드로 대체). 문법 검증(`bash -n` 13·`py_compile` 10) 통과, `tools/` 잔여 하드코딩 0(점검 문구 제외). 증거 해시 재기록.
- **증거/배포 트리 정제 (2026-09-26)**: `evidence/`의 trial raw 압축 전 사본 `coverage/` 디렉토리 4개(remote_off/on × trial_01/02, ~537MB) 제거 — `coverage.tar.gz`와 집합 동일성(4/4)을 검증 후 삭제, 원천 증빙(tar.gz·trial_evidence.json·coverage_sets/) 불변. 증거 해시 목록(SHA256SUMS·analysis_summary·manifest·report) 영향 없음. `dist/`(20260926 아카이브 2종 + SHA256SUMS, 1.1GB)도 제거 — `tools/release-assembly.sh`가 bundle에서 재생성(배포 산출물 = 재생성 가능 파생물).
- **배포 준비 (2026-09-26)**: 루트 `rename-dirs.sh` 삭제 — 1회성 디렉토리 개명 배치로 완료 후 잔여 불요(재실행 시 `MISSING` 오류). 전환 기록은 본 문서 '디렉토리 개명 (2026-09-25)' 항목이 담당.
