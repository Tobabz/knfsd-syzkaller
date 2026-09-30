# tools/ — knfsd-syzkaller 포워드포트 도구

핸드오프 패치 시리즈(`bundle/patches/`: kernel 11패치 + syzkaller 15패치)를 **신규
커널/syzkaller rc로 전진 이식**하는 자동화 파이프라인입니다.
설계 계약(`report/design-spec.md` R1..R6, 기계 판정 `fport-design-gate.sh`)이 **최종 권위**이며,
패치 적용은 그 계약을 가시화하는 구현 단계일 뿐입니다. 사람의 손이 필요한 단계는
신규 rc 충돌 시 패치를 재생성하는 것 하나뿐입니다.

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

## 설계 게이트 R1..R6 (R3 철회)

```sh
bash tools/fport-design-gate.sh -v     # exit 0 = DESIGN HOLDS
```

| 게이트 | 계약 | 실측 (reuse 본체) |
|---|---|---|
| R1 build-integrity | 부트스트랩 `status: pass` + mem_sanitizer ∈ {kasan,kcsan} | PASS |
| R2 remote-contribution | OFF fs/nfsd=0 vs ON>0, converged | PASS (0 vs 1,748) |
| ~~R3 throughput-bound~~ | ~~ON/OFF exec·RPC/s ≥ 0.90~~ — 2026-09-26 철회 (환경 의존 가짜 실패; 비율은 증거에 기록 유지) | — |
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
| `README-tests.md` | T1–T7 검증 배터리 체크리스트 |
| `bootstrap-kcov-env.py` | env 부트스트랩 — 시리즈 적용은 `fport-apply.sh` 연동 |
| `run-ab.sh`·`analyze-ab.sh`·`run_ab_adapted.py` | 일반 코퍼스 AB 하네스 (관례 절대경로 — `<root>` 구조만 준비하면 됨) |
| `make-base-image.sh` | 사이트 로컬 베이스·키쌍 생성 (create-image.sh -d bookworm; 자산 해제 모델의 필수 선행, sudo 필요) |
| `release-assembly.sh` | (선택) 유지보수 스냅샷 조립 (SHA256SUMS 3항목 기반, raw/베이스/키 미포함 — `--minimal`은 3항목만) |
| `tool-requirements.txt` | 팀메이트 호스트 의존성 정형화 (README-HANDOFF 'Reproduce' 전제) |

| `ganesha-lane.sh` | NFS-Ganesha 레인 fixture (knfsd/both/ganesha 3모드, 별도 tmpfs·별도 export) |
| `ganesha-lane-run.sh` | Ganesha 축 러너 (fixture + 전용 deps tarball + 전용 코퍼스) |
| `build-ganesha-deps.sh` | `guest-deps-ganesha.tar.gz` 생성 — root 불필요, `.deb`→의존성 closure→주입 트리 |
| `build-ganesha-asan.sh`·`ganesha-asan-container.sh` | bookworm 4.3-2 소스·패치로 Ganesha 실행 파일/코어/VFS를 GCC ASan으로 빌드하고 별도 deps tar 생성 (Docker 사용) |
| `ganesha-asan-lane-run.sh`·`run-ganesha-asan-smoke.py` | 게스트에서 ASan 실로드·NFSv4 호출 결과·로그·정리 검증 (원격 KCOV AB와 분리) |
| `nfs-proxy/build-guest.sh`·`nfs-proxy/ganesha-asan-relay-run.sh` | Debian bookworm ABI 프록시와 2클라이언트 × 2백엔드 ASan 게스트 릴레이 게이트 |
| `run_frozen_phase9_vm_ganesha.py` | phase9 러너 적응 사본 — 백엔드 중립 lane 게이트 |
| `nfs_remote_kcov_ganesha_v41_workload.prog` | 두 구현이 모두 통과하는 코퍼스 (호출 수·인덱스 불변) |
| `lane-quote-lint.sh` | `sh -c '...'` 영역 게이트 — 아포스트로피 0개 + 영역 자체가 셸로 파싱됨 |
## 검증·증거 규율

```sh
bash tools/fport-pipeline.sh --mode reuse
```

- 번들(`bundle/patches/` 2종 시리즈)은 검증 기준 — 시리즈 수정 시 게이트 R6 재확인.

---

## NFS-Ganesha 병렬 축 (2026-09-26) — A 미실증(프록시 선행), B 실증

knfsd와 **병렬로** 수행해 퍼징 처리량을 높이는 축이다. 동시에 병렬 퍼징이 만드는
**부작용을 완화하는 설계**를 고도화한다. 둘은 성격이 다른 작업이라 따로 판정한다.

| | 목표 | 판정 |
|---|---|---|
| **A** | knfsd 퍼징과 병렬 수행해 벽시계당 처리량 증대 | **미실증** — 프록시 미구현 |
| **B** | 병렬 퍼징의 부작용을 완화하는 설계 고도화 | **대부분 실증** |

### A-1. 단일 Ganesha로 클라이언트 마운트·RPC 유지 (실증)

`bookworm nfs-ganesha 4.3-2`를 `.deb`에서 root 없이 추출해
`bundle/src/guest-deps-ganesha.tar.gz`로 주입했다. 기존 `guest-deps.tar.gz`는 이미
기록된 AB/S3/S4 증거의 입력이므로 건드리지 않았고 **별도 tarball**을 썼다(각각 별도
해시 기록). 게스트 이미지 재굽기도 필요 없다.

| 항목 | 관측 |
|---|---|
| `ganesha_live` / `ganesha_listen` | 1 / 1 |
| `tcp_connections` | 2 (두 클라이언트 모두 Ganesha 경유) |
| 워크로드 | 34콜 × 2 = 68콜, lock 충돌 기대값 2 충족 |
| 로컬 커버리지 레코드 | 371,608 |
| cleanup 누출 | mount / namespace / source_tree 모두 0 |

### ASan 계측 Ganesha (별도 현장 자산)

```sh
tools/build-ganesha-deps.sh           # 일반 Ganesha tarball이 아직 없다면 먼저 생성
tools/build-ganesha-asan.sh
tools/ganesha-asan-lane-run.sh
```

빌더는 Debian bookworm 컨테이너의 GCC 12·`libasan.so.8`을 써서 4.3-2 소스와
Debian 패치로 실행 파일, `libganesha_nfsd.so.4.3`, VFS 플러그인을 함께 계측한다.
`bundle/src/guest-deps-ganesha-asan.tar.gz`는 **별도 gitignored 자산**이다.
기존 `guest-deps.tar.gz`·일반 Ganesha tarball은 보존한다. 소스 SHA·빌드 설정·
산출물 해시는 빌더가 출력하는 작업 디렉터리의 `provenance.txt`에 남는다.
빌더는 기존 출력 파일 덮어쓰기를 거부하며 `--out`으로 새 경로를 지정할 수 있다.
ASan 사용 시 fixture는 Ganesha를 `-F`로 시작해 stderr 보고서를 레인 로그에
남긴다. 스모크 게이트는 라이브 PID의 `/proc/PID/maps`에서 `libasan.so.8`을
확인하고 두 클라이언트의 34콜×2 결과, 로그, cleanup을 판정한다.

기존 Ganesha 러너에서 선택하려면 `KOOV_GANESHA_DEPS`와
`KOOV_GANESHA_ASAN_OPTIONS`를 함께 설정하고 별도 `KOOV_EVIDENCE_DIR`을
사용한다. 단, 그 러너의 **원격 KCOV `.extra` AB 게이트는 사용자 공간
Ganesha에 적용되지 않으므로**, ASan 동작 판정에는 위 스모크 게이트를 쓴다.

### A-2. knfsd + ASan Ganesha 동시 릴레이 — 네 게스트 NFSv4 마운트 확인

`SERVER_IMPL=both`에서 `.1:2049`·`.5:2049` 프록시가 각각 knfsd `:20490`·
Ganesha `:20491`로 고정 라우팅한다. 클라이언트 `.2`·`.6`에 반대편 `/30`
목적지 경로를 추가해 각자 두 백엔드를 마운트한다. 두 클라이언트는 **같은 백엔드의
트리를 공유**하고 **백엔드 간 저장소는 다르다**. 게스트의 교차 읽기·쓰기·삭제로
이를 확인하고, 프록시 스냅샷의 네 `(client,backend)` 카운터에서 C2S/S2C
왕복과 동시 활성 연결 4개를 확인했다. ASan Ganesha의 실로드, 생존,
ASan 보고 0, fixture 정리 누출 0도 통과했다.

```sh
tools/nfs-proxy/build-guest.sh
tools/nfs-proxy/ganesha-asan-relay-run.sh
```

syzkaller 변경은 기존 시리즈 뒤에 `bundle/patches/syzkaller/0017-*.patch`로
추가됐다. `tools/nfs-proxy/build-syzkaller.sh`가 이미 포워드포트된
`KOOV_SYZ_TARGET`(기본 `env/syzkaller`)에 해당 패치를 적용·빌드한다.
`syz_open_nfs_lane_pair(client,backend)`와
`syz_socket_connect_nfs_pair(client,backend)`는 4조합을 고르고 기존
단일 백엔드 pseudo-call은 별칭으로 남는다. 샌드박스에는 해당 proc의 네
마운트와 **`/nfs-lane/control/arm.sock`만** 추가한다. `syz_arm_nfs_proxy`
규칙은 syzkaller 프로그램 바이트에 포함된다. 등록 ACK는 적용 성공이 아니며
규칙 FD를 닫거나 프로그램이 끝나면 해제된다. 와이어 레코드의 확정된 필드와
COMPOUND 본문 raw region만 선택·변조하며, 프록시 PRNG는 없다.

```sh
tools/nfs-proxy/build-syzkaller.sh
KOOV_NFS_PROXY_GUEST=bundle/src/nfs-proxy-control-guest \
KOOV_SYZ_FOUR_WORKLOAD=tools/nfs-proxy/test/guest-syzkaller-mutate.prog \
KOOV_EVIDENCE_DIR=evidence/ganesha-asan-relay-replay \
    tools/nfs-proxy/ganesha-asan-relay-run.sh
```

게스트에서는 executor가 4연결로 각각 실제 RPC를 보내고 응답을 받는다.
`(client0,Ganesha)`의 C2S/S2C XID를 한 번씩 변조한 델타를 원본·대체
바이트와 함께 저장한 후, 각 델타를 별도 게스트 프록시 `--replay`에 공급해
같은 백엔드 응답에서 재적용을 확인한다. ASan·마운트 공유/격리·정리 검사도
함께 실행한다. 저장된 델타 사본의 anchor만 변경한 원본 불일치 음성 게이트는
`refused_orig=1`, 적용 0, replay 실패와 원본 응답을 게스트에서 확인한다.
상세 판정과 증거 해시는 `report/design-spec.md`를 참조한다.

`tools/nfs-proxy/ganesha-asan-relay-ab-run.sh`는 이미지 변환 확인 후
arm OFF/ON 각각 30회 × 2 trial의 네 경로·ASan A/B를 수행한다. 실제
네 trial이 모두 통과했고, ON은 trial마다 두 방향 각 30개 델타를 적용했다.
executor 처리율 중앙값은 OFF 0.63251 → ON 0.59396 exec/s(-6.10%).
별도의 기존 knfsd 원격-KCOV 정식 A/B 회귀도 4 trial·분석 PASS였다.
실험 정의·해시는 보고서에 있다.

### B. 실증된 설계 (병렬 부작용 완화)

**스토리지 분리 — 게스트 실측.** 한 레인 안에서 두 서버가 하나의 가변 FS 트리를 공동
소유하면 안 된다. 클라이언트는 한쪽 응답만 보므로 다른 쪽 부작용이 주 응답을 **조용히
덮어쓴다.** 그래서 별도 tmpfs를 쓴다.

```
backing_source          = frozen-phase9-lane0
ganesha_backing_source  = frozen-phase9-lane0-ganesha     ← 실제로 다름 (게스트 실측)
```

**격리가 새 데몬을 따라가는가 — 실측.** Ganesha와 `dbus-daemon`을 새로 띄우면 게이트가
몰랐던 시나리오지만, 기존 격리가 그대로 작동했다(`mount_leaks`/`namespace_leaks`/
`source_tree_leaks` 모두 0).

**tmpfs 상한 — 실측.** 두 백엔드 모두 `size=262144k`로 상한이 걸려 있다. 한 백엔드가
메모리를 먹어도 다른 백엔드가 죽지 않도록 게이트로 강제하고 증거 JSON에 기록한다.

**죽은 보조 서버 탐지 — 실시간 릴레이 검증 확보.** 병렬 퍼징의 핵심 위험은 **두 번째
서버가 조용히 죽어도 결과가 정상처럼 나오는 것**인데, 이 축이 고친 계측기 결함이
정확히 그 지점에 걸려 있었다.

| 결함 | 병렬 퍼징에서의 의미 |
|---|---|
| 게이트가 `$!`을 감시 (fork 후 pid 불일치) | 죽은 보조 서버를 "정상"으로 기록 → **병렬성이 없는데도 모름** |
| 게이트가 `/proc/net/tcp`만 봄 | 살아있는 보조 서버를 "미리슨"으로 오탐 |
| nfsd 누출 검사가 없는 nfsd를 누출로 오탐 | 실제 누출을 가림 |

### 원격 KCOV는 보조 백엔드 검증 수단이 될 수 없다

ON 그룹에서 원격 커버리지 파일이 **0개**다(executions=2, 기대 2). 원격 KCOV 섹션은
`sunrpc_fuzz` 상관 도메인으로 **RPC를 처리한 스레드**에 귀속되는데, knfsd는 커널
스레드가 처리하므로 되지만 **userspace 서버에는 커널 처리 스레드가 없어 귀속 대상이
없다.** 도메인 생성은 성공해도 0개다.

이건 **축의 실패가 아니다** — 그 채널을 재려고 했던 축이 아니었다. 다만 실제 제약이
하나 생긴다: **원격 KCOV를 "두 번째 서버가 실제로 트래픽을 처리하는가"의 검증 수단으로
쓸 수 없다.** 그래서 보조 백엔드 검증은 프로세스 존재 + 리스너 + **백엔드 자체
신호**(처리한 RPC 수 등)로 구성해야 한다. 별도 게스트 릴레이 스모크에서는
서버의 실제 NFSv4 응답·트리 I/O와 프록시 귀속 카운터를 함께 게이트한다.
syzkaller 변조에서는 전후 로그의 네 요청/응답 및 2개 델타의 적용·재생
횟수도 확인한다. A/B 측정은 별도 판정한다.

### 두 구현의 실제 행동 차이 (관찰 자료)

NFSv4 pseudoroot에 엔트리를 만드는 쓰기에서 knfsd는 0, Ganesha 4.3은 `EROFS`. 의사
코드상 다른 실패(EROFS → ENOENT)로 보이던 것이었고, 하나의 원인이 두 표면이었던
것이며 `Pseudo = /`로 정리했다.

### 이 축에서 배운 것 (도구 설계에 남긴 규칙)

| 교훈 | 남긴 형태 |
|---|---|
| `sh -n`은 `sh -c '...'` 내부를 **파싱하지 않는다**(문자열 리터럴) | `lane-quote-lint.sh`가 영역을 추출해 `sh -n`/`dash -n` 통과 확인 |
| 게이트가 **잘못된 pid**를 보면 확신에 찬 false negative | 생존 판정을 "이 pid 존재"가 아니라 "프로세스 존재 + 리스너 확인"으로 |
| 게이트가 **IPv6 리스너**를 못 본다 | tcp6 포함 검사 + 양쪽 테이블 합산 |
| 게이트 실패를 **설정 탓**으로 돌리면 게이트가 못 찾는 버그가 남는다 | 근거 없는 원인 규명을 코드 주석에 남기고 계측부터 다시 |
| `.deb` soname 심볼릭 링크(`*.so.N`)는 `-type f` 필터를 통과 못 한다 | 링크를 해석해 링크 이름으로 설치 + 게이트 |
| lane PATH에 보이는 주입 디렉터리는 `usr/sbin`뿐 | `usr/bin`에 두면 보이지 않음 — 배치를 빌드가 assert |
| guest base가 "surely" 가진다고 **가정하면** 게스트가 이름을 알려준다 | `NEEDED` 분류를 빌드 출력에 + `MUST_FETCH` assert |

두 번째 항목이 이 축의 가장 비싼 교훈이었다. 데몬이 기동 중 한 번 fork하는데 `$!`을
감시한 게이트가 **8회 연속으로 "Ganesha 죽음"을 보고**했다. 실제로는 그 동안 431 KiB
커버리지가 수집되고 있었다. 게이트가 틀린 프로세스를 보면 없는 병렬성을 "있다"고
판정하므로, 병렬 축에서 이건 오탐이 아니라 **가장 위험한 오류**다.

### 다음 작업

**프록시 게스트 릴레이는 확인됐다.** 다음은 샌드박스 고정 경로의 `arm` IPC,
생성/재생 델타, syzkaller `(client,backend)` 연결 선택의 실제 통합이다.

## 문서 맵

| 문서 | 내용 |
|---|---|
| `report/design-spec.md` | Ψ/R1,R2,R4,R5 설계 계약 + 재구현 지침 |


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

- **릴리스 자산 없음 (2026-09-26 자산 해제 모델)**: 상류 소스(커널·syzkaller)는
  bootstrap이 핀 ref에서 클론(`--kernel-repo`/`--syz-repo`), 베이스·키쌍은
  `tools/make-base-image.sh`로 **사이트별 생성** (raw `bookworm-base.img`는
  커밋·배포 절대 금지).
- 커밋된 부트스트랩 입력은 `bundle/SHA256SUMS`(고정 **3항목**:
  `guest-deps.tar.gz`·`patches/kernel.config`·`README-HANDOFF.md`)로 핀.
- KCSAN 변형 핀 `patches/kernel-kcsan.config`(KASAN off · `CONFIG_KCSAN=y`)는
  **선택 입력**으로 `KOOV_KCONFIG`가 선택하며 루트 SHA256SUMS 밖 —
  개별 무결성은 git 과 bootstrap manifest 의 `pins.kconfig` 가 핀한다.
- (선택) `bash tools/release-assembly.sh` → 유지보수용 스냅샷
  `dist/knfsd-syzkaller-forward-port-<날짜>[-minimal].tar.gz` (배포 아님);
  `--minimal`은 정확히 3항목만. AB 하네스 `run-ab.sh`는 생성 키를
  `KOOV_SSH_KEY`로 넘긴다.

## 경계

- **번들 독립 구조** (2026-09-25): `repo/` 트리·`apply_patch_series.sh` 의존 제거.
  `bundle/` = `src/`(원천) · `patches/`(독립 시리즈) · `ab-runner/`(AB 런처) ·
  `baker/`(프로비저닝) · `corpus/`(코퍼스 전처리),
  원본 `knfsd-fuzz-HEAD.tar.gz`는 해시를 `README-HANDOFF.md`에 기록 후 삭제.
- **파이프라인 스코프**: `--kind`는 `kernel|syzkaller`만. R6는 번들 2종 검증(2/2).
  상세는 `design-spec.md`.
- **env/ 빌드 산출물**은 부트스트랩이 만든 일반 코퍼스 AB 오라클 — `--mode full` 포팅 시 신선 환경으로 교체.

## 라이선스

- `tools/`·`bundle/`(`ab-runner/`·`baker/`·`corpus/`)·`report/` 문서: **MIT** (`LICENSE`, 작업 루트)
- 커널 시리즈: **GPL-2.0**(파생), syzkaller 시리즈: **MIT**(상류 소유)
  — 세부 귀속·고지는 `THIRD-PARTY-LICENSES.md`
