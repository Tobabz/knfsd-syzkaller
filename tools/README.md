# tools/ — knfsd-syzkaller 환경 구축 도구

베이스 이미지 생성, 환경 부트스트랩(커널 두 종류·syzkaller 빌드·VM 이미지 bake·검증), 패치 시리즈 적용,
그리고 Ganesha·NFS 프록시 빌드 도구를 모아 둔 디렉터리입니다.
A/B 하네스, 관측기, 설계 게이트, 포워드포트 오케스트레이터(`fport-pipeline.sh`)는
커밋 `7833ed3`에서 제거했습니다. 시드는 stock syz-manager로 실행합니다(`README.md` 3절).

## 진입점

```sh
sudo bash tools/make-base-image.sh --out artifacts         # 사이트별 베이스 이미지 + 키쌍
python3 tools/bootstrap-kcov-env.py env \
    --base-image artifacts/bookworm-base.img \
    --ssh-key artifacts/bookworm.id_rsa \
    --deps-tar bundle/src/guest-deps-lane.tar.gz --minor 2  # env/images/<variant>/ 생성

python3 tools/bump-kernel.py latest                        # 새 커널 태그(rc 포함)로 시리즈 이월 → BASE 갱신
python3 tools/bootstrap-kcov-env.py env ... --update       # 새 커널로 다시 빌드·검증 (최근 1개만 유지)
```

## 도구 목록

| 도구 | 용도 |
|---|---|
| `make-base-image.sh` | 사이트 로컬 베이스·키쌍 생성 (create-image.sh -d bookworm; sudo 필요, 산출물은 `SUDO_USER` 소유로 되돌림) |
| `bootstrap-kcov-env.py` | env 부트스트랩 — `--variant kasan\|kcsan`별 out-of-tree 커널 빌드, syzkaller 빌드, VM 이미지 bake, variant별 부팅 검증 |
| `fport-apply.sh` | 시리즈 적용 — `fport-apply.sh [--dry-run] <kind> <target>` (bootstrap이 호출; BASE와 다른 베이스도 `git am -3`으로 시도) |
| `bump-kernel.py` | 새 커널 태그로 이월 — `bump-kernel.py <태그\|latest>`; 충돌 시 손으로 해결 후 `--export <클론>` (해결 기록은 `cache/rr-cache-kernel`) |
| `kernel_base.py` | `bundle/patches/BASE` 읽기·쓰기와 커널 태그 정렬·`latest` 조회 (bootstrap·bump가 공용) |
| `release-assembly.sh` | (선택) 번들 스냅샷 tar 조립 |
| `tool-requirements.txt` | 호스트 의존성 목록 |
| `lane-quote-lint.sh` | `bundle/lane/lane.sh`의 `sh -c '...'` 영역 게이트 — 아포스트로피 0개 + 영역 자체가 셸로 파싱됨 |
| `assemble-guest-deps.py` | Ganesha deps에 프록시 바이너리를 넣어 lane deps tar 생성 — bootstrap의 `--deps-tar` |
| `build-ganesha-deps.sh` | V15.6 빌드 중 Bookworm 의존성 기반을 임시 생성 |
| `build-ganesha-v15.sh`·`ganesha-v15-container.sh`·`package-ganesha-v15.sh` | 공식 V15.6 커밋에서 Bookworm 호환 실행 파일·VFS·libntirpc을 빌드해 별도 deps tar 생성 (Docker 사용) |
| `check-ganesha-v15-guest.py` | v4.1/v4.2 네 마운트, 읽기·쓰기, 직접 경로, 선택적 시드, 정리 검증 |
| `build-ganesha-asan.sh`·`ganesha-asan-container.sh` | bookworm 4.3-2 소스·패치로 Ganesha 실행 파일/코어/VFS를 GCC ASan으로 빌드하고 별도 deps tar 생성 (Docker 사용) |
| `nfs-proxy/` | NFS 프록시 소스·테스트와 빌드 스크립트 (`build.sh`, `build-guest.sh`, `build-syzkaller.sh`, `guest-build.sh`) |

## 환경 변수 (`KOOV_*`)

스크립트의 경로는 자기 위치에서 유도합니다. 현재 코드가 읽는 주요 변수:

| 변수 | 기본값 | 용도 |
|---|---|---|
| `KOOV_WORK_ROOT` | 스크립트 위치의 부모 | 작업 루트(파생 경로 기준) |
| `KOOV_BUNDLE` | `<root>/bundle/patches` | 패치 시리즈 위치 |
| `KOOV_LANE` | `<root>/bundle/lane` | bake 입력(lane 스크립트·부팅 래퍼·서비스) 위치 |
| `KOOV_BAKER` | `<root>/bundle/baker` | 이미지 baker 위치 |
| `KOOV_ARTIFACTS_DIR` | `<root>/artifacts` | `make-base-image.sh` 출력 위치 |
| `KOOV_SYZ_TARGET` | `<root>/env/syzkaller` | `nfs-proxy/build-syzkaller.sh`의 대상 트리 |

Ganesha·프록시 스크립트가 읽는 `KOOV_GANESHA_*`, `KOOV_NFS_PROXY_*`, `KOOV_TMPFS_SIZE`, `KOOV_KNFS_PORT`,
`KOOV_UBSAN_OPTIONS`는 각 스크립트 머리 주석을 참조합니다.

## syzkaller 재빌드 조건과 두 축

bootstrap은 지금 매번 syzkaller를 처음부터 빌드합니다(재사용 없음). 재빌드가 필요한 경우는 아래뿐입니다.
`make`는 `sys/*/*.txt`·`sys/*/*.const`가 바뀌면 설명 생성(`syz-sysgen`)을 다시 하고, manager·execprog·db·executor가
모두 그 생성물에 의존하므로 설명이 바뀌면 이들을 함께 다시 만들어야 합니다.

| 축 | 언제 | syzkaller 재빌드 |
|---|---|---|
| **커널 릴리스** | 커널 베이스가 바뀜 (`bump-kernel.py`, `--kernel-ref`) | **불필요** — 빌드 입력은 syzkaller 트리와 도구체인뿐 |
| **시나리오 개발** | syzlang(`sys/linux/*.txt`, `.const`), executor 의사 시스템 콜, `pkg/vminfo`, execprog 변경, 또는 syzkaller 커밋 변경 | **필수** |

그 밖의 경우: 시드(`.prog`)나 syz-manager cfg만 바뀌면 불필요합니다. 커널 시리즈가 UAPI(KCOV ioctl 등)를 바꾸면
executor가 `executor_linux.h`에 따로 둔 정의와 맞춰야 하므로 필요합니다. 이미지 재생성과는 별개이며, 새 의사 시스템
콜이 새 게스트 구조(마운트, 소켓)를 요구할 때만 lane 스크립트와 이미지가 바뀝니다.

`manifest.json`은 이 구분을 기록합니다.

| 필드 | 내용 |
|---|---|
| `kernel.series_sha256`, `syzkaller.series_sha256` | 패치 시리즈의 파일명·내용 해시(적용 순서 포함) |
| `changes.axis` | 직전 성공 manifest와 비교한 결과: `kernel-release`, `scenario`, `both`, `none`, `first-run`, `unknown` |
| `changes.kernel_base` 등 | 커널 베이스·커널 시리즈·syzkaller 베이스·시리즈 각각의 변경 여부 (`syzkaller_inputs_changed`가 시나리오 축) |
| `timing_seconds` | 단계별 소요 시간(`kernel_clone`, `kernel_apply`, `kernel_build_<variant>`, `kernel_export`, `syzkaller_clone`, `syzkaller_apply`, `syzkaller_build`, `bake`, `verify`, `total`) |

`unknown`은 직전 manifest에 시리즈 해시가 없거나(이 필드가 생기기 전 실행) 실행이 기록 전에 실패한 경우입니다.
커널 시리즈만 바뀐 경우(예: `bump-kernel.py --export` 이후)는 어느 축도 아니라서 `none`이고 `kernel_series`만 참입니다.
syzkaller 재사용을 도입할지는 `kernel-release` 실행에서 `syzkaller_*` 시간이 얼마인지 보고 정합니다.

## 배포

- **릴리스 자산 없음 (2026-09-26 자산 해제 모델)**: 상류 소스(커널·syzkaller)는
  bootstrap이 핀 ref에서 클론(`--kernel-repo`/`--syz-repo`), 베이스·키쌍은
  `tools/make-base-image.sh`로 **사이트별 생성** (raw `bookworm-base.img`는
  커밋·배포 절대 금지).
- 커밋된 부트스트랩 입력: `bundle/src/guest-deps.tar.gz`, `bundle/patches/kernel.config`(KASAN),
  `bundle/patches/kernel-kcsan.config`(KCSAN, KASAN off · `CONFIG_KCSAN=y`) — 두 config는
  bootstrap의 `--variant`가 고르며, 개별 무결성은 git과 bootstrap manifest의
  `kernel.variants.<variant>.config_sha256`가 기록합니다.
- `bundle/patches/BASE`: 시리즈가 적용되는 것으로 확인된 마지막 베이스(커널 태그·커밋, syzkaller 커밋).
  bootstrap과 `fport-apply.sh`가 읽고 `bump-kernel.py`가 갱신합니다. syzkaller는 고정합니다.
- (선택) `bash tools/release-assembly.sh` → 유지보수용 번들 스냅샷 (배포 아님).

## lane 스크립트 하나

lane 스크립트는 `bundle/lane/lane.sh` 하나입니다. 변형은 파일을 복사하지 않고 환경 변수로 고릅니다.

| 변수 | 기본값 | 누가 정하는가 |
|---|---|---|
| `NFS_MINOR_VERSION` | `1` | bake가 서비스 drop-in에 씁니다 (`--minor 1\|2`). knfsd와 Ganesha 마운트에 모두 적용됩니다 |
| `SERVER_IMPL` | `both` | `both`는 lane마다 knfsd와 Ganesha를 프록시 뒤에 둡니다. `knfsd`·`ganesha`는 프록시를 거치지 않는 진단용입니다 |
| `KOOV_TMPFS_SIZE` | `256m` | lane마다 tmpfs 상한 |

`both`가 기본이라 이미지의 deps에 `ganesha.nfsd`와 `nfs-proxy`가 없으면 bootstrap이 시작 전에 거부합니다.
부팅 래퍼(`boot-fixture.sh`)와 서비스(`fixture.service`)도 같은 디렉터리에 있습니다. 이미지 안의 경로
(`/opt/frozen-phase9/lane.sh`)는 그대로입니다.

기존 시드의 `nfs-lane/client0`·`client1`은 같은 knfsd export를 보는 두 클라이언트입니다.
`both`에서도 이 의미를 유지하며, Ganesha는 `client0-ganesha`·`client1-ganesha`로 선택합니다.
두 서버 모두 요청한 minor 버전을 사용합니다.
호스트 입력 검사는 `python3 tools/test-lane-inputs.py`, 셸 검사는 `sh tools/lane-quote-lint.sh`로 실행합니다.
게스트의 두 백엔드와 기본 별칭은 `tools/nfs-proxy/test/guest-four-mounts.sh`로 확인합니다.

### Ganesha V15.6 빌드·검증

Ganesha V15.6의 FSAL_VFS는 `tmpfs` export를 제외하므로 lane은 크기가
제한된 ext4 루프 저장소를 사용합니다. v4.1·v4.2 이미지에서 네 마운트의
교차 읽기·쓰기, 직접 마운트, 정리와 루프 장치 해제를 확인했습니다.

```sh
tools/build-ganesha-v15.sh
tools/nfs-proxy/build-guest.sh --out bundle/src/nfs-proxy-lane
python3 tools/assemble-guest-deps.py \
    --ganesha-deps bundle/src/guest-deps-ganesha-v15.6.tar.gz \
    --proxy bundle/src/nfs-proxy-lane \
    --out bundle/src/guest-deps-lane.tar.gz
python3 tools/bootstrap-kcov-env.py env \
    --base-image artifacts/bookworm-base.img \
    --ssh-key artifacts/bookworm.id_rsa \
    --deps-tar bundle/src/guest-deps-lane.tar.gz --minor 2
python3 tools/check-ganesha-v15-guest.py \
    --image env/images/bookworm-kcov-fresh-v2.qcow2 \
    --seed bundle/corpus/nfs-normal/basic-v41-ganesha-tcp.prog
```

v4.1 이미지는 bootstrap의 `--minor 1`로 생성합니다. 기존 `env/`를
갱신하면서 컴파일 결과를 재사용할 때는 `--update --skip-build`를 지정합니다.
빌더와 deps 조립기는 기존 출력 덮어쓰기를 거부하므로 이미 만든 자산을
재사용하거나 새 출력 경로를 지정합니다.

`build-ganesha-v15.sh`는 Ganesha 커밋 `98eb4beb642674d4188361008495bb6d585d393d`와
libntirpc 커밋 `848ab93b63174338ad72875bddd5680113f64b39`를 확인합니다.
빌드 중 필요한 Bookworm 의존성 기반은 임시 생성 후 제거합니다.
이미지 입력 해시는 인접한 `.json`과 `env/manifest.json`에 기록됩니다.

## 경계

- **번들 독립 구조** (2026-09-25): `bundle/` = `src/`(원천) · `patches/`(독립 시리즈) ·
  `lane/`(bake 입력: lane 스크립트 하나·부팅 래퍼·서비스) · `baker/`(프로비저닝) · `corpus/`(시드 코퍼스).
- **파이프라인 스코프**: `fport-apply.sh`의 `--kind`는 `kernel|syzkaller`만.

## 문서 맵

| 문서 | 내용 |
|---|---|
| `report/design-spec.md` | 설계 계약 기록 (활성 게이트는 manifest 기반 Ψ1·Ψ2·R1만) |
| `report/normal-flow-corpus.md` | 정상 NFS 실행 흐름 코퍼스의 범위·감사 기록 |

## 라이선스

- `tools/`·`bundle/`(`lane/`·`baker/`·`corpus/`)·`report/` 문서: **MIT** (`LICENSE`, 작업 루트)
- 커널 시리즈: **GPL-2.0**(파생), syzkaller 시리즈: **MIT**(상류 소유)
  — 세부 귀속·고지는 `THIRD-PARTY-LICENSES.md`

---

## NFS-Ganesha 병렬 축 (2026-09-26) — A 미실증(프록시 선행), B 실증

> **기록 안내 (2026-10-01).** 아래는 2026-09-26 시점의 작업 기록입니다. 본문이 언급하는 러너·스모크·A/B 게이트
> (`ganesha-lane-run.sh`, `ganesha-lane-control.sh`, `ganesha-lane-parity.sh`, `ganesha-asan-lane-run.sh`,
> `run-ganesha-asan-smoke.py`, `run_frozen_phase9_vm_ganesha.py`, `nfs-proxy/ganesha-asan-relay-run.sh`,
> `nfs-proxy/ganesha-asan-relay-ab-run.sh`, `nfs-proxy/run-ganesha-asan-relay-*.py`)와 그 증거는
> 커밋 `7833ed3`에서 제거되었습니다. `build-ganesha-*.sh`, `nfs-proxy/` 소스와 빌드 스크립트는 그대로 유효합니다.

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

### ASan 계측 Ganesha (기존 4.3 진단 자산)

```sh
tools/build-ganesha-deps.sh           # 일반 Ganesha tarball이 아직 없다면 먼저 생성
tools/build-ganesha-asan.sh
```

이 자산은 현재 V15.6 lane 빌드와 별개이며 v4.2 기본 이미지에 주입할 대상이 아닙니다.
빌더는 Debian bookworm 컨테이너의 GCC 12·`libasan.so.8`을 써서 4.3-2 소스와
Debian 패치로 실행 파일, `libganesha_nfsd.so.4.3`, VFS 플러그인을 함께 계측한다.
ASan tarball은 현재 보관하지 않습니다. 빌더를 다시 실행하면 별도 gitignored
자산으로 생성할 수 있습니다. 소스 SHA·빌드 설정·산출물 해시는 빌더가 출력하는
작업 디렉터리의 `provenance.txt`에 남습니다.
빌더는 기존 출력 파일 덮어쓰기를 거부하며 `--out`으로 새 경로를 지정할 수 있다.
ASan 진단 당시에는 fixture가 Ganesha를 `-F`로 시작해 stderr 보고서를 레인
로그에 남겼고, 라이브 PID의 `/proc/PID/maps`에서 `libasan.so.8` 로드 여부와
두 클라이언트의 34콜×2 결과, cleanup을 판정했다. 사용자 공간 Ganesha에
원격 KCOV `.extra` 게이트는 적용되지 않는다.

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
