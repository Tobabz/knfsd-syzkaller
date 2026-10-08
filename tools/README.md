# tools/ — knfsd-syzkaller 환경 구축 도구

베이스 이미지 생성, 환경 부트스트랩(커널 두 종류·syzkaller 빌드·VM 이미지 bake·검증), 패치 시리즈 적용,
그리고 Ganesha·프록시 기반의 NFS 특화 Mutation Engine 빌드 도구를 모아 둔 디렉터리입니다.
시드는 bootstrap이 패치·빌드한 syzkaller의 syz-manager로 실행합니다(`README.md` 3절).

## 진입점

[호스트 준비 안내](tool-requirements.txt)에 따라 준비한 뒤 저장소 루트에서 실행합니다.
Python 환경은 [pyproject.toml](../pyproject.toml)과 [.python-version](../.python-version)이 명세합니다.

```sh
uv sync --locked
sudo bash tools/make-base-image.sh --out artifacts         # 사이트별 베이스 이미지 + 키쌍
uv run python tools/bootstrap-kcov-env.py env \
    --base-image artifacts/bookworm-base.img \
    --ssh-key artifacts/bookworm.id_rsa \
    --deps-tar bundle/src/guest-deps-lane.tar.gz --version 4.2  # env/images/<variant>/ 생성

uv run python tools/bump-kernel.py latest                        # 새 커널 태그(rc 포함)로 시리즈 이월 → BASE 갱신
uv run python tools/bootstrap-kcov-env.py env ... --update       # 새 커널로 다시 빌드·검증 (최근 1개만 유지)
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
| `assemble-guest-deps.py` | Ganesha deps에 Mutation Engine 바이너리(`nfs-proxy`)를 넣어 lane deps tar 생성 — bootstrap의 `--deps-tar` |
| `build-ganesha-deps.sh` | V15.6 빌드 중 Bookworm 의존성 기반을 임시 생성 |
| `build-ganesha-v15.sh`·`ganesha-v15-container.sh`·`package-ganesha-v15.sh` | 공식 V15.6 커밋에서 Bookworm 호환 실행 파일·VFS·libntirpc을 빌드해 별도 deps tar 생성 (Docker 사용) |
| `check-ganesha-v15-guest.py` | v4.1/v4.2 네 마운트, 읽기·쓰기, 직접 경로, 선택적 시드, 정리 검증 |
| `check-nfs-versions-guest.py` | 공통 이미지의 v3/v4.0/v4.1/v4.2 마운트·교차 읽기/쓰기·백엔드 격리·정리 검증 |
| `prepare-live-lane-config.py` | 기존 manager 설정에서 lane 스크립트 스냅샷·읽기 전용 9P 공유·버전·해시를 고정한 새 설정 생성 |
| `test-lane-inputs.py` | VM 부팅 없이 deps 조립·입력 검사·lane 설정 helper·시드 해시 검증 |
| `flow-trace/` | 정상 NFS 실행의 이벤트 수집과 스레드 전환 판정 (`flow-trace/README.md`) |
| `build-ganesha-asan.sh`·`ganesha-asan-container.sh` | bookworm 4.3-2 소스·패치로 Ganesha 실행 파일/코어/VFS를 GCC ASan으로 빌드하고 별도 deps tar 생성 (Docker 사용) |
| `nfs-proxy/` | 프록시 기반의 NFS 특화 Mutation Engine 소스·테스트와 빌드 스크립트 (`build.sh`, `build-guest.sh`, `build-syzkaller.sh`, `guest-build.sh`) |

## 환경 변수 (`KOOV_*`)

스크립트의 경로는 자기 위치에서 유도합니다. 현재 코드가 읽는 주요 변수:

| 변수 | 기본값 | 용도 |
|---|---|---|
| `KOOV_WORK_ROOT` | 저장소 루트 | `make-base-image.sh`, `release-assembly.sh`, `nfs-proxy/build-syzkaller.sh`의 작업 루트. bootstrap에는 적용되지 않음 |
| `KOOV_BUNDLE` | `<root>/bundle/patches` | 패치 시리즈 위치 |
| `KOOV_LANE` | `<root>/bundle/lane` | bootstrap의 호스트 주입 lane 스크립트와 bake되는 부팅 래퍼·서비스 위치 |
| `KOOV_BAKER` | `<root>/bundle/baker` | 이미지 baker 위치 |
| `KOOV_ARTIFACTS_DIR` | `<root>/artifacts` | `make-base-image.sh` 출력 위치 |
| `KOOV_SYZ_TARGET` | `<root>/env/syzkaller` | `nfs-proxy/build-syzkaller.sh`의 대상 트리 |
| `KOOV_BUNDLE_DIR` | `<root>/bundle` | `nfs-proxy/build-syzkaller.sh` 전용 번들 루트(`patches/syzkaller`를 덧붙임) |

Ganesha·Mutation Engine 스크립트가 읽는 `KOOV_GANESHA_*`, `KOOV_NFS_PROXY_*`, `KOOV_TMPFS_SIZE`, `KOOV_KNFS_PORT`,
`KOOV_UBSAN_OPTIONS`는 각 스크립트 머리 주석을 참조합니다.

## syzkaller 재빌드 조건과 두 축

bootstrap은 기본적으로 syzkaller를 처음부터 빌드합니다. `--skip-build`는 기존 커널·syzkaller 산출물을 재사용합니다.
재빌드가 필요한 경우는 아래와 같습니다.
`make`는 `sys/*/*.txt`·`sys/*/*.const`가 바뀌면 설명 생성(`syz-sysgen`)을 다시 하고, manager·execprog·db·executor가
모두 그 생성물에 의존하므로 설명이 바뀌면 이들을 함께 다시 만들어야 합니다.

| 축 | 언제 | syzkaller 재빌드 |
|---|---|---|
| **커널 릴리스** | 커널 베이스가 바뀜 (`bump-kernel.py`, `--kernel-ref`) | **불필요** — 빌드 입력은 syzkaller 트리와 도구체인뿐 |
| **시나리오 개발** | syzlang(`sys/linux/*.txt`, `.const`), executor 의사 시스템 콜, `pkg/vminfo`, execprog 변경, 또는 syzkaller 커밋 변경 | **필수** |

그 밖의 경우: 시드(`.prog`)나 syz-manager cfg만 바뀌면 불필요합니다. 커널 시리즈가 UAPI(KCOV ioctl 등)를 바꾸면
executor가 `executor_linux.h`에 따로 둔 정의와 맞춰야 하므로 필요합니다. 이미지 재생성과는 별개입니다.
`lane.sh` 변경은 호스트 스크립트 스냅샷을 다시 준비하면 적용됩니다. 부팅 래퍼·서비스·게스트 의존성·baker가 바뀌면
이미지를 다시 만듭니다.

`manifest.json`은 이 구분을 기록합니다.

| 필드 | 내용 |
|---|---|
| `kernel.series_sha256`, `syzkaller.series_sha256` | 패치 시리즈의 파일명·내용 해시(적용 순서 포함) |
| `changes.axis` | 직전 성공 manifest와 비교한 결과: `kernel-release`, `scenario`, `both`, `none`, `first-run`, `unknown` |
| `changes.kernel_base` 등 | 커널 베이스·커널 시리즈·syzkaller 베이스·시리즈 각각의 변경 여부 (`syzkaller_inputs_changed`가 시나리오 축) |
| `timing_seconds` | 단계별 소요 시간(`kernel_clone`, `kernel_apply`, `kernel_build_<variant>`, `kernel_export`, `syzkaller_clone`, `syzkaller_apply`, `syzkaller_build`, `bake`, `verify`, `total`) |

`unknown`은 직전 manifest에 시리즈 해시가 없거나(이 필드가 생기기 전 실행) 실행이 기록 전에 실패한 경우입니다.
커널 시리즈만 바뀐 경우(예: `bump-kernel.py --export` 이후)는 어느 축도 아니라서 `none`이고 `kernel_series`만 참입니다.

## 배포

- **릴리스 자산 없음**: 상류 소스(커널·syzkaller)는
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
| `NFS_VERSION` | `4.1` | 부팅 래퍼가 `vm.cmdline`의 `koov.nfs_version=3\|4.0\|4.1\|4.2`를 읽어 전달합니다. 두 백엔드의 마운트에 적용됩니다 |
| `SERVER_IMPL` | `both` | `both`는 lane마다 Mutation Engine을 통해 knfsd와 Ganesha에 연결합니다. `knfsd`·`ganesha`는 서버에 직접 연결하는 진단용입니다 |
| `KOOV_TMPFS_SIZE` | `256m` | lane마다 tmpfs 상한 |

`both`가 기본이라 이미지의 deps에 `ganesha.nfsd`와 `nfs-proxy`가 없으면 bootstrap이 시작 전에 거부합니다.
부팅 래퍼(`boot-fixture.sh`)와 서비스(`fixture.service`)도 같은 디렉터리에 있습니다. 래퍼는 읽기 전용 9P
공유의 `lane.sh`를 `/run/frozen-phase9/lane.sh`로 복사하고 지정된 SHA-256과 비교합니다. 서비스의
setup·status·cleanup은 모두 이 복사본을 사용합니다.

기존 시드의 `nfs-lane/client0`·`client1`은 같은 knfsd export를 보는 두 클라이언트입니다.
`both`에서도 이 의미를 유지하며, Ganesha는 `client0-ganesha`·`client1-ganesha`로 선택합니다.
두 서버 모두 요청한 버전을 사용합니다. v3는 별도 TCP MOUNT 포트와 `nolock`을 사용하므로
서로 다른 클라이언트 사이의 NLM 잠금은 이 fixture에서 제공하지 않습니다.

**특이사항 — NFSv3 잠금:** 현재 `nolock` 마운트의 파일 잠금은 같은 클라이언트 안에서만
효력이 있으며, Ganesha도 `Enable_NLM = false`로 실행합니다. NLM/NSM용
`flow-trace/`의 S5·S5b는 별도 loopback 구성을 사용합니다.

퍼징은 서버별 syz-manager 설정·workdir·`corpus.db`를 분리하고 한 번에 하나씩 실행합니다.
각 새 DB에는 해당 서버의 기본 시드만 넣으며 DB 병합이나 공유 corpus hub를 사용하지 않습니다.
knfsd는 `experimental.remote_cover=true`, Ganesha는 `false`로 두고 로컬 클라이언트
커널 커버리지를 사용합니다. 시드 선택과 DB 운영 방법은
[코퍼스 사용 안내](../bundle/corpus/nfs-normal/README.md#campaign-setup)를 따릅니다.
재사용 이미지의 host lane 설정도 서버별로 각각 준비해야 합니다.
병렬 실행은 manager 최상위 `snapshot=false`로 선택합니다. `vm.snapshot`은 QEMU의
임시 디스크 쓰기 옵션이며 기본값 `true`를 유지해 bake된 이미지를 보존합니다.

호스트 입력 검사는 `uv run python tools/test-lane-inputs.py`, 셸 검사는 `sh tools/lane-quote-lint.sh`로 실행합니다.
게스트의 두 백엔드와 기본 별칭은 `tools/nfs-proxy/test/guest-four-mounts.sh`로 확인합니다.
네 버전의 마운트·교차 읽기/쓰기·정리는
`uv run python tools/check-nfs-versions-guest.py --version VERSION`으로 각각 확인합니다
(`VERSION`은 `3`, `4.0`, `4.1`, `4.2` 중 하나).

### Ganesha V15.6 빌드·검증

Ganesha V15.6의 FSAL_VFS는 `tmpfs` export를 제외하므로 lane은 크기가
제한된 ext4 루프 저장소를 사용합니다.

```sh
uv run tools/build-ganesha-v15.sh
tools/nfs-proxy/build-guest.sh --out bundle/src/nfs-proxy-lane
uv run python tools/assemble-guest-deps.py \
    --ganesha-deps bundle/src/guest-deps-ganesha-v15.6.tar.gz \
    --proxy bundle/src/nfs-proxy-lane \
    --out bundle/src/guest-deps-lane.tar.gz
uv run python tools/bootstrap-kcov-env.py env \
    --base-image artifacts/bookworm-base.img \
    --ssh-key artifacts/bookworm.id_rsa \
    --deps-tar bundle/src/guest-deps-lane.tar.gz --version 4.2
uv run python tools/check-ganesha-v15-guest.py \
    --image env/images/bookworm-kcov-fresh.qcow2 \
    --seed bundle/corpus/nfs-normal/basic-v41-ganesha-tcp.prog
```

`--version 3|4.0|4.1|4.2`는 같은 이미지를 선택한 버전으로 부팅해 검증합니다.
기존 `--minor 1|2`도 각각 v4.1/v4.2 별칭으로 사용할 수 있습니다.
기존 `env/`를 갱신하면서 컴파일 결과를 재사용할 때는 `--update --skip-build`를 지정합니다.
빌더와 deps 조립기는 기존 출력 덮어쓰기를 거부하므로 이미 만든 자산을
재사용하거나 새 출력 경로를 지정합니다.

Ganesha와 libntirpc의 고정 커밋은 [build-ganesha-v15.sh](build-ganesha-v15.sh)가 명세하고 확인합니다.
빌드 중 필요한 Bookworm 의존성 기반은 임시 생성 후 제거합니다.
이미지 입력 해시는 인접한 `.json`에, 실행 시 주입한 lane 스크립트 해시는
`env/manifest.json`의 variant별 검증 결과에 기록됩니다. syz-manager에서는
`tools/prepare-live-lane-config.py`로 해시가 고정된 호스트 스크립트 스냅샷과
`workdir_template`·`vm.qemu_args`·`vm.cmdline`을 가진 새 설정을 준비합니다.

## 경계

- **번들 구조**: `bundle/` = `src/`(원천) · `patches/`(독립 시리즈) ·
  `lane/`(호스트 주입 스크립트·bake되는 부팅 래퍼와 서비스) · `baker/`(프로비저닝) · `corpus/`(시드 코퍼스).
- **파이프라인 스코프**: `fport-apply.sh`의 위치 인자 `<kind>`는 `kernel|syzkaller`만.

## 문서 맵

| 문서 | 내용 |
|---|---|
| `report/normal-flow-corpus.md` | 정상 NFS 흐름의 범위와 판정 기준 |
| `report/normal-flow-threads.md` | 실행 주체·스레드 전환 판정과 측정 기준 커널 |
| [report/validation-history.md](../report/validation-history.md) | 과거 캠페인과 검증 결과 |
| `docs/design/decisions/2026-10-05-callback-attribution.md` | kernel 0004의 callback 귀속 계약·측정 결과·한계 |

부트스트랩 무결성 판정은 `env/manifest.json`의 `status == "pass"`와 각
variant의 `verify.variants.<variant>.mem_sanitizer` 값(`kasan` 또는 `kcsan`)을
확인합니다. 커널 설정의 `CONFIG_KCOV=y`도 확인합니다. 이는 빌드·부팅
조건의 확인이며, 특정 시드의 NFS 도달이나 원격 커버리지 수집을 증명하지 않습니다.
`--skip-verify`도 `status == "pass"`를 기록하지만 `verify`는 `"skipped"`입니다.
업데이트 실패 시 이전 `manifest.json`은 보존되지만 산출물 전체가 복구되지는 않습니다.
이미 교체된 커널·VM 이미지나 syzkaller 바이너리를 이전 manifest만으로 검증됐다고 간주하지 않습니다.

## 라이선스

- `tools/`·`bundle/`(`lane/`·`baker/`·`corpus/`)·`report/` 문서: **MIT** (`LICENSE`, 작업 루트)
- 커널 시리즈: **GPL-2.0**(파생), syzkaller 시리즈: **Apache-2.0**(상류 소유)
  — 세부 귀속·고지는 `THIRD-PARTY-LICENSES.md`
