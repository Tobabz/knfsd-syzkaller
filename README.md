# knfsd-syzkaller

Linux 커널의 **NFS 서브시스템(knfsd)**을 syzkaller로 퍼징하기 위한 **커스텀 syzkaller 퍼징 환경 생성 도구**입니다.
KCOV(커널 커버리지)·KASAN 계측 커널과 **remote KCOV 커버리지 모델**(NFS 서버 측 커버리지를 원격 수집)을 반영해,
베이스 이미지 → 패치 적용 커널/바이너리 → VM 부팅 이미지까지 퍼징 환경을 자동 구축합니다.

체크인된 커스텀 시리즈(kernel **11** 패치 + syzkaller **15** 패치, `bundle/patches/`)는 신규 커널/syzkaller
rc가 나오면 전진 이식(forward-port) 파이프라인(P0..P7)이 재적용·재빌드합니다. 환경 유효성은 설계 계약 게이트
**R1..R6**(`tools/fport-design-gate.sh`)이 기계 판정합니다.

## 설계 반영점

| 항목 | 내용 |
|---|---|
| 계측 | KCOV + KASAN 부팅 커널 |
| 커버리지 모델 | **remote KCOV** — knfsd 서버 측 커버리지를 원격 수집(`remote_cover`·`cover_edges`); fs/nfsd·net/sunrpc의 PC가 이 경로로 귀속 |
| A/B 인과 검증 | remote 커버리지 **ON/OFF를 유일 변수**로 한 퍼징 실험 — OFF에서 fs/nfsd 커버리지 0, ON에서 1,748 PC 수집 (게이트 R2) |
| 퍼징 레인 | 고정 34-call NFS 레인 워크로드 · mount 네임스페이스 클라이언트0/1 (`/nfs-lane`) |
| NFS 버전 | `--minor 1\|2`로 NFS 마이너 버전 선택 (매니페스트에 기록) |
| 부팅 모델 | 커널을 이미지 **외부에서 `-kernel`로 주입** — 베이스 이미지는 커널과 독립, rc마다 재베이크만 수행 |
| 적용 무결성 | 패치 적용 시 sha 검증 + `git am -3` (drift 시 rerere·변형 fallback) |

## 요구사항 (호스트)

- Linux + KVM(`/dev/kvm`) + QEMU, sudo, `git`·`python3`·`sha256sum`·`qemu-img`
- 커널 빌드 툴체인(gcc/make/`flex`·`bison`·`libelf` 등)과 Go ≥1.23 (syzkaller 빌드)
- 디스크 여유 ~30 GiB — 부트스트랩이 상류(kernel `v7.3-rc4`·syzkaller `801f09666`)를 핀 ref에서 클론해 빌드

## 적용 방법 — 명령·입력·출력

### 1. 베이스 이미지 생성 (사이트당 1회)

```sh
sudo bash tools/make-base-image.sh --out artifacts
```

- **입력**: 호스트 root(sudo) + debootstrap + 네트워크 (pinned syzkaller 트리의 `create-image.sh -d bookworm`)
- **출력**: `artifacts/bookworm-base.img`(2 GiB raw ext4, 커널 미포함) · `artifacts/bookworm.id_rsa[.pub]`(SSH 키쌍, `.id_rsa` 권한 600)

### 2. 퍼징 환경 프로비저닝 (빌드 + 베이크)

```sh
python3 tools/bootstrap-kcov-env.py env \
  --base-image artifacts/bookworm-base.img \
  --ssh-key artifacts/bookworm.id_rsa \
  --deps-tar bundle/src/guest-deps.tar.gz \
  --minor 1
```

| 입력 | 설명 |
|---|---|
| `--base-image` · `--ssh-key` · `--deps-tar` (필수) | 1단계 산출물 + 게스트 의존성 |
| `--minor 1\|2` (필수) | NFS 마이너 버전 |
| kernel/syzkaller 소스 (기본) | pin ref에서 클론 — kernel `v7.3-rc4`, syzkaller `801f09666` |
| `--kernel-repo`/`--syz-repo` (선택) | 클론 URL 교체 |
| `--kernel-tarball`/`--syz-tarball` (선택) | 오프라인 원본 아카이브 대체 |

- **동작**: 상류 클론 → 시리즈 적용(11+15) → `bzImage`·`vmlinux` + syzkaller 바이너리 빌드 → VM 부팅 이미지 베이크(`bookworm-kcov-fresh-v1.raw`) → 레인 상태 검증
- **출력**: `env/` — `env/linux/arch/x86/boot/bzImage`, `env/linux/vmlinux`, `env/syzkaller/bin/…`, `env/bookworm-kcov-fresh-v1.raw`, **`env/manifest.json`**(소스·핀·빌드 상태 전부 기록)

### 3. A/B 퍼징 · 증거 수집

```sh
KOOV_SSH_KEY=artifacts/bookworm.id_rsa bash tools/run-ab.sh
bash tools/analyze-ab.sh
```

- **입력**: 2단계의 `env/`(bzImage·이미지·vmlinux) + `KOOV_SSH_KEY`(기본 `bundle/src/bookworm.id_rsa`)
- **동작**: fresh `-snapshot` VM에서 remote 커버리지 **OFF/ON × 2트라이얼 × 30실행**, 고정 34-call 레인 워크로드 실행(증거 T1..T6). 분석 단계는 raw PC 심볼화 · NFS 오퍼레이션별 핸들러 게이트 · 성능 지표(T7·T9)
- **출력**: `evidence/` — OFF/ON 커버리지, 심볼화 결과, 핸들러 게이트, 실행·RPC 처리율

### 4. 설계 게이트 판정

```sh
bash tools/fport-design-gate.sh -v
```

- **입력**: `env/manifest.json` + `evidence/` 분석 결과
- **출력**: R1..R6 판정 — **exit 0 = DESIGN HOLDS** (1 = 게이트 실패, 2 = 전제조건 위반)

### 5. 신규 rc 전진 이식 (커널/syzkaller)

```sh
bash tools/fport-pipeline.sh --mode full --kind kernel \
  --target <신선 클론 경로> --new-base <신규 rc 커밋 해시>
```

- **입력**: 신규 rc ref(커밋 해시) · **출력**: `runs/port-kernel-<스탬프>/` 런 매니페스트 + `port-run.md` (P0..P7 일괄: 적용→빌드→게이트→AB 증거→보고서)

## 명령 요약

| 단계 | 명령 | 입력 → 출력 |
|---|---|---|
| 재검증 | `bash tools/fport-pipeline.sh --mode reuse` | 기존 증거 → 게이트 재판정 (빠름·결정적) |
| 베이스 | `sudo bash tools/make-base-image.sh --out artifacts` | sudo+debootstrap → `artifacts/bookworm-base.img`·키쌍 |
| 부트스트랩 | `python3 tools/bootstrap-kcov-env.py env --base-image … --ssh-key … --deps-tar … --minor 1` | base·키·deps + 상류 → `env/` (bzImage·바이너리·이미지·manifest) |
| A/B | `KOOV_SSH_KEY=… bash tools/run-ab.sh && bash tools/analyze-ab.sh` | `env/` → `evidence/` (OFF/ON 커버리지·지표) |
| 게이트 | `bash tools/fport-design-gate.sh -v` | manifest+evidence → R1..R6 (0=HOLDS) |
| rc 포팅 | `bash tools/fport-pipeline.sh --mode full --kind kernel --target … --new-base <해시>` | 신규 rc → `runs/port-*` 보고서 |
| 포터빌리티 | `bash tools/portability-check.sh` | 구문 검사 + 이동 실행 + 게이트 일괄 (0=통과) |
| 증거 갱신 | `bash tools/fport-evidence.sh` | 도구·문서 수정 후 증거 해시 재기록 |

## 구성

| 경로 | 내용 |
|---|---|
| `tools/` | 파이프라인 P0..P7 · 게이트 R1..R6 · AB 하네스 · 베이스 생성 (사용법 `tools/README.md`) |
| `bundle/` | 불변 입력 — 패치 시리즈 · guest-deps · 커널 설정 · 매니페스트 (`bundle/README-HANDOFF.md`) |
| `report/` | 설계 계약 · 검증 결과 · 변경 대장 (증거 해시 `report/evidence-forward-port.sha256`) |
| `LICENSE` · `THIRD-PARTY-LICENSES.md` | MIT + 벤더 컴포넌트 귀속 |

## 라이선스

MIT (`LICENSE`) — 커널 시리즈 GPL-2.0(파생) · syzkaller 시리즈 Apache-2.0 등 벤더 컴포넌트 귀속은 `THIRD-PARTY-LICENSES.md`.
