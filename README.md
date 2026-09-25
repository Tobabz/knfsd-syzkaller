# knfsd-syzkaller

핸드오프 패치 시리즈(kernel 11 + syzkaller 15)를 신규 커널/syzkaller rc로
**전진 이식**하는 자동화 파이프라인입니다. 설계 계약은 `report/design-spec.md`
(게이트 R1..R6), 기계 판정은 `tools/fport-design-gate.sh`가 수행합니다.

## 구성

| 경로 | 내용 |
|---|---|
| `tools/` | 파이프라인 P0..P7·게이트 R1..R6·AB 하네스·배포 조립 (`tools/README.md`) |
| `bundle/` | 불변 입력 — 패치·픽스처·guest-deps·매니페스트 (`bundle/README-HANDOFF.md`); 베이스·키쌍은 `tools/make-base-image.sh`로 사이트 생성 |
| `report/` | 설계 계약·검증 결과·변경 대장 (증거 해시 `report/evidence-forward-port.sha256`) |
| `LICENSE` · `THIRD-PARTY-LICENSES.md` | MIT + 벤더 컴포넌트 귀속 |

## 빠른 시작 · 게이트

```sh
bash tools/fport-pipeline.sh --mode reuse    # 로컬 재검증 (빠름, 결정적)
bash tools/fport-design-gate.sh -v          # R1..R6 기계 판정 (exit 0 = DESIGN HOLDS)
bash tools/portability-check.sh             # 구문 + /tmp 이동 실행 + 게이트 일괄
bash tools/fport-evidence.sh                # 도구·문서 수정 후 증거 해시 재기록
```

신규 rc 포팅: `bash tools/fport-pipeline.sh --mode full --kind kernel
--target <신선 클론> --new-base <해시>` (전 과정 및 페이즈는 `tools/README.md`).

## 재현 (자급자족 저장소 — 릴리스 자산 없음)

2026-09-26부터 어떤 릴리스 자산도 배포하지 않습니다. 상류 소스(커널
`v7.3-rc4`, syzkaller `801f09666`)는 bootstrap이 `--kernel-repo`/`--syz-repo`
핀 ref에서 클론하고, 베이스 이미지·키쌍은 `tools/make-base-image.sh`로
사이트별 생성합니다 (create-image.sh 산출물은 바이트 비결정 — 각 사이트의
생성물이 곧 그 사이트의 검증 대상).

```sh
sudo bash tools/make-base-image.sh --out artifacts   # base + keypair (1회)
python3 tools/bootstrap-kcov-env.py env \
  --base-image artifacts/bookworm-base.img \
  --ssh-key artifacts/bookworm.id_rsa \
  --deps-tar bundle/src/guest-deps.tar.gz --minor 1
KOOV_SSH_KEY=artifacts/bookworm.id_rsa bash tools/run-ab.sh   # evidence
bash tools/fport-design-gate.sh -v                            # R1..R6
```

선택적으로 `bash tools/release-assembly.sh`로 유지보수용 스냅샷 아카이브를
만들 수 있습니다 (배포가 아님).

## 라이선스

MIT (`LICENSE`) — 커널 시리즈 GPL-2.0(파생)·syzkaller 시리즈 Apache-2.0 등
벤더 컴포넌트 귀속은 `THIRD-PARTY-LICENSES.md`.