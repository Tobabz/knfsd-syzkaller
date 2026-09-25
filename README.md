# knfsd-fuzz forward-port

핸드오프 패치 시리즈(kernel 11 + syzkaller 15)를 신규 커널/syzkaller rc로
**전진 이식**하는 자동화 파이프라인입니다. 설계 계약은 `report/design-spec.md`
(게이트 R1..R6), 기계 판정은 `tools/fport-design-gate.sh`가 수행합니다.

## 구성

| 경로 | 내용 |
|---|---|
| `tools/` | 파이프라인 P0..P7·게이트 R1..R6·AB 하네스·배포 조립 (`tools/README.md`) |
| `bundle/` | 불변 입력 — 패치·픽스처·생성물(베이스 gz 등)·매니페스트 (`bundle/README-HANDOFF.md`); 상류 소스는 bootstrap이 핀 ref에서 클론 |
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

## 배포 자산

상류 소스(커널 `v7.3-rc4`, syzkaller `801f09666`)는 배포하지 않습니다 —
bootstrap이 `--kernel-repo`/`--syz-repo` 핀 ref에서 **클론**합니다
(오프라인 약속 철회 2026-09-26). `bundle/`에는 프로젝트 생성물만
`bundle/SHA256SUMS`(6항목)로 핀되어 있으며, 대용량 이진(베이스 gz 등)은
별도 자산으로 배포합니다:

```sh
bash tools/release-assembly.sh       # dist/knfsd-fuzz-forward-port-<날짜>.tar.gz
```

자산을 받아 `bundle/src/`를 복원한 뒤 `bundle/README-HANDOFF.md`의
"Reproduce" 절차로 환경을 재구축할 수 있습니다 (raw 베이스 이미지는
`bookworm-base.img.gz`를 전개).

## 라이선스

MIT (`LICENSE`) — 커널 시리즈 GPL-2.0(파생)·syzkaller 시리즈 Apache-2.0 등
벤더 컴포넌트 귀속은 `THIRD-PARTY-LICENSES.md`.