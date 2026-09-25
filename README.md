# knfsd-fuzz forward-port

핸드오프 패치 시리즈(kernel 11 + syzkaller 15)를 신규 커널/syzkaller rc로
**전진 이식**하는 자동화 파이프라인입니다. 설계 계약은 `report/design-spec.md`
(게이트 R1..R6), 기계 판정은 `tools/fport-design-gate.sh`가 수행합니다.

## 구성

| 경로 | 내용 |
|---|---|
| `tools/` | 파이프라인 P0..P7·게이트 R1..R6·AB 하네스·배포 조립 (`tools/README.md`) |
| `bundle/` | 불변 입력 — 패치 시리즈·픽스처·매니페스트 (`bundle/README-HANDOFF.md`); `src/` 대용량 이진은 릴리스 자산으로 별도 배포 |
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

`bundle/src/`(커널·syzkaller 소스, 베이스 이미지, 키쌍)는 git에 트래킹하지
않습니다. `bundle/SHA256SUMS`로 핀하고, 릴리스 자산으로 배포합니다:

```sh
bash tools/release-assembly.sh       # dist/knfsd-fuzz-forward-port-<날짜>.tar.gz
```

자산을 받아 `bundle/src/`를 복원한 뒤 `bundle/README-HANDOFF.md`의
"Reproduce" 절차로 환경을 재구축할 수 있습니다 (raw 베이스 이미지는
`bookworm-base.img.gz`를 전개).

## 라이선스

MIT (`LICENSE`) — 커널 시리즈 GPL-2.0(파생)·syzkaller 시리즈 MIT 등
벤더 컴포넌트 귀속은 `THIRD-PARTY-LICENSES.md`.