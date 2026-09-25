# 패치 forward-port 구성 가이드 — "rc4 이상 최신 메인라인에도 그대로 적용"

> 작성: 2026-09-23 · knfsd-fuzz 핸드오프 번들 (`~/work/bundle`)
> 상태: 분석·도구 구현 완료 (2026-09-23: coccinelle 제거 → **설계 의도 기반 재생성** 전환). 권장 구성 = **4계층 조합**.

---

## 0. 먼저, 사실로부터 — 왜 "그대로 적용"이 지금은 불가능한가

시리즈 11종(커널)을 실측한 결과:

| 지표 | 값 |
|---|---|
| 패치 수 / 파일 수 | 11 / **43** |
| 총 훙크 수 | **435** |
| uapi 헤더 수정 훙크 | 2 (`include/uapi/linux/kcov.h`, `include/uapi/linux/tcp.h`) |
| 고변동 파일 훙크 | `kernel/kcov.c` 50, `net/ipv4/tcp.c` 22, `fs/nfs/nfs4proc.c` 21, `net/sunrpc/svc.c` 16, `svcsock.c` 15, `xprtsock.c` 15, `xprt.c` 10, `sched.c` 7, `svc_xprt.c` 6 … |
| 구조체 본문 삽입 훙크 | 13 (uapi 구조체 포함) |

이 시리즈는 순수 부가(additive)가 아닌 **기존 함수·구조체·switch·uapi에 문맥을 끼워 넣는** 패치입니다. `git am -3`(3-way)은 "주변 문맥이 같을 때"만 병합하므로, mainline이 그 주변을 리팩터링하면 적용이 깨집니다. **의미를 보존하는 텍스트 패치로 "임의의 미래 메인라인"에 그대로 적용하는 것은 일반적으로 불가능**합니다(결정 불가).

따라서 구성의 목표는 세 가지입니다:
**① as-is 성공 면적을 최대화 ② 실패를 크고 정확하게 ③ 수리가 저렴하고 재검증이 결정적이게.**

아래 A~D 4계층이 그 목표를 담습니다.

---

## 1. 계층 A — 패치 작성 규칙 (drift 면적을 원천 축소)

새 패치를 쓸 때(그리고 기존 11종을 유지보수할 때) 지키는 규칙. 문맥 민감도를 낮추면 미래 리팩터링과 충돌할 확률이 줄어듭니다.

1. **핵심 로직은 새 파일로** — `net/sunrpc/fuzz.c`, `fuzz_conn.c`, `kernel/kcov_request.c`로 이미 분리됨(이 패턴 유지). 새 파일은 절대 충돌하지 않음.
2. **구조체/열거형/switch는 끝에만 추가** — 멤버는 `struct` 끝, 값은 `enum` 끝, case는 `switch` 끝. mainline은 앞쪽에 넣는 경향 → 뒤쪽이 가장 안정.
3. **uapi 변경은 신규 번호로만** — 기존 ioctl/flags 재용도 금지, 신규 define 추가. uapi는 ABI 테이블이라 drift 최악 등급.
4. **함수당 훙크 1개, 앵커는 시그니처+내 주석 마커** — 예: `svc_process()` 시작부 의도 기록(§3)처럼 함수 서명 자체를 앵커로. 시그니처가 바뀌면 실패가 즉시 드러나므로 안전(무음 오적용 없음).
5. **Kconfig는 파일 끝에 append** — `depends on` 새 옵션으로 게이팅, 기존 라인 불변.
6. **`#ifdef CONFIG_KCOV` 가드 유지** — 패치가 "추가만" 하면 어느 커널에든 적용되고, 컴파일 타임에 유무를 결정(§4 검증으로 확인).

> 이 규칙은 앞으로의 패치에 적용되는 원칙이며, 이미 11종이 침습적이므로 실질은 계층 B~D가 담당합니다.

---

## 2. 계층 B — 적용 기계: `tools/fport-apply.sh` + `tools/fport-variant.sh`

레포의 `apply_patch_series.sh` 의존은 **2026-09-25 번들 독립화로 제거**되었습니다.
`fport-apply.sh`는 `bundle/patches/{kernel,syzkaller}`의 시리즈를 **자체 적용**(sha 검증 +
`git am -3`)하며, 한 경로에 두 준비 수준이 있습니다.

### fport-apply.sh — 자체 시리즈 적용 (단일 경로)
- **base match** (target HEAD == 검증 베이스 `93f51579…`): `sha256sum -c` 검증 + rerere 켠 채
  `git am -3` (변형 폴백 불필요)
- **drift** (HEAD ≠ 검증 베이스, 즉 새 rc): 아래 준비까지 포함
  1. `sha256sum -c`로 시리즈 무결성 검증
  2. 클린 트리 검사
  3. `rerere.enabled=true` + `autoUpdate=true` → 충돌 해결을 **한 번 기록하면 이후 모두 자동 재생**
  4. `VARIANT_DIR`에서 "target이 포함하는 변형 베이스"를 찾아 **기록된 `rr-cache`(결정 해시)를 신선 클론에 시드**
  5. 패치별 `git am -3` — 실패 시 해당 패치·훙크를 지목하고 `am --abort`로 트리 복원, 종료 코드로 실패 전달
  6. 성공 시 적용 커밋 수·HEAD 출력, `PREP_POST_APPLY_HOOK`(예: §4 검증) 실행 가능

### fport-variant.sh — rc 경계마다 변형 기록 (유지보수 연산)
```
fport-variant.sh kernel <repo> <new-rc-base>
```
- target clone(스크래치)에서 `checkout new_base` → rerere on → 이전 변형의 rr-cache 시드 → `git am -3`로 재베이스
- 새 변형 번들(`0001-*.patch…` + `SHA256SUMS` + `META{variant_base, applied_base}` + `rr-cache/`)을 export
- 이후 그 rc 이후의 아무 트리에서 `fport-apply.sh`를 돌리면 **결정이 자동 재생되어 as-is 적용** — rc 창 안에서는 "그대로 적용"이 성립

> 메커니즘 요지: "무한히 미래"를 보장하는 게 아니라, **한 번 rc마다 재베이스 + 결정 기록으로 매번 그 창에서 as-is**를 만드는 것입니다. 결정(conflict resolution)은 `.git/rr-cache`에 해시 고정되어 재현 가능합니다.

---

## 3. 계층 C — 설계 의도 기반 패치 재생성

`git am -3`(계층 B)이 리팩터링된 훙크를 못 풀면, 패치를 **재작성**한다. 기준은
**자연어 설계 기록**이다 — design-spec.md §2(R1..R6 관찰 가능 계약) + 아래
**패치별 의도 인덱스**. 패치 파일은 의도의 구현 후보일 뿐이므로, 의도가 유지되는 한
새 rc 트리에 맞는 새 텍스트 패치를 만들어 적용하는 것이 유일한 수동
체크포인트(§7, exit 10)가 된다.

### 패치별 의도 인덱스 (재생성의 기준 — "패치가 무엇을 원하는가")

커널 11종 (`bundle/patches/kernel/`):

| # | 의도 (Subject) | 해당 계약 |
|---|---|---|
| 0001 | sunrpc: KCOV 원격 커버리지 지원 (svc_process 진입 훅) | R2/R4 경로 |
| 0002 | sunrpc: 명시적 NFS fuzz 논리 출처 (origin 태깅) | R2 기여 식별 |
| 0003 | sunrpc: TCP fuzz 연결 상관 (lane→conn 귀속) | R2/R4 |
| 0004 | kcov: 요청 세대 토큰 수명주기 | R4 심도 |
| 0005 | kcov: 트랜잭션 NFS 원격 속성 (거래 단위 귀속) | R4 |
| 0006 | sunrpc: 속성 중단 후 논리 쿠키 보존 | R5 무결성 |
| 0007 | kcov: NFS 원격 요청 커버리지 집계 | R4 수집 |
| 0008 | sunrpc: 원격 속성 회귀 경로 하드닝 | R5 |
| 0009 | sunrpc: raw RPC fuzz 속성 인터페이스 | R2/R4 |
| 0010 | kcov: 지연·비동기 NFS 서버 작업 귀속 | R4 심도 |
| 0011 | sunrpc: 멀티 레인 속성 진단 | R5 증거 |

syzkaller 15종 (`bundle/patches/syzkaller/`):

| # | 의도 (Subject) |
|---|---|
| 0001..0005 | executor: KCOV 요청 세대를 프로그램 실행 수명에 바인딩·관리 |
| 0006 | sys/linux: opt-in SunRPC fuzz 메시지 기술 |
| 0007..0010 | executor: 프로세스별 고정 NFS lane 바인딩·격리·실패 시 닫힘 |
| 0011..0012 | execprog: 원격 커버리지 측정 토글·타임스탬프 |
| 0013..0014 | executor: 고정 lane 행잉 구분·마커 은닉 |
| 0015 | sys/linux: 프로토콜 형태 NFS fuzz 오퍼레이션 |

### 재생성 절차 (고변동 파일 우선)

1. **우선순위**: `kernel/kcov.c`(50훙크), `net/ipv4/tcp.c`(22), `fs/nfs/nfs4proc.c`(21),
   `net/sunrpc/svc.c`(16)·`svcsock.c`(15)·`xprtsock.c`(15) — 이 6파일이 미래 충돌의 9할.
2. 실패 훙크 → 위 인덱스에서 해당 패치의 **의도**를 확인 → design-spec의 해당 계약과
   대조 → 새 트리에서 의도가 들어갈 위치를 확정 → 계층 A 규칙을 지켜 새 텍스트 패치 작성.
   **새 파일·Kconfig·문서는 텍스트 diff 유지** (변화 없음).
3. `fport-apply.sh` 재실행 → §4 게이트 세트로 diff·거동 동일성 검증
   (기존 693/694행 verbatim 검증 방식과 동일).
4. 시계열: 깨진 훙크만 순차 재생성 (전량 재작성 불필요).

> 의도의 대상 구문 자체가 사라졌다면(예: `svc_process` 분할) 어떤 방식도 실패한다.
> 그때는 "구조가 바뀌었음"이 즉시 드러나 조용한 오적용보다 훨씬 안전하고, 재생성
> 불가 판정은 design-spec §3의 계약 재협의 입력이 된다.

---## 4. 계층 D — 검증 프로토콜: "applied ≠ correct"

어떤 경로로 적용하든, **적용 성공은 의미론적 정확성의 증거가 아닙니다.** 따라서 적용 후 아래 게이트(전체 T1~T10 중 서브셋)를 반드시 통과시켜야 as-is 판정을 내립니다:

| 단계 | 게이트 | 스크립트 |
|---|---|---|
| 1 | 부트스트랩 manifest `status: pass`, `verify.target_kasan: true` | bootstrap + `verify` |
| 2 | AB 러너 ON 트라이얼 `bindings {(0,0),(1,1)}`, `converged: true`, off fs/nfsd=0 vs on>0 | `run-ab.sh` + `analyze-ab.sh` |
| 3 | 원격 커버리지 심도 (일반 코퍼스): fs/nfsd `on_only ≥ 100`, net/sunrpc `on_only > 0`, 핸들러 랭킹 ≥ 10행 + `nfsd4_proc_compound` | `analyze-ab.sh` 산출물 (`set_analysis` + `coverage_sets/`) |
| 4 | 증거 연쇄: `status=PASS`, `integrity_pass=true`, 기여 지분 ≥ 95%, 커버리지 셋 6종 존재 | `analyze-ab.sh` + `coverage_sets/` |


게이트가 실패하면 **패치를 "적용 실패"로 취급**하고 해시 고정된 원본 베이스로 되돌려 §3 재생성을 다시 진행합니다. 이 프로토콜 덕분에 "as-is 적용 + 검증 통과"가 같은 위치에 기록되어 핸드오프 감사가 가능해집니다.

---

## 5. rc 배포 시 체크리스트 (운영 절차)

```
1. 새 rc 출시 (예: v7.4-rc1)
2. fport-variant.sh kernel linux-repo <rc1-base>   # 한 번 재베이스, 결정 기록
3. 부트스트랩(신선 WSL2): fport-apply.sh kernel <fresh-clone>
   → 변형 시드 + rerere 재생으로 적용 (대부분 as-is)
4. §4 게이트 4종 실행
5. 실패 시: 설계 의도 기록(§3)으로 해당 패치 재생성 → 게이트 재실행
6. 결과를 리포팅 (적용 베이스 해시, 게이트 상태)
```

---

## 6. 정직한 경계

- **"임의의 미래 메인라인에 100% as-is"는 보장 불가** — 타깃 구문 자체가 (a) 사라지거나 (b) 의미론적으로 재작성되면 어떤 수단도 실패합니다. 이때는 실패가 **크고 정확**하며, 수리는 해당 패치의 재생성 하나로 좁혀집니다(§3).
- syzkaller(Go) 측 15+3패치도 동일 원칙: 변형 시드(fport-apply/fport-variant는 `kind`로 동일 적용) + Go AST 기반 삽입(텍스트 문맥 최소화).
- 이 구성이 "검증 가능한 재현"을 깨지 않습니다: 모든 결정·변형·적용 결과는 **해시에 고정**되어 감사 가능.
- **검증 코퍼스 (추후 작업, 2026-09-25 결정)**: 현재 게이트는 단일 일반 NFS 코퍼스 + OFF/ON 대조군으로 판정. 패치의 도달 지점이 다방향(디스패치 NFSv4 · TCP 상관 · kcov 수집 · 지연 작업 귀속)이므로, **도달 지점별 전용 검증 코퍼스 설계**를 별도 작업으로 남겨둔다. 그 전까지 R4(경로 도달 심도)가 코퍼스 적합성의 최소 안전장치 역할을 한다.

---

## 7. 파이프라인 자동화 — `tools/fport-pipeline.sh`

체크리스트(§5) 전체를 하나의 결정적 런으로 엮는 오케스트레이터. **설계 게이트(§4)가 최종 권위**이고, 패치 적용은 그 중간 구현 단계일 뿐입니다.

### 페이즈 (런 매니페스트 `~/work/runs/port-<kind>-<ts>/`에 기록)

| 페이즈 | 내용 | 자동화 |
|---|---|---|
| P0 provision | 도구·번들 SHA·타깃·증거 존재 검사 | ✅ |
| P1 detect | 베이스 drift 판정 + 시리즈 적용 여부(**sentinel** 신규 파일 존재 — 커밋 무관) | ✅ |
| P2 variant | `--new-base <sha>` 트리거 시 `fport-variant.sh`가 rc 변형 기록 | ✅ |
| P3 apply | 자체 적용 — base match / drift=rerere+3way+변형 시드 (fport-apply) / 이미 적용=skip | ✅ |
| P4 build-check | vmlinux·qcow2 산출물 해시 (전량 재빌드는 신선 env 부트스트랩에서) | ✅ |
| P5 gates | `fport-design-gate.sh` 설계 게이트 R1..R6 (기계 오라클) | ✅ |
| P6 evidence | 일반 코퍼스 AB→분석 하네스 (reuse 모드: 기존 증거 재사용) | ✅(full)/⏭(reuse) |
| P7 report | 매니페스트 + `port-run.md`, 종료 코드 | ✅ |

### 종료 코드 (CI 매핑용)

`0=HOLDS · 1=게이트 실패 · 2=전제조건 위반 · 10=적용 실패(인간 체크포인트) · 20=환경 실패`

### 유일한 인간 체크포인트 (그리고 어떻게 구조화되는가)

P3가 실패하면 파이프라인은 **실패한 패치·훙크 진단과 함께 코드 10으로 중지**합니다. 그 한 지점에서 인간은 의도 인덱스(§3)를 바탕으로 해당 패치를 재생성해 번들을 갱신하고 재실행하면 **P3부터 재개**됩니다. 그 외의 모든 판정은 자동입니다.
게이트 실패(P5)도 "어느 요구사항이 깨졌는지"를 게이트가 곧 진단으로 알려주며, 전제 위반은 `2`로 구분되어 "실패"가 아니라 **계약 경계**로 기록됩니다.

### 호스티드 CI 매핑 (선택)

러너(신선 WSL2)에서: 새 커널 rc 태그 감지(또는 수동 dispatch `--new-base`) → `fport-pipeline.sh --mode full` 실행 → 산출물(매니페스트+증거) 아티팩트 업로드. 게이트 판정이 CI 상태가 되고, 코드 `10`만 "인간 조치 필요"로 라우팅됩니다. 로컬 재현은 `fport-pipeline.sh --mode reuse`로 언제든 수행 (위 실측 1회 실행 기록: `~/work/runs/port-kernel-20260923-*/`).

### 환경 이식 — 경로 관례 제거 (2026-09-25)

fport-* 파이프라인 경로는 더 이상 절대 경로에 고정되지 않습니다. **스크립트 위치에서 작업 루트를 자동 유도**하고, 필요 시 환경변수로 오버라이드합니다 (`/tmp`에서 실행한 reuse 검증: exit 0 · DESIGN HOLDS — CWD 무관).

- **기본 유도**: `<루트>/tools/*.sh`의 부모 = 작업 루트 → `bundle/`·`env/`·`evidence/`·`report/`·`runs/` 하위를 자동 파생. 번들 구조를 통째로 옮기면 그대로 동작합니다.
- **오버라이드** (`KOOV_WORK_ROOT` 하나면 전체 이동, 개별 재정의도 가능):

| 변수 | 용도 |
|---|---|
| `KOOV_WORK_ROOT` | 작업 루트 전체 재배치 |
| `KOOV_BUNDLE` | 번들 (불변 repo) — apply·variant·design-gate·hygiene·risk 공통 |
| `KOOV_MANIFEST` | 부트스트랩 매니페스트 |
| `PORT_RUNS` | 런 매니페스트 저장소 |
| `KOOV_PATCH_VARIANTS` | 변형 기록 저장소 |

- **유일한 불변 고정값은 `expected_base` 커밋 해시** — 경로가 아니라 콘텐츠 식별자라 이식 대상이 아닙니다.

### 디렉토리 배치 (명칭 개편 2026-09-25 — 역할·권위는 이 표)

| 디렉토리 | 내용 | 성격 |
|---|---|---|
| `tools/` | 파이프라인·분석·진단 스크립트 (`fport-*`, AB 하네스) | 실행 코드 |
| `bundle/` | **독립 번들** — `src/`(원천)·`patches/`(독립 시리즈)·`ab-runner/`(AB 런처)·`baker/`(프로비저닝)·`corpus/`(코퍼스) | ✅ 불변 입력 |
| `env/` | 커널 빌드·vmlinux·qcow2·syzkaller·매니페스트 | 산출물/환경 |
| `evidence/` | AB 대조 증거 (분석 요약·커버리지 셋) — 게이트 oracle | ✅ 생성 증거 |
| `runs/` | 파이프라인 런 매니페스트 (`port-<kind>-<ts>/`) | 실행 기록 |
| `report/` | 문서·SVG·개명 대장·증거 해시 | 기록·문서 |

- **하이픈 제거**: `ab-results`·`port-runs`의 구분자 없이 단일어 명칭으로 통일.
- **이식 범위 (실태)**: 파이프라인(`fport-*`) 경로는 스크립트 위치에서 유도 + `KOOV_*` 오버라이드. AB 하네스(`run-ab.sh`, `run_ab_adapted.py` 등)는 새 구조(`bundle/`·`env/`·`evidence/`)와 일치하는 관례 절대경로를 문자열로 참조 — `--mode full` 전에 그 구조만 준비하면 됩니다.

---

## 새 산출물 (tools/)

| 파일 | 역할 |
|---|---|
| `fport-patch-hygiene.py` | 패치 위생 분석 (43파일/435훙크/uapi/구조체 수치; spatch 의존 없음) |
| `fport-patch-risk.py` | drift 위험 지표 (uapi·고변동 파일·구조체 삽입 훙크 목록) |
| `fport-apply.sh` | 자체 시리즈 적용 (base match / drift=rerere+3way+변형 시드) |
| §3 의도 인덱스 | 패치별 의도(커널 11 + syzkaller 18종) — 재생성 기준 (이 문서 §3) |
| `fport-variant.sh` | rc 재베이스 변형 기록 (rr-cache 포함) |