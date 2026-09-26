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
| 1 | 부트스트랩 manifest `status: pass`, `verify.mem_sanitizer ∈ {kasan, kcsan}` | bootstrap + `verify` |
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

### S4 검증 코퍼스 판정 — async COPY offload hop 미귀속 (2026-09-26)

검증 코퍼스 설계의 첫 이행으로 `reach-copy-offload`(S4: NFSv4.2 async COPY offload
thread-hop, 패치 0003/0009/0010, lane_minor 2)를 OFF/ON 대조로 판정했다. 결과는
**PASS가 아니라 정직 경계 기록**이다. 원격 kcov 채널 자체는 정상이며, **비동기
COPY가 포함된 워크로드에서만 서버측 원격 커버리지가 전무**하다는 것이 결정적
증거로 확정되었다.

| 실행 (동일 인프라·동일 날) | workload | ON extra | 판정 근거 |
|---|---|---|---|
| v1 (evidence2) | 동기-only 10콜 | **10 파일 (233K+ PC)** | 채널 정상 기준선 |
| **v1 재실행 대조 (evidence5)** | **동기-only 10콜** | **10 파일 재현 (6394 unique PC)** | 오늘 재현: 인프라 무결 |
| v2 (evidence3) | 비동기-only 11콜 | 0 | 동기 RPC(open/pwrite/ftruncate) 처리조차 미귀속 |
| 하이브리드 (evidence4) | 동기+비동기 19콜 | 0 | 동기 leg 클라 커버리지는 v1과 동일(CALL5 copy 3141 vs 3135)한데 extra=0 |

- **채널 인프라 정상 입증**: v1(evidence2)과 동일한 kernel `5b22ba55` · image
  `78ac48d0` · executor `2947f148` · execprog `3fef7a42` · fixture
  `b2b47a9e...`로 오늘 재실행(evidence5)해도 ON extra=10이 재현됐다.
  evidence5 드레인 phase8은 async 카운터 전부 0(동기만 있으므로 기대값)이고,
  동기 sentinel(`nfsd4_copy`·`_nfsd_copy_file_range`·`nfsd4_open`·`nfsd4_write`
  ·`svc_process_common`)이 전부 PRESENT, 비동기 sentinel은 부재 — v1과 동일한
  정상 기준선.
- **비동기 영향 확정**: v2(비동기-only)와 하이브리드(같은 프로그램 안에 동기
  COPY + 비동기 COPY, 19콜) 모두 ON extra=0. 하이브리드에서 동기 leg가 클라
  커버리지로 완전히 정상 수행됐음에도 extra=0이므로, **비동기 COPY hop이
  존재하는 실행에서는 원격 귀속 자체가 수집되지 않는다**. 이는 단순 플레이크가
  아니라 워크로드 특성이다(2회 재현).
- **공식 파이프라인 재판정 (evidence5, 대조군)**: `analyze-ab.sh` +
  `reach-assert.py`(manifest-v1.json)로 재판정한 결과 evidence2와 **완전
  동일** — fs/nfsd on_only PC 1380(evidence2와 동일값), `nfsd4_copy`
  asserted=True, async sentinel 전부 부재, 통합 verdict FAIL(동기-only
  코퍼스의 기대 프로파일). 대조군 FAIL은 "async 트리거 부재"이지 채널
  이상이 아님을 공식 판정으로 확인.
- **async leg 발화 증명**: 하이브리드 OFF 드레인 phase8 `async_child_rejected
  10` — continuation save가 실행당 1회 시도되어 OFF(원격 세션 없음)에서 전량
  거부된 것. v2 OFF와 동일.
- **경계 기록**: S4 코퍼스로는 "비동기 COPY offload hop(연속 저장 → 서버
  worker kthread → CB_OFFLOAD 콜백 leg)의 원격 커버리지 귀속"을 **입증하지
  못했다**. 동기 COPY 검증(v1)은 여전히 유효하므로, 이 입증 공백은
  `sunrpc_fuzz_svc_continuation_save`/`saved_work_start|stop` 귀속 경로의
  부재(extra=0)로 좁혀진다. 후속 조사 대상: ON 실행에서 세션이 비동기 hop
  시점에 파괴/중단되는지(phase8 드레인이 validate 중단으로 미수집) — 실행
  파이프라인의 ON 검증이 extra=0에서 즉시 중단되어 ON 드레인 phase8이 없으므로,
  이 관측 공백 자체를 기록으로 남긴다.

**판정 요약**: S4 = 정직 경계(비동기 hop 미귀속, PASS 불가). 인프라 문제로
올리지 않는다 — v1 재실행(evidence5)이 같은 날·같은 인프라에서 extra=10을
재현했기 때문.

---
### S3 스파이크 판정 — sunrpc 계속형(deferred-resume) hop 귀속 정상 (2026-09-26)

deferred-resume hop(`svc_defer` → `svc_deferred_recv` 재생)의 원격 커버리지
귀속을 독립 스파이크(Gate 8)로 판정했다. 결과는 **PASS — 귀속 정상**이다.
이는 S4의 "async COPY hop 미귀속"이 saved-work 공통 결함이 아니라
**연속 저장 계열 전체가 정상이고 async COPY hop에만 한정된 특이**로 좁힌다.

**사용 가능한 트리거 — V2(export flush) 하나뿐**: NFSv4의 gid/idmap 지연은
`nfs4xdr.c:6785`의 `clear_bit(RQ_USEDEFERRAL)`(NFSv4 decode 후 명시적 해제)과
`nfs4idmap.c:666/704`의 `WARN_ON_ONCE(RQ_USEDEFERRAL)`로 문서상 원천
불가능하다. 남은 유일한 경로는 mountd SIGSTOP + (nfsd.export·auth.unix.ip)
cache flush로 강제한 캐시 미스 → `rqst_exp_get_by_name`(export.c:1920-1930)
→ `cache_check` → `svc_defer`(svc_xprt.c:1320) → mountd SIGCONT →
`svc_deferred_recv`(svc_xprt.c:1355) 재생이다.

**게이트 실행 — frozen Gate 8 (첫 실행)**: `run_frozen_phase8_vm.py`를
수정 없이 실행했다(산출물 `~/frozen-gate8-s3-evidence4/`). 실행 인자/해시:
kernel `5b22ba55` · image `78ac48d0` ·
lane `tools/ab-lane-fixture-gate8.sh`(`ddf3a583…`) · bootstrap
`frozen_phase3_bootstrap.sh`(`4e8414c0…`) · deps `f214e8f4…` — S4
evidence5와 같은 기준선 인프라. `--lane-script`에 **phase9-fixture
retirement prelude + `frozen_phase1_lane.sh` 본문 바이트 동일** 래퍼를
주입했다. 이미지가 부팅 시 4-lane fixture를 자동 기동해 게이트 8의
`create 0`을 충돌시키므로(`printf: I/O error`로 1·2차가 실패), S4의
`tools/ab-lane-fixture-v42.sh`와 같은 prelude로 fixture를 먼저 정리했다.

**판정 계약 (validate_gate, 전 항목 True)**:
- `deferred-normal_probe_contract` = True — `status=pass`,
  `local_entries=31449`, **`remote_entries=20975 (>0)`**: deferred-normal
  스파이크에서 원격 세션이 실제로 수집됨 → **hop 귀속 정상 판정식**.
- `real_deferred_replay_completed` = True — `deferred_child_created=1` 이고
  `deferred_restored`/`grant_ok`/`start_ok`/`completed` 각각 =1, 비정상
  카운터 전부 0: `svc_defer`→재생→grant→start→complete 생애주기 완결.
- deferred-abort-2종: `remote_entries=0`(요구값) — abort-before-grant는
  restored→abort_before_grant→owner_none→dropped, abort-after-grant는
  restored→grant_ok→start_ok→pause_entered→pause_released→completed,
  각각 생애주기 정확. **abort 계열은 미귀속이 기대값과 일치**.
- 부수 발견 — **async-normal도 remote_entries=791265**: 게이트 8의
  KCOV_REMOTE_ENABLE(common_handle, 5000ms) 계측으로는 async COPY hop도
  귀속된다. S4의 extra=0은 어트리뷰션 결함이 아니라
  syz-executor 기반 채널 특이로 재해석 여지가 생긴다(후속 확인 대상).
- phase3 도메인 스냅샷: `domain_created=1, domain_joined=2,
  domain_retired=4, lane_epoch_collision=0`. 게이트 lane0(epoch 5)이
  단일 도메인으로 깨끗하게 할당됐고(충돌 0), 부팅 fixture의 4-lane이
  retired 상태로 정리됐으며 최종 연결은 epoch 5(10.77.0.x) 2개뿐 —
  **래퍼 prelude가 부팅 fixture를 실제로 retirement했다는 기계적 증거**.
  `isolated_lane_is_nfsv42`, `wire_ordinals_aligned`,
  phase4/5/6 exact drain, lifecycle/controls clean 전부 True. 최종
  `cleanup_returncode=0, validation_returncode=0`.

**결론**: sunrpc 계속형(deferred-resume) hop은 원격 커버리지 귀속이
**정상 동작**한다(V2 export-flush 트리거에서 시작해 재생·수집까지 완결).
S4의 관측(비동기 COPY만 extra=0, 동기-only 대조는 extra=10)은
"연속 저장 hop 귀속 경로 부재"가 아니라 **async COPY offload hop에 한정된
특이**로 판정 범위가 좁혀졌다. 후속 과제: async 특이를 별도 스파이크로
격리해 원인(세션 파괴/중단 시점)을 좁힌다(S4 후속으로 이미 기록됨).

### S3b 스파이크 판정 — 확장 GENERATION 윈도우: async COPY hop 귀속 유지 (2026-09-26)

S3의 후속 과제("async 특이를 별도 스파이크로 격리") 이행 — 옵션 B대로
**GENERATION 수집 윈도우를 확장**해 async COPY offload hop이 원격 커버리지에
잡히는지 재판정했다. 결과는 **PASS — 확장 윈도우에서도 async hop 귀속 유지**
(async-normal remote_entries=795460).

**커널 상한 발견 (FINISH 윈도우는 5000ms 하드 캡)**: probe의
`.timeout_ms`는 소스의 상수이지만 그 값은 커널
`kcov_request_generation_finish()`(kernel/kcov_request.c:1117-1125)가
`timeout_ms > 5000`이면 `-EINVAL`로 거부한다. baseline probe의
`.timeout_ms = 5000`은 이미 **커널 허용 최대값**이고, 하네스 변경만으로는
FINISH 드레인 그레이스를 더 늘릴 수 없다(커널·패치 수정 금지). 하네스가
실제로 건드릴 수 있는 유일한 "윈도우"는 **GENERATION_BEGIN→FINISH 구간
(세션이 OPEN으로 남는 시간)**이다.

**OPEN 윈도우 확장은 서버측 만료와 무관**: `kcov_request_root_attributable()`
(kernel/kcov_request.c:1270-1276)은 generation이 OPEN이면
`retry_deadline`과 무관하게 귀속을 허용한다. retry_deadline(5000ms)은
CLOSING(FINISH 호출 후)에서만 관여하므로, **FINISH를 늦추는 방식으로 윈도우를
확장해도 서버 세션은 만료되지 않는다**.

**구현 (도구/사본만 변경)**: `tools/frozen-phase8-probe-window.c` —
baseline `bundle/ab-runner/frozen_phase8_probe.c`(`f291ae53…`)에서
async-normal 시나리오만 workload child 종료 후 generation을
`GEN_WINDOW_HOLD_MS=15000`(15s) 추가로 유지한 뒤 FINISH하도록 변경.
`.timeout_ms = 5000`(커널 cap)은 기존 코드 그대로, deferred/abort 경로
불변, probe JSON에 `"generation_window_hold_ms": 15000`을 기록.
입력 해시: probe `28e32529…`만 변경, 나머지(S3 evidence4 기준선과 동일 —
kernel `5b22ba55` · image `78ac48d0` · lane `ddf3a583…` · bootstrap
`4e8414c0…` · deps `f214e8f4…`) 그대로.

**실행·결과 (Gate 8 재실행)**:

| 시나리오 | S3 baseline (evidence4) | 확장 윈도우 (evidence6 1차* ) | 확장 윈도우 (evidence7 재실행) |
|---|---|---|---|
| async-normal remote | 791265 | 799575 | **795460** |
| deferred-normal remote | 20975 | 20987 | 20958 |
| async/deferred abort remote | 0 | 0 | 0 |
| 게이트 체크 | 전부 True | 전부 True | 전부 True (status=pass) |

- **async-normal remote_entries=795460(>0)**: 15s 확장 윈도우에서도 async
  COPY offload hop(연속 저장 → worker kthread → CB_OFFLOAD leg)이 원격
  세션에 정상 귀속된다. baseline(791265) 대비 +8310 원격 PC 기록 증가 —
  윈도우를 길게 잡아도 귀속이 사라지지 않고 오히려 조금 더 수집된다.
- **deferred-normal 20958**: S3와 일관(±10 수준 잡음). **abort 2종
  remote=0**: 정확 드레인 계약 유지.
- evidence7: 게이트 28/28 체크 True, `cleanup_returncode=0,
  validation_returncode=0`, image 불변(`sha256_after = 78ac48d0`),
  status=pass.

**부수 발견 — phase8 러너의 KCSAN 거짓 양성 (evidence6 1차)**: 1차 실행은
게이트 체크 전부 True였지만 **최종 dmesg 검사에서 실패 처리**됐다. dmesg에
`BUG: KCSAN: data-race in _find_next_zero_bit / sbitmap_find_bit`
(blk-mq sbitmap, 사전 존재·무해·크래시 아님)가 떴고, phase8 러너의
`FATAL_KERNEL_RE`(run_frozen_phase8_vm.py:62)는 `BUG:` 앞에
`(?! KCSAN:)` 제외가 없어(reach 러너 run-reach-adapted.py는 제외 존재)
KCSAN 리포트를 치명 진단으로 오인했다. 실행·게이트 로직 자체는 정상이었고
재실행(evidence7)에서 클린 PASS. 러너·커널·패치 수정 없이 spike가
통과했으므로 보고상으로만 기록한다.

**판정**: 확장 GENERATION 윈도우(GENERATION_BEGIN→FINISH 구간 + 15s hold)
에서 async COPY offload hop 원격 커버리지 귀속이 유지된다. 윈도우 길이는
async-hop 귀속의 제한 인자가 아니다 — S3의 부수 발견(791265)을 재확인했고,
S4의 syz-executor 채널 extra=0은 채널 특이(실행기 세션 수명 관리)로 해석이
강화됐다. 다만 FINISH 그레이스(5000ms)와 retry_deadline(5000ms)은 커널
상한이라, 하네스로는 BEGIN→FINISH span만 확장 가능하다는 경계가 문서화된다.

---

### S4b 스파이크 판정 — syz 채널 async COPY 미계측 원인 특정: 원격 scratch 용량 초과 (2026-09-26)

S3b의 후속 질문("probe 채널이 아니라 **syz 채널**로 async COPY를 계측하고 싶다")
에 대한 답을 experimentally 확정했다. 결론: **윈도우가 원인이 아니며, 원격
scratch 용량 초과가 원인이다.** S4가 기록한 "정직 경계"는 이제 메커니즘 수준으로
좁혀졌다.

**Q1. 그 윈도우는 syzkaller의 윈도우인가?** → **아니다.** upstream syzkaller에는
generation 개념이 없다. 이 저장소의 syzkaller은 §3의 syzkaller 패치 18종으로
커널 세션 ABI(`ioctl 'c' 109~112`)를 사용하도록 패치되어 있으며, **syz-executor도
probe와 동일한 커널 generation 세션을 구동한다.** 차이는 숫자뿐이다:

| 구동자 | 세션 시작 | FINISH 드레인 | 비고 |
|---|---|---|---|
| frozen probe (Gate 8) | `GENERATION_BEGIN` | `5000ms` (ABI 상한) | + 선택 hold |
| syz-executor (S4) | 프로그램마다 BEGIN | `min(1000 × slowdown, 5000)ms` | 러너가 `-slowdown=1` 하드코딩 → 1000ms |

`tools/run-reach-adapted.py:388`의 `-slowdown=1`이 1000ms를 만들므로, 재빌드 없이
플래그만으로 5000ms(ABI 최대)까지 올릴 수 있었다.

**Q2. 기존 S4 로그는 무엇을 말하는가?** — 재분석 결과, **extra=0은 드레인 실패가
아니다.** `reach-copy-evidence3/remote_on/trial_01/executor.log`(1037줄) 전문에서
executor의 실패 진단 문자열이 **0건**이다:
`KCOV generation begin failed` / `... begin returned generation zero` /
`... bind failed` / `... finish failed` 모두 부재 → BEGIN·BIND·FINISH가 모두
성공했다. `.extra` 부재는 게시 불가(abort) 경로가 아니라 **"빈 창"** 경로
(`write_extra_output()`의 `cover_collect()` 결과 size==0)였다.

**재현 실행** — `tools/run-reach-adapted-window.py`(신규 사본, 원본
`run-reach-adapted.py` `2f3b8cea…` 대비 3곳 변경):
1. `-slowdown=1` → `-slowdown=5` (FINISH 드레인 1000ms → 5000ms, ABI 상한)
2. ON `.extra` 개수 부전 검사를 **raise 해제**하고 기록만 — 원래 이 raise가
   `phase9.wait_for_drains()` **앞에서** 실행을 끊어 S4 evidence3/4에 서버측
   드레인 카운터가 아예 없었다(관측 공백의 직접 원인)
3. `validate_gate`의 `extra_files_exact`는 그대로 실패시키므로 판정 의미 불변

코퍼스 `reach-copy-offload.prog`(11콜, async `copy_file_range` count 32MiB ←
ftruncate 16MiB 소스), `--mode on --trials 1 --executions 10 --procs 2`,
`KOOV_EXPECTED_CALLS=11`(첫 실행은 S4용 10 콜 설정残り 때문에 `CALL 10`에서
로그 검증이 실패했다 — 설정 문제이며 코퍼스/채널 무관). 산출물
`~/reach-window-evidence7/`.

**판정**: `coverage_loss_zero`, `extra_files_exact`, `remote_result_integrity`
3항목 실패(extra 여전히 0)이지만, **이번에는 드레인 카운터가 수집됐다.** 그
카운터가 원인을 확정한다:

| 카운터 (ON, 10 executions) | 값 | 해석 |
|---|---|---|
| `generation_begin` / `committed` / `aborted` | 11 / 11 / 0 | 세션 수명 전부 정상 종료 |
| `mapping_exact_owner_match` / `mismatch` | 88 / 0 | 소유자 매핑 전부 일치 |
| `remote_start_granted` / `ok` / `stop` | 88 / 88 / 88 | **귀속 자체는 88회 전부 성공** |
| `remote_start_nested` / `incomplete` | 0 / 0 | 중첩·불완전 진입 없음 |
| `remote_section_created` / `completed` / `discarded` | 88 / 78 / **10** | 실행당 1개가 폐기 |
| `fault_scratch_limit` | **0** | 주입된 fault 아님 — 진짜 용량 초과 |
| `scratch_overflow` | **10** | 실행당 1회 용량 초과 |
| `scratch_trace_entries` | 18,709,479 | 제출된 총 엔트리 |
| `aggregate_entries_merged` | 8,223,729 | 실제 병합된 엔트리 |
| `aggregate_merge_truncated` | 0 | 병합 측 용량은 충분 |
| `remote_result_valid` / `incomplete` | 11 / **10** | 10개 세션이 INCOMPLETE로 강등 |
| `aggregate_quarantined` / `publish_suppressed` | 10 / **10** | **게시 억제(fail-closed)** |
| `aggregate_published` / `entries_published` | 1 / **0** | 게시된 엔트리 0 |
| `owner_lane_match` / `cross_lane_attribution` | 78 / 0 | 레인 귀속 정상 |
| `extra_files` (expected 10) | **0** | 사용자공간에 빈 영역 → 파일 미작성 |

**용량 초과 증명(정확히 일치)** — `request_area_capacity()`
(kernel/kcov_request.c:699)는 TRACE_PC 모드에서 `size - 1`을 반환하고,
`ticket->scratch_size = ctx->kcov->remote_size`(kernel/kcov.c:2014)이며
`kExtraCoverSize = 1024 << 10`(executor/common_linux.h:13) = 1,048,576이다.

```
용량          = 1,048,576 - 1 = 1,048,575 엔트리
버려진 엔트리 = 18,709,479 - 8,223,729 = 10,485,750
초과 횟수     = 10
10,485,750 / 10 = 1,048,575  ← 용량과 정확히 일치 ✔
정상 섹션 평균 = 8,223,729 / 78 = 105,432 엔트리
```

즉 **async COPY kthread 섹션 하나가 원격 scratch 천장(1,048,575)을 정확히 채우고
넘쳤다.** `kcov_request_generation_merge_scratch()`가 `src_entries`를 용량으로
잘라 `overflow=true`를 세우고 → `kcov_request_remote_degrade(...,
KCOV_REQUEST_REMOTE_INCOMPLETE, ..._SCRATCH_OVERFLOW)`로 세션을 강등 →
`remote_section_discarded`·`aggregate_quarantined`·`aggregate_publish_suppressed`가
각 10 → 사용자에게는 **빈 영역**이 전달되어 `.extra` 파일이 생성되지 않는다.

**인과 사슬**:

```
async COPY kthread 섹션의 원격 기록량 > scratch 용량(1,048,575)
   └─ merge_scratch: src_entries = capacity 로 절단, overflow=true
        └─ remote_degrade(INCOMPLETE, SCRATCH_OVERFLOW)   ← 부분 커버리지 게시 금지 설계
             ├─ remote_section_discarded += 1  (실행당 1회, 총 10)
             ├─ aggregate_quarantined / publish_suppressed += 1
             └─ aggregate_entries_published += 0
                  └─ 사용자공간 area 비어 있음 → cover_collect().size==0
                       └─ .extra 파일 미작성 → extra_files=0   ← S4의 관측값
```

**판정 요약**: S4의 extra=0은 (a) 윈도우 부족도, (b) 귀속 실패도 아니다 —
**귀속은 88/88 성공했고, 기록이 scratch 용량에서 잘린 뒤 fail-closed로 게시가
억제된 것**이다. 따라서:
- **윈도우 확장(S3b, `-slowdown=5`)은 이 증상의 해법이 아니다** — 드레인은 이미
  성공하고 있었다(`generation_committed=11, aborted=0`). 실행은 이 결론을
  실증했다(extra 여전히 0, 단 드레인 카운터는 확보).
- S4 코퍼스의 async COPY는 count 32MiB로 probe의 4MiB보다 작업량이 크다. 정상
  RPC 섹션 평균 105,432 엔트리에 비해 async 섹션은 용량을 초과하므로, 기록량
 (unique PC인지 반복 기록인지 포함)이 작업량에 비례하는지 여부는 아직 미구분 —
  다음 스파이크의 대상이다.
- 해법 후보: (i) `kExtraCoverSize` 상향(syzkaller 컴파일타임 상수 → executor
  재빌드 필요), (ii) overflow 시 절단본 게시로 정책 변경(커널), (iii) 코퍼스
  작업량 축소로 임계 아래로(재빌드 0, 코퍼스 사본으로 즉시 시험 가능).
  이 문서 범위(재빌드·커널 수정 금지)에서는 (iii)만 즉시 실행 가능하다.

`kcsan_reports=0`, fixture cleanup 무누수, `base_image.unchanged=true`.

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