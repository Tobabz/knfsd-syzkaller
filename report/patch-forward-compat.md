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

커널 12종 (`bundle/patches/kernel/`):

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
| 0012 | kcov: 원격 섹션 반복 PC 이벤트 억제 (면적을 코드 크기에 비례) | R4 수집 |

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
- **검증 코퍼스 (추후 작업, 2026-09-25 결정)**: 현재 게이트는 단일 일반 NFS 코퍼스 + OFF/ON 대조군으로 판정. 패치의 도달 지점이 다방향(디스패치 NFSv4 · TCP 상관 · kcov 수집 · 지연 작업 귀속)이므로, **도달 지점별 전용 검증 코퍼스 설계**를 별도 작업으로 남겨둔다. 그 전까지 R4(경로 도달 심도)가 코퍼스 적합성의 최소 안전장치 역할을 한다. → **2026-09-26 일부 해소**: 전용 코퍼스는 `bundle/corpus/reach-copy-offload/`(S4)로 실렸고, 두 번째 축(동일 wall-clock 내 도달 코드량 확대 = NFS-Ganesha 병행)은 `tools/ganesha-lane.sh`로 토대만 마련됐다. 판정 결과는 아래 두 절 참조.
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
`KOOV_EXPECTED_CALLS=11`(첫 실행은 S4용 10 콜 설정이 남아 있어 `CALL 10`에서
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

### 레인 격리 하드닝 + 싱글쿼트 함정 가드 (2026-09-26)

Ganesha 병행 축의 착수에 앞서, **기존 결함 하나를 실제로 고치고** 그 과정에서 나온
**문법 검사가 못 잡는 부류의 실패**를 빌드 타임 가드로 만들었다. 둘 다 측정
채널의 신뢰도와 직결된다.

#### (a) 레인 tmpfs 무한 크기 — 기존 결함, 게이트로 승격

`frozen_phase9_lane.sh`의 레인 백킹 tmpfs는 `size=` 없이 마운트된다
(`mount -t tmpfs -o mode=0755`). runaway 코퍼스 프로그램이 게스트 RAM을 고갈하면
VM이 OOM kill되고, 그 결과는 **커널 버그와 구분 불가**가 되어 증거 장부를 통과한다.
Ganesha와 무관한 결함이며, 어느 지점에서든 고칠 수 있었다.

`tools/ganesha-lane.sh`는 `KOOV_TMPFS_SIZE`(기본 `256m`)로 상한을 걸고, 상한이
없으면 **기동 자체를 거부**한다:

```sh
status_backing_options=$(nsenter -t "$status_server_pid" -m -n -- \
    findmnt -n -o OPTIONS -- "$status_lane_root/server/export")
case "$status_backing_options" in
    *size=*) ;;
    *) echo "KOOV: lane tmpfs is not size-bounded (OPTIONS=$status_backing_options)" >&2
       exit 1 ;;
esac
```

게이트가 아니라 보고로만 남기면 "하드닝이 걸렸는지"를 증거에서 확인할 수 없다.
그래서 상한을 status JSON에 실었다 — 게스트 실측값:

```
backing_options = rw,relatime,seclabel,size=262144k,mode=755
```

`256m`이 커널에서 `262144k`로 정규화된다. 따라서 글로브는 `*size=*`로 두어야 하며
(`size=16M`·`size=1048576k` 통과 확인), 단위 고정 문자열 비교는 틀린다.

#### (b) `sh -c '...'` 싱글쿼트 함정 — 게스트에서만 드러나는 실패

레인 서버 블록 전체는 **하나의 싱글쿼트 인자**다:

```sh
ip netns exec ... unshare --mount --propagation private sh -c '
    ... 여러 줄, 주석 포함 ...
' sh "$root" "$lane" "10.89.$lane.0/29"
```

주석 안의 아포스트로피 하나가 이 문자열을 조용히 닫는다. 이후 줄은 outer 셸이
셸 코드로 재파싱하고, **`sh -n`은 통과시킨다**. 실제로 겪은 사례: 주석
`the secondary's side effects`가 `side`라는 단어를 무관한 `sh -c`의 이름 인자
(`$0`)로 밀어내 게스트에서 아래와 같이 died:

```
side: 3: 1: parameter not set          (rc=2, dash)
```

`$0`이 `side`인 이유까지는 dash의 보고 형식으로 역추적했다 —
`dash -c 'set -u; a=$1; ...' side`가 정확히 이 형태를 낸다. 게스트 1회 부팅
(약 5분)을 소모해 특정됐고, **로컬 문법 검사는 한 번도 걸러내지 못했다.**

`tools/lane-quote-lint.sh`가 이를 빌드 타임 실패로 만든다:

1. `sh -c '...'` 영역에 아포스트로피 0개
2. 그 영역 개수가 pristine 원본(`bundle/ab-runner/frozen_phase9_lane.sh`)과 정확히 동일

| 대상 | 판정 |
|---|---|
| `bundle/ab-runner/frozen_phase9_lane.sh` (원본) | PASS (32행, 0개) |
| `tools/ab-lane-fixture.sh` / `-v42.sh` | PASS (32행, 0개) |
| `tools/ganesha-lane.sh` | PASS (106행, 0개) |
| 아포스트로피 재주입 사본 | **FAIL — 해당 라인 지목** |

#### (c) 동등성 실증 — fork는 knfsd 경로에서 무해하다

원본 대비 **11개 편집**(전부 정확히 1회 매칭, diff 11 hunk, +162행). 기본값
`SERVER_IMPL=knfsd`·`SERVER_PORT=2049`는 기존 동작을 재현한다. 검사는
`tools/ganesha-lane-parity.sh`(fork) vs `tools/ganesha-lane-control.sh`(기존
fixture) — runner·코퍼스·이미지·설정 전부 동일, `--lane-fixture`만 다름:

| 항목 | 결과 |
|---|---|
| 단계 수 / 이름 | **104 / IDENTICAL** |
| 비정상 rc | 양쪽 동일 (`executor-poll` rc=1 ×2 — 폴링 정상 동작) |
| 공유 status 값 | 전부 일치 (`lane_epoch=5`, `backing_source='frozen-phase9-lane0'`, `server_threads=4`, `tcp_connections=2`, 식별자·IP) |
| 신규 status 필드 | `server_port`, `ganesha_live`, `ganesha_listen`, `ganesha_backing_source`, `backing_options`, `ganesha_backing_options` (누락 0) |
| status JSON `printf` 균형 | 원본 29/29, fork 35/35 — 정적 사전 검사로 보장 |

게시 대상 게이트의 대조 실행은 `tools/ganesha-lane-control.sh`
(`evidence/ganesha-lane-control/`)에 남아 있다.

**정직한 경계**: `SERVER_IMPL=ganesha|both`은 **아직 실행 검증되지 않았다.**
fixture는 준비됐고 게이트도 걸렸지만, 게스트 이미지에 Ganesha가 없으므로
`ganesha.nfsd`를 실행할 수 없다. ASAN 빌드 후 bake가 선행이다. 또한
`SERVER_IMPL`을 호스트에서 게스트로 넘길 배구는 아직 없다(`cleanup_fixture`는
KOOV 변수를 참조하지 않으므로 `setup` 호출 하나에만 `env` 접두를 걸면 되는
조건은 확인됨). 이 축은 S4와 교차검증 불가 — Ganesha는 v4.2 미지원이므로
코퍼스 기준이 v4.1이다.

---

### S4c 스파이크 판정 — dedup 적용으로 syz 채널 async COPY 계측 성립 (2026-09-26)

S4b가 규명한 scratch 용량 초과를 **커널 패치로 직접 해결**했다. dedup이
드러낸 두 번째 결함(사용자공간 출력 버퍼 6 MiB 한계)까지 규명·정렬한 결과,
**async COPY offload hop이 syzkaller 채널에서 10/10 계측**된다. 게이트 판정은
`dedup=1`에서 **PASS**. 원인은 두 단으로 걸려 있었다 — 둘을 함께 제거해야
async hop이 측정된다.

**패치 (kernel 0012, 신규)** — `kcov: suppress repeated PC events in remote
coverage sections`. `kernel/kcov.c` 1개 파일 +115/-3, 4개 hunk 전부 additive:

- 원격 섹션의 scratch는 PC **이벤트 로그**(기본블록/엣지 실행 1회당 1칸,
  중복 제거 없음)라 면적이 *작업량*에 비례한다 → 루프하는 섹션(async COPY
  kthread)이 천장을 채우고 fail-closed로 전량 폐기된다.
- 티켓별 **512슬롯 직접매핑 최근-seen 캐시**(4KB `kcalloc`)를 두고, 이 섹션이
  이미 기록한 PC는 스킵한다. 미스·충돌·이전 섹션 잔재는 **기존대로 append**
  하므로 **구조적으로 새 PC를 누락할 수 없다**(확률적 dedup이 측정 도구로
  부적합한 이유인 조용한 커버리지 손실이 발생하지 않는다).
- 기본값 **off** = 패치 이전 동작 그대로. `/sys/kernel/debug/kcov_remote_dedup`
  읽기/쓰기로 **한 부팅 안에서 A/B** 가능. 원격 섹션만 대상(토글을 먼저 검사)
  이므로 로컬 per-thread 커버리지 계약은 불변.

**패치 검증**: 11-패치 상태(`0148323cb`) worktree에 `git apply` 후 결과가
빌드된 `kernel/kcov.c`와 **바이트 동일**. 재현성·감사 가능성 유지.
커널 산출물: `bzImage-dedup-0012` = `ea120cbe…`, 베이스라인
`bzImage-baseline-5b22ba55` = `5b22ba55…`(S3/S4 증거 기준선) **보존** —
`tools/bootstrap-kcov-env.py`는 `rm -rf ~/kcsan-env`를 하므로 재실행하지
않고 기존 트리에서 증분 build만 수행했다.

**A/B 설계**: 동일 커널(`ea120cbe`) · 동일 코퍼스(`reach-copy-offload.prog`,
async `copy_file_range` 32MiB) · 동일 `-slowdown=5` 러너 — **유일한 차이는
`--dedup 0|1` 토글**. 산출물 `~/reach-dedup-evidence-d0/`, `-d1/`.

| 카운터 (ON, 10 executions) | dedup=0 | dedup=1 | 해석 |
|---|---|---|---|
| `scratch_overflow` | 10 | **0** | ★ 용량 초과 사라짐 |
| `remote_section_discarded` | 10 | **0** | 폐기 0 |
| `remote_result_incomplete` | 10 | **0** | INCOMPLETE 강등 0 |
| `aggregate_quarantined` / `publish_suppressed` | 10 / 10 | **0 / 0** | ★ 게시 억제 0 |
| `aggregate_entries_published` | 0 | **5,158,711** | ★ 실제로 게시됨 |
| `aggregate_published` | 1 | **11** | 전 세션 게시 |
| `.extra` 파일 (기대 10) | 0 | **2** | ★ 사용자공간에 파일 생성 |
| `aggregate_entries_merged` | 8,223,065 | 5,158,711 | −37% (dedup 효과) |
| `remote_start_granted` / `ok` / `stop` | 88 / 88 / 88 | 88 / 88 / 88 | **불변** |
| `mapping_exact_owner_match` / `mismatch` | 88 / 0 | 88 / 0 | **불변** |
| `generation_begin` / `committed` / `aborted` | 11 / 11 / 0 | 11 / 11 / 0 | **불변** |
| `ordinal_mismatch` / `cross_lane_attribution` | 0 / 0 | 0 / 0 | **불변** |
| 게이트 | **fail** (3 checks) | **pass** (0 failed) | 판정 |

**핵심 통찰 — dedup은 귀속 경로를 건드리지 않았다**: 귀속(88/88/88)·세대
수명주기(11/11/0)·레인 귀속(78)·ordinal 정합이 **완전히 동일**하다. dedup이
바꾼 것은 "기록이 저장되는 방식"뿐이고, 그 결과 overflow가 사라져
**fail-closed가 발동하지 않게 되어** 게시가 살아났다. 즉 S4b의 진단
(귀속 아님 / 윈도우 아님 / 용량 초과)이 그대로 증명되고, 그 진단이 가리킨
위치만 고쳐 해결되었다.

**async hop 실측 증거 (심볼라이즈)**: 게시된 `.extra`를 System.map으로
해석하면 **`nfsd4_do_async_copy` 20건**이 포함된다(파일당 466,008 records /
788 distinct symbols). 함께 나타난 것: `nfsd4_copy` 27, `vfs_copy_file_range`
160, `nfsd_copy_file_range` 7. 즉 **kthread → CB_OFFLOAD leg을 포함한 async
COPY offload hop이 syzkaller 원격 커버리지에 실제로 계측된다** — probe 채널
없이, S4가 실패했던 그 채널에서.

**후속 — 출력 버퍼 6 MiB 한계 발견 및 10/10 달성**: dedup 적용 후 `.extra`가
10회 중 **2회**만 나왔고, executor에 계측을 넣어 원인을 규명했다. 커널은
11개 세대 전부를 게시했고(`entries_published = entries_merged`), executor도
466k~530k를 **10회 전부 정상 판독**했다(`overflow=0`). 그런데 manager가 받은
`extra:` 레코드는 2건뿐이었다. 계산이 1% 이내로 일치한다:

```
출력 버퍼 = 6,291,456 B (6 MiB = executor kMaxOutputCoverage = 6<<20)
프로그램당 call 커버리지 = 280,519 × 8B = 2.24 MB
──────────────────────────────────────────────────────────
466k 케이스: 2.24 + 466,330×8 = 5.97 MB ≤ 6.29 MB  ✓ 통과
528k 케이스: 2.24 + 529,000×8 = 6.47 MB > 6.29 MB  ✗ 잘림
```

원인은 **사용자공간 출력 버퍼 경계**다. 원격 extra 레코드는 출력 스트림
**맨 뒤**에 추가되므로(`write_output(-1, ...)`), 버퍼가 꽉 차면 가장 마지막에
붙은 extra가 **조용히 잘려 나간다**. 배제된 가설: `late_merge_after_refs_zero=0`,
`merge_started == merge_completed == 88`, `merge_truncated=0`, `publish_readers=0`,
`fault_scratch_limit=0` — 커널·병합·게시 경로는 무결했고 유실은 executor 출력
경계에서만 발생했다.

**수정은 출력 버퍼 상한 정렬**이다. 두 상수는 **쌍**이므로 한쪽만 키우면
즉시 깨진다(48 MiB 시도가 `call 0 failed with errno 998`로 실패):
```
executor.cc  kMaxOutputCoverage = 6 << 20   (6 MiB)
flatrpc.go   ConstMaxOutputSize = 14680064  (14 MiB, manager가 준비하는 공유메모리)
```
→ executor를 **이미 제공되는 14 MiB에 정렬**(Go 수정 불필요, 공유메모리 레이아웃
그대로): `kMaxOutputCoverage = 14 << 20`. 필요 용량은 ~6.5 MB였으므로 충분하다.

**최종 결과 — async 10/10** (산출물 `~/reach-bigbuf-async/`, 게이트 PASS):

| 카운터 (ON, 10 executions) | dedup=0 / 6MiB | dedup=1 / 14MiB |
|---|---|---|
| `.extra` 파일 (기대 10) | 0 | **10** |
| `extra_shortfall` | true | **false** |
| `scratch_overflow` / `discarded` | 10 / 10 | **0 / 0** |
| `remote_result_incomplete` | 10 | **0** |
| `aggregate_entries_published` | 0 | **5,158,919** |
| `aggregate_published` | 1 | **11** |
| `remote_start_granted` / `ok` / `stop` | 88 / 88 / 88 | 88 / 88 / 88 (불변) |
| `owner_lane_match` / `ordinal_mismatch` | 78 / 0 | 78 / 0 (불변) |
| 게이트 | fail (3 checks) | **pass** |

**async hop 실측 — 10개 파일 전부에서 확인**: 각 `.extra`에
`nfsd4_do_async_copy` 20건이 포함되고(466k~530k records, 566~809 distinct
symbols), 함께 나타난 것은 `nfsd4_copy`, `vfs_copy_file_range`,
`nfsd_copy_file_range`. 즉 **kthread → CB_OFFLOAD leg을 포함한 async COPY
offload hop이 syzkaller 채널에서 10/10 계측된다.**

**동기 경로 무회귀**: v1 동기-only 대조군(`~/reach-bigbuf-v1/`)도
`status=pass`, `extra_files 10/10`, `extra_shortfall=false` — dedup이 동기
경로를 오염시키지 않는다.

**재사용 규칙 (계측 재빌드 시 반드시 준수)**:
1. **재빌드 페어링** — `syz-executor`만 재빌드하면 git revision이
   `…f+`(dirty)로 바뀌어 manager가
   `mismatching manager/executor git revisions for VM 0`으로 **VM 가동을
   거부**한다. 같은 tree에서 `make executor execprog`로 둘 다 빌드해야 한다.
2. **출력 버퍼 쌍** — `executor.kMaxOutputCoverage`는
   `flatrpc.ConstMaxOutputSize`(14 MiB) 이하여야 한다. 원격 집계가
   ~466k 엔트리를 넘으면 extra가 조용히 잘린다.
3. **커널 보존** — `tools/bootstrap-kcov-env.py`는 `rm -rf ~/kcsan-env`를
   하므로 절대 재실행하지 않는다(베이스라인 `5b22ba55` 소멸). 증분 build만.

**남은 한계 (정직하게)**: dedup 캐시는 512슬롯 직접매핑이라 *직전 반복*만
잡고, 10/10은 출력 버퍼 정렬로 얻어진 것이지 캐시 용량 여유로 얻어진 것이
아니다. 더 큰 코드베이스·KCSAN 빌드·모듈 다수 환경에서는 512슬롯으로는
`scratch_overflow`가 재발할 수 있어, 그 경우 슬롯 확장(4K~16K) 또는 정확한
해시 집합(고유 PC × 16~32B, 초과 시 append 강등)이 다음 단계다. dedup=1
실행에서 KCSAN 리포트 1건이 관측되었으나(blk-mq 계열 기존 레이스, 크래시
아님) reach 러너의 `FATAL_RE`이 KCSAN을 제외하며 게이트는 PASS다. series
subject의 `/11`·`/12` 혼재는 기존 11개 해시를 증거로 보존한 의도적 선택이며,
다음 전체 재생성 시 `/12`로 정규화된다(내용 diff 없음).

**판정**: dedup은 "있으면 좋은 최적화"가 아니라 **S4 증상의 직접 해법**이었다.
근본 원인은 "필요한 것은 집합인데 커널이 로그를 준다"는 표현 불일치였고,
무손실 필터로 이를 끊자 fail-closed가 사뿐히 발동하지 않아 원격 게시가
살아났다. 부수 효과로 병합 트래픽 −37%.

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