# knfsd-fuzz 설계 명세 (자연어 계약 사양) — DESIGN-SPEC

> 버전: 1.0 · 2026-09-23 · 소유: 핸드오프 번들 검증 워크플로
> 관계 문서: `patch-forward-compat.md`(적용 기계), `T1-T10-results.md`(게이트 기록)
> 이 문서는 **패치가 아니라 계약**이다. 패치는 계약의 "이 버전 구현 후보"일 뿐이다.

---

## 0. 보장의 재정의 — 자연어 설계가 100%를 보장하는 방식

### 문제의 근원
스크립트(패치/적용기)는 **문법적** 조건을 검사한다: "이 라인들이 이 위치에 들어갔는가".
문법은 베이스 커널의 문맥에 묶여 있으므로, 미래 커널에 대한 보장은 **시간 귀납**(미래를 예측)이 되고
그 귀납은 증명 불가능하다 — 이것이 "스크립트로 100% 불가능"의 정확한 의미다.

### 해법: 판정 대상을 문법 → 계약으로
자연어 설계는 **의미론적 계약**을 정의한다: "타깃 커널은 어떤 **관찰 가능한 성질**을 만족해야 한다".
성질은 베이스에 묶이지 않는다(관측은 버전과 무관). 그리고 각 성질은 자연어로 서술하되,
**기계 게이트(오라클 프로브)** 로 닫아 둔다.

리팩터링 때문에 패치가 안 들어가도, 계약 게이트가 성립하면 **설계는 적용된 것**이다.
패치가 안 들어가는 것은 "구현이 새 타깃에 맞지 않음"일 뿐, "설계 실패"가 아니다.

### 보장 정리 (형식 스케치)
```
정의:  설계 D가 타깃 T에 적용됨  ⟺  ∀ r ∈ R : gate_r(T) = pass
       (R = 요구사항 집합, gate_r = 기계 실행 가능한 오라클 판정식)
주장:  각 gate_r은 유한 검사(JSON/파일 판독, 프로브 실행)로 판정 가능
       하고, T에만 의존하며, 시간 변수에 무관하다.
결론:  "적용" 판정은 T마다 결정적으로 내려진다(전칭이 유한 검사로 환원).
       미래 커널은 "또 다른 T"일 뿐이므로 시간 귀납이 필요 없다.
        ⇒ 요구사항이 성립하는 임의의 타깃에서 보장은 100% (논리 판정).
한계(정직): 계약이 성립하려면 전제조건 Ψ(T)가 참이어야 한다(§1).
       Ψ가 깨지면 설계는 "적용 불가"(UNSUPPORTED)로 판정 — 이는 보장의 경계이지 실패가 아니다.
```
**"100%" 두 종류:**
- P1 "패치 텍스트가 미래 커널에 무조건 들어간다" — **불가** (문법·문맥 의존, 결-정 불가).
- P2 "설계 요구사항이 타깃에서 성립한다" — **가능** (위 정리). 이 문서는 P2를 형식화한 것.

---

## 1. 전제조건 Ψ(T) — 계약이 유효한 타깃의 최소 표면

| Ψ | 자연어 요구 | 기계 게이트 (오라클) |
|---|---|---|
| Ψ1 | 타깃 커널은 KCOV를 컴파일함 | `.config`에 `CONFIG_KCOV=y` 또는 `vmlinux`에 kcov 심볼 존재 |
| Ψ2 | 타깃 커널은 메모리 새니타이저(KASAN **또는** KCSAN — Kconfig `!KASAN` 상호 배타) 한 종류를 컴파일함 | `manifest.verify.mem_sanitizer ∈ {kasan, kcsan}` (레거시: `verify.target_kasan == true`) |
| Ψ3 | NFSv4 서버 디스패치 경로가 존재 (`svc_process→nfsd_dispatch→nfsd4_proc_compound`) | R4'의 `nfsd4_proc_compound` on_only 존재 게이트 — 경로 부재 시 게이트 전체 false로 드러남 |
| Ψ4 | 시즈컬러 원격 커버 데이터 모델 유지 (remote_cover · cover_edges) | R5' 대조 산출물·커버리지 셋이 self-consistent |

Ψ가 하나라도 false면 전체 설계 판정은 **UNSUPPORTED** (실패 아님). §6 참조.

---

## 2. 요구사항 R1..R6 — 자연어 계약 + 기계 게이트

각 요구사항은 4열로 닫힌다: **자연어(무엇이 참이어야 하는가)** → **게이트(어떻게 확인하는가)** →
**오라클(어디서 읽는가)** → **통과 기준(수치)**. 실행: `tools/fport-design-gate.sh`.

### R1 부팅·빌드 무결성
- 자연어: 패치된 커널/시즈컬러는 부팅 가능한 이미지를 만들고 메모리 새니타이저(KASAN **또는** KCSAN)가 활성화된다.
- 게이트: `manifest.status == "pass"` **그리고** `manifest.verify.mem_sanitizer ∈ {kasan, kcsan}`
- 오라클: `~/work/env/manifest.json`
- 통과: 두 조건 모두 참.

### R2 원격 커버리지 기여 (인과 귀속)
- 자연어: remote 커버리지의 유일한 변수는 ON/OFF 토글이다. ON일 때만 NFS 서버(fs/nfsd)
  고유 심볼 PC가 커버리지에 나타나고, OFF는 0이다 — 즉 관측 기여의 100%가 remote 메커니즘에서 온다.
- 게이트: `group_statistics.off."fs/nfsd".mean == 0` **그리고**
  `group_statistics.on."fs/nfsd".mean > 0` **그리고** `all_trials_converged == true`
  **그리고** `controls_equal_except_remote_toggle == true`
- 오라클: `~/work/evidence/analysis_summary.json`
- 통과: 4조건 모두 참. (실측: off 0, on 1,748 → remote 기여 100%)

### R3 스루풋 회귀 상한
- 자연어: remote 활성화가 퍼징 실행 스루풋을 파괴하면 안 된다 (상한 회귀).
- 게이트: `on.exec_per_second.mean / off.exec_per_second.mean ≥ 0.90`
- 오라클: `analysis_summary.json.group_statistics.{on,off}.exec_per_second.mean`
- 통과: 비율 ≥ 0.90. (실측: 9.25/9.63 = 0.9605 → pass)

### R4 원격 커버리지 심도 (일반 코퍼스·속성 폭)
- 자연어: **일반 NFS 코퍼스(AB 워크로드)**가 서버 실행에 도달해 원격 커버리지가 폭넓은 심볼
  다양성을 만든다 — 다수의 fs/nfsd 핸들러와 net/sunrpc 계층까지 원격 속성이 미친다.
- 게이트: `set_analysis."fs/nfsd".on_only ≥ 100` **그리고** `set_analysis."net/sunrpc".on_only > 0`
  **그리고** 랭킹 CSV 유효 행 ≥ 10 **그리고** `nfsd4_proc_compound` 행 존재 (on_only PC > 0)
- 오라클: `~/work/evidence/analysis_summary.json`(set_analysis) + `coverage_sets/fs_nfsd_on_only_ranked.csv`
- 통과: 4조건 모두 참. (실측: fs/nfsd on_only 1,748 · net/sunrpc on_only 299 · 핸들러 15,
  `nfsd4_proc_compound` on_only 42)

### R5 관측 연결·증거 연쇄 (일반 코퍼스)
- 자연어: 일반 코퍼스 실행의 증거 산출물(대조 보고서·커버리지 셋·무결성 플래그·기여 지분)이
  self-consistent하게 존재하고, 원격 ON이 관측의 유일 원인으로 확정된다.
- 게이트: `status == "PASS"` **그리고** `integrity_pass == true`
  **그리고** `primary.remote_contribution_share_percent ≥ 95`
  **그리고** `coverage_sets/` 내 핵심 6종 파일 존재 (on_only pcs ×3 계열 + 랭킹 CSV)
- 오라클: `~/work/evidence/analysis_summary.json` + `~/work/evidence/coverage_sets/`
- 통과: 4조건 모두 참. (실측: PASS · true · 100% · 파일 존재)

### R6 적용·재현 결합 (감사 계약)
- 자연어: 패치 적용은 시리즈 해시로 고정되고 매니페스트가 그 해시를 검증한다.
- 게이트: 2개 번들 `sha256sum -c` 성공 **그리고** `manifest.pins.kernel_series` 길이 11,
  `syz_series` 길이 15
- 오라클: 번들 `SHA256SUMS`(handoff) + `manifest.json`
- 통과: 검증 성공 + 핀 수 일치.

---

## 3. 계약 위반 시 행동 (재구현 지침)

게이트가 false면 **설계 미적용**으로 판정하고 다음 순서로 수리한다:
1. `fport-design-gate.sh -v`로 어느 요구사항이 깨졌는지 단정 (게이트가 곧 진단).
2. 깨진 계약에 해당하는 훙크를 **설계 의도 기록**(§2 자연어 + patch-forward-compat §3 의도 인덱스)과
   대조해 새 텍스트 패치로 재생성 (고변동 파일 6종 우선).
3. `fport-variant.sh`로 rc 재베이스 변형 기록 → `fport-apply.sh` 재적용.
4. §2 게이트 세트 전체 재실행. **전부 pass가 되기 전까지 설계는 미적용**으로 유지한다.

이 규칙 때문에 "미래 커널에 일부 패치가 안 들어감"은 설계 실패가 아니라
**검증 가능한 구현 갱신 절차의 정상 입력**이 된다.

---

## 4. 게이트 실행 명세

```
tools/fport-design-gate.sh            # 전 게이트 판정, 종료코드 0=HOLDS / 1=FAIL / 2=UNSUPPORTED
tools/fport-design-gate.sh -v         # 상세 수치 출력
```
출력: 요구사항별 PASS/FAIL + 수치, 그리고 최종 판정
`DESIGN HOLDS on <target> : YES/NO(UNSUPPORTED)`.

---

## 5. 판정 기록 (이번 타깃, 2026-09-23)

| 요구사항 | 게이트 수치 (요약) | 판정 |
|---|---|---|
| R1 | status=pass, mem_sanitizer=kasan (kcsan 허용) | PASS |
| R2 | off fs/nfsd=0, on=1748, converged=true, controls_eq=true | PASS |
| R3 | 9.25/9.63 = 0.9605 ≥ 0.90 | PASS |
| R4 | set_analysis fs/nfsd on_only=1748 · net/sunrpc on_only=299 · 핸들러 15 · nfsd4_proc_compound 42 | PASS |
| R5 | status=PASS · integrity=true · 기여 지분 100% · 커버리지 셋 6종 존재 | PASS |
| R6 | 번들 sha256 3/3, 핀 11/15/true | PASS |

기계 실행 판정: `tools/fport-design-gate.sh` (이 문서와 동일 R-번호).

---

## 6. 번들·파이프라인 스코프 (2026-09-25)

파이프라인(`--kind`)은 `kernel|syzkaller`만 지원하며, R6는 2개 시리즈
(`bundle/patches/kernel`·`bundle/patches/syzkaller`, 각 11/15 패치)의 SHA256SUMS
자기 일치를 검증한다. (2026-09-25 번들 독립화: `repo/` 트리·`apply_patch_series.sh`
의존 제거, 원본 배치 → `src/`·`patches/`·`ab-runner/` 독립 배치, fport-apply 자체 적용.
2026-09-26 관심사 분리: `ab-runner/`(런처·fixture) · `baker/`(이미지 프로비저닝) · `corpus/`(코퍼스 전처리))
설계 계약(§2 R1..R6)과 파이프라인은 모두 일반 코퍼스(AB 워크로드)만 참조한다.
**경계**: `env/` 빌드 산출물(커널·syz 트리, 베이크 이미지)은 과거 부트스트랩이 만든
것이지만 일반 코퍼스 AB 증거의 오라클로 **유지** — 신규 rc 포팅(full 모드)에서
신선 환경으로 자연 교체된다 (증거 `T1-T10-results.md`의 주석 참조).

---

## 7. 메모리 새니타이저 확장: KASAN → KASAN|KCSAN (2026-09-26)

전제 Ψ2와 R1은 "KASAN 단일"에서 **"KASAN 또는 KCSAN"** 으로 확장되었다
(Kconfig `!KASAN` 배타성 — 통상 빌드는 두 종류 중 최대 하나만 컴파일된다).

- `stage_verify`는 빌드 `.config`(결정적) **그리고** 런타임 증거(부팅 로그의
  KASAN 초기화 라인 또는 `/proc/kallsyms`의 KCSAN 심볼)를 교차해 활성
  새니타이저를 판정하고 `verify.mem_sanitizer` 로 기록한다
  (`target_kasan`·`target_kcsan` 레거시 미러 동시 기록).
- 게이트: `verify.mem_sanitizer ∈ {kasan, kcsan}` (레거시 `target_kasan==true` 호환).
- KCSAN 타깃의 AB 증거(R2~R5)는 해당 커널에서 새로 산출해야 하며, KCSAN
  리포트는 기본 panic 이 아니므로 크래시 기반 판정의 해석에 유의한다.