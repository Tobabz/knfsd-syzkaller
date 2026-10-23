# Job State Graph (repair/state graph)

> 상태: draft · 최종 확인: 2026-10-13
> 상위 설계: `01-two-stage-agent-architecture.md` §12, §14 12번
> 선행 계약: `02`–`08`, `../03-nfs-proxy/05-mutation-delta-replay.md` §27–§29
> 관련 구현: `agent_pipeline/` (Stage 1: §3, §5, §6, §8. Stage 2: §4 전체와 §5의 Stage 2 부분. Compiler는
> `agent_pipeline/rule_compiler.py`. gate·campaign·replay의 Runner backend와 artifact 기반 Stage 2 Judge는 미구현).
> 구현 스택은 `../decisions/2026-10-13-agent-implementation-stack.md`
> 관련 게이트: Q1 / Stage 2 baseline-with-rules gate / Q2 / Replay

## 요약

Controller가 candidate job을 어떤 상태에 두고, 어떤 결과를 받으면 어디로 옮기는지 정한다. 상태는 job이 Agent,
Runner, 사람, issue 중 무엇을 기다리는지이고, 전이는 verdict와 typed 거부 사유로만 결정적으로 계산한다.
이 표가 틀리면 Q1이 증명되지 않은 job이 Stage 2로 가거나, 인프라 문제가 LLM repair로 가서 budget을 쓰거나,
끝나지 않는 repair loop가 생긴다.

## 해결하려는 문제

Controller는 아직 없으므로 관측된 증상은 없다. 문제는 설계 공백이다. 실패별 경로는 `01` §3, §12, `03` §14,
`05` §13, `06` §13, `07` §7, `08` §12, §15, §16에 흩어져 있지만, 어느 문서도 다음을 정하지 않았다.

- gap 상태(`07` §7) 밖의 job 상태 이름과 전이
- repair loop가 언제 끝나는가
- 전이마다 무엇을 기록하고, Controller가 재시작하면 어디서 이어 가는가
- repair 때 Agent에 무엇을 넘기는가

이것을 구현이 정하면 다음 오독이 생길 수 있다.

- bundle 없이 죽은 Runner를 `NOT_REACHED`처럼 처리해 맞는 plan을 Agent가 고친다. `06` §3이 경고하는 경우다.
- repair budget 소진을 "도달 불가"로 기록한다. `01` §3과 §12는 음성 결론을 금지한다.
- 재시작 뒤 이전 시도의 Runner 결과를 새 시도에 적용해 evidence lineage가 섞인다.

## 구조

그림 1. Stage 1과 intake

```text
 submitted
   | {intake, harness binding}
   +-- intake invalid ----------------------> rejected
   +-- no validated harness ----------------> blocked_harness_gap
   v
 s1_analysis [A]
   | CandidateAnalysis
   v
 s1_planning [A]
   +-- unsupported -------------------------> blocked_harness_gap
   +-- reanalysis_required -----------------> s1_analysis      (repair)
   | plan
   v
 {HCAP check, Materializer}
   +-- typed reject ------------------------> s1_planning      (repair)
   +-- neutral_control_unavailable ---------> blocked_harness_gap
   | ReachabilityHarness
   v
 s1_approval [H]   (only when approval policy requires it)
   +-- deny --------------------------------> s1_planning      (repair)
   | approve
   v
 s1_running [R] -- sealed bundle --> {Q1 Judge}
   +-- NOT_REACHED -------------------------> s1_planning      (repair)
   +-- INCONCLUSIVE infra / loss -----------> s1_running       (rerun)
   +-- INCONCLUSIVE evidence / mapping -----> blocked_operator
   +-- INCONCLUSIVE unsupported_attribution > blocked_harness_gap
   | REACHED
   v
 s1_reached ---- campaign_mode mutate ----> s2_strategy      (Figure 2)
            +--- campaign_mode fixed -----> s1_fixed         (Figure 2a)

 a sealed crash in an s1_running bundle -> crash finding, s1_replaying, then
 the verdict's row above (§3)

 [A] Agent  [R] Runner  [H] human  {..} deterministic step inside a transition
 (repair) agent_repair budget, (rerun) runtime_retry budget (§6)
```

그림 2a. fixed campaign과 Stage 1 replay

```text
 s1_fixed [R]  up to P attempt tasks at a time -- sealed bundle --> {Q1 Judge, crash report}
   +-- infra / unsealed --------------------> s1_fixed  (rerun the attempt)
   +-- K consecutive not_reached -----------> blocked_operator(fixed_not_reaching)
   +-- N attempts without a crash ----------> s1_reached(fixed_no_signal)
   | first crash: no new attempts; in-flight attempts finish
   v
 s1_replaying [R]  each crash, M runs one at a time -- bundle --> {crash report}
   | k/M recorded per crash
   v
 crash_review [H]
   +-- resume ------------------------------> s1_fixed (same campaign)
   | close
   v
 closed(crash_reported)

 s1_replaying also replays a crash finding of s1_running (§3); it then goes
 to the row the run's verdict chose, not to crash_review.
```

그림 2. Stage 2

```text
 s2_strategy [A]
   +-- unsupported -------------------------> blocked_harness_gap
   | MutationRuleSet
   v
 {Compiler}
   +-- agent-fixable reject ----------------> s2_strategy      (repair)
   +-- unsupported_capability /
   |   requires_state_lineage --------------> blocked_harness_gap
   | CompiledMutationRule[]
   v
 s2_gate [R] -- sealed bundles --> {Q1 / M1 Judge, gate table 01 §3}
   +-- Q1 NOT_REACHED ----------------------> blocked_operator
   +-- INCONCLUSIVE (by reason, §4) --------> s2_gate (rerun) / blocked_*
   +-- baseline intent NOT_APPLIED ---------> s2_strategy      (repair)
   | pass
   v
 s2_campaign [R] -- sealed segments --> {Q2 / M1 Judge, campaign tally}
   +-- Q2 without APPLIED rule in window ---> s2_campaign  (triage item)
   +-- repair threshold --------------------> s2_strategy      (repair)
   +-- fuzz budget exhausted ---------------> blocked_operator
   | Q2 OBSERVED + APPLIED rule in window
   v
 s2_replaying [R] -- replay bundle --> {replay comparator}
   | REPLAY_*
   v
 crash_review [H]
   +-- resume ------------------------------> resume_point (default s2_campaign)
   | close
   v
 closed(crash_reported)
```

그림 3. 막힘, 종료, 외부 이벤트

```text
 any non-terminal state
   +-- budget exhausted / agent failure / fail-closed -> blocked_operator [H]
   |                         resume -> resume_point    close -> closed
   +-- operator cancel ---------------------------------> closed(cancelled)

 blocked_harness_gap [I]                                           (07 §7)
   +-- issue resolved -> retry_pending -> {re-binding} -> resume_point
   +-- issue deferred -> parked [I] -> issue reopened -> blocked_harness_gap
   |                                   issue resolved -> retry_pending
   +-- issue wont_fix -> closed_unsupported

 waiting states: blocked_operator, crash_review, blocked_harness_gap, parked
   +-- identity / HCAP / JudgeProfile change -> state kept, resume_point updated

 [I] issue tracker   {re-binding} applies the invalidation rules of 01 §11.2
```

## 설계

### 1. 상태

상태는 job이 무엇을 기다리는지를 나타낸다.

| 상태 | 기다리는 것 | 들어오는 경로 |
|---|---|---|
| `submitted` | Controller 처리 (queue) | candidate 제출 |
| `s1_analysis` | Agent: Candidate Analysis | binding 성공, `reanalysis_required` |
| `s1_planning` | Agent: Reachability Planning | analysis 완료, Stage 1 repair |
| `s1_approval` | 사람: review manifest 승인 | materialize 성공, approval policy가 요구할 때 |
| `s1_running` | Runner: Stage 1 실행 (scenario와 neutral control, `06` §11) | materialize 또는 승인, 재실행 |
| `s1_reached` | 없음. Q1 package를 보존하고 Stage 2 시작을 기다린다 | Q1 `REACHED`, fixed campaign이 crash 없이 끝남 |
| `s1_fixed` | Runner: fixed campaign의 attempt들(§3.1) | `s1_reached`에서 `campaign_mode` `fixed`, `crash_review`의 `resume` |
| `s1_replaying` | Runner: Stage 1 crash의 replay 실행(§3.1) | fixed campaign의 crash, `s1_running` bundle의 crash finding |
| `s2_strategy` | Agent: Mutation Strategy | Stage 2 시작, Stage 2 repair |
| `s2_gate` | Runner: baseline-with-rules gate와 neutral run (`01` §3) | compile 성공, 재실행 |
| `s2_campaign` | Runner: fuzz campaign | gate 통과, crash review 뒤 재개 |
| `s2_replaying` | Runner: `CrashContextWindow` replay | window에 `APPLIED` rule이 있는 Q2 `OBSERVED` |
| `crash_review` | 사람: crash report 검토 | replay 비교 verdict, fixed campaign crash의 replay |
| `blocked_harness_gap` | issue (`07` §7) | gap |
| `retry_pending` | Controller 처리 (queue, `07` §7) | issue resolved |
| `parked` | issue 재개 또는 해결 (`07` §7) | issue deferred |
| `blocked_operator` | 사람: operator 동작 (§5) | budget 소진(§6), fail-closed 경로(§2–§4) |
| `rejected` | 종료 | intake 거부 (`02` §3) |
| `closed_unsupported` | 종료 (`07` §7) | issue wont_fix |
| `closed` | 종료 | crash review 종료, operator close 또는 cancel |

- 결정적 component(intake 검증, harness binding, HCAP 검사, Materializer, Compiler, Q1·M1·Q2 Judge, replay
  comparator)는 상태가 아니다. 전이 안에서 실행한다.
- job의 미완료 task는 최대 하나다(`pending_task`). 예외는 `s1_fixed`의 attempt task들이다. `s1_fixed`는
  `pending_task` 없이 attempt task를 `fixed_parallelism`개까지 함께 둔다(`FixedCampaign.in_flight`, §3.1).
  Agent, Runner, 사람에게 보낸 요청은 `task_id`를 가진다.
  전이가 만드는 요청(재실행, `resume`, repair 포함)은 모두 새 `task_id`를 받는다. 같은 `task_id`는 §8의 재발송과
  재시작 처리에서만 쓴다.
- `blocked_harness_gap`, `blocked_operator`, `parked`, `retry_pending`, `crash_review`는 `resume_point`(다시 들어갈
  상태와 그 입력)를 기억한다.
- `blocked_operator`, `crash_review`, `blocked_harness_gap`, `parked`는 사람이나 issue의 결정을 기다리는 대기
  상태다(`s1_approval`은 제외한다, 근거 13). 대기 상태는 그 상태의 operator 동작이나 issue 이벤트로만 끝나고,
  재평가 이벤트(§5)는 `resume_point`만 바꾼다.

### 2. 전이 규칙

전이는 현재 상태, 이벤트, 결정적 component의 출력, JobPolicy의 함수다. 경로를 정하는 값은 verdict의 status와
reason, typed 거부 사유, Agent Task 출력의 variant뿐이다. Agent 출력의 내용(plan, rule)은 component의 입력이며
경로를 직접 정하지 않는다.

Agent Task 출력의 variant는 다음과 같다. 각 variant의 내용은 오른쪽 계약이 소유한다.

| Agent Task | variant | 내용의 소유 |
|---|---|---|
| Candidate Analysis | `analysis` | `03` §5. Analysis는 gap 가능성만 적고 unsupported를 판정하지 않는다(`03` §8) |
| Reachability Planning | `plan` | `05` §4 |
| | `unsupported(gap_class, missing_capability_id, reason)` | `05` §8, `07` §3 |
| | `reanalysis_required(reason)` | 선택한 path나 state 가정이 틀렸다는 Agent의 판단(`03` §14) |
| Mutation Strategy | `rule_set` | `08` §5 |
| | `unsupported(mutation_engine, missing_capability_id, reason)` | `08` §15 |

- `missing_capability_id`는 HCAP data의 controlled vocabulary에 있어야 한다(`07` §3). vocabulary 밖이면
  `blocked_operator(gap_id_unknown)`로 보낸다. Agent에게 기존 id 중 하나를 고르라고 돌려보내지 않는다.
- 빈 `missing_capability_id`는 출력 형식 결함이다. Agent executor의 출력 검증이 같은 실행 안에서 거부하고 다시 받으므로
  `agent_repair`에 세지 않는다. 저장된 이전 출력처럼 빈 id가 Controller에 닿으면 `blocked_operator(gap_id_unknown)`로
  보낸다(#81 D5).
- Mutation Strategy는 맞는 id가 없으면 `mutation_engine.unlisted`와 `CapabilityProposal`(layer `semantic_subset`,
  `proxy`, `compiler_lowering`)을 함께 낸다. Planning처럼 proposal은 `gap_proposal_ref`로 job에 붙는다.
- host 생성은 pipeline이 스스로 내는 gap id `semantic_mutation.unpromoted`, `state_lineage`,
  `mutation_engine.unlisted`를 모든 HCAP revision의 vocabulary에 넣는다(#81 D6).
- 결과는 `task_id`가 job의 `pending_task`와 같을 때만 전이를 만든다. Agent task는 attempt도 같아야 한다(§8).
  다르면(취소되거나 교체된 task나 attempt의 늦은 결과) artifact로 저장만 한다.
- `task_id`가 맞지만 아래 표에 없는 결과(새 reason 값, 상태에 맞지 않는 결과)는 `blocked_operator(unexpected_event)`로
  보낸다. 앞 단계를 건너뛰거나 가장 가까운 행으로 해석하지 않는다.
- Runner가 봉인 bundle 없이 끝나면(§8의 `ended_unsealed`) Judge를 부르지 않고 verdict도 만들지 않는다. 이 경우는
  §3–§4의 "봉인 bundle 없는 Runner 종료" 행(재실행)으로 처리한다.

### 3. Stage 1 전이

표의 경로 의미는 근거 열의 문서가 소유한다. 이 표는 그것을 상태로 옮긴 것이다. 둘이 다르면 근거 문서가 맞고
이 표를 고친다.

| 상태 | 이벤트와 조건 | 다음 상태 | counter (§6) | 근거 |
|---|---|---|---|---|
| `submitted` | intake 실패 | `rejected(reason)` | — | `02` §3 |
| `submitted` | intake 통과, `kernel_commit`용 검증된 harness 없음 | `blocked_harness_gap(remote_kcov_attribution, remote_kcov.kernel_revision.<commit>)` | — | `01` §11.2, `07` §2 |
| `submitted` | intake 통과, harness와 `hcap_revision` 묶음 | `s1_analysis` | — | `01` §11.2 |
| `s1_analysis` | `analysis` | `s1_planning` | — | `03` §13 |
| `s1_planning` | `plan`, HCAP 검사 실패(없는 capability, `usable_by`에 `agent_stage1` 없음, 다른 `hcap_revision`) | `s1_planning` (repair, `hcap_invalid`) | agent_repair | `04` §1.1, `05` §8 |
| `s1_planning` | `plan`, Materializer typed 거부(`neutral_control_unavailable`, `host_authority_unavailable` 제외) | `s1_planning` (repair, `materializer_rejected`) | agent_repair | `05` §11, §13 |
| `s1_planning` | `plan`, Materializer `host_authority_unavailable`(build approval에 없는 `hcap_revision`, 깨진 build artifact·HCAP·admission 기록, parser identity 불일치) 또는 HCAP 검사가 host catalog 자체를 읽을 수 없다(깨진 catalog). plan을 고쳐 해결할 수 없다. catalog나 dependency 파일이 없거나 읽기가 실패하면 전이 없이 다음 poll에서 다시 시도한다 | `blocked_operator(host_authority)`. `resume_point`는 materialize다 | — | `05` §11, §13 |
| `s1_planning` | `plan`, Materializer `neutral_control_unavailable` | `blocked_harness_gap(fixture_or_tool, neutral_control.<profile>)` | — | `05` §11 |
| `s1_planning` | `plan`, materialize 성공, approval policy가 승인을 요구 | `s1_approval` | — | `05` §11, `02` §8 |
| `s1_planning` | `plan`, materialize 성공, 승인 불필요 | `s1_running` | — | |
| `s1_planning` | `unsupported` | `blocked_harness_gap(gap_class, missing_capability_id)` | — | `05` §8, `07` §2 |
| `s1_planning` | `reanalysis_required` | `s1_analysis` (repair, `reanalysis_requested`) | agent_repair | `03` §14 |
| `s1_approval` | approve. 승인이 가리키는 review manifest hash가 현재 harness의 hash와 같음 | `s1_running` | — | `05` §11 |
| `s1_approval` | approve, hash 다름 | 상태 유지. 승인으로 받지 않는다 | — | `02` §6 |
| `s1_approval` | deny(note) | `s1_planning` (repair, `reviewer_denied`) | agent_repair | |
| `s1_running` | Q1 `REACHED` | `s1_reached`. JobPolicy `campaign_mode`가 `mutate`이면 바로 Stage 2를 시작한다(§4 첫 행). `none`이면 `s1_reached(evidence_only)`에서 기다린다 | — | `06` §12 |
| `s1_running` | Q1 `NOT_REACHED` | `s1_planning` (repair, `q1_not_reached`) | agent_repair | `06` §13 |
| `s1_running` | Q1 `INCONCLUSIVE(infra)`, `INCONCLUSIVE(loss)`, 봉인 bundle 없는 Runner 종료 | `s1_running` (같은 harness 재실행) | runtime_retry | `06` §13, `01` §12 |
| `s1_running` | Q1 `INCONCLUSIVE(evidence)`, `INCONCLUSIVE(mapping)` | `blocked_operator(q1_evidence)`, `blocked_operator(q1_mapping)` | — | `06` §13, `01` §11.1 |
| `s1_running` | Q1 `INCONCLUSIVE(unsupported_attribution)` | `blocked_harness_gap(remote_kcov_attribution, remote_kcov.context.<expected_context>)` | — | `06` §7, §13 |
| `s1_running` | verdict의 `candidate_id`나 `execution_harness_id`가 job과 다름 | `blocked_operator(q1_evidence)` | — | `01` §11.1 |

- ambient control의 결과(`06` §11)는 기록만 하고 전이를 바꾸지 않는다.
- `s1_running`의 bundle에 crash report(`06` §10)가 봉인돼 있으면 Controller는 crash finding
  (`Job.crash_findings`의 `CrashFinding`)을 job에 붙인다. Runner task, bundle, harness, plan, 그 실행의 Q1 verdict,
  crash 종류와 첫 crash 줄, panic 여부를 담는다. 그 다음 위 표가 고른 행을 바로 따르지 않고 `s1_replaying`에서
  finding을 replay한다(§3.1). replay가 끝나면 finding에 `k/M`을 기록하고 검토 대기(`review` `queued`)로 두며,
  job은 그 실행의 verdict가 고른 행으로 간다. crash는 job을 멈추지 않는다(#81 R2). 실행이 끝난 crash(`WARNING:`,
  panic하지 않은 KASAN 보고)는 Q1 verdict대로 진행하고, panic으로 끝나지 못한 실행은 `INCONCLUSIVE(infra)` 행대로
  다시 실행한다. finding은 지워지지 않는다. Q1 crash finding의 검토는 job 상태가 아니라 job에 붙은 목록이다
  (`crash_review`는 fixed campaign crash만 쓴다, #81 D8, R2, R3).
- `s1_running`에 들어가는 모든 전이(재실행과 `resume` 포함)는 그때의 approval policy를 적용한다. 승인이 필요한데
  그 harness의 review manifest가 승인되지 않았으면 `s1_approval`로 간다(`05` §11).
- `REACHED`로 넘어갈 때 Controller는 `Stage2Input`(`01` §5.1)의 구성 artifact와 verdict id를 job에 고정한다.

### 3.1 fixed campaign과 Stage 1 replay

fixed campaign은 Q1이 `REACHED`인 harness와 program을 그대로 새 VM에서 여러 번 돌려 crash를 찾는다(#81 D11–D15).
program을 바꾸지 않으므로 Agent도 Compiler도 부르지 않는다. 시작 조건과 identity 검사는 Stage 2 시작(§4 첫 두 행)과
같다. attempt 하나는 Runner task 하나이고 봉인 bundle 하나다. Runner 입력은 Stage 1 실행과 같다(job의 harness).

| 상태 | 이벤트와 조건 | 다음 상태 | counter (§6) | 근거 |
|---|---|---|---|---|
| `s1_reached` | fixed 시작(JobPolicy `campaign_mode` `fixed`, 또는 operator `start_fixed`). Q1 evidence의 identity가 job의 bound identity와 같음 | `s1_fixed` (새 fixed campaign, attempt를 `min(fixed_parallelism, fixed_attempts)`개 보낸다) | — | #81 D11 |
| `s1_reached` | fixed 시작, identity 다름 | §5의 identity 변경 처리 | — | `01` §11.2 |
| `s1_fixed` | attempt bundle에 crash report가 있음(Q1 verdict와 무관) | crash를 campaign에 기록(`crash`). 새 attempt를 보내지 않는다. 남은 attempt가 모두 끝나면 `s1_replaying` | — | #81 D12, D13 |
| `s1_fixed` | Q1 `REACHED`, crash 없음 | `reached_no_crash`로 센다. 연속 `not_reached`를 0으로 | — | D12 |
| `s1_fixed` | Q1 `NOT_REACHED`, crash 없음 | `not_reached`로 센다. 연속 `not_reached`에 더한다 | — | D12 |
| `s1_fixed` | Q1 `INCONCLUSIVE(infra)`, `INCONCLUSIVE(loss)`, crash 없음, 또는 봉인 bundle 없는 Runner 종료 | 같은 attempt 번호로 새 task를 보낸다. attempt로 세지 않는다 | runtime_retry | D12 |
| `s1_fixed` | Q1 `INCONCLUSIVE(evidence)`, `INCONCLUSIVE(mapping)`, `INCONCLUSIVE(unsupported_attribution)`, verdict의 identity가 job과 다름 | 남은 attempt를 취소하고 §3의 같은 행(`blocked_operator(q1_*)`, `blocked_harness_gap`). `resume_point`는 `s1_fixed`(같은 campaign) | — | `06` §13 |
| `s1_fixed` | 연속 `not_reached`가 `fixed_not_reached_limit`에 닿음 | 남은 attempt를 취소하고 `blocked_operator(fixed_not_reaching)`. `resume`은 연속 수를 0으로 되돌려 같은 campaign을 이어 간다 | — | D13 |
| `s1_fixed` | 센 attempt(`reached_no_crash` + `not_reached`)가 `fixed_attempts`에 닿고 crash 없음 | `s1_reached(fixed_no_signal)`. 이후 operator가 `start_stage2`로 mutate를 시작할 수 있다 | — | D13 |
| `s1_fixed` | 위 행이 아니고 crash도 없음 | 끝난 attempt 자리에 다음 attempt를 보낸다(보낸 attempt + 남은 attempt < `fixed_attempts`일 때) | — | D11 |
| `s1_replaying` | replay bundle | crash report가 원래 crash와 같은 signature면 재현으로 센다. 다음 replay를 보낸다. M번째(`fixed_replays`)가 끝나면 다음 crash, 마지막 crash가 끝나면 아래 행 | — | D14 |
| `s1_replaying` | 마지막 replay, fixed campaign의 crash | `crash_review(fixed_crash)`. crash마다 `k/M`과 `reproduced`(`k>0`)를 기록한다. `k=0`이어도 간다. `resume_point`는 `s1_fixed`(같은 campaign) | — | D14 |
| `s1_replaying` | 마지막 replay, `s1_running`의 crash finding | finding에 `k/M`을 기록하고 `review`를 `queued`로 둔다. job은 그 실행의 verdict가 고른 §3의 행으로 간다 | — | R2, R3 |
| `s1_replaying` | 봉인 bundle 없는 Runner 종료 | 같은 replay를 다시 실행한다. 봉인 bundle이 있으면 Q1 verdict와 무관하게 crash report만 보고 센다 | runtime_retry | |
| `s1_replaying` | replay bundle이 이 task의 것이라는 host provenance가 없음 | `blocked_operator(replay_evidence)`. `resume`이 그 replay를 다시 실행한다 | — | `01` §11.1 |
| `crash_review` | resume, fixed campaign | `s1_fixed`. 같은 campaign의 수를 이어 간다. 기록한 crash는 남고, 새 crash가 나면 그 crash만 replay한다 | — | |

- **attempt와 병렬.** `s1_fixed`는 attempt task를 `fixed_parallelism`(P)개까지 함께 둔다. Controller는 P개를 보내고,
  Runner는 VM slot(§8)이 빈 만큼만 실행한다. 그래서 실제 병렬 수는 `min(P, 빈 slot)`이고, slot이 P보다 적어도
  설정을 거부하지 않는다(R1). attempt 결과는 그 task가 `in_flight`에 있을 때만 받는다. 같은 task의 결과는 한 번만
  센다. lease가 끊겨 Runner가 같은 task를 다시 실행해도 Controller가 받는 최종 결과는 하나다(§8).
- **첫 crash.** crash가 난 뒤에도 이미 보낸 attempt는 끝까지 돌리고(D11) 그 결과도 센다. 그 사이에 난 crash도
  campaign에 더한다. 남은 attempt가 모두 끝나면 모은 crash 전부를 순서대로 replay한다.
- **crash record.** attempt 번호, Runner task, bundle, harness, program ref, runtime selection, Q1 verdict, crash
  종류와 첫 crash 줄, panic 여부. journal과 rule set은 없다(D14). 같은 `CrashFinding` 형식으로 `Job.crash_findings`에
  남기고 출처(`q1`, `fixed`)를 적는다.
- **replay.** crash마다 같은 program을 새 VM에서 `fixed_replays`(M)번, 한 번에 하나씩 돌린다(P=1). replay 하나는
  Runner task 하나다. 재현 여부는 replay bundle의 crash report가 원래 crash와 같은 signature(crash 종류와, 숫자를
  지운 첫 crash 줄)인지로 정한다. 다른 crash가 나면 재현으로 세지 않고 그 replay 기록에 남긴다. race는 재현이
  안 돼도 crash가 무효가 아니므로 `k=0`도 검토로 보낸다(`reproduced=false`).
- **campaign 기록.** `FixedCampaign`이 campaign id, 보낸 attempt 수, 센 attempt 수(`reached_no_crash`,
  `not_reached`, 도달률), 연속 `not_reached`, crash 목록, `in_flight` task를 가진다. 전이 기록은 attempt마다 소비한
  Q1 verdict를 남긴다.
- **중복 crash.** 같은 harness에서 같은 signature의 crash를 이미 replay했거나 replay를 기다리고 있으면 새 finding은
  `duplicate`로 남고 replay하지 않는다. fixed campaign도 그 crash로는 멈추지 않는다(매 attempt의 boot `WARNING`이
  campaign을 매번 멈추지 않게). crash 수에는 더한다.
- **끝.** crash 없이 센 attempt가 `fixed_attempts`에 닿으면 `s1_reached(fixed_no_signal)`, 검토한 crash가 있었으면
  `s1_reached(fixed_complete)`이다. 같은 harness로 `s1_reached`에 다시 들어와도(JudgeProfile 재판정) campaign을 또
  시작하지 않는다. operator `start_fixed`는 새 campaign을 시작한다.
- **재평가 이벤트와 취소.** binding 변경이 job을 `s1_fixed`나 `s1_replaying` 밖으로 보내면(harness 재생성 등)
  `in_flight`의 모든 task와 replay task를 `cancelling_tasks`에 더한다(§8). identity가 그대로면 job은 그 자리에서
  이어 간다(§5). operator `close`·`cancel`도 모두 취소한다. replay가 끝나기 전에 job이 replay를 떠나면 그 finding은
  `abandoned`로 남는다. replay는 crash가 난 harness로만 돌릴 수 있기 때문이다. JudgeProfile 재판정은
  `s1_replaying`의 replay를 끊지 않고, Q1 crash finding의 replay가 끝난 뒤 갈 행만 바꾼다.

### 4. Stage 2 전이

Stage 2는 Proxy M4 이후 구현한다(`../decisions/2026-10-13-agent-implementation-stack.md` 결정 1). 아래 표는
기존 계약이 정한 경로를 상태로 옮긴 것이고, 계약이 정하지 않은 부분은 사람 결정(`blocked_operator`)으로
둔다(한계와 미결 사항).

| 상태 | 이벤트와 조건 | 다음 상태 | counter (§6) | 근거 |
|---|---|---|---|---|
| `s1_reached` | Stage 2 시작(JobPolicy 또는 operator). Q1 evidence의 ExecutionHarnessIdentity가 job의 bound identity와 같음 | `s2_strategy` | — | `01` §5.1 |
| `s1_reached` | Stage 2 시작, identity 다름 | §5의 identity 변경 처리 | — | `01` §11.2 |
| `s2_strategy` | `rule_set`, Compiler 성공 | `s2_gate` | — | `08` §12 |
| `s2_strategy` | `rule_set`, Compiler 거부 `unknown_path`, `type_mismatch`, `message_type_inconsistent`, `selector_mismatch`, `missing_required_field` | `s2_strategy` (repair, `compiler_rejected`) | agent_repair | `08` §12 |
| `s2_strategy` | `rule_set`, Compiler 거부 `unsupported_capability`, `requires_state_lineage` | `blocked_harness_gap(mutation_engine, missing_capability_id)`. `resume_point`는 그 rule set을 다시 compile하는 지점이다 | — | `08` §12, §15, `07` §7 |
| `s2_strategy` | `unsupported` | `blocked_harness_gap(mutation_engine, missing_capability_id)` | — | `08` §15 |
| `s2_gate` | gate Q1 `NOT_REACHED` | `blocked_operator(gate_regression)` | — | `01` §3, `08` §16 |
| `s2_gate` | gate Q1 `INCONCLUSIVE(infra)`, `INCONCLUSIVE(loss)`, 봉인 bundle 없는 Runner 종료 | `s2_gate` 재실행 | runtime_retry | `01` §3 |
| `s2_gate` | gate Q1 `INCONCLUSIVE(evidence)`, `INCONCLUSIVE(mapping)` | `blocked_operator(q1_evidence)`, `blocked_operator(q1_mapping)` | — | `01` §3, `06` §13 |
| `s2_gate` | gate Q1 `INCONCLUSIVE(unsupported_attribution)` | `blocked_harness_gap(remote_kcov_attribution, remote_kcov.context.<expected_context>)` | — | `01` §3, `06` §13 |
| `s2_gate` | Q1 `REACHED`, 평가한 rule 중 M1 `INCONCLUSIVE`가 있음 | `s2_gate` 재실행 | runtime_retry | `01` §3 |
| `s2_gate` | Q1 `REACHED`, `targets_baseline_traffic=true`인 intent의 M1이 `NOT_APPLIED` | `s2_strategy` (repair, `gate_not_applied`) | agent_repair | `01` §3, `08` §16 |
| `s2_gate` | 봉인 bundle이 이 task의 것이라는 host provenance가 없거나, Judge 결과가 그 bundle이 아닌 다른 bundle을 가리킴 | `blocked_operator(q1_evidence)` | — | `01` §11.1 |
| `s2_gate` | 그 밖 | `s2_campaign` (새 campaign) | — | `01` §3 |
| `s2_campaign` | Q2 `OBSERVED`, `CrashContextWindow`에 `APPLIED` rule이 있음 | campaign 정지, `s2_replaying` | — | `01` §3, §12 |
| `s2_campaign` | Q2 `OBSERVED`이고 window에 `APPLIED` rule이 없음, 또는 Q2 `INCONCLUSIVE` | 상태 유지. crash evidence를 보존하고 triage 항목을 만든다 | — | `01` §3, §12 |
| `s2_campaign` | Q2 `NOT_OBSERVED`. 아래 JobPolicy 임계값과 fuzz budget에 닿지 않음 | 상태 유지. verdict를 기록하고 임계값 집계에 더한다. 실행 중인 campaign task를 계속 기다린다 | — | `01` §11.1, §12 |
| `s2_campaign` | JobPolicy 임계값: 도달한 generation에서 hypothesis가 계속 `NOT_APPLIED` | campaign 정지, `s2_strategy` (repair, `campaign_not_applied`) | agent_repair | `01` §12 |
| `s2_campaign` | JobPolicy 임계값: 도달한 generation에서 `APPLIED`, Q2 미관측 | campaign 정지, `s2_strategy` (repair, `campaign_no_signal`) | agent_repair | `01` §12 |
| `s2_campaign` | JobPolicy 임계값: 도달한 generation의 M1 `INCONCLUSIVE` 반복 | campaign 정지, `blocked_operator(evidence_path)` | — | `01` §3 |
| `s2_campaign` | fuzz budget 소진 | campaign 정지, `blocked_operator(campaign_budget_exhausted)` | — | `01` §11.1 |
| `s2_campaign` | 봉인 bundle이 이 task의 것이라는 host provenance가 없거나, Judge 결과가 그 bundle이 아닌 다른 bundle을 가리킴 | campaign 정지, `blocked_operator(campaign_evidence)` | — | `01` §11.1 |
| `s2_campaign` | 봉인 bundle 없는 Runner 종료. 그 전에 봉인한 bundle은 위 행대로 처리한다 | `s2_campaign` (같은 rule set으로 campaign을 이어 가는 새 task) | runtime_retry | `01` §11.2 |
| `s2_campaign` | campaign task가 마지막 bundle을 봉인하고 끝남(`sealed`). 그 bundle을 위 행대로 먼저 처리하고, campaign이 정지하지 않았을 때 | fuzz budget이 남았으면 `s2_campaign` (campaign을 이어 가는 새 task), 아니면 위의 fuzz budget 소진 행 | — | `01` §11.1 |
| `s2_replaying` | 비교 verdict(`REPLAY_EQUIVALENT`, `REPLAY_DIVERGED`, `REPLAY_INCONCLUSIVE`, `REPLAY_INVALID`) | `crash_review`. `resume_point`는 `s2_campaign`이다. campaign의 binding(identity, `hcap_revision`)이 job의 지금 binding과 다르면 `s2_campaign`에 §5의 해당 변경 행을 적용한 지점이다 | — | `../03-nfs-proxy/05` §29, `01` §11.2 |
| `s2_replaying` | 봉인 bundle 없는 Runner 종료 | `s2_replaying` 재실행 | runtime_retry | |
| `s2_replaying` | replay bundle의 manifest·correlation 검증 실패 | `blocked_operator(replay_evidence)`. evidence를 고친 뒤 `resume`이 replay를 다시 실행한다 | — | `../03-nfs-proxy/05` §29 |
| `crash_review` | close | `closed(crash_reported)` | — | `01` §13 |
| `crash_review` | resume | `resume_point` | — | |

- triage 항목은 job 상태를 바꾸지 않는 사람 검토 목록이다. job에 붙어 있고(`Job.triage`), campaign id, Runner task,
  봉인 bundle 참조, 그 bundle의 Q2 verdict(status, reason)와 M1 verdict, window에서 `APPLIED`인 rule, 늦게 왔는지,
  그리고 `APPLIED` crash를 어디로 보냈는지(`routing`: `none`, `replayed`, `queued`, `unrouted`)를 담는다. window에
  `APPLIED` rule이 있어 replay로 간 crash도 항목을 남긴다.
- **gate 반복.** gate task 하나가 JobPolicy `gate_repetitions`만큼 반복하고 반복마다 bundle 하나를 봉인한다. 각
  반복에 위 표의 `s2_gate` 행을 적용하고, 가장 위의 행(Q1 identity 불일치, `NOT_REACHED`, Q1 `INCONCLUSIVE`, M1
  `INCONCLUSIVE`, `NOT_APPLIED`, 통과 순)을 gate 결과로 한다. 표에 없는 값이 하나라도 있으면
  `blocked_operator(unexpected_event)`다. `sealed`인데 bundle 수가 반복 수와 다르면 `unexpected_event`다.
- **campaign 단위와 집계.** campaign은 gate 통과로 시작하고 campaign id를 받는다. campaign task는 실행 중에 bundle을
  여러 번 봉인하고(fuzz VM instance의 실행 구간 하나가 bundle 하나, `01` §8.2), Controller는 `status(task_id)`의
  목록을 순서대로 한 번씩 받는다. 한 bundle의 집계는 실행한 program 수와, Stage 2 Q1이 `REACHED`인 generation을
  hypothesis M1으로 나눈 수다: hypothesis 하나라도 `APPLIED`, 모두 `NOT_APPLIED`, 그 밖(`INCONCLUSIVE`). campaign은
  이 수를 더한다(`CampaignTally`). 임계값 행은 다음 조건이고 위에서부터 처음 맞는 행을 적용한다. 값은 JobPolicy가
  가진다.
  - `campaign_not_applied`: `APPLIED` generation이 없고 `NOT_APPLIED` generation이
    `campaign_not_applied_generations` 이상
  - `campaign_no_signal`: window에 `APPLIED` rule이 있는 Q2 `OBSERVED`가 campaign에 없고 `APPLIED` generation이
    `campaign_no_signal_generations` 이상
  - `evidence_path`: `INCONCLUSIVE` generation이 `campaign_inconclusive_generations` 이상
  - `campaign_budget_exhausted`: 실행한 program이 `fuzz_budget_executions` 이상
  `crash_review`의 `resume`은 같은 campaign을 집계와 함께 이어 간다. `evidence_path`와 `campaign_budget_exhausted`의
  operator `resume`은 그 행을 만든 수를 0으로 되돌린다. 되돌리지 않으면 다음 bundle이 같은 행으로 다시 멈춘다.
  새 gate는 새 campaign이다.
- **늦게 온 campaign evidence.** campaign을 정지한 뒤 도착한 campaign evidence(결과를 받지 않기로 한 campaign
  task가 종료 전에 봉인한 bundle)도 받아 Judge를 돌린다. 결과는 triage 항목(`late`)으로 남고 campaign 집계와
  counter를 바꾸지 않는다. window에 `APPLIED` rule이 있는 crash는 `01` §12대로 replay와 검토에 보내되, 사람이 정한
  대기를 깨지 않는 경우에만 보낸다.
  - job이 같은 campaign의 crash를 replay하거나 검토하는 중(`s2_replaying`, `crash_review`)이면 `crash_queue`에
    넣는다(`queued`). `crash_review`의 `resume`은 queue가 비어 있지 않으면 `resume_point` 대신 queue의 첫 crash를
    replay하고, 그 replay도 `crash_review`로 간다. `resume_point`는 그대로 넘어간다. `close`는 queue에 남은 crash를
    triage 항목으로만 둔 채 `closed(crash_reported)`로 간다.
  - job이 그 campaign의 `s2_campaign`에 있거나(앞 task의 cancel이 끝나기 전에 campaign을 이어 가려던 경우), 그
    campaign이 멈추며 시작한 Mutation Strategy repair(`campaign_not_applied`, `campaign_no_signal`)를 기다리면 그
    작업을 멈추고 `s2_replaying`으로 간다(`replayed`). `01` §12는 `APPLIED` crash에서 autonomous mutation repair를
    멈춘다. `crash_review`의 `resume_point`는 이어 가던 campaign, 또는 같은 repair다. 그 repair는 이미 counter에 센
    것이라 다시 세지 않는다.
  - 그 밖(대기 상태, Stage 1, 다른 rule set의 gate, 종료된 job)이면 상태를 바꾸지 않고 triage 항목에
    `unrouted`로 표시한다. 사람이 그 항목을 보고 정한다.

### 5. 외부 이벤트와 operator 동작

아래 표의 identity, `hcap_revision`, JudgeProfile·RemoteKcovSupportBoundary 변경을 재평가 이벤트라 한다. 대기
상태(§1)는 재평가 이벤트로 끝나지 않는다. 대기 상태의 job에 재평가 이벤트가 오면 Controller는 다시 binding하고,
job이 기준 지점에 있었다면 표가 만들었을 결과로 `resume_point`를 바꾼다. 기준 지점은 `resume_point`이고,
`resume_point`가 대기 상태면 그 대기 상태의 `resume_point`다.

- 결과가 기준 지점과 같으면 `resume_point`는 기준 지점이다. 바뀐 것이 없으면 기록만 한다.
- 결과가 지금 상태(reason 포함)와 같으면 `resume_point`는 그 결과의 `resume_point`다. job은 이미 그 상태에서
  기다리므로, 그 상태를 끝내는 동작이 결과가 갈 곳으로 보낸다.
- 결과가 다른 대기 상태면(예: reason이 다른 `blocked_operator`) 그 상태가 자기 `resume_point`와 함께
  `resume_point`가 된다. 재개하면 job은 그 대기 상태로 들어가고, 그 상태를 끝내는 동작이 그 `resume_point`로
  보낸다.
- 결과인 대기 상태의 `resume_point`는 표가 정한다. 행이 따로 정하지 않으면 그 결과를 낸 단계이고(Q1 판정이면
  `s1_running`), 교체 없는 폐기로 생긴 `blocked_harness_gap`은 기준 지점이다. 앞선 재평가가 기준 지점을 바꿔
  놓았어도 재개는 지금 판정이 정한 곳으로 간다(근거 16).
- 재판정 결과로 `resume_point`를 정하면 job은 그 verdict를 소비한 것으로 기록하고, 다음 재판정은 그 verdict와
  비교한다.
- 상태, `state_reason`, 기다리던 사람 task와 issue는 그대로 둔다. job을 `resume_point`로 보내는 것은 그 상태의
  operator 동작이나 issue 이벤트뿐이다.

| 이벤트 | 대상 | 처리 | 근거 |
|---|---|---|---|
| issue resolved | `blocked_harness_gap`, `parked` | `retry_pending`. 다시 binding한 뒤 `resume_point`로 간다. binding이 바뀌었으면 먼저 표 위 규칙대로 `resume_point`를 바꾼다. identity가 바뀌었으면 아래 identity 변경 행을, identity가 같고 `hcap_revision`만 바뀌었으면(build를 바꾸지 않은 promotion) 아래 `hcap_revision` 변경 행을 적용한다. 그 `hcap_revision`의 변경 이벤트가 issue 이벤트보다 늦게 오거나 오지 않아도 같다 | `07` §7 |
| issue deferred | `blocked_harness_gap` | `parked` | `07` §7 |
| issue reopened | `parked` | `blocked_harness_gap`. 같은 gap과 `resume_point`로 issue를 다시 기다린다 | `07` §7 |
| issue wont_fix | `blocked_harness_gap`, `parked` | `closed_unsupported(reason)` | `07` §7 |
| bound ExecutionHarnessIdentity 변경(harness build 교체·폐기) | binding 뒤의 비종료 상태(`s2_replaying` 제외) | 진행 중인 task는 결과를 받지 않는다. 다시 binding하고 identity 재수립 지점(표 아래)으로 간다. 대기 상태는 표 위 규칙대로 `resume_point`만 바꾼다 | `01` §11.2, `07` §7 |
| 같은 변경 | `s2_replaying` | 다시 binding만 한다. replay는 crash evidence의 harness identity로 계속한다(`../03-nfs-proxy/05` §25). 바뀐 binding은 `crash_review`의 `resume_point`에 반영된다(§4) | `01` §11.2, §12 |
| `hcap_revision`만 변경 | 비종료 상태(`s2_replaying` 제외. 대기 상태는 표 위 규칙) | `s1_analysis`, `s1_planning`은 진행 중인 task의 결과를 받지 않고 같은 Agent Task를 새 `hcap_revision`으로 다시 시작한다. 그 밖의 상태는 plan과 evidence를 새 HCAP으로 결정적으로 다시 검증해, 실패하면 `s1_planning`(repair, `hcap_changed`)으로 간다. 통과하면 MutationRuleSet을 입력으로 쓰는 지점(`s2_gate`, `s2_campaign`, §4의 Compiler 거부 행이 정한 `resume_point`)은 그 rule set을 다시 compile해 `s2_gate`로 가고(거부는 §4의 Compiler 행), Mutation Strategy를 기다리는 `s2_strategy`는 진행 중인 task의 결과를 받지 않고 그 Agent Task를 새 `hcap_revision`으로 다시 시작한다. 나머지 상태는 그대로 둔다. harness는 새 HCAP에서 나온 CallAdmissionProfile·NeutralControlCatalog ref가 harness에 기록된 ref와 다를 때만 다시 materialize한다(진행 중인 Runner task는 결과를 받지 않는다). 같으면 harness를 유지하고 그 `hcap_revision`으로 다시 검증했다고 기록한다 | `01` §11.2, `07` §7 |
| 같은 변경 | `s2_replaying` | 다시 binding만 한다. replay는 기록된 rule set을 쓰고 Compiler를 다시 부르지 않는다(`../03-nfs-proxy/05` §26). 바뀐 binding은 `crash_review`의 `resume_point`에 반영된다(§4) | `01` §11.2 |
| JudgeProfile 또는 RemoteKcovSupportBoundary 새 버전 채택 | 비종료 상태(대기 상태는 표 위 규칙) | Controller는 채택한 버전을 저장하고, 재시작하면 설정 기본값보다 저장값을 쓴다. job이 마지막으로 소비한 verdict의 봉인 bundle에 새 verdict를 만들어 기록한다. status와 reason이 같으면 새 verdict를 소비하고(`Stage2Input`이 새 authority의 verdict를 가리킨다) 상태는 그대로 둔다. 이 규칙 이전에 저장된 이벤트(`consume_same_verdict` 없음)는 버전만 바꾼 것으로 replay한다. PR 브랜치 중간 커밋 bf1d16c는 새 verdict를 소비하면서도 이 필드를 쓰지 않았으므로, 그 커밋으로 만든 DB는 replay를 지원하지 않는다(`ReplayMismatch`로 멈춘다). 일반적으로 이력 호환은 main에 병합된 버전이 쓴 DB만 보장한다. 병합 전 PR 커밋(예: cleanup 추적을 바꾸던 d702a61)으로 만든 DB는 replay와 업그레이드를 지원하지 않는다. 그 verdict를 소비할 때의 binding(identity, `hcap_revision`)이 job의 지금 binding과 다르거나, job이 그 verdict 뒤에 plan이나 harness를 바꿨으면 전이를 만들지 않는다. binding이 다르면 binding 변경이 정한 경로(identity 재수립 지점, `hcap_revision` 행)가 그대로 남는다. 그 밖에는 그 verdict를 소비한 전이의 출발 상태에서 §3–§4 표를 다시 적용하고(binding이 같으므로 `Stage2Input`도 유효하다, `01` §5.1), 진행 중인 task는 결과를 받지 않는다. 새 규칙이 요구하는 evidence가 bundle에 없으면 그 Runner 단계를 다시 실행한다 | `01` §11.2 |
| JobPolicy 변경 | 비종료 상태 | 이후 전이에만 적용한다. 기존 verdict와 전이 기록은 바꾸지 않는다 | `01` §11.1 |
| operator `resume` | `blocked_operator` | `resume_point`로 간다. 소진된 counter를 0으로 되돌리고 그 사실을 기록한다 | |
| operator `route(to)` | `blocked_operator(gate_regression)` | `s2_gate` 또는 `s2_strategy`. `resume_point`가 이 상태에 들어올 때와 다르면(재평가 이벤트가 binding을 바꿨거나 gate verdict를 다르게 판정했다) 받지 않고 기록만 한다. 그때는 `resume`이 지금 `resume_point`로 보낸다 | `01` §5.1, §11.2 |
| operator `close`, `cancel` | 비종료 상태 | `closed(operator_closed)`, `closed(cancelled)`. 진행 중인 task는 결과를 받지 않는다 | |

**identity 재수립 지점.** 저장된 plan이 있으면 새 `hcap_revision`으로 다시 검증하고 다시 materialize한다. 둘 다
통과하면 `s1_running`(승인이 필요하면 `s1_approval`)이다. 실패하면 §3의 HCAP 검사·Materializer 행이 정하는 곳이며,
repair로 가면 cause는 `hcap_changed`다. plan이 없으면 Stage 1의 Agent 상태(`s1_analysis` 또는 `s1_planning`)를 다시
시작한다. Stage 2에 있었어도 Q1을 새 identity에서 다시 세운다(`01` §11.2). 다시 binding할 검증된 harness build가
없으면(교체 없는 폐기) §3의 binding 실패 행과 같은 `blocked_harness_gap(remote_kcov_attribution,
remote_kcov.kernel_revision.<commit>)`이다. 대기 상태에서는 이 검증과 materialize를 identity 변경 때 하고, 그 결과가
`resume_point`가 된다. 승인 필요 여부는 `s1_running`에 들어갈 때 정한다(§3).

외부 이벤트가 부른 재실행(`hcap_changed` 포함)은 budget을 쓰지 않는다. 원인은 전이 기록에 남는다.

### 6. budget

| counter | 세는 것 | 0으로 되돌리는 때 | 한도에 닿으면 |
|---|---|---|---|
| `agent_repair[stage1]` | Stage 1에서 `(repair)` 전이의 수(cause `hcap_changed` 제외). 전이마다 Agent Task 하나를 부른다 | operator `resume` | `blocked_operator(stage1_repair_budget)` |
| `agent_repair[stage2]` | Stage 2에서 `(repair)` 전이의 수(cause `hcap_changed` 제외) | operator `resume` | `blocked_operator(stage2_repair_budget)` |
| `agent_retry` | 같은 Agent Task 요청의 연속 실행 실패: provider 오류, timeout, usage limit, 프레임워크의 출력 검증 재시도를 다 쓴 뒤에도 schema에 맞지 않는 출력 | Agent Task 성공, 새 요청 시작 | `blocked_operator(agent_failure)` |
| `runtime_retry[step]` | 같은 Runner 입력의 연속 재실행 (`s1_running`, `s1_fixed`, `s1_replaying`, `s2_gate`, `s2_campaign`, `s2_replaying`). `s1_fixed`는 campaign의 연속 infra attempt를 센다 | 그 단계가 재실행이 아닌 행으로 끝날 때, Runner 입력이 바뀔 때. `s2_campaign`은 이어 간 campaign이 bundle을 봉인할 때도(campaign evidence는 §4의 campaign 임계값이 따로 센다). 재실행 행으로 가는 결과는 판정된 verdict여도(`INCONCLUSIVE(loss)`, gate의 M1 `INCONCLUSIVE`) 되돌리지 않는다 | `blocked_operator(runtime_retry_exhausted)` |
| campaign 임계값, fuzz budget | `01` §11.1, §12 | — | §4 표 |
| fixed campaign 수 | 센 attempt(`fixed_attempts`), 연속 `not_reached`(`fixed_not_reached_limit`) | 연속 수: `reached_no_crash`, operator `resume` | §3.1 표 |

- 한도 N은 재시도 횟수다. 처음 한 번 뒤에 센 일이 N번까지 일어날 수 있다. counter가 N인 상태에서 한 번 더 일어나면 그 일 대신
  `blocked_operator`로 간다.
- 한도 값은 JobPolicy가 소유한다(`01` §11.1의 retry / repair budget, campaign repair 임계값). Q1 뒤에 할 일
  `campaign_mode`와 approval policy도 JobPolicy 값이다.
- 외부 이벤트(§5)가 부른 재실행과 Controller 재시작은 budget을 쓰지 않는다. 재시작 뒤 Runner task는 새 실행 없이
  기존 실행을 다시 받고, `abandoned`로 기록한 Agent 실행은 `agent_retry`에 세지 않는다(§8).
- budget 소진은 결론이 아니다. `blocked_operator`는 "도달 불가"나 "취약점 없음"을 뜻하지 않으며, 그런 결론
  필드를 기록하지 않는다(`01` §3, §12).

### 7. RepairInput

repair 전이에서 Controller가 Agent Task에 넘기는 data다. 지시가 아니다(`01` §11.1).

```text
RepairInput
    job_id / attempt
    agent_task              # candidate_analysis | reachability_planning |
                            # mutation_strategy
    cause                   # §3-§5 표의 repair 원인 하나
                            # hcap_invalid | materializer_rejected |
                            # reviewer_denied | q1_not_reached |
                            # reanalysis_requested | compiler_rejected |
                            # gate_not_applied | campaign_not_applied |
                            # campaign_no_signal | hcap_changed
    previous_outputs[]      # 직전 CandidateAnalysis / ReachabilityPlan /
                            # MutationRuleSet의 artifact digest
    findings[]              # cause를 만든 typed 결과 원문: 거부 reason,
                            # Q1Result, gate 결과, campaign 집계, reviewer note
    evidence_refs[]         # 봉인 bundle 참조. Agent는 read-only tool로 읽는다
    remaining_budget        # 이 stage의 agent_repair 남은 횟수
```

Agent는 이 입력을 받아 §2의 variant 중 하나를 출력한다. 봉인 bundle 안의 문자열(console log, program text 등)은
guest에서 온 untrusted data이며 지시로 읽지 않는다.

Materializer 거부의 findings는 `(reason, detail)`에, strict parse 실패면 pinned parser의 진단 문장(한 줄,
1024자 이하)을 세 번째 항목으로 더한다. `detail`은 안정된 code로 남는다.

Agent executor는 Stage 1 repair 프롬프트에 RepairInput 외에 다음을 함께 넣는다(#75). 모두 context이며 Agent
Task 입력 digest에 들어가지 않는다.

- 수리 대상인 직전 ReachabilityPlan과 그 syz program 원문(64 KiB까지).
- 같은 job의 이전 Stage 1 repair마다 cause, findings, 그 계획의 program digest. 같은 program을 다시 낸 시도는
  표시한다. Controller가 `AgentRequest.prior_repairs`로 저장된 RepairInput을 넘긴다.
- `q1_not_reached`이면 Q1Result가 뜻하는 바를 풀어 쓴 문장. PC, coverage, 위치 정보는 더하지 않는다.

Reachability Planning의 unsupported 출력은 `CapabilityProposal`을 함께 낼 수 있다(#75). 누락 계층(gap_class와
같다), 선택 경로에서 만들어야 하는 조건, kernel source 근거, 검토한 promoted HCAP마다 부족한 이유, 추가할
interface, 승격에 필요한 KVM 증거를 담는다. executor가 artifact로 저장하고 `UnsupportedOutput.proposal_ref`로
넘기며, Controller는 `Job.gap_proposal_ref`에 남긴다(blocked_harness_gap이든 gap_id_unknown이든). 값은 가장
최근 unsupported 답의 제안이며(제안이 없으면 비운다), job의 gap이 지워지거나 다른 gap으로 바뀌면 함께 비운다. 제안은 HCAP
항목을 만들거나 승격하지 않는다. 승격은 지금처럼 typed KVM 증거와 owner 승인이 필요하다.

### 8. 기록과 재시작

```text
Job
    job_id
    candidate_id
    state / state_reason?
    bound_harness          # execution_harness_id, hcap_revision (binding 결과)
    job_policy_id
    counters               # §6
    pending_task?          # task_id, kind (agent | runner | human),
                           # 입력 digest, agent면 지금 attempt
    fixed?                 # s1_fixed의 campaign과 in_flight attempt task (§3.1)
    crash_findings[]       # Stage 1 crash (q1 | fixed), replay k/M과 검토 상태
    cancelling_tasks[]     # cancel을 보내고 종료 응답을 기다리는 Runner task
    uncleaned_tasks[]      # lease는 끝났지만 실행 정리를 확인하지 못한 Runner task
    resume_point?          # 대기 상태(§1)와 retry_pending일 때. 대기 상태를
                           # 가리키면 그 상태의 resume_point도 둔다(§5)

Transition                 # append-only
    job_id, seq
    from, to, reason?
    event                  # task 결과 | 외부 이벤트 | operator 동작
    consumed[]             # verdict id, artifact digest, operator action id
    job_policy_id
    at

AgentAttempt
    task_id, attempt, job_id
    agent_task
    repair_input?          # §7의 digest
    model_id               # 실제로 응답한 provider:model
    output_ref? | failure?
    usage
```

Controller가 Runner에 요구하는 task 계약은 다음과 같다. Runner task 하나는 실행 하나다.

```text
submit(task_id, input)    task_id를 durable하게 기록한 뒤 실행을 시작한다.
                          이미 받은 task_id면 새로 실행하지 않고 status를
                          돌려준다. input이 다르거나 cancel된 task_id면
                          실행하지 않고 거부한다
status(task_id)           state와 지금까지 봉인한 bundle 목록(순서대로)
                          state: unknown | running | sealed
                                 | ended_unsealed(reason)
cancel(task_id)           실행을 멈추고 끝난 뒤 최종 status를 돌려준다.
                          모르는 task_id면 cancel된 것으로 기록하고
                          ended_unsealed(cancelled)를 돌려준다
```

backend가 실행 종료를 확인하지 못하면(예: 프로세스 정리 실패) Runner는 완료를 기록하지 않고 lease 만료를 기다린다.
만료되면 `ended_unsealed(cleanup_unconfirmed)`로 끝낸다. 이것은 확인된 cancel도, runtime 재시도 대상도 아니다.
Controller는 그 task를 `uncleaned_tasks`에 남기고, 종료 상태가 아닌 job은 `blocked_operator(execution_cleanup)`로
보낸다. operator가 실행이 사라졌음을 확인하고 `resume`하면 목록을 비우고 멈춘 곳에서 이어 간다. 종료된 job은
그대로 두되 기록에 task가 남는다. 이미 다른 이유로 대기 중인 job은 그 이유를 유지하지만, `uncleaned_tasks`가
남아 있는 동안에는 어떤 경로로도 Runner task를 보내지 않고 `blocked_operator(execution_cleanup)`로 간다.

정리는 lease보다 오래 걸릴 수 있다. 만료로 attempt가 이미 끝난 뒤에 도착한 종료 미확인 보고도 버리지 않는다.
Runner는 그 attempt(generation, worker, token)로 보고를 인증해 보관하고(`cleanup_reports()`), Controller는
poll·recover마다 그 task를 job의 `uncleaned_tasks`에 기록한 뒤에야 보고를 확인 처리한다. 늦게 온 결과의 bundle은
여전히 받지 않는다.

`sealed`는 마지막 bundle까지 봉인하고 끝났다는 뜻이고, `ended_unsealed`는 마지막 bundle 없이 끝났다는 뜻이다.
campaign처럼 실행 중에 bundle을 여러 번 봉인하는 task는 `running` 동안에도 목록이 늘어난다.

- 전이 하나는 `Transition` 추가, `Job` 갱신, 다음 task의 `pending_task` 기록을 한 SQLite transaction으로 commit한다.
  task 발송은 commit 뒤에 한다.
- Runner task 발송이 실패하거나 응답이 없으면 같은 `task_id`로 다시 submit한다. submit은 `task_id`에 대해
  멱등이므로 몇 번 보내도 실행은 하나다.
- 결과를 받지 않기로 한 Runner task(§5의 재평가 이벤트, operator `close`·`cancel`, campaign 정지)는 아직 보내지
  않은 것까지 그 전이와 같은 transaction에서 `cancelling_tasks`에 더하고, commit 뒤에 `cancel`을 보낸다. 종료를
  답한 task는 목록에서 뺀다. 같은 job의 다음 Runner task는 목록이 빈 뒤에 보낸다. 그래서 job의 Runner 실행은
  `s1_fixed`의 attempt를 빼면 한 번에 하나다. 그 뒤에 온 bundle은 전이를 만들지 않는다(§2). campaign evidence는
  §4대로 triage 항목만 만든다.
- **VM slot.** Runner는 host의 KVM slot 수만큼 실행을 함께 돌린다. slot 수는 Runner가 시작할 때 host의 CPU와
  메모리로 계산한다: `min((cpus - reserve_cpus) // vm_cpus, (memory - reserve_memory) // vm_memory)`, 최소 1(#81 R6).
  같은 설정이 큰 host에서 더 많이 돌린다. Stage 1 실행, fixed attempt, replay, Stage 2 lease가 같은 slot을 나눠
  쓴다(R4). slot은 backend 자원 잠금(`<resource_key>/kvm-<i>`)이고, 빈 slot이 없으면 task는 Runner queue에서
  기다린다. Controller는 slot을 모른다.
- 결정적 component는 입력의 순수 함수다. commit 전에 Controller가 죽으면 같은 이벤트로 전이를 다시 계산한다.
- Controller가 재시작하면 `pending_task`나 `cancelling_tasks`가 있는 job을 다시 본다.
  - `cancelling_tasks`의 task마다 `cancel`을 다시 보내고, 목록이 빈 뒤에야 Runner `pending_task`를 다룬다.
  - Runner task: 같은 `task_id`로 다시 submit해 status를 받는다. Runner가 이미 받은 task면 새로 실행하지 않는다.
    목록에서 아직 받지 않은 bundle을 순서대로 받고, 그 뒤 `running`이면 계속 기다리고, `sealed`나 `ended_unsealed`면
    실행 중에 응답을 받았을 때와 같이 §3–§4 표로 처리한다. Runner가 받지 못한 task(commit 뒤 발송 전에 Controller가
    죽었다)는 이 submit으로 시작한다. Runner가 응답하지 않으면 다시 실행하지 않고 기다린다.
  - Agent task: 이전 attempt를 `abandoned`로 기록하고 같은 `task_id`, 같은 입력의 새 attempt를 보낸다. LLM 대화를
    이어 붙이지 않는다. Controller는 지금 attempt의 출력만 받으므로 이전 attempt가 뒤늦게 끝나도 그 출력은
    artifact로 저장만 한다. Agent Task는 read-only tool만 쓰므로(`../decisions/2026-10-13-agent-implementation-stack.md`
    결정 2) 남은 실행의 영향은 비용뿐이다.
  - 사람 task: 계속 기다린다.
- Runner는 자신이 재시작한 뒤 이어 갈 수 없는 실행을 `ended_unsealed(runner_restart)`로 답한다. 이 계약의 Runner 쪽
  구현은 `01` §14 14번이 정한다.
- 현재 상태는 `Transition`을 처음부터 다시 적용한 결과와 같아야 한다.
- 여러 verdict를 모아 경로를 정한 전이(gate, campaign 임계값)는 소비한 verdict와 JobPolicy identity를 `consumed[]`와
  `job_policy_id`로 남긴다(`01` §11.1).

## 설계 근거

1. **상태는 기다리는 곳이고 결정적 component는 전이 안에서 실행한다.** component는 입력의 순수 함수라 전이를
   다시 계산해도 결과가 같다. 그래서 재시작 때 중간 상태를 복구할 필요가 없고, 상태 수가 Agent·Runner·사람·issue
   접점 수로 제한된다.
2. **INCONCLUSIVE는 Agent repair로 보내지 않는다.** 관측이 깨진 실행을 미도달로 처리하면 Agent가 맞는 scenario를
   고친다(`06` §3). build·fixture·설정 문제는 LLM repair 대상이 아니다(`01` §12).
3. **`infra`와 `loss`만 자동 재실행하고 `evidence`와 `mapping`은 사람에게 보낸다.** `mapping`과 boundary 버전 불일치는
   같은 harness build에서 결정적으로 다시 나오므로 재실행은 budget만 쓴다. manifest·correlation 불일치는 무결성
   문제라 재실행이 원인을 가린다.
4. **budget 소진은 종료가 아니라 `blocked_operator`다.** 음성 결론을 기록하지 않아야 하고(`01` §3), 사람이 budget을
   늘려 이어 갈 수 있어야 한다.
5. **vocabulary에 없는 gap id는 사람에게 보낸다.** `missing_capability_id`는 HCAP이 소유하는 controlled vocabulary다
   (`07` §3). Agent가 맞지 않는 기존 id를 고르면 다른 harness 작업이 끝났을 때 job이 잘못 재시도된다.
6. **Planning이 `reanalysis_required`를 낼 수 있다.** Analysis를 다시 할지는 선택한 path나 state 가정이 틀렸는지에
   달려 있고(`03` §14), 이것은 Q1Result만으로 Controller가 가를 수 없는 reasoning 판단이다.
7. **window에 `APPLIED`가 없는 crash와 Q2 `INCONCLUSIVE`는 campaign을 멈추지 않고 triage로 보낸다.** `01` §12는 이
   경우를 "별도 triage"로 둔다. mutation과 연관되지 않은 crash로 job을 멈추면 일반 syzkaller crash가 campaign을
   끝낸다. Q2 `INCONCLUSIVE`는 `NOT_OBSERVED`가 아니므로(`01` §8.2) 버리지 않고 보존한다.
8. **window에 `APPLIED`가 있는 crash는 campaign을 멈추고 review를 기다린다.** `01` §12는 autonomous mutation repair를
   멈추고 evidence를 freeze하고 replay한 뒤 human review로 보낸다. 같은 rule set으로 fuzzing을 계속할지는 사람이
   정한다(`crash_review`의 `resume`).
9. **job당 미완료 task는 하나이고(`s1_fixed`의 attempt는 예외, 근거 18) 결과는 `task_id`로 대조한다.** 전이마다 소비한 verdict를 정확히 하나의 시도에
   묶어야 evidence lineage가 섞이지 않는다(`01` §11.1). 재시작 뒤 다시 실행한 Agent task는 attempt까지 대조한다.
   그래야 `abandoned`로 기록한 실행의 출력이 전이를 만들지 않는다. 전이가 만드는 요청마다 새 `task_id`를 주는
   것은 Runner가 `task_id`에 대해 멱등이기 때문이다. 같은 `task_id`를 쓰면 다시 실행해야 할 단계가 이전 실행의
   결과를 돌려받는다.
10. **재시작은 Runner 실행을 새로 만들지 않는다.** Controller는 같은 `task_id`로 다시 submit하고, Runner는
    `task_id`마다 실행을 하나만 둔다. 실패한 것은 Controller이므로 scenario를 다시 실행하지도 budget을 쓰지도 않는다.
    한 Runner task가 두 번 실행되면 VM 비용이 늘고, 한 `task_id`에 bundle이 둘 생겨 어느 쪽을 소비했는지에 따라
    evidence lineage가 갈린다. 결과를 버린 Runner task도 종료를 확인한 뒤에 다음 task를 보낸다. 버린 campaign도
    끝날 때까지 VM을 쓰고 evidence를 봉인하며, replay는 freeze한 evidence가 필요하기 때문이다(`01` §12). 모르는
    `task_id`의 `cancel`을 기록해 두는 것은 늦게 도착한 submit이 버린 task를 시작하지 못하게 하려는 것이다.
11. **Q1 뒤에 할 일은 JobPolicy `campaign_mode`가 정한다.** 기본값 `none`에서는 Q1이 결과물이고 `REACHED` job은
    `s1_reached(evidence_only)`에서 기다린다. `mutate`만 Stage 2를 자동으로 시작한다. 모든 후보가 mutation
    campaign을 필요로 하지는 않고, promotion된 semantic subset이 없는 동안 Mutation Strategy를 부르면
    `mutation_engine` gap만 생긴다(`04` §5). `campaign_mode`는 job이 `s1_reached`에 들어갈 때 읽는다.
    `PolicyChanged`는 이후 전이에만 적용되므로 이미 `s1_reached`에서 기다리는 job은 operator `start_stage2`로
    시작한다(#81).
12. **승인 단계는 approval policy가 요구할 때만 둔다.** approval policy는 trusted controller의 execution policy이고
    (`02` §8), 승인 대상은 review manifest가 hash로 묶는다(`05` §11). 승인 필요 여부는 `s1_running`에 들어갈 때마다
    그때의 policy로 정한다. JobPolicy 변경은 이후 전이에만 적용되므로(`01` §11.1), 대기 중 계산한 `resume_point`를
    그대로 따르면 policy가 승인을 요구하게 된 뒤에도 승인 없이 실행된다.
13. **재평가 이벤트는 대기 상태를 끝내지 않는다.** `blocked_operator`와 `crash_review`는 사람이 이어 갈지 정하는
    지점이고(§6, `01` §12), gap 상태는 issue가 정한다(`07` §7). harness 교체나 HCAP·JudgeProfile 변경은 그 결정을
    대신하지 않으므로 `resume_point`만 바꾼다. 상태를 옮기면 승인이 필요 없는 정책에서 harness 교체만으로 실행이
    재개되고, `campaign_mode`가 `mutate`이면 campaign까지 다시 돈다. `s1_approval`은 대기 상태에 넣지 않는다. identity가
    바뀌면 승인할 harness 자체가 바뀌므로 새 review manifest의 승인을 다시 기다린다. 이전 binding에서 소비한
    verdict의 재판정은 기록만 한다. 그 verdict로 세운 경로는 binding 변경이 이미 무효로 했기 때문이다(`01` §11.2).
    재판정이 이 순서를 뒤집으면 새 identity에서 Q1을 다시 세우지 않고 이전 gate 결과로 campaign에 간다.
14. **replay는 identity나 HCAP이 바뀌어도 기록된 입력으로 마친다.** replay 입력은 crash와 같은 harness identity와
    기록된 rule set이다(`../03-nfs-proxy/05` §25, §26). 새 binding으로 옮기면 비교의 전제가 깨지고, Stage 1이나
    gate로 돌리면 window에 `APPLIED` rule이 있는 crash가 사람 검토에 닿지 않는다(`01` §12). 바뀐 binding은 검토 뒤
    campaign을 이어 갈 지점(`crash_review`의 `resume_point`)에만 쓴다. 정지 중인 campaign에서 늦게 온 crash가 이
    경로에 닿는 경우는 §4가 정한다.
17. **늦게 온 `APPLIED` crash는 사람의 대기를 깨지 않는 곳에서만 replay로 보낸다.** `01` §12는 `APPLIED` crash를
    freeze·replay·검토로 보내라고 하지만, 대기 상태는 그 상태의 동작으로만 끝난다(근거 13). 그래서 같은 campaign의
    검토가 진행 중이면 queue에 넣어 그 검토 뒤에 replay하고, campaign이나 그 campaign이 시작한 Agent repair처럼
    자동으로 돌던 작업은 멈추고 replay한다. 나머지는 `unrouted` triage로 사람에게 맡긴다. replay 입력은 crash의
    identity와 기록된 rule set이라(근거 14) job이 그 뒤 어디에 있든 replay할 수는 있지만, 대기 중인 job을 옮기면
    사람이 정할 일을 Controller가 정하게 된다.
15. **`runtime_retry`는 재실행을 끝내는 결과에서만 0으로 돌아간다.** 판정된 `INCONCLUSIVE(loss)`와 gate의 M1
    `INCONCLUSIVE`도 유효한 verdict지만 같은 입력을 다시 실행하게 한다. 이런 결과로 counter를 되돌리면 반복되는
    관측 실패가 한도에 닿지 않는다.
16. **대기 상태 결과의 `resume_point`는 그 결과의 것이다.** 기준 지점은 앞선 재평가가 바꿔 놓은 곳일 수 있다. 재판정이
    `resume_point`를 `s1_reached`로 바꾼 뒤 다음 재판정이 지금 상태와 같은 `INCONCLUSIVE(evidence)`를 주면, 기준
    지점으로 돌아가는 규칙은 `REACHED`가 아닌 verdict로 `s1_reached`에 들어가 `Stage2Input`을 고정한다. 결과가 정한
    `resume_point`는 지금 판정이 갈 곳이고, 대기 상태가 아닌 job이 같은 이벤트로 가는 곳과 같다.

18. **fixed campaign의 attempt만 job 안에서 함께 돌린다.** attempt는 같은 harness의 독립 실행이라 서로의 결과가
    다음 입력을 바꾸지 않는다. 그래서 순서가 경로를 바꾸지 않고(첫 crash 뒤에도 남은 attempt는 끝까지 센다), 결과를
    `task_id`로 대조하는 규칙(근거 9)은 그대로다. 결과에 따라 다음 입력이 바뀌는 단계(repair, gate, replay)는 하나씩
    둔다. replay는 같은 crash를 M번 돌리는 중 다른 VM의 부하가 재현율을 흐리지 않도록 P=1이다(D14).
19. **Q1 crash finding은 replay한 뒤 job을 verdict대로 보낸다.** `01` §12의 replay·검토 규칙은 fixed crash와 같게
    적용하고(R3), job을 멈추지는 않는다(R2). replay를 job이 나중에 쉴 때로 미루면 job이 다른 harness로 옮겨 간 뒤
    replay할 수 없게 된다. 검토는 사람의 대기 상태가 아니라 job에 붙은 목록이다.

## 검토한 대안

| 선택지 | 얻는 것 | 비용·한계 | 채택 여부와 이유 |
|---|---|---|---|
| 결정적 component도 상태로 둔다(`materializing`, `judging`) | 진행 위치가 더 잘 보인다 | 상태가 늘고 재시작 때 중간 상태를 처리해야 한다 | 채택 안 함. component가 오래 걸리게 되면(예: Materializer가 원격 build를 하면) 재검토 |
| Agent가 다음 단계를 고른다 | 유연하다 | 경로가 비결정적이 되고 verdict의 의미를 Agent가 바꿀 수 있다(`01` §10) | 채택 안 함 |
| 모든 INCONCLUSIVE를 자동 재실행 | 사람 개입이 준다 | 결정적 실패에 budget을 쓰고 무결성 실패를 가린다 | 채택 안 함 |
| budget 소진을 종료 상태로 | 단순하다 | 이어 갈 수 없고, 종료가 음성 결론처럼 읽힌다 | 채택 안 함 |
| job 전체 budget 하나 | 단순하다 | infra 재실행이 Agent repair 몫을 먹는다. `01` §12는 둘을 다른 문제로 나눈다 | 채택 안 함 |
| vocabulary에 없는 gap id를 Agent에 돌려보냄 | 자동화 | 맞지 않는 id에 묶일 수 있다 | 채택 안 함. vocabulary가 안정되면 재검토 |
| `APPLIED` crash 뒤에도 campaign 계속 | 같은 budget으로 더 탐색한다 | review 전에 같은 crash를 반복할 수 있고, 계속할지는 사람 판단이다 | 채택 안 함. `crash_review`에서 `resume`할 수 있다 |
| 재평가 이벤트가 대기 상태의 job도 옮긴다 | 사람 개입 없이 새 harness로 이어 간다 | budget 소진이나 crash 검토로 멈춘 job이 harness 교체만으로 다시 실행되고, `campaign_mode`가 `mutate`이면 campaign까지 간다 | 채택 안 함. 대기 사유별로 자동 재개 조건을 정하게 되면 재검토 |
| 대기 중 identity 변경을 재개할 때 적용한다 | 대기 중 여러 번 바뀌어도 한 번만 계산한다 | `resume_point`가 실제로 갈 곳을 보여 주지 않는다 | 채택 안 함. 대기 중 다시 materialize하는 비용이 커지면 재검토 |
| 재시작 때 Runner의 실행을 모두 멈추고 다시 보낸다 | Runner 계약이 단순하다 | 진행 중인 VM 시간을 버리고, 멈췄다는 확인이 여전히 필요하다 | 채택 안 함. Runner가 task 기록을 durable하게 둘 수 없으면 재검토 |
| Runner 실행을 Controller의 자식 프로세스로 둔다 | Controller와 함께 끝나므로 중복 실행이 없다 | Controller 재시작마다 campaign이 끊기고, Runner를 다른 호스트로 옮길 수 없다 | 채택 안 함. Runner를 한 호스트에 고정하고 Controller 재시작보다 짧은 실행만 맡기게 되면 재검토 |
| 늦게 온 `APPLIED` crash를 triage로만 남긴다 | 단순하다. 정지 뒤의 evidence가 경로를 바꾸지 않는다 | `01` §12의 replay·검토에 닿지 않는 `APPLIED` crash가 생긴다. 여러 VM이 같은 window에서 함께 crash하면 흔하다 | 채택 안 함. §4의 queue와 repair 중단 규칙을 쓴다 |
| 늦게 온 `APPLIED` crash가 대기 상태의 job도 replay로 옮긴다 | 모든 `APPLIED` crash가 replay된다 | budget 소진이나 gap으로 멈춘 job이 사람 동작 없이 다시 실행된다(근거 13) | 채택 안 함. `unrouted` triage로 남긴다 |
| fixed attempt N개를 task 하나가 돌린다 | Controller 상태가 단순하다 | lease가 길어지고, 중간에 끊기면 센 attempt를 복구할 수 없다 | 채택 안 함(#81 D11) |
| Q1 crash finding을 `crash_review`로 보내 job을 멈춘다 | 검토가 빠르다 | 일반 crash(boot WARNING 등)가 Stage 1 진행을 끊는다 | 채택 안 함(#81 R2) |
| `runtime_retry`를 유효한 verdict에서 0으로 되돌린다 | verdict가 나왔으면 관측 경로가 동작한 것으로 본다 | 판정된 `INCONCLUSIVE(loss)`나 gate의 M1 `INCONCLUSIVE`가 반복되면 한도에 닿지 않는다 | 채택 안 함. 한도가 재실행 loop를 끝내는 유일한 장치다. 재실행 사이에 관측이 나아졌는지 판정하는 규칙이 생기면 재검토 |

## 영향

- **상류**: Q1·M1·Q2·Replay의 status와 reason(`06` §7, §10, `01` §7.1, §8.2, `../03-nfs-proxy/05` §29), Materializer와
  Compiler의 거부 사유(`05` §13, `08` §12), gap 상태(`07` §7), identity 무효화(`01` §11.2)가 바뀌면 §3–§5 표를 함께
  고친다. 표에 없는 새 값은 §2에 따라 `blocked_operator(unexpected_event)`로 가므로 조용히 잘못 라우팅되지 않는다.
- **하류**: Controller의 job 저장소 schema, Agent Task 출력 variant(§2), JobPolicy 항목(§6), triage 목록, Runner가
  구현할 task 계약(§8). 이 표가 틀리면 Q1 없는 Stage 2 진입, 잘못된 repair, 끝나지 않는 loop가 생긴다.
- **운영**: budget이 LLM 호출과 VM 시간을 묶는다. `blocked_operator`가 사람 개입 지점이라 한도가 작으면 사람
  부담이 커지고, 크면 비용이 커진다. job의 Runner 실행은 한 번에 하나라(§8) Runner의 `cancel` 응답이 늦으면 그
  job의 다음 Runner task도 늦어진다. fixed campaign은 job 하나가 VM slot을 `fixed_parallelism`개까지 쓰므로 다른
  job의 Stage 1 실행이 slot을 기다릴 수 있다.

## 신뢰성 요구

| 항목 | 내용 |
|---|---|
| 오류 방향 | 거짓 진행이 더 위험하다. Stage 2 진입, crash report, gap 해소 뒤 재시도는 근거 verdict가 기록된 경우에만, 대기 상태의 재개는 그 상태의 operator 동작이나 issue 이벤트가 기록된 경우에만 일어나야 한다. 거짓 정지(불필요한 `blocked_operator`)는 사람 시간만 쓴다 |
| 실패 방식 | fail-closed. 정의되지 않은 결과, 알 수 없는 reason, 검증 실패는 `blocked_operator`로 간다. 앞 단계를 건너뛰지 않는다 |
| 관측 가능성 | `Transition` 기록이 이벤트, 소비한 verdict와 artifact, JobPolicy identity를 남긴다. `blocked_*`는 reason을, 대기 상태와 `retry_pending`은 `resume_point`를 가진다. Runner task의 상태는 `status(task_id)`로 확인한다 |
| 재현성 | 같은 상태, 이벤트, component 출력, JobPolicy에서 같은 전이가 나온다. Agent 출력은 재현되지 않으므로 artifact로 저장하고 다시 만들지 않는다 |

## 검증 오라클

Controller 구현의 host test로 확인한다. LLM은 부르지 않는다(고정 출력 fake model). Runner 결과는 고정 봉인
bundle fixture로 대신한다.

1. §3–§5 표의 행마다 테스트가 있다. 입력 상태와 이벤트에서 표의 다음 상태와 counter 변화가 나온다.
2. 음성 대조:
   - Q1 `REACHED`가 아닌 verdict로는 `s2_*` 상태에 들어가지 않는다.
   - identity가 다른 `REACHED` evidence로는 `s2_strategy`에 들어가지 않는다.
   - `INCONCLUSIVE`(`infra`, `loss`, `evidence`, `mapping`)는 Agent Task를 부르지 않는다.
   - `task_id`가 다른 결과는 전이를 만들지 않는다.
   - 표에 없는 reason 값은 `blocked_operator(unexpected_event)`로 간다.
   - 대기 상태(`blocked_operator`, `crash_review`, `blocked_harness_gap`, `parked`)에서 재평가 이벤트는 상태와
     `state_reason`을 바꾸지 않고 `resume_point`만 바꾼다. 그 뒤 `resume`은 바뀐 `resume_point`로 가고, gate 뒤
     재평가 이벤트(binding 변경, gate verdict 재판정)로 `resume_point`가 바뀐 job의 `route(to)`는 받지 않는다.
     `blocked_operator(replay_evidence)`의 `resume_point`(replay)는 identity나 `hcap_revision`이 바뀌어도 그대로다.
   - 재평가 결과가 다른 대기 상태여서 그 상태로 재개한 job은 그 상태를 끝내면 그 결과의 `resume_point`로 간다. 그 뒤
     재평가 결과가 다시 지금 상태와 같아지면 `resume_point`는 그 결과의 `resume_point`로 돌아간다.
   - `blocked_operator(q1_evidence)`에서 재판정이 `resume_point`를 `s1_reached`로 바꾼 뒤 다음 재판정이 다시
     `INCONCLUSIVE(evidence)`를 주면, `resume`은 `s1_reached`가 아니라 `s1_running`으로 간다. `REACHED`가 아닌
     verdict로 `Stage2Input`을 고정하지 않는다.
   - gate Q1 `INCONCLUSIVE(evidence)`로 `blocked_operator(q1_evidence)`에 있는 job에서 identity를 바꾼 뒤 support
     boundary가 바뀌어 이전 gate가 `REACHED`와 통과하는 M1로 재판정돼도, `resume`은 `s2_campaign`이 아니라 새
     identity의 identity 재수립 지점으로 간다. 재판정한 verdict는 기록만 된다.
   - 임계값과 fuzz budget 아래의 Q2 `NOT_OBSERVED` campaign bundle은 campaign을 멈추지 않는다. 실행 중에 받은
     bundle이면 같은 task를 계속 기다리고, `sealed`로 끝난 task의 마지막 bundle이면 처리한 뒤 다음 task로 이어 간다.
   - `s2_strategy`에서 `hcap_revision`이 바뀌고 plan이 새 HCAP 검증에 실패하면 Mutation Strategy를 다시 부르지
     않고 `s1_planning`(repair, `hcap_changed`)으로 간다. Compiler 거부로 `blocked_harness_gap(mutation_engine)`에
     있는 job은 gap을 닫은 promotion 뒤 Mutation Strategy를 다시 부르지 않고 저장된 rule set을 다시 compile한다.
   - 같은 identity에서 gap을 닫은 promotion의 issue resolved가 그 `hcap_revision`의 변경 이벤트보다 먼저 와도
     `retry_pending`은 plan을 새 HCAP으로 다시 검증한다. 실패하면 `s1_planning`(repair, `hcap_changed`)으로 가고,
     통과하면 저장된 rule set을 다시 compile한다. 뒤에 온 변경 이벤트는 job의 binding이 이미 그 revision이므로
     아무것도 바꾸지 않는다.
   - approval policy가 승인을 요구하도록 바뀐 뒤에는 대기 중 계산한 `resume_point`가 `s1_running`이어도, `resume`은
     승인되지 않은 harness를 실행하지 않고 `s1_approval`로 간다.
   - `s2_replaying` 중 identity나 `hcap_revision`이 바뀌어도 replay 결과는 `crash_review`로 간다. 그 `resume`은
     `s2_campaign`이 아니라 identity가 바뀌었으면 identity 재수립 지점으로, `hcap_revision`만 바뀌었으면 plan
     검증을 통과한 경우 다시 compile한 `s2_gate`로 간다.
3. 종료성: 모든 한도를 1로 둔 JobPolicy에서 항상 repair나 재실행을 부르는 결과만 주면 유한한 전이 뒤
   `blocked_operator`에 닿는다. 판정된 `INCONCLUSIVE`가 counter를 되돌리지 않는지는 `runtime_retry` 한도를 2 이상으로
   두고 아래 순서로 확인한다. 재실행이 한도만큼 일어난 다음 결과는 재실행 대신
   `blocked_operator(runtime_retry_exhausted)`로 가고, 그동안 `runtime_retry`는 0으로 돌아가지 않는다.
   - `s1_running`: Q1 `INCONCLUSIVE(infra)`와 `INCONCLUSIVE(loss)`를 번갈아 준다.
   - `s2_gate`: Q1 `REACHED`이고 M1 `INCONCLUSIVE`인 결과와 Q1 `INCONCLUSIVE(loss)`를 번갈아 준다.
4. 재시작: 각 상태에서 commit 직후 Controller를 죽였다 살리면 같은 상태와 `pending_task`로 이어지고, `Transition`을
   처음부터 다시 적용한 상태가 저장된 상태와 같다.
5. 재시작과 중복 실행: fake Runner가 `task_id`별 submit 횟수와 실행 시작 횟수를 센다.
   - 실행 중에 Controller를 재시작하면 실행 시작은 한 번이고, 그 실행의 bundle로 전이가 일어난다.
   - commit 뒤 발송 전에 Controller를 죽이면 재시작 뒤 실행이 한 번 시작된다.
   - 결과를 버린 Runner task가 끝났다는 응답 전에는 같은 job의 다음 Runner task를 보내지 않는다.
     `cancelling_tasks`와 아직 보내지 않은 Runner `pending_task`가 함께 있을 때 Controller를 재시작해도 같다.
     첫 task가 끝나기 전에 재평가 이벤트가 다시 와서 보내지 않은 task까지 버려도, 두 task가 모두 종료를 답한
     뒤에야 다음 task를 보낸다.
   - `cancel`이 submit보다 먼저 Runner에 닿으면 늦게 온 submit은 실행을 시작하지 않고, 그 `cancel`은
     `ended_unsealed(cancelled)`를 받는다.
   - `resume`이나 재실행 행이 부른 Runner 단계는 새 `task_id`로 실제로 다시 실행된다.
   - campaign 실행 중에 Controller를 죽였다 살리면 그동안 봉인된 bundle을 빠짐없이 순서대로 받는다.
   - 재시작 전 attempt의 Agent 출력은 늦게 와도 전이를 만들지 않는다.
6. fixed campaign(§3.1): fake Runner로 attempt 0개, 1개, N개, P개 병렬을 돌린다.
   - lease가 attempt 중간에 끊겨 Runner가 같은 task를 다시 실행해도 그 attempt는 한 번만 센다.
   - 첫 crash 뒤 새 attempt를 보내지 않고, 이미 보낸 attempt의 결과와 crash를 모두 받은 뒤 replay한다.
   - 연속 K회 `not_reached`는 `blocked_operator(fixed_not_reaching)`, crash 없는 N회는
     `s1_reached(fixed_no_signal)`이다. infra attempt는 세지 않고 `runtime_retry` 한도에서 멈춘다.
   - replay는 `k/M`을 기록하고 `k=0`이어도 `crash_review`로 간다(`reproduced=false`).
   - `s1_running`의 crash finding은 replay한 뒤 그 실행의 verdict 행으로 가고, job은 `crash_review`에 멈추지 않는다.
   - 위 모두에서 `Transition`을 처음부터 다시 적용한 상태가 저장된 상태와 같다.

증명하지 않는 것: Agent 출력의 품질, Runner와 Judge의 정확성(각자의 오라클: `06`, `01` §8.2, `../03-nfs-proxy/05`),
실제 provider 장애 양상.

## 실패 양상과 진단

| 증상 | 가능한 원인 | 구분하는 관측 | 조치 |
|---|---|---|---|
| job이 Runner를 기다리는 상태(`s1_running` 등)에 오래 머문다 | Runner가 응답하지 않는다, 실행이 끝나지 않는다, 결과를 버린 이전 task의 `cancel` 응답이 오지 않는다 | `status(task_id)` 응답, job의 `pending_task`와 `cancelling_tasks`, Runner의 task 기록 | Runner를 확인한다. Controller는 Runner가 끝났다고 답하기 전에는 그 task를 다시 실행하지 않고 다음 Runner task도 보내지 않는다 |
| `s1_planning`과 `s1_running`을 오간 끝에 `blocked_operator(stage1_repair_budget)` | 시나리오 선택 실패, 분석 오류, Q1 관측 범위 문제. 어느 쪽인지 모를 수 있다 | `AgentAttempt`의 `RepairInput`과 Q1Result 순서, `observations` | 사람이 검토해 budget을 늘려 `resume`하거나 close |
| `blocked_operator(runtime_retry_exhausted)`. 여러 job에서 함께 나올 수 있다 | 인프라 문제(VM, fixture), 반복되는 관측 손실(`loss`), gate의 M1 evidence 경로 문제 | 재실행마다의 Q1 reason과 gate의 M1 verdict, 같은 harness build인지 | harness·infra·evidence 경로를 고친 뒤 `resume` |
| `blocked_operator(unexpected_event)` | Controller 구현과 이 표의 불일치, 또는 상류 문서의 새 reason | `Transition`의 event와 상태 | 표나 구현을 고친다 |
| `blocked_operator(execution_cleanup)` | Runner backend가 실행 정리를 확인하지 못한 채 lease가 끝났다(signal 실패, 죽지 않는 프로세스) | job의 `uncleaned_tasks`, Runner의 attempt 기록, backend 자원 상태(`ProcessSupervisor`면 `quarantined`) | 실행이 사라졌는지 확인한 뒤 `resume` |
| `blocked_operator(host_authority)` | registry가 build approval보다 먼저 새 `hcap_revision`을 공개했다, build artifact·HCAP·admission 기록이 깨졌다, parser build가 harness identity와 다르다 | `Transition`의 Materializer 거부 detail | 호스트 쪽 기록을 고친 뒤 `resume`(다시 materialize한다) |
| `blocked_operator(gap_id_unknown)` | HCAP vocabulary에 없는 capability가 필요하다 | `unsupported` 출력의 `reason`에 적힌 필요한 capability | vocabulary를 확장해 `resume`하거나 close |
| issue가 해결됐는데 `blocked_harness_gap`에 남아 있다 | issue 상태 이벤트를 받지 못했다 | tracker 상태와 job의 issue 참조 | 원인 모름. tracker 연동을 확인한다 |
| operator `route(to)`가 받아지지 않는다 | gate를 실행한 뒤 재평가 이벤트가 binding을 바꿨거나 gate verdict를 다르게 판정해 `resume_point`가 바뀌었다 | `Transition`의 재평가 이벤트 기록, `resume_point` | `resume`으로 지금 `resume_point`에 보낸다 |

## 한계와 미결 사항

- **결정됨:** 상태 목록, 전이 규칙(§2), Stage 1 전이(§3), 대기 상태와 재평가 이벤트 규칙(§5), budget counter의
  종류와 되돌리는 조건(§6), 기록과 재시작 규칙, Controller가 요구하는 Runner task 계약(§8).
- **구현됨(2026-10-18):** `DurableRunner`가 task, cancel, lease, completion과 streaming bundle을 SQLite에
  durable하게 기록한다. 재시작 뒤 이어 갈 수 없는 실행은 `ended_unsealed(runner_restart)`로 끝내며, Controller는
  같은 `task_id`의 상태를 다시 소비한다. Stage 2의 segment 단위 bundle과 host 연결은
  `agent_pipeline/stage2/README.md`가 기록한다.
- **결정됨(2026-10-18, 구현 기본값. 저장소 소유자 결정 아님):** 정지 중인 campaign에서 늦게 온 `APPLIED` crash는
  §4의 "늦게 온 campaign evidence" 규칙(queue, repair 중단, `unrouted` triage)을 따른다(근거 17).
- **결정됨(2026-10-13, 저장소 소유자):** JobPolicy 기본값은 Stage 1 repair 한도 3회, `agent_retry` 한도 3회, `runtime_retry` 한도
  3회, 실행 전 사람 승인 불필요다.
  `run_stage2`는 Stage 2 구현 전까지 거짓만 받고, 구현 뒤 기본값을 참으로 바꾼다
  (`agent_pipeline/contracts.py`의 `JobPolicy`).
  **현재(2026-10-19, 구현 기본값):** Stage 2 backend가 들어와 `run_stage2`는 참도 받고, PR #61에서 gate,
  bounded campaign, replay의 standalone host 경로를 실제 KVM으로 확인했다. campaign 임계값은 아직 저장소 소유자
  결정이 아니며 실제 candidate의 전체 service 경로도 #57에서 검증해야 하므로 기본값은 거짓이다. 기본값을 참으로
  바꾸는 시점은 저장소 소유자가 정한다.
  **결정됨(2026-10-23, 저장소 소유자, #81 D1–D4):** `run_stage2`는 `campaign_mode`(`none`·`fixed`·`mutate`)로
  바뀌고 기본값은 `none`이다. `run_stage2`만 있는 기존 policy는 참이면 `mutate`, 거짓이면 `none`으로 읽고,
  두 값이 어긋나면 거부한다. 거짓은 mutation을 시작하지 않는다는 뜻이라 `fixed`와도 어긋나지 않는다. `fixed`는
  fixed campaign이 들어올 때까지 받지 않는다.
  **결정됨(2026-10-23, 저장소 소유자, #81 D11–D15, R1–R6):** fixed campaign(§3.1)과 VM slot pool(§8). JobPolicy 값
  `fixed_attempts`=50, `fixed_replays`=5, `fixed_not_reached_limit`=5, `fixed_parallelism`=4는 Stage 2 임계값처럼
  자리값이다.
- **결정됨(2026-10-13, 저장소 소유자):** `agent_retry`는 요청 단위로 센다. 새 요청이 시작되면 0에서 센다.
- **결정됨(2026-10-13, 저장소 소유자):** candidate 하나에 job 여러 개(예: sanitizer별)를 둘 수 있다. 같은
  target(commit, location)은 같은 `candidate_id`다(`02` §7).
- **결정됨(2026-10-18, 구현 기본값):** gate 반복은 각 반복에 gate 표를 적용하고 가장 위의 행을 gate 결과로 한다
  (§4, `01` §3). 기본 반복 수는 1이다.
- **미결:** gate Q1 `NOT_REACHED`의 자동 진단. 지금은 사람 결정(`blocked_operator(gate_regression)`)이다. 후보는 같은
  target mode에서 빈 rule set으로 gate를 다시 돌려 rule의 영향과 runtime 퇴행을 가르는 것이다. 빈 rule set으로
  target mode를 켤 수 있는지는 미검증이다.
- **결정됨(2026-10-18, Controller 쪽):** campaign evidence의 이벤트 단위는 campaign task가 실행 중에 봉인한 bundle
  하나다(§4). bundle 하나가 무엇을 담는지(fuzz VM instance의 실행 구간)와 Runner 쪽 봉인 구현은 `01` §14 14번이
  정한다.
- **구현 기본값(2026-10-18, Runner 쪽):** Runner lease는 실행 중에 bundle을 더할 수 있다(`DurableRunner.append_bundle`).
  Stage 2 host command가 끝낸 segment 하나가 bundle 하나이고, 더한 즉시 `status().bundles`에 순서대로 보인다. lease가
  봉인 없이 끝나도 이미 더한 bundle은 task에 남는다(`agent_pipeline/stage2/README.md`).
- **미결:** campaign 임계값과 fuzz budget의 기본값(`JobPolicy`의 `campaign_*_generations`, `fuzz_budget_executions`).
  지금 값은 loop를 끝내기 위한 자리값이며 저장소 소유자 결정이 아니다.
- **미결:** `RepairInput.findings`에 넣을 coverage 요약의 형식(예: target 파일에서 관측된 함수). 첫 Stage 1 repair
  구현에서 정한다.
- **결정됨(2026-10-18, 형식):** triage 항목은 job에 붙은 `TriageItem`이다(§4). **미결:** 처리 주체와, 사람이 항목을
  닫는 동작.
- **미결:** Stage 2 실행 전 사람 승인. 기존 계약의 approval binding은 Stage 1 review manifest뿐이다(`05` §11).
- **구현 범위(#46):** `s1_reached`·`s2_strategy` 행과 Compiler 결과 행은 `tests/agent_pipeline/test_stage2_strategy.py`가
  가짜 model과 가짜 Compiler로 확인한다. `campaign_mode`가 `mutate`가 아니면 Stage 2는 operator 동작
  `start_stage2`로 시작한다. Compiler는 `rule_compiler.ArtifactMutationRuleCompiler`이고, host 설정에 promotion된
  Proxy build(`Stage1Config.nfs_proxy`)가 없으면 rule set은 `blocked_operator(stage2_compiler_unavailable)`에서
  기다린다. `agent_repair[stage2]`의 한도(`stage2_repair_budget`)는 Stage 1과 같은 3회로 두었다(저장소 소유자 결정
  아님).
- **구현 범위(gate 이후):** `s2_gate`, `s2_campaign`, `s2_replaying`, `crash_review` 행, §5의 Stage 2 부분(binding
  변경, `route(to)`), §4의 반복·집계·늦은 evidence 규칙은 `tests/agent_pipeline/test_stage2_gate.py`가 가짜 Stage 2
  Judge와 가짜 Runner로 확인한다. Judge는 `components.Stage2Judge`(Q1·M1 gate, Q2·M1 campaign, replay comparator)로
  주입한다. artifact 기반 구현은 `stage2.judge.ArtifactStage2Judge`이고, gate·campaign·replay를 실행하는 Runner
  backend는 `stage2.engine.Stage2CommandEngine`이다(`agent_pipeline/stage2/README.md`). 둘 다
  `tests/agent_pipeline/test_stage2_service.py`가 합성 host command로 `s1_reached`부터 `crash_review`까지 확인한다.
  Stage 2 backend가 설정되지 않은 host(`Stage1Config.stage2` 없음)에서는 compile한 rule set이
  `blocked_operator(stage2_gate_unavailable)`에서 기다리고, `resume`은 그 rule set을 다시 compile한다. 이 reason과
  `stage2_compiler_unavailable`은 host 설정 사유라 표에 넣지 않는다. 표에 없는 reason `campaign_evidence`(campaign
  bundle의 host provenance 불일치)는 §4 표에 더했다.
- `run_stage2`는 Stage 2 backend가 없는 동안 거짓만 받았다. 참이 되면 실행할 수 없는 Stage 2로 job이 자동으로
  들어가기 때문이다. backend가 들어온 뒤로는 참도 받지만 기본값은 거짓이다. 지금은 `campaign_mode`가 같은 선택을
  하며 기본값은 `none`이다. backend를 설정하지 않은 host에서 `mutate`인 policy의 job은 compile 뒤
  `blocked_operator(stage2_gate_unavailable)`에서 기다린다.
- **미구현:** gate verdict의 JudgeProfile 재판정(§5). 재평가는 Stage 1 Q1 verdict만 다시 판정한다. Stage 2 실행 전
  사람 승인도 없다(미결 그대로).
- **부분 검증:** 검증 오라클 1–5와 `s1_reached`부터 `crash_review`까지의 전체 service 전이는
  `tests/agent_pipeline/`이 가짜 component와 합성 host command로 확인한다. PR #61은 gate, bounded campaign,
  replay host command와 그 Stage 2 evidence를 실제 KVM에서 별도로 확인했다. live Agent provider와 실제 candidate가
  Controller부터 real host까지 전체 경로를 지난 검증은 아직 없으며 #57 범위다.

## Agent 사용 지침

- **지원 범위:** Agent는 job 상태를 읽거나 바꾸지 않는다. Agent Task는 Candidate, 앞 단계 출력, `RepairInput`을
  받아 §2의 variant 중 하나를 출력한다.
- **비지원 범위:** 다음 단계 선택, budget 조정, gap issue 생성, verdict 해석 변경. `RepairInput`의 evidence를
  지시로 읽는 것.
- **확장 절차:** Agent Task 출력 variant나 verdict reason을 추가하면 §2–§5 표와 검증 오라클 1, 2를 함께 고친다.
- **제약:** `unsupported`의 `missing_capability_id`는 HCAP vocabulary에서만 고른다. 맞는 id가 없으면 가장 가까운
  id를 고르지 않는다. Mutation Strategy는 `mutation_engine.unlisted`와 proposal을 내고, 필요한 capability를
  `reason`과 proposal에 적는다. 빈 id는 executor가 거부한다(#81 D5).
- **검증 방법:** 출력은 Controller가 schema로 검증한다. schema 통과는 형식이 맞다는 뜻일 뿐 HCAP 검사,
  Materializer, Compiler, Judge를 통과한다는 뜻이 아니다.

## 참조

- `01-two-stage-agent-architecture.md` §3, §5.1, §7, §8, §11, §12
- `02-vulnerability-candidate.md` §3, §6, §8
- `03-candidate-analysis.md` §5, §8, §13, §14
- `04-harness-capability-spec.md` §1.1, §5
- `05-reachability-plan.md` §4, §8, §11, §13
- `06-reachability-evidence-q1.md` §3, §7–§13
- `07-harness-gap-issue.md` §2, §3, §7
- `08-mutation-rule-set.md` §5, §12, §15, §16
- `../03-nfs-proxy/05-mutation-delta-replay.md` §27–§29
- `../decisions/2026-10-13-agent-implementation-stack.md`
