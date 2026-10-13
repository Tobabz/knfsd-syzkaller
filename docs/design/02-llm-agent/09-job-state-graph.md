# Job State Graph (repair/state graph)

> 상태: draft · 최종 확인: 2026-10-13
> 상위 설계: `01-two-stage-agent-architecture.md` §12, §14 12번
> 선행 계약: `02`–`08`, `../03-nfs-proxy/05-mutation-delta-replay.md` §27–§29
> 관련 구현: 없음 (Controller 미구현). 구현 스택은 `../decisions/2026-10-13-agent-implementation-stack.md`
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
 s1_reached ---- JobPolicy run_stage2 -----> s2_strategy      (Figure 2)

 [A] Agent  [R] Runner  [H] human  {..} deterministic step inside a transition
 (repair) agent_repair budget, (rerun) runtime_retry budget (§6)
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
   +-- resume ------------------------------> s2_campaign
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
   +-- issue deferred -> parked [I] -> issue reopened or resolved -> re-evaluate
   +-- issue wont_fix -> closed_unsupported

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
| `s1_reached` | 없음. Q1 package를 보존하고 Stage 2 시작을 기다린다 | Q1 `REACHED` |
| `s2_strategy` | Agent: Mutation Strategy | Stage 2 시작, Stage 2 repair |
| `s2_gate` | Runner: baseline-with-rules gate와 neutral run (`01` §3) | compile 성공, 재실행 |
| `s2_campaign` | Runner: fuzz campaign | gate 통과, crash review 뒤 재개 |
| `s2_replaying` | Runner: `CrashContextWindow` replay | window에 `APPLIED` rule이 있는 Q2 `OBSERVED` |
| `crash_review` | 사람: crash report 검토 | replay 비교 verdict |
| `blocked_harness_gap` | issue (`07` §7) | gap |
| `retry_pending` | Controller 처리 (queue, `07` §7) | issue resolved |
| `parked` | issue 재개 또는 해결 (`07` §7) | issue deferred |
| `blocked_operator` | 사람: operator 동작 (§5) | budget 소진(§6), fail-closed 경로(§2–§4) |
| `rejected` | 종료 | intake 거부 (`02` §3) |
| `closed_unsupported` | 종료 (`07` §7) | issue wont_fix |
| `closed` | 종료 | crash review 종료, operator close 또는 cancel |

- 결정적 component(intake 검증, harness binding, HCAP 검사, Materializer, Compiler, Q1·M1·Q2 Judge, replay
  comparator)는 상태가 아니다. 전이 안에서 실행한다.
- job의 미완료 task는 최대 하나다(`pending_task`). Agent, Runner, 사람에게 보낸 요청은 `task_id`를 가진다.
- `blocked_harness_gap`, `blocked_operator`, `parked`, `retry_pending`은 막힌 위치 `resume_point`(다시 들어갈
  상태와 그 입력)를 기억한다.

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

- `missing_capability_id`는 HCAP data의 controlled vocabulary에 있어야 한다(`07` §3). 비었거나 vocabulary 밖이면
  `blocked_operator(gap_id_unknown)`로 보낸다. Agent에게 기존 id 중 하나를 고르라고 돌려보내지 않는다.
- 결과는 `task_id`가 job의 `pending_task`와 같을 때만 전이를 만든다. 다르면(취소되거나 교체된 task의 늦은 결과)
  artifact로 저장만 한다.
- `task_id`가 맞지만 아래 표에 없는 결과(새 reason 값, 상태에 맞지 않는 결과)는 `blocked_operator(unexpected_event)`로
  보낸다. 앞 단계를 건너뛰거나 가장 가까운 행으로 해석하지 않는다.
- Runner가 봉인 bundle 없이 끝나면 Judge를 부르지 않고 verdict도 만들지 않는다. 이 경우는 §3–§4의 "봉인
  bundle 없는 Runner 종료" 행(재실행)으로 처리한다.

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
| `s1_planning` | `plan`, Materializer typed 거부(`neutral_control_unavailable` 제외) | `s1_planning` (repair, `materializer_rejected`) | agent_repair | `05` §11, §13 |
| `s1_planning` | `plan`, Materializer `neutral_control_unavailable` | `blocked_harness_gap(fixture_or_tool, neutral_control.<profile>)` | — | `05` §11 |
| `s1_planning` | `plan`, materialize 성공, approval policy가 승인을 요구 | `s1_approval` | — | `05` §11, `02` §8 |
| `s1_planning` | `plan`, materialize 성공, 승인 불필요 | `s1_running` | — | |
| `s1_planning` | `unsupported` | `blocked_harness_gap(gap_class, missing_capability_id)` | — | `05` §8, `07` §2 |
| `s1_planning` | `reanalysis_required` | `s1_analysis` (repair, `reanalysis_requested`) | agent_repair | `03` §14 |
| `s1_approval` | approve. 승인이 가리키는 review manifest hash가 현재 harness의 hash와 같음 | `s1_running` | — | `05` §11 |
| `s1_approval` | approve, hash 다름 | 상태 유지. 승인으로 받지 않는다 | — | `02` §6 |
| `s1_approval` | deny(note) | `s1_planning` (repair, `reviewer_denied`) | agent_repair | |
| `s1_running` | Q1 `REACHED` | `s1_reached`. JobPolicy `run_stage2`가 참이면 바로 Stage 2를 시작한다(§4 첫 행) | — | `06` §12 |
| `s1_running` | Q1 `NOT_REACHED` | `s1_planning` (repair, `q1_not_reached`) | agent_repair | `06` §13 |
| `s1_running` | Q1 `INCONCLUSIVE(infra)`, `INCONCLUSIVE(loss)`, 봉인 bundle 없는 Runner 종료 | `s1_running` (같은 harness 재실행) | runtime_retry | `06` §13, `01` §12 |
| `s1_running` | Q1 `INCONCLUSIVE(evidence)`, `INCONCLUSIVE(mapping)` | `blocked_operator(q1_evidence)`, `blocked_operator(q1_mapping)` | — | `06` §13, `01` §11.1 |
| `s1_running` | Q1 `INCONCLUSIVE(unsupported_attribution)` | `blocked_harness_gap(remote_kcov_attribution, remote_kcov.context.<expected_context>)` | — | `06` §7, §13 |

- ambient control의 결과(`06` §11)는 기록만 하고 전이를 바꾸지 않는다.
- `REACHED`로 넘어갈 때 Controller는 `Stage2Input`(`01` §5.1)의 구성 artifact와 verdict id를 job에 고정한다.

### 4. Stage 2 전이

Stage 2는 Proxy M4 이후 구현한다(`../decisions/2026-10-13-agent-implementation-stack.md` 결정 1). 아래 표는
기존 계약이 정한 경로를 상태로 옮긴 것이고, 계약이 정하지 않은 부분은 사람 결정(`blocked_operator`)으로
둔다(한계와 미결 사항).

| 상태 | 이벤트와 조건 | 다음 상태 | counter (§6) | 근거 |
|---|---|---|---|---|
| `s1_reached` | Stage 2 시작(JobPolicy 또는 operator). Q1 evidence의 ExecutionHarnessIdentity가 job의 bound identity와 같음 | `s2_strategy` | — | `01` §5.1 |
| `s1_reached` | Stage 2 시작, identity 다름 | §5의 identity 변경 처리 | — | `01` §11.2 |
| `s2_strategy` | `rule_set`, Compiler 성공 | `s2_gate` | — | `08` §12 |
| `s2_strategy` | `rule_set`, Compiler 거부 `unknown_path`, `type_mismatch`, `message_type_inconsistent`, `missing_required_field` | `s2_strategy` (repair, `compiler_rejected`) | agent_repair | `08` §12 |
| `s2_strategy` | `rule_set`, Compiler 거부 `unsupported_capability`, `requires_state_lineage` | `blocked_harness_gap(mutation_engine, missing_capability_id)` | — | `08` §12, §15 |
| `s2_strategy` | `unsupported` | `blocked_harness_gap(mutation_engine, missing_capability_id)` | — | `08` §15 |
| `s2_gate` | gate Q1 `NOT_REACHED` | `blocked_operator(gate_regression)` | — | `01` §3, `08` §16 |
| `s2_gate` | gate Q1 `INCONCLUSIVE(infra)`, `INCONCLUSIVE(loss)`, 봉인 bundle 없는 Runner 종료 | `s2_gate` 재실행 | runtime_retry | `01` §3 |
| `s2_gate` | gate Q1 `INCONCLUSIVE(evidence)`, `INCONCLUSIVE(mapping)` | `blocked_operator(q1_evidence)`, `blocked_operator(q1_mapping)` | — | `01` §3, `06` §13 |
| `s2_gate` | gate Q1 `INCONCLUSIVE(unsupported_attribution)` | `blocked_harness_gap(remote_kcov_attribution, remote_kcov.context.<expected_context>)` | — | `01` §3, `06` §13 |
| `s2_gate` | Q1 `REACHED`, 평가한 rule 중 M1 `INCONCLUSIVE`가 있음 | `s2_gate` 재실행 | runtime_retry | `01` §3 |
| `s2_gate` | Q1 `REACHED`, `targets_baseline_traffic=true`인 intent의 M1이 `NOT_APPLIED` | `s2_strategy` (repair, `gate_not_applied`) | agent_repair | `01` §3, `08` §16 |
| `s2_gate` | 그 밖 | `s2_campaign` | — | `01` §3 |
| `s2_campaign` | Q2 `OBSERVED`, `CrashContextWindow`에 `APPLIED` rule이 있음 | campaign 정지, `s2_replaying` | — | `01` §3, §12 |
| `s2_campaign` | Q2 `OBSERVED`이고 window에 `APPLIED` rule이 없음, 또는 Q2 `INCONCLUSIVE` | 상태 유지. crash evidence를 보존하고 triage 항목을 만든다 | — | `01` §3, §12 |
| `s2_campaign` | JobPolicy 임계값: 도달한 generation에서 hypothesis가 계속 `NOT_APPLIED` | campaign 정지, `s2_strategy` (repair, `campaign_not_applied`) | agent_repair | `01` §12 |
| `s2_campaign` | JobPolicy 임계값: 도달한 generation에서 `APPLIED`, Q2 미관측 | campaign 정지, `s2_strategy` (repair, `campaign_no_signal`) | agent_repair | `01` §12 |
| `s2_campaign` | JobPolicy 임계값: 도달한 generation의 M1 `INCONCLUSIVE` 반복 | campaign 정지, `blocked_operator(evidence_path)` | — | `01` §3 |
| `s2_campaign` | fuzz budget 소진 | campaign 정지, `blocked_operator(campaign_budget_exhausted)` | — | `01` §11.1 |
| `s2_replaying` | 비교 verdict(`REPLAY_EQUIVALENT`, `REPLAY_DIVERGED`, `REPLAY_INCONCLUSIVE`, `REPLAY_INVALID`) | `crash_review` | — | `../03-nfs-proxy/05` §29 |
| `s2_replaying` | 봉인 bundle 없는 Runner 종료 | `s2_replaying` 재실행 | runtime_retry | |
| `s2_replaying` | replay bundle의 manifest·correlation 검증 실패 | `blocked_operator(replay_evidence)`. evidence를 고친 뒤 `resume`이 replay를 다시 실행한다 | — | `../03-nfs-proxy/05` §29 |
| `crash_review` | close | `closed(crash_reported)` | — | `01` §13 |
| `crash_review` | resume | `s2_campaign` | — | |

- triage 항목은 job 상태를 바꾸지 않는 사람 검토 목록이다. job id, 봉인 bundle 참조, 그 bundle의 Q2·M1 verdict를
  담는다.
- campaign을 정지한 뒤 도착한 campaign evidence도 저장하고 Judge를 돌린다. 결과는 triage 항목으로만 남고 전이를
  만들지 않는다.

### 5. 외부 이벤트와 operator 동작

| 이벤트 | 대상 | 처리 | 근거 |
|---|---|---|---|
| issue resolved | `blocked_harness_gap`, `parked` | `retry_pending`. 다시 binding하고, identity가 바뀌었으면 아래 identity 변경 규칙을 적용한 뒤 `resume_point`로 간다 | `07` §7 |
| issue deferred | `blocked_harness_gap` | `parked` | `07` §7 |
| issue wont_fix | `blocked_harness_gap`, `parked` | `closed_unsupported(reason)` | `07` §7 |
| bound ExecutionHarnessIdentity 변경(harness build 교체·폐기) | binding 뒤의 비종료 상태 | 진행 중인 Runner task는 결과를 받지 않는다. 다시 binding한다. 저장된 plan이 있으면 새 `hcap_revision`으로 다시 검증해 통과하면 다시 materialize해 `s1_running`(승인이 필요하면 `s1_approval`)으로, 실패하면 `s1_planning`(repair, `hcap_changed`)으로 간다. plan이 없으면 진행 중이던 Agent 상태를 다시 시작한다. Stage 2에 있었어도 Q1을 새 identity에서 다시 세운다 | `01` §11.2, `07` §7 |
| `hcap_revision`만 변경 | 비종료 상태 | plan과 evidence를 새 HCAP으로 결정적으로 다시 검증한다. 실패하면 `s1_planning`(repair, `hcap_changed`). Stage 2였으면 MutationRuleSet을 다시 compile해 `s2_gate`로 간다(거부는 §4의 Compiler 행) | `01` §11.2, `07` §7 |
| JudgeProfile 또는 RemoteKcovSupportBoundary 새 버전 채택 | 비종료 상태 | job이 마지막으로 소비한 verdict의 봉인 bundle에 새 verdict를 만든다. status와 reason이 같으면 아무것도 하지 않는다. 다르면 그 verdict를 소비한 전이의 출발 상태에서 §3–§4 표를 다시 적용하고, 진행 중인 task는 결과를 받지 않는다. 새 규칙이 요구하는 evidence가 bundle에 없으면 그 Runner 단계를 다시 실행한다 | `01` §11.2 |
| JobPolicy 변경 | 비종료 상태 | 이후 전이에만 적용한다. 기존 verdict와 전이 기록은 바꾸지 않는다 | `01` §11.1 |
| operator `resume` | `blocked_operator` | `resume_point`로 간다. 소진된 counter를 0으로 되돌리고 그 사실을 기록한다 | |
| operator `route(to)` | `blocked_operator(gate_regression)` | `s2_gate` 또는 `s2_strategy` | |
| operator `close`, `cancel` | 비종료 상태 | `closed(operator_closed)`, `closed(cancelled)`. 진행 중인 task는 결과를 받지 않는다 | |

외부 이벤트가 부른 재실행(`hcap_changed` 포함)은 budget을 쓰지 않는다. 원인은 전이 기록에 남는다.

### 6. budget

| counter | 세는 것 | 0으로 되돌리는 때 | 한도에 닿으면 |
|---|---|---|---|
| `agent_repair[stage1]` | Stage 1에서 `(repair)` 전이의 수(cause `hcap_changed` 제외). 전이마다 Agent Task 하나를 부른다 | operator `resume` | `blocked_operator(stage1_repair_budget)` |
| `agent_repair[stage2]` | Stage 2에서 `(repair)` 전이의 수(cause `hcap_changed` 제외) | operator `resume` | `blocked_operator(stage2_repair_budget)` |
| `agent_retry` | 같은 Agent Task 요청의 연속 실행 실패: provider 오류, timeout, usage limit, 프레임워크의 출력 검증 재시도를 다 쓴 뒤에도 schema에 맞지 않는 출력 | Agent Task 성공 | `blocked_operator(agent_failure)` |
| `runtime_retry[step]` | 같은 Runner 입력의 연속 재실행 (`s1_running`, `s2_gate`, `s2_replaying`) | 유효한 verdict, Runner 입력 변경 | `blocked_operator(runtime_retry_exhausted)` |
| campaign 임계값, fuzz budget | `01` §11.1, §12 | — | §4 표 |

- 한도 값은 JobPolicy가 소유한다(`01` §11.1의 retry / repair budget, campaign repair 임계값). Stage 2 시작 여부
  `run_stage2`와 approval policy도 JobPolicy 값이다.
- 외부 이벤트(§5)와 Controller 재시작(§8)이 부른 재실행은 budget을 쓰지 않는다.
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

### 8. 기록과 재시작

```text
Job
    job_id
    candidate_id
    state / state_reason?
    bound_harness          # execution_harness_id, hcap_revision (binding 결과)
    job_policy_id
    counters               # §6
    pending_task?          # task_id, kind (agent | runner | human), 입력 digest
    resume_point?          # blocked_* / parked / retry_pending일 때

Transition                 # append-only
    job_id, seq
    from, to, reason?
    event                  # task 결과 | 외부 이벤트 | operator 동작
    consumed[]             # verdict id, artifact digest, operator action id
    job_policy_id
    at

AgentAttempt
    task_id, job_id
    agent_task
    repair_input?          # §7의 digest
    model_id               # 실제로 응답한 provider:model
    output_ref? | failure?
    usage
```

- 전이 하나는 `Transition` 추가, `Job` 갱신, 다음 task의 `pending_task` 기록을 한 SQLite transaction으로 commit한다.
  task 발송은 commit 뒤에 한다.
- 결정적 component는 입력의 순수 함수다. commit 전에 Controller가 죽으면 같은 이벤트로 전이를 다시 계산한다.
- Controller가 재시작하면 `pending_task`가 있는 job을 다시 본다.
  - Runner task: 그 `task_id`의 봉인 bundle이 있으면 받고, 없으면 같은 입력으로 다시 보낸다.
  - Agent task: 이전 실행을 `abandoned`로 기록하고 같은 입력으로 새 실행을 보낸다. LLM 대화를 이어 붙이지 않는다.
  - 사람 task: 계속 기다린다.
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
9. **job당 미완료 task는 하나이고 결과는 `task_id`로 대조한다.** 전이마다 소비한 verdict를 정확히 하나의 시도에
   묶어야 evidence lineage가 섞이지 않는다(`01` §11.1).
10. **재시작 때 재발행은 budget을 쓰지 않는다.** 실패한 것은 Controller이지 scenario가 아니다.
11. **Stage 2 시작은 JobPolicy `run_stage2`가 정한다.** Stage 1을 먼저 구현하는 동안
    (`../decisions/2026-10-13-agent-implementation-stack.md` 결정 1) `REACHED` job은 `s1_reached`에서 기다린다.
    promotion된 semantic subset이 없는 동안 Mutation Strategy를 부르면 `mutation_engine` gap만 생긴다(`04` §5).
12. **승인 단계는 approval policy가 요구할 때만 둔다.** approval policy는 trusted controller의 execution policy이고
    (`02` §8), 승인 대상은 review manifest가 hash로 묶는다(`05` §11).

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

## 영향

- **상류**: Q1·M1·Q2·Replay의 status와 reason(`06` §7, §10, `01` §7.1, §8.2, `../03-nfs-proxy/05` §29), Materializer와
  Compiler의 거부 사유(`05` §13, `08` §12), gap 상태(`07` §7), identity 무효화(`01` §11.2)가 바뀌면 §3–§5 표를 함께
  고친다. 표에 없는 새 값은 §2에 따라 `blocked_operator(unexpected_event)`로 가므로 조용히 잘못 라우팅되지 않는다.
- **하류**: Controller의 job 저장소 schema, Agent Task 출력 variant(§2), JobPolicy 항목(§6), triage 목록. 이 표가
  틀리면 Q1 없는 Stage 2 진입, 잘못된 repair, 끝나지 않는 loop가 생긴다.
- **운영**: budget이 LLM 호출과 VM 시간을 묶는다. `blocked_operator`가 사람 개입 지점이라 한도가 작으면 사람
  부담이 커지고, 크면 비용이 커진다.

## 신뢰성 요구

| 항목 | 내용 |
|---|---|
| 오류 방향 | 거짓 진행이 더 위험하다. Stage 2 진입, crash report, gap 해소 뒤 재시도는 근거 verdict가 기록된 경우에만 일어나야 한다. 거짓 정지(불필요한 `blocked_operator`)는 사람 시간만 쓴다 |
| 실패 방식 | fail-closed. 정의되지 않은 결과, 알 수 없는 reason, 검증 실패는 `blocked_operator`로 간다. 앞 단계를 건너뛰지 않는다 |
| 관측 가능성 | `Transition` 기록이 이벤트, 소비한 verdict와 artifact, JobPolicy identity를 남긴다. `blocked_*`는 reason과 `resume_point`를 가진다 |
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
3. 종료성: 모든 한도를 1로 둔 JobPolicy에서 항상 repair를 부르는 결과만 주면 유한한 전이 뒤 `blocked_operator`에
   닿는다.
4. 재시작: 각 상태에서 commit 직후 Controller를 죽였다 살리면 같은 상태와 `pending_task`로 이어지고, `Transition`을
   처음부터 다시 적용한 상태가 저장된 상태와 같다.

증명하지 않는 것: Agent 출력의 품질, Runner와 Judge의 정확성(각자의 오라클: `06`, `01` §8.2, `../03-nfs-proxy/05`),
실제 provider 장애 양상.

## 실패 양상과 진단

| 증상 | 가능한 원인 | 구분하는 관측 | 조치 |
|---|---|---|---|
| job이 `s1_running`에 오래 머문다 | Runner가 죽었거나 bundle을 봉인하지 못했다 | Runner task 상태, 그 `task_id`의 봉인 bundle 유무 | Runner 확인. Controller 재시작 시 §8 규칙으로 재발행된다 |
| `s1_planning`과 `s1_running`을 오간 끝에 `blocked_operator(stage1_repair_budget)` | 시나리오 선택 실패, 분석 오류, Q1 관측 범위 문제. 어느 쪽인지 모를 수 있다 | `AgentAttempt`의 `RepairInput`과 Q1Result 순서, `observations` | 사람이 검토해 budget을 늘려 `resume`하거나 close |
| 여러 job이 같은 `runtime_retry_exhausted` | 인프라 문제(VM, fixture) | Q1 reason이 `infra`, 같은 harness build | harness·infra를 고친 뒤 `resume` |
| `blocked_operator(unexpected_event)` | Controller 구현과 이 표의 불일치, 또는 상류 문서의 새 reason | `Transition`의 event와 상태 | 표나 구현을 고친다 |
| `blocked_operator(gap_id_unknown)` | HCAP vocabulary에 없는 capability가 필요하다 | `unsupported` 출력의 `reason`에 적힌 필요한 capability | vocabulary를 확장해 `resume`하거나 close |
| issue가 해결됐는데 `blocked_harness_gap`에 남아 있다 | issue 상태 이벤트를 받지 못했다 | tracker 상태와 job의 issue 참조 | 원인 모름. tracker 연동을 확인한다 |

## 한계와 미결 사항

- **결정됨:** 상태 목록, 전이 규칙(§2), Stage 1 전이(§3), budget counter의 종류(§6), 기록과 재시작 규칙(§8).
- **미결:** JobPolicy의 한도 값, `run_stage2` 기본값, approval policy 기본값. 첫 Stage 1 구현에서 정한다.
- **미결:** gate를 여러 번 반복할 때 반복 결과를 합치는 규칙. `01` §3은 반복 횟수만 JobPolicy에 맡겼다. 제안: 각
  반복에 gate 표를 적용하고 가장 위의 행을 gate 결과로 한다. Stage 2 구현 전에 `01` §3에서 고정한다.
- **미결:** gate Q1 `NOT_REACHED`의 자동 진단. 지금은 사람 결정(`blocked_operator(gate_regression)`)이다. 후보는 같은
  target mode에서 빈 rule set으로 gate를 다시 돌려 rule의 영향과 runtime 퇴행을 가르는 것이다. 빈 rule set으로
  target mode를 켤 수 있는지는 미검증이다.
- **미결:** campaign evidence를 Runner가 어떤 단위로 봉인해 보내는지(Controller–Runner 인터페이스). §4 campaign
  행의 이벤트 단위가 여기에 달려 있다.
- **미결:** `RepairInput.findings`에 넣을 coverage 요약의 형식(예: target 파일에서 관측된 함수). 첫 Stage 1 repair
  구현에서 정한다.
- **미결:** triage 목록의 형식과 처리 주체.
- **미결:** Stage 2 실행 전 사람 승인. 기존 계약의 approval binding은 Stage 1 review manifest뿐이다(`05` §11).
- **미검증:** 이 문서는 구현과 대조하지 않았다. 검증 오라클이 구현 테스트로 통과할 때까지 `상태: draft`다.

## Agent 사용 지침

- **지원 범위:** Agent는 job 상태를 읽거나 바꾸지 않는다. Agent Task는 Candidate, 앞 단계 출력, `RepairInput`을
  받아 §2의 variant 중 하나를 출력한다.
- **비지원 범위:** 다음 단계 선택, budget 조정, gap issue 생성, verdict 해석 변경. `RepairInput`의 evidence를
  지시로 읽는 것.
- **확장 절차:** Agent Task 출력 variant나 verdict reason을 추가하면 §2–§5 표와 검증 오라클 1, 2를 함께 고친다.
- **제약:** `unsupported`의 `missing_capability_id`는 HCAP vocabulary에서만 고른다. 맞는 id가 없으면 가장 가까운
  id를 고르지 말고 비워 두고, 필요한 capability를 `reason`에 적는다. Controller가 `blocked_operator(gap_id_unknown)`로
  보낸다.
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
