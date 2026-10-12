# ReachabilityEvidence / Q1 Judge Contract

> 상태: current detailed design
> 상위 설계: `01-two-stage-agent-architecture.md`
> 입력: `ReachabilityPlan` + `ReachabilityHarness` runtime execution
> 목적: Stage 1 실행 결과를 구조화하고 candidate 도달 여부(Q1)를 판정한다.

## 1. 요소의 종류

~~~text
ReachabilityEvidence
    Type:        DATA
    Produced by: isolated Runner (EvidenceManifest로 봉인)

Q1 Judge
    Type:        COMPONENT
    Executed by: Application / validation layer (Controller 측)

Q1Result
    Type:        DATA
    Produced by: Q1 Judge
~~~

Q1 Judge는 Agent Task가 아니다. Judge 실행 위치와 evidence 신뢰 경계는
`01-two-stage-agent-architecture.md` §11.1이 소유한다(issue #11).

## 2. Stage 1의 마지막 구간

~~~text
ReachabilityPlan
      |
      v
ReachabilityHarness
      |
      v
[RUNNER TASK]
VM / fixture / scenario / KCOV
      |
      v
[DATA] ReachabilityEvidence
      |
      v
[COMPONENT] Q1 Judge
      |
      v
[DATA] Q1Result
      |
      +-- REACHED ------> Stage 2
      |
      +-- NOT_REACHED --> Reachability repair
      |
      +-- INCONCLUSIVE -> runtime/observability repair
                          unsupported_attribution이면 HarnessGapSignal (§13)
~~~

## 3. 왜 boolean이 아닌가

`false` 하나로는 다음 두 상황을 구분할 수 없다.

~~~text
A. scenario는 정상 실행됐지만 target에 실제로 도달하지 못함

B. VM/fixture/KCOV/trace 관측이 깨져 도달 여부를 알 수 없음
~~~

B를 `not_reached`로 처리하면 Agent가 잘못된 scenario repair를 시작할 수 있다.

따라서 Q1 상태는 `REACHED`, `NOT_REACHED`, `INCONCLUSIVE` 세 가지다.

## 4. ReachabilityEvidence

최소 구조:

~~~text
ReachabilityEvidence
    candidate_id

    execution
        execution_harness_identity # host-stamped (01 §11.2)
        nfs_version
        lane
        lane_trace_mode            # identity의 koov.nfs_trace (HCAP-03)
        scenario_artifact

    fixture
        boot_ok
        fixture_ok
        lane_ok

    remote_kcov
        collection_started
        collection_completed
        coverage_artifacts
        generation_attributed

    sunrpc_fuzz
        generation_begin
        remote_start_ok
        aggregate_published
        generation_aborted
        scratch_overflow
        outstanding_tokens
        remote_refs
        counter_deltas{}           # profile이 정한 context별 counter의 window delta (§6.1)

    target_observation
        mapping_method
        observed
        observed_locations[]

    ambient_control                # non-oracle evidence (§11, issue #10)
        control_evidence_ref       # neutral run의 봉인 evidence
        control_window
        target_ambient_observed    # true | false

    runtime_errors[]
~~~

## 5. target_observation

Candidate는 source location이고 KCOV는 runtime PC를 수집하므로 build별 mapping이 필요하다.

~~~text
candidate source location
        |
        v
kernel build / vmlinux
        |
        v
runtime PC mapping
        |
        v
remote KCOV observed PCs
        |
        v
target_observation
~~~

function candidate는 path + symbol + resolved source range에 대응하는 code location이 관측되어야 한다.
source-range candidate는 관측 PC가 build debug mapping을 통해 requested source range에 대응해야 한다.

mapping은 evidence의 ExecutionHarnessIdentity가 가리키는 vmlinux와 KASLR 설정으로 한다. plan은 build를
pin하지 않으므로 같은 plan을 다른 identity에서 다시 실행해도 mapping은 그 실행의 build로 다시 만든다
(01 §11.2).

## 6. Q1 Judge 입력

~~~text
Q1 Judge
    inputs:
        VulnerabilityCandidate
        ReachabilityPlan.q1_observation   # target, expected_context
        ReachabilityEvidence           # 봉인된 bundle. manifest hash 대조 후 사용
        JudgeProfile (Q1)              # Q1AdmissibilityProfile (§6.1)
        RemoteKcovSupportBoundary      # §6.1
~~~

Judge는 Agent의 자유 텍스트가 아니라 plan의 구조화된 observation requirement를 사용한다.

Q1의 target hit/miss 판정에 사용할 수 있는 observation channel은 하나뿐이다.

~~~text
allowed:
    generation-attributed remote KCOV coverage

not allowed:
    KCOV_NFSD_OBSERVE global stream
    local task KCOV
    tracepoint
    kprobe
    flow-trace verdict
    dmesg presence
    functional side effect
~~~

debugfs counter와 fixture 상태는 Q1의 positive evidence가 아니다.
remote KCOV 실행이 판정 가능한 상태였는지를 확인하는 health/admissibility gate다.

### 6.1 support boundary와 admissibility profile

`NOT_REACHED`를 판정 가능하게 하는 두 artifact를 둔다(issue #9).

~~~text
RemoteKcovSupportBoundary            # 버전이 있는 Repository Design Data
    checked-in attribution patch가 program generation에 귀속하는 execution context
    알려진 비귀속 context
    attribution kernel patch를 바꾸는 commit에서 함께 갱신한다

Q1AdmissibilityProfile               # Q1 JudgeProfile (01 §11.1)
    generation integrity 요구
    context별 loss / rejection counter, delta window, 허용 기준
    정상 동작에서 움직이는 counter
    trace mode / evidence 요구
~~~

첫 버전의 boundary는 kernel patch 0002–0004와 `docs/design/decisions/2026-10-05-callback-attribution.md`를
근거로 한다.

~~~text
귀속 context
    request        lane server netns의 request 처리 (0002)
    async_copy     async COPY continuation (0003)
    callback_v41   NFSv4.1 server callback (0004). D6 제외: bc_close, bc_destroy, CB_NULL

비귀속 context
    transport accept / pre-dispatch
    ownerless background work
    client-side code
    NFSv4.0 callback
~~~

- Judge는 PC에서 context를 추론하지 않는다. context는 plan의 `expected_context`(05 §9)가 주장한다.
- boundary 버전은 evidence의 kernel build에 들어간 attribution patch와 맞아야 한다. 맞지 않으면
  `INCONCLUSIVE(evidence)`다.
- profile의 counter 예: request는 window 안의 `lane_owner_failed`, async는 `async_child_rejected`,
  `deferred_child_rejected`, `child_token_rejected`, callback은 `cb_section_owner_none`,
  `cb_section_lane_unhealthy`, `cb_section_epoch_mismatch`, 모든 귀속 context는 `new_root_rejected_*`,
  `remote_grant_rejected_*`다. program 사이의 `lane_owner_no_generation`과 FINISH 뒤 `close_fds()`가 만드는
  `lane_owner_failed`는 정상 동작으로 표시한다.
- delta window는 context별로 profile이 정하며, FINISH 뒤에 거부되는 late section(예: callback)을 포함해야
  한다.
- HCAP-03이 두 artifact를 `authority_refs`로 digest 참조한다(04 §1.1, issue #14). 두 artifact의
  serialization도 HCAP과 같은 규칙(schema와 canonical digest)을 따른다.

## 7. Q1Result

~~~text
Q1Result
    candidate_id
    execution_harness_id           # 봉인 evidence의 identity digest (01 §11.2)
    judge_profile_id
    evidence_manifest_sha256
    support_boundary_id            # 사용한 RemoteKcovSupportBoundary 버전
    status
        reached
        not_reached
        inconclusive

    reason                         # inconclusive이면 §10의 reason 하나
    gap_signal?                    # reason이 unsupported_attribution일 때
        gap_class                  # remote_kcov_attribution
        missing_capability_id      # remote_kcov.context.<expected_context>
    target_observed
    execution_valid
    observations[]
~~~

status는 세 값만 둔다. attribution 지원 여부는 reachability의 네 번째 값이 아니라 `INCONCLUSIVE`의 reason과
gap signal로 표현한다(issue #9).

## 8. REACHED 조건

§8–§10의 판정 순서는 다음과 같다(issue #9).

~~~text
1. 봉인 evidence / generation correlation이 유효하지 않거나 현재 generation의 aggregate가 없음
       -> INCONCLUSIVE(infra | evidence | loss)
2. target source -> PC mapping 불가
       -> INCONCLUSIVE(mapping)
3. published coverage에 target PC가 있음
       -> REACHED
4. target PC가 없음
   a. expected_context가 RemoteKcovSupportBoundary 밖
       -> INCONCLUSIVE(unsupported_attribution) + HarnessGapSignal
   b. 그 context의 loss / rejection delta가 profile 허용 범위 밖
       -> INCONCLUSIVE(loss)
   c. 그 밖
       -> NOT_REACHED
~~~

REACHED는 다음이 모두 만족될 때다.

~~~text
VM boot valid
fixture/lane valid
remote KCOV collection valid
remote KCOV is generation-attributed (correlation이 host-stamped 값과 일치)
generation_begin observed
remote_start_ok valid
current generation의 aggregate가 publish되어 수집됨
target code location observed
~~~

kernel은 generation이 committed, drained, not aborted이고 `remote_result`가 VALID일 때만 aggregate를
publish한다(patch 0001). scratch overflow와 merge truncation은 generation을 incomplete로 만들어 publish를
막는다. 따라서 `generation_aborted == 0`, `scratch_overflow == 0`, outstanding token과 remote ref drain은
publish의 전제이며, 이 counter들은 publish되지 않은 이유를 진단하는 데 쓴다.

loss는 PC를 지울 뿐 만들지 않는다. 그러므로 유효하게 publish된 coverage에서 target이 관측되면 loss
counter와 `expected_context`에 관계없이 REACHED다. 계획과 다른 attributed execution에서 실행됐어도
같다(§11).

정확한 counter 기대값은 Q1AdmissibilityProfile(§6.1)이 소유하며 Agent가 임의로 완화하지 않는다.

## 9. NOT_REACHED 조건

실행과 관측이 정상이고, target이 없다는 사실을 loss로 설명할 수 없을 때만 사용한다.

~~~text
REACHED의 유효성 조건(target 관측 제외)이 모두 성립
target source -> PC mapping 유효
target_observed == false
q1_observation.expected_context가 RemoteKcovSupportBoundary 안
Q1AdmissibilityProfile이 그 context에 지정한 loss / rejection counter의 window delta가 허용 범위 안
~~~

debugfs counter는 lane별이 아니라 전역이다. 다른 lane의 delta가 섞이면 NOT_REACHED를 막는 쪽으로만
작용하므로 판정은 보수적으로 남는다. 그래도 Q1 판정 run(Stage 1, baseline-with-rules gate)은 한 lane만
program을 실행해 이 오차를 줄인다.

이 결과는 Stage 1 scenario/path/state 선택의 repair 근거가 된다. baseline-with-rules gate의 NOT_REACHED도
같은 조건을 따른다(01 §3).

## 10. INCONCLUSIVE 조건

다음과 같은 경우 candidate 미도달이라고 단정하지 않는다. reason은 하나를 기록한다.

~~~text
infra                     VM boot / fixture / lane 실패, runner 조기 종료,
                          generation abort / drain timeout으로 aggregate 미publish
evidence                  필요한 evidence 없음, coverage가 generation-attributed가 아님,
                          manifest hash / correlation / counter 불일치 (01 §11.1),
                          support boundary 버전이 kernel build와 맞지 않음
loss                      scratch overflow, merge truncation 등으로 aggregate 미publish,
                          또는 target 미관측이고 expected_context의 loss / rejection delta가 허용 범위 밖
mapping                   target source -> PC mapping 불가
unsupported_attribution   target 미관측이고 expected_context가 support boundary 밖
~~~

`unsupported_attribution`은 HarnessGapSignal로, 나머지는 Agent reasoning보다 runtime/observability 문제를
먼저 해결하는 쪽으로 보낸다(§13).

## 11. Remote KCOV 밖의 관측

flow trace, tracepoint, kprobe 같은 도구는 path 분석과 디버깅에는 사용할 수 있지만 Q1 oracle은 아니다.

~~~text
Q1
    = candidate target PC가
      현재 program generation에 귀속된
      remote KCOV coverage에 존재하는가?
~~~

필요한 ordering/handoff를 remote KCOV로 증명할 수 없더라도 Q1 정의를 확장하지 않는다.
그 정보는 별도 diagnostic/analysis concern으로 남긴다.

target이 관측되지 않았고 plan의 `expected_context`가 RemoteKcovSupportBoundary 밖이면 `NOT_REACHED`가
아니라 `INCONCLUSIVE(unsupported_attribution)`이며, Judge는 HarnessGapSignal을 낸다(§13).

### automatic / background execution

Q1은 candidate code location의 **도달 여부**를 판정한다.
따라서 현재 program generation에 정당하게 귀속된 remote KCOV라면
target이 직접 syscall/RPC 처리에서 실행됐는지, 자동 kernel work에서 실행됐는지를 구분하지 않는다.

~~~text
direct path:
    syscall / RPC
        -> target

automatic path:
    scenario establishes state
        -> timer / workqueue / callback / lease renewal
        -> target

both:
    target PC in generation-attributed remote KCOV
        -> Q1 REACHED
~~~

예를 들어 NFSv4 lease renewal, delayed work, callback, asynchronous COPY처럼
scenario가 만든 상태에서 이어지는 자동 실행은 유효한 reachability path다.

Q1은 특정 syscall/RPC가 target의 직접 원인이었다는 causal claim을 하지 않는다.
그 경로에 대한 설명은 CandidateAnalysis와 ReachabilityPlan이 소유한다.

같은 lane의 다른 자동 traffic이 target을 실행하더라도 Q1 정의상 target은 reached다.
원인 구분이 후속 분석에 필요하면 matched control이나 추가 diagnostic을 사용할 수 있지만,
그 결과를 Q1 reached/not_reached 조건으로 사용하지 않는다.

### ambient control

Q1 정의는 그대로 두고, Stage 2로 넘길 harness는 matched neutral control을 함께 실행한다(issue #10).

~~~text
neutral program
    lane만 열고 scenario NFS operation은 실행하지 않는다

같게 맞추는 조건
    execution / harness identity, fixture mode, NFS version, route / topology,
    lease 설정, trace mode, 비교 가능한 관측 window
~~~

결과는 비대칭으로 해석한다.

~~~text
target_ambient_observed = true
    scenario 없이도 target이 실행될 수 있다.
    Q1 REACHED를 scenario 경로가 유지됐다는 근거로 쓰지 않는다.

target_ambient_observed = false
    이 control window에서 관측되지 않았다는 뜻일 뿐이다.
    ambient 실행이 불가능하다거나 scenario가 Q1을 일으켰다는 증명이 아니다.
~~~

ambient control은 oracle이 아니며 Q1, M1, Q2를 바꾸지 않는다. Stage 2에서의 해석은 01 §3이 정한다.

## 12. Stage 2 handoff

Stage 2로 넘길 수 있는 것은 `Q1Result.status == reached`인 경우뿐이다.

~~~text
Q1Result(REACHED)
      |
      +-- ReachabilityPlan
      +-- ReachabilityHarness
      +-- ReachabilityEvidence
      |
      v
Stage 2 Mutation Strategy
~~~

Stage 2는 이 reachability baseline을 유지해야 한다. `target_ambient_observed`이면 baseline 유지 여부를
Q1만으로 확인할 수 없다(01 §3).

## 13. repair routing

~~~text
Q1 = NOT_REACHED
    |
    +-- wrong path/state hypothesis
    |      -> Candidate Analysis / Reachability Planning
    |
    +-- scenario choice insufficient
           -> Reachability Planning

Q1 = INCONCLUSIVE
    |
    +-- infra / loss / evidence / mapping
    |      -> Runner / observability repair
    |
    +-- unsupported_attribution
           -> HarnessGapSignal
           -> Controller가 HarnessGapIssue(remote_kcov_attribution)를 생성하거나 연결 (07 §2)
~~~

Q1 상태만으로 source patch를 생성하지 않는다.
