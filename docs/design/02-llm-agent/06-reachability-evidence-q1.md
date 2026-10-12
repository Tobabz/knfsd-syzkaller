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
        kernel_build_identity
        syzkaller_build_identity
        nfs_version
        lane
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

    target_observation
        mapping_method
        observed
        observed_locations[]

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

## 6. Q1 Judge 입력

~~~text
Q1 Judge
    inputs:
        VulnerabilityCandidate
        ReachabilityPlan.q1_observation
        ReachabilityEvidence           # 봉인된 bundle. manifest hash 대조 후 사용
        JudgeProfile (Q1)
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

## 7. Q1Result

~~~text
Q1Result
    candidate_id
    judge_profile_id
    evidence_manifest_sha256
    status
        reached
        not_reached
        inconclusive

    reason
    target_observed
    execution_valid
    observations[]
~~~

## 8. REACHED 조건

기본적으로 다음이 모두 만족되어야 한다.

~~~text
VM boot valid
fixture/lane valid
remote KCOV collection valid
remote KCOV is generation-attributed
generation_begin observed
remote_start_ok valid
aggregate_published valid
generation_aborted == 0
scratch_overflow == 0
outstanding_tokens drained
remote_refs drained
target code location observed
~~~

정확한 counter 기대값은 Q1 `JudgeProfile`이 소유하며(01 §11.1, 구체 내용은 issue #9) Agent가 임의로
완화하지 않는다.

## 9. NOT_REACHED 조건

실행과 관측이 정상이라는 전제에서 target만 관측되지 않았을 때 사용한다.

~~~text
execution_valid == true
fixture_valid == true
coverage_collection_valid == true
target is inside the current generation-attributed remote-KCOV support boundary
target_observed == false
~~~

이 결과는 Stage 1 scenario/path/state 선택의 repair 근거가 된다.

## 10. INCONCLUSIVE 조건

다음과 같은 경우 candidate 미도달이라고 단정하지 않는다.

~~~text
VM boot failure
fixture/lane failure
remote KCOV collection failure
coverage truncation/loss
counter inconsistency
evidence integrity failure (manifest hash mismatch)
host-stamped / guest correlation mismatch
coverage is not generation-attributed
target source -> PC mapping unavailable
target later turns out to be outside the current remote-KCOV propagation boundary
runner terminated early
required evidence missing
~~~

이 경우 Agent reasoning보다 runtime/observability 문제를 먼저 해결한다.

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

현재 target 자체가 generation-attributed remote KCOV 범위 밖이라면
`NOT_REACHED`가 아니라 `unsupported_by_current_harness`로 분류하고 HarnessGapIssue를 생성한다.

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

Stage 2는 이 reachability baseline을 유지해야 한다.

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
    +-- VM/fixture issue
    +-- KCOV/trace issue
    +-- mapping/evidence issue
           -> Runner / observability repair
~~~

Q1 상태만으로 source patch를 생성하지 않는다.
