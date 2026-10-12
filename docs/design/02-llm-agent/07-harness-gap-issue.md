# Harness Gap Issue Contract

> 상태: current detailed design
> 상위 설계: `01-two-stage-agent-architecture.md`
> 목적: `unsupported_by_current_harness`를 일회성 실패가 아니라 재사용 가능한 harness 개선 이슈로 관리한다.

## 1. 이 요소는 무엇인가

```text
HarnessGapIssue
    Type:        DATA / WORK ITEM
    Created by:  Application Controller
    Managed in:  issue tracker
    Blocks:      candidate Stage 1 or Stage 2
```

현재 repository는 GitHub를 사용하므로 초기 구현의 issue tracker는 GitHub Issues가 자연스럽다.
Controller 내부 계약은 특정 tracker API에 종속되지 않도록 둔다.

## 2. 생성 조건

다음 상황에서 issue를 생성하거나 기존 open issue에 연결한다.

```text
CandidateAnalysis / Reachability Planning / Mutation Strategy
        |
        v
required capability not present
        |
        v
unsupported_by_current_harness
        |
        v
create or link HarnessGapIssue

Q1 Judge
        |
        v
INCONCLUSIVE(unsupported_attribution) + HarnessGapSignal (06 §7)
        |
        v
create or link HarnessGapIssue(remote_kcov_attribution)

Controller harness binding (01 §11.2)
        |
        v
candidate.kernel_commit용 검증된 harness build 없음
        |
        v
create or link HarnessGapIssue(remote_kcov_attribution,
                               remote_kcov.kernel_revision.<commit>)
```

Agent Task와 Q1 Judge는 gap을 알릴 뿐이며 issue 생성과 연결은 Controller가 한다(§1).

같은 gap(§3의 key)이 이미 open 상태라면 새 issue를 만들지 않고 기존 issue에 candidate를 연결한다.

## 3. Issue 데이터

```text
HarnessGapIssue
    issue_id
    tracker_ref

    blocked_candidates[]

    stage
        stage1_reachability
        stage2_mutation

    gap_class

    missing_capability_id      # HCAP data의 controlled vocabulary (04 §1.1)

    reason

    required_behavior

    proposed_extension

    validation_required[]

    status
        open
        in_progress
        resolved
        deferred
        wont_fix

    resolution?                # status=resolved일 때
        resolution_class       # §8
        hcap_revision          # gap을 닫은 HCAP revision
        execution_harness_id?  # harness build가 바뀌었으면 (01 §11.2)
```

같은 gap의 key는 `(gap_class, missing_capability_id)`다(issue #13). `missing_capability_id`는 자유 텍스트가
아니라 HCAP data의 controlled vocabulary이며, 서로 다른 작업을 구분하는 데 필요한 revision이나 scope를 담는다.
예를 들어 kernel revision마다 harness가 따로 필요하므로 `remote_kcov.kernel_revision.<commit>`은 commit을
포함한다.

## 4. gap_class

```text
syzlang
pseudo_syscall_executor
fixture_or_tool
mutation_engine
remote_kcov_attribution
```

기존 capability로 표현되는 새 sequence나 seed는 gap이 아니다. Agent가 job-local program으로 쓰고
Materializer가 검증한다(`05` §11, issue #12). 성공한 program을 `bundle/corpus`로 올리는 것은 선택적인
유지보수이며 candidate를 막지 않는다. plan의 runtime allowlist(`05` §10) 밖의 환경 동작은
`fixture_or_tool`, syscall/RPC/XDR 표현이 없으면 `syzlang` 또는 `pseudo_syscall_executor`다.

### syzlang

필요한 syscall/RPC operation/XDR shape를 현재 description으로 안정적으로 표현할 수 없는 경우.

### pseudo_syscall_executor

일반 syscall/syzlang만으로 불가능한 executor-side 환경 primitive가 필요한 경우.

예:

```text
lane resource acquisition
special namespace-bound connection
fixture control lifetime
response-derived executor state handling
```

### fixture_or_tool

daemon, topology, timing, namespace, mount mode 등 runtime environment가 부족한 경우.

### mutation_engine

현재 Proxy capability로 필요한 semantic selector, runtime field resolution, mutation 또는 replay 의미를 표현할 수 없는 경우.

예: 이전 transaction의 state를 참조하는 intent는 missing capability `state_lineage`다(issue #6).
capability id의 machine-readable 표현은 HCAP data가 소유한다(04 §1.1).

### remote_kcov_attribution

candidate를 실행할 수는 있지만 현재 program generation에 귀속되는 remote KCOV로
target PC를 관측할 수 없는 경우. candidate의 kernel revision용으로 계측을 옮기고 검증한 harness build가
없는 경우도 이 class다(01 §11.2). 이때 id `remote_kcov.kernel_revision.<commit>`은 그 revision용으로 검증된,
attribution이 가능한 kernel harness가 없다는 것만 뜻한다. binding이 성공한 뒤 발견되는 syzlang, fixture,
mutation capability 부족은 각자의 gap class로 간다(issue #13).

예:

```text
pre-dispatch path가 global NFSD observer에만 보임
ownerless/background work
새 async continuation path
현재 propagation이 없는 callback/workqueue path
client-side target without remote attribution
candidate.kernel_commit용 harness build 없음 (remote_kcov.kernel_revision.<commit>)
```

귀속 여부의 기준은 RemoteKcovSupportBoundary(06 §6.1)다. Q1 Judge는 target이 관측되지 않았고 plan의
`expected_context`가 boundary 밖일 때 이 class의 HarnessGapSignal을 낸다.

지원이 필요하면 remote-KCOV attribution을 확장하는 kernel harness patch가 필요할 수 있다.
이 patch는 vulnerability fix가 아니며 explicit human approval을 요구한다.

## 5. Harness Extension Work

issue가 생성되면 candidate job 안에서 즉시 source를 바꾸지 않는다.

```text
Candidate
   |
   v
unsupported_by_current_harness
   |
   v
HarnessGapIssue
   |
   v
separate Harness Extension Work
   |
   +-- syzlang
   +-- pseudo-syscall/executor
   +-- fixture/tool
   +-- mutation engine
   +-- reusable seed/scenario
   |
   v
validation
   |
   v
Harness Capability Specification update
   |
   v
blocked Candidate retry
```

이렇게 하면 한 candidate를 위해 만든 capability가 이후 candidate에서도 재사용된다.

## 6. Patch 종류의 구분

### Harness-extension patch — pre-crash 가능

```text
syzkaller syzlang description
pseudo-syscall / executor
pkg/vminfo coordination
fixture scripts
host/guest tools
proxy / mutation engine
flow-trace tooling
remote-KCOV attribution kernel instrumentation (human-approved)
```

이 patch는 취약점 수정이 아니라 fuzz harness 기능 확장이다.

### Linux kernel remote-KCOV attribution patch — pre-crash human-approved

Q1 remote KCOV 범위를 넓히기 위해 Linux kernel source를 추가 변경해야 한다면 자동으로 수행하지 않는다.

```text
remote_kcov_attribution issue
        |
        v
human decision
```

현재 checked-in kernel patch 0001~0004도 이 종류의 harness instrumentation precedent다.
다만 target kernel code를 바꾸면 reachability와 timing 자체를 교란할 수 있으므로 human review가 필요하다.
계측 series를 다른 kernel revision으로 옮기는 일도 같은 검토를 거친다(01 §11.2).

### Vulnerability-fix kernel patch — post-crash only

```text
Q1 reached
M1 applied
Q2 crash observed
        |
        v
Crash Report
        |
        v
root cause
        |
        v
kernel vulnerability fix patch
```

## 7. Candidate job 상태

Harness gap이 있으면 candidate job은 실패 완료가 아니라 blocked 상태로 남는다. Candidate 자체는
immutable이며 아래 상태는 job workflow의 것이다(issue #13).

```text
blocked_harness_gap
    issue_ref, gap_class, missing_capability_id
        |
        +-- issue resolved
        |       -> retry_pending
        |       -> 새 harness binding에 01 §11.2의 무효화 규칙을 적용하고 막힌 stage를 재개
        |
        +-- issue deferred
        |       -> parked
        |       -> issue가 다시 열리거나 resolved되면 다시 평가
        |
        +-- issue wont_fix
                -> closed_unsupported(reason)        # terminal
```

retry에서 ExecutionHarnessIdentity가 바뀌었으면 Stage 1 Q1을 새 identity에서 다시 세운 뒤 진행한다. build를
바꾸지 않고 promotion만 바뀐 경우(예: `mutation_engine` gap을 닫은 subset promotion)에는 identity가 같으므로
plan을 새 `hcap_revision`으로 다시 검증하고 MutationRuleSet을 다시 compile한 뒤 Stage 2를 재개한다.

## 8. 실제 patch 필요성 측정

patch 필요 비율을 사전에 숫자로 가정하지 않는다.
각 blocked candidate마다 다음 resolution class를 기록한다.

```text
existing_capability_only
syzlang_extension
pseudo_syscall_extension
fixture_or_tool_extension
mutation_engine_extension
remote_kcov_attribution_extension
```

누적 candidate 수가 쌓이면 이 값으로 실제 harness-extension 비율을 계산한다.

## 9. 현재 repo 기준 정성 예상

실제 candidate 모집단이 없으므로 퍼센트는 정하지 않는다.
현재 `knfsd-syzkaller`의 지원 범위를 기준으로 다음 정도를 예상한다.

| 유형 | 예상 빈도 | 이유 |
|---|---|---|
| 기존 capability와 job-local program만 사용 (gap 아님) | **common** | 기존 VFS/raw RPC/lane/KCOV capability 조합으로 새 state sequence를 만드는 경우가 많음 |
| syzlang extension | **rare / conditional** | 현재 NFSv3/v4 TCP와 많은 NFSv4 op shape를 이미 표현; description에 없는 op/type/resource 관계일 때 필요 |
| pseudo-syscall/executor extension | **very rare** | lane open/connect/raw send/proxy arm 같은 전용 primitive가 이미 존재; 새로운 executor-side primitive가 꼭 필요할 때만 해당 |
| fixture/tool/topology extension | **conditional; unsupported 경계에서는 common** | pNFS, GSS/TLS, UDP/RDMA, LOCALIO, NAT, lane-veth NLM 등은 환경 capability 자체가 부족 |
| mutation-engine extension | **conditional** | semantic decoder/resolver 또는 concrete mutation/replay capability가 부족할 때 |
| remote-KCOV attribution kernel extension | **rare / conditional** | 현재 request/async COPY/NFSv4.1 callback attribution 밖의 target을 Q1로 지원할 때 필요 |
| vulnerability-fix kernel patch | **Q2 이후에만** | crash report 이후 root-cause/fix phase의 작업 |

현재 지원 범위인 NFSv3/v4.0/v4.1/v4.2 TCP, mounted VFS, raw C2S RPC와
generation-attributed remote KCOV 범위 안의 candidate라면 source-level harness extension보다
job-local scenario/materialization만으로 Q1을 구성할 가능성이 높다.

반대로 현재 명시적 비지원/미결 범위에 걸리는 candidate라면 fixture/tool 또는 다른 capability 확장이
필요할 가능성이 높다.
