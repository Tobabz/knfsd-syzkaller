# Harness Gap Issue Contract

> 상태: current detailed design
> 상위 설계: `01-two-stage-agent-architecture.md`
> 목적: `unsupported_by_current_harness`를 만나면 pipeline이 필요한 harness를 생성해 job을 이어 가고(§5), 그 작업을
> 재사용 가능한 harness 개선 이슈로 기록한다. harness가 없다는 이유로 job을 멈추지 않는다.

## 1. 이 요소는 무엇인가

```text
HarnessGapIssue
    Type:        DATA / WORK ITEM
    Created by:  Application Controller
    Managed in:  issue tracker
    Triggers:    Harness Generation (§5). job은 생성된 harness로 이어 간다
    Blocks:      Harness Generation이 실패했을 때만 candidate Stage 1 or Stage 2 (§7)
```

HarnessGapIssue는 job을 세우는 장치가 아니라 기록이다. 어떤 gap을 만났고, pipeline이 무엇을 생성했고, 그것이
어떤 검증을 통과했는지를 남긴다. 같은 gap을 만난 다른 job은 이 기록으로 이미 생성된 harness를 재사용한다.

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

Agent Task와 Q1 Judge는 gap을 알릴 뿐이며 issue 생성과 연결은 Controller가 한다(§1). Controller는 issue를
만들거나 연결한 뒤 기다리지 않고 바로 Harness Generation(§5)을 시작한다.

같은 gap(§3의 key)이 이미 open 상태라면 새 issue를 만들지 않고 기존 issue에 candidate를 연결한다. 그 gap의
Harness Generation이 진행 중이면 job은 그 작업에 붙고, 이미 검증된 staged harness가 있으면 그것을 바로 쓴다(§5).

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

    generation[]               # Harness Generation 시도 기록 (§5)
        attempt
        extension_ref          # 생성한 patch set의 artifact digest
        validation_bundle_ref  # 봉인된 검증 evidence
        result                 # validated | rejected(reason) | infeasible(reason)
        staged_hcap_revision?  # validated일 때
        execution_harness_id?  # build가 바뀌었으면

    status
        open
        in_progress            # Harness Generation 진행 중
        staged                 # 생성한 harness가 검증을 통과해 job들이 쓰는 중. promotion 검토 대기
        resolved               # promotion 완료 (§5.3)
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
자연 경로가 workqueue에서 도는 경우 (예: lease 만료의 laundromat, 04 §3.2)
candidate.kernel_commit용 harness build 없음 (remote_kcov.kernel_revision.<commit>)
```

귀속 여부의 기준은 RemoteKcovSupportBoundary(06 §6.1)다. Q1 Judge는 target이 관측되지 않았고 plan의
`expected_context`가 boundary 밖일 때 이 class의 HarnessGapSignal을 낸다.

지원이 필요하면 remote-KCOV attribution을 확장하는 kernel harness patch가 필요할 수 있다.
이 patch는 vulnerability fix가 아니다. Harness Generation이 이 patch(계측 series의 kernel revision 이식 포함)를
생성하고 §5.2의 검증을 통과하면 job이 그 harness로 이어 간다. 사람 검토는 promotion(§5.3)과 crash review에서
하며, job 진행의 선행 조건이 아니다.

## 5. Harness Generation

harness gap은 job을 멈추는 사유가 아니다. Controller는 gap을 받으면 Harness Generation을 시작하고, 생성한
harness가 검증을 통과하면 job을 그 harness로 이어 간다.

```text
Candidate job
   |
   v
gap (unsupported_by_current_harness, binding 실패, unsupported_attribution, Compiler 거부 ...)
   |
   v
HarnessGapIssue 생성/연결 (기록)
   |
   v
Harness Generation  [AGENT TASK + RUNNER TASK]          job 상태: harness_generating (09 §3.2)
   |
   |  입력: GapRef, CapabilityProposal(있으면), candidate, CandidateAnalysis, 현재 HCAP
   |
   +-- syzlang
   +-- pseudo-syscall/executor
   +-- fixture/tool
   +-- mutation engine (semantic subset, Proxy, compiler lowering)
   +-- remote-KCOV attribution kernel instrumentation
   +-- 계측 series의 candidate.kernel_commit 이식 (01 §11.2)
   +-- reusable seed/scenario
   |
   v
validation (Runner, §5.2)
   |
   +-- 통과 -> staged hcap_revision (+ 새 ExecutionHarnessIdentity)
   |            -> job을 다시 binding하고 막혔던 지점(resume_point)에서 이어 간다
   |            -> promotion 검토 (§5.3, job을 막지 않음)
   |
   +-- 실패 -> 실패 evidence를 넘겨 다시 생성 (harness_generation budget, 09 §6)
   |
   +-- budget 소진 또는 생성 불가 판단
            -> blocked_harness_gap (§7)
```

이렇게 하면 한 candidate를 위해 만든 capability가 이후 candidate에서도 재사용되고, 그 capability가 없다는
이유로 candidate가 사람을 기다리지 않는다.

### 5.1 생성 범위와 격리

- Harness Generation은 Stage 1/2 Agent Task(Analysis, Planning, Mutation Strategy)와 별개의 Agent Task다.
  Stage 1/2 Agent는 지금처럼 source를 바꾸지 않고 gap을 알리기만 한다(`01` §13).
- 생성물은 patch set이다: `bundle/` 아래 syzlang, executor, fixture, host spec entry, Proxy/compiler 변경,
  kernel 계측 patch. promoted HCAP과 main branch에는 쓰지 않고 staging 영역(job과 gap key로 이름 붙인 branch나
  artifact)에만 쓴다.
- 생성 Agent는 파일과 shell 권한을 가진다(2026-10-25 사용자 결정). 설계 문서와 repository를 직접 읽고, gap
  key마다 하나인 git worktree(staging)에서 code를 고치고, build와 test를 스스로 돌려 patch set을 다듬는다.
  container나 VM은 쓰지 않는다. 지킬 것은 두 가지다.
  - 판정 근거를 쓰지 못한다. 생성 Agent는 별도 OS 사용자로 돌고, Controller state, artifact store, 다른 gap의
    worktree에 쓸 수 없다(읽기 전용이거나 접근 불가). promoted HCAP과 main branch는 읽기만 한다.
  - credential을 보지 못한다. LLM API key, GitHub token 같은 secret이 없는 환경 변수와 파일 권한으로 실행한다.
  network 권한은 주지 않는다.
- 구현은 pydantic-ai(2.55.0)의 Workspace API를 쓴다. `LocalWorkspace(worktree, env=...)` capability가 tool에
  `ctx.workspace`(파일 읽기·쓰기, 명령 실행)를 주며, 명령에는 `PATH`, `HOME`, `LANG`, `LC_*`와 넘긴 `env`만
  전달하므로 이 process의 secret 환경 변수는 새지 않는다. `LocalWorkspace`는 파일 시스템을 격리하지 않으므로
  위의 OS 사용자 권한이 그 경계다. 모델에 노출할 file·shell tool은 이 API 위에 직접 정의한다(library가 정해 둔
  tool은 없다). 사람 확인이 필요한 명령이 생기면 `ApprovalRequiredToolset`으로 묶을 수 있다.
- 생성 Agent가 worktree에서 돌린 build와 test 결과는 판정이 아니다. staged revision을 만드는 판정은 Runner가
  patch set만 받아 새 격리 VM 환경(기본 KVM)에서 다시 build하고 §5.2를 실행해 낸다. Agent worktree의 산출물(binary,
  log)은 그 판정에 쓰지 않는다.
- 생성물의 트리거는 `04` §3.2를 따른다. 클라이언트가 유도한 서버 동작은 허용하지만, 실행 중에 harness가 서버를
  직접 조작하는 행위(서버 관리 인터페이스 쓰기, 서버 데몬 정지·종료·재시작, 서버 설정 변경)를 하는 executor·helper·fixture 동작은 만들지 않는다. 자연 경로가
  귀속되지 않으면 우회하지 않고 그 context의 귀속 계측을 함께 생성한다.
- vulnerability fix patch는 생성하지 않는다(§6). target kernel code의 동작을 바꾸는 patch는 계측으로 보지 않고
  거부한다.

### 5.2 검증

생성한 harness는 다음을 Runner에서 통과해야 staged revision이 된다. 판정은 결정적이며 생성 Agent가 하지 않는다.

```text
build PASS (선택한 sanitizer variant)
bootstrap 검증 (기존 harness와 같은 기준)
proposal의 promotion_evidence (VM 실행, 기본 KVM)
새 capability를 쓰는 smoke program과 neutral control
기존 HCAP capability 회귀 (기존 seed와 lane 경로가 같은 결과)
remote_kcov_attribution이면: 알려진 target에서 attribution이 성립하고, RemoteKcovSupportBoundary가 그 계측을 기술함
mutation_engine이면: 생성한 semantic subset이 M7 promotion gate(03-nfs-proxy/06 §30)를 통과하고, 그 registry digest가
    staged revision의 HCAP-10 authority_refs에 들어감
트리거 기준 (04 §3.2): 새 capability의 실행 중 트리거가 NFS 클라이언트의 행위뿐이고 harness가 서버를 직접 조작하지 않음
```

통과하면 Controller는 staged `hcap_revision`(status `staged`, `04` §1.1)과 build가 바뀌었으면 새
ExecutionHarnessIdentity를 만든다. 이 revision은 promoted HCAP과 구분되며, 그 위에서 만든 plan, verdict,
crash report는 staged revision과 생성 patch set의 digest를 기록한다.

### 5.3 promotion

staged revision을 공유 HCAP으로 올리는 promotion은 사람이 검토한다(`04` §1.1). promotion은 job을 막지 않는다.
staged harness로 진행 중인 job은 그대로 진행하고, promotion이 끝나면 issue가 `resolved`가 되며 `09` §5의
`hcap_revision` 재평가 규칙이 job들을 promoted revision으로 옮긴다. promotion 검토가 생성물을 거부하면 그
staged revision으로 만든 결과는 거부 사실과 함께 남기고, 해당 job은 `09` §5의 binding 변경 규칙으로 다시
gap 경로에 들어간다.

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
remote-KCOV attribution kernel instrumentation (Harness Generation이 생성, §5.2 검증)
```

이 patch는 취약점 수정이 아니라 fuzz harness 기능 확장이다.

### Linux kernel remote-KCOV attribution patch — pre-crash, pipeline 생성

Q1 remote KCOV 범위를 넓히기 위해 Linux kernel source를 추가 변경해야 하면 Harness Generation이 계측 patch를
생성하고 §5.2로 검증한다.

```text
remote_kcov_attribution gap
        |
        v
Harness Generation (계측 patch 또는 계측 series 이식)
        |
        v
§5.2 검증 -> staged harness로 job 진행
        |
        v
promotion 검토 (사람, job을 막지 않음)
```

현재 checked-in kernel patch 0001~0004도 이 종류의 harness instrumentation precedent다.
target kernel code를 바꾸면 reachability와 timing 자체를 교란할 수 있으므로 §5.2의 기존 capability 회귀와
attribution 검증을 통과해야 하고, 생성 patch set의 digest가 evidence와 crash report에 남아 crash review와
promotion 검토에서 사람이 볼 수 있어야 한다. 계측 series를 다른 kernel revision으로 옮기는 일도 같다(01 §11.2).

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

Harness gap이 있으면 candidate job은 멈추지 않고 harness를 생성하는 상태로 간다. Candidate 자체는
immutable이며 아래 상태는 job workflow의 것이다(issue #13). 전이의 정확한 규칙은 `09` §3.2가 소유한다.

```text
gap(gap_class, missing_capability_id)
    |
    v
harness_generating
    issue_ref, gap_class, missing_capability_id, resume_point
        |
        +-- 같은 gap key의 staged harness가 이미 있음
        |       -> 바로 다시 binding하고 resume_point로 간다
        |
        +-- Harness Generation 검증 통과
        |       -> staged hcap_revision으로 다시 binding
        |       -> 01 §11.2의 무효화 규칙을 적용하고 막혔던 stage를 재개
        |
        +-- 검증 실패
        |       -> 실패 evidence로 다시 생성 (harness_generation budget)
        |
        +-- budget 소진, 생성 Agent의 infeasible 판단
                -> blocked_harness_gap (fallback)

blocked_harness_gap
    issue_ref, gap_class, missing_capability_id
        |
        +-- issue resolved (사람이 harness를 만들었거나 promotion됨)
        |       -> retry_pending
        |       -> 새 harness binding에 01 §11.2의 무효화 규칙을 적용하고 막힌 stage를 재개
        |
        +-- operator retry_generation
        |       -> harness_generating (budget을 0으로 되돌림)
        |
        +-- issue deferred
        |       -> parked
        |       -> issue가 다시 열리거나 resolved되면 다시 평가
        |
        +-- issue wont_fix
                -> closed_unsupported(reason)        # terminal
```

`blocked_harness_gap`은 더 이상 gap의 기본 도착지가 아니다. 자동 생성이 실패했을 때만 쓰는 fallback이다.

retry나 생성 뒤 ExecutionHarnessIdentity가 바뀌었으면 Stage 1 Q1을 새 identity에서 다시 세운 뒤 진행한다. build를
바꾸지 않고 capability만 바뀐 경우(예: `mutation_engine` gap을 닫은 subset)에는 identity가 같으므로
plan을 새 `hcap_revision`으로 다시 검증하고 MutationRuleSet을 다시 compile한 뒤 Stage 2를 재개한다.

## 8. 실제 patch 필요성 측정

patch 필요 비율을 사전에 숫자로 가정하지 않는다.
gap을 만난 각 candidate마다 다음 resolution class를 기록한다. Harness Generation이 해결한 경우와 사람이 해결한
경우를 구분해 남긴다(`resolved_by`: `generation` | `human`).

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
