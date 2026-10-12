# Harness Capability Specification

> 상태: current detailed design
> 상위 설계: `01-two-stage-agent-architecture.md`
> 목적: Agent가 매 candidate마다 `knfsd-syzkaller` 전체를 다시 탐색하지 않고,
> 현재 harness가 제공하는 기능과 제약을 구조적으로 참조하도록 한다.

## 1. 이 요소는 무엇인가

```text
Harness Capability Specification
    Type:        REPOSITORY DESIGN DATA
    Maintained by: repository maintainers
    Read by:     Agent SDK / Controller / Materializer / Rule Compiler
    Generated per job: NO
```

이 문서는 Agent의 출력이 아니다.

`knfsd-syzkaller` 구현이 바뀌었을 때 함께 갱신하는 **harness의 capability catalog**다.

### 1.1 authority 구조

capability 판단의 authority는 machine-readable HCAP 하나다(issue #14). 이 Markdown 문서는 그 데이터를
설명하는 view이며 독립된 authority가 아니다.

```text
machine-readable HCAP (canonical)         hcap_revision = canonical digest
    coarse repository capability
    interface / constraints / usable_by
    status + validated_scope
    evidence_refs
    authority_refs: 세부 authority artifact의 digest 참조
        |
        +-- RemoteKcovSupportBoundary / Q1AdmissibilityProfile (06 §6.1)
        +-- promoted semantic capability registry (§4)

rendered Markdown (이 문서)
    설명용 view. machine data에서 생성하거나 machine data와 대조한다
```

- `hcap_revision`은 canonical machine-readable HCAP의 digest다. plan과 evidence가 이 값을 pin한다
  (identity 체계는 issue #13).
- Controller는 plan의 `required_capabilities`, `status`, `usable_by`를 이 데이터로 검증한다. Harness
  Materializer는 call을 capability `interface`와 대조하고, Mutation Rule Compiler는 promoted semantic
  registry(§4)를 쓴다.
- 세부 지원 목록은 authority artifact가 소유하고 HCAP은 digest로 참조한다. 같은 목록을 HCAP이나 문서에
  복제하지 않는다.
- serialization 형식(JSON, YAML, TOML 등)은 구현 선택이다. schema와 하나의 canonical digest 표현이 있으면
  된다.
- artifact와 drift guard(§7.2)는 그것이 필요한 첫 implementation milestone에서 도입한다. 그 전까지는 이
  Markdown이 interim catalog이며 §3 형식과 §7.1 규칙을 따른다.

## 2. 왜 필요한가

매 candidate마다 Agent가 다음을 처음부터 다시 탐색하면 비용과 판단 편차가 커진다.

```text
어떤 pseudo-syscall이 있는가?
어떤 NFS version을 지원하는가?
raw RPC를 보낼 수 있는가?
S2C mutation이 가능한가?
KCOV attribution은 어떻게 되는가?
어떤 normal-flow seed가 있는가?
어떤 기능이 아직 실험 상태인가?
```

따라서 다음 구조로 바꾼다.

```text
                   repository implementation
                            |
                            v
               Harness Capability Spec
                            |
             +--------------+--------------+
             |                             |
             v                             v
      Candidate Analysis           Reachability Planning
             |                             |
             +--------------+--------------+
                            |
                            v
                    selected capabilities
```

Agent는 필요할 때 spec의 `source_refs`가 가리키는 구현을 상세 확인할 수 있지만,
capability discovery 자체를 매 job마다 repo-wide search로 반복하지 않는다.

## 3. capability entry 형식

각 capability는 다음 형태로 기술한다.

```text
Capability
    id
    name
    purpose

    usable_stage[]              # 기능상 속하는 stage
        stage1
        stage2

    usable_by[]                 # 이 capability를 쓸 수 있는 소비자 (issue #8)
        agent_stage1
        agent_stage2
        manual_legacy_campaigns

    interface
    inputs
    outputs
    constraints[]

    status
        validated
        validated_subset
        partially_validated
        experimental
    validated_scope             # status=validated_subset이면 필수

    evidence_refs[]             # 검증 기록
    authority_refs[]            # 세부 authority artifact의 digest 참조 (§1.1)
    source_refs[]
```

`status`는 기능 존재 여부와 runtime 검증 수준을 구분한다. 검증된 범위는 status 값에 넣지 않고
`validated_scope`에 데이터로 둔다(issue #14).
Agent는 기본적으로 `validated` capability와 `validated_subset`의 scope 안을 우선 사용하고,
`partially_validated` / `experimental` 사용과 scope 밖 사용은 plan에 명시한다.

`usable_stage`는 capability가 기능상 어느 stage에 속하는지를, `usable_by`는 누가 그것을 쓸 수 있는지를
나타낸다. `usable_by`에 `agent_stage1`이나 `agent_stage2`가 없는 capability는 Agent pipeline이 쓰지 않는다.

Harness Materializer는 Agent가 제안한 program의 각 call이 plan의 required capability `interface`에
속하는지 확인한다(`05` §11, issue #12). interface의 authority는 machine-readable HCAP이다(§1.1).

## 4. 현재 capability catalog

### HCAP-01 — Lane filesystem access

```text
id: HCAP-01
name: NFS lane filesystem access
usable_stage: [stage1]
usable_by: [agent_stage1]
status: validated_subset
validated_scope:
    syz_open_nfs_lane / syz_open_nfs_lane_pair 경로
    profile open(0020)과 broad-knfsd 노출은 scope 밖 (experimental)

interface:
    syz_open_nfs_lane$client0
    syz_open_nfs_lane$client1
    syz_open_nfs_lane_pair$client{0,1}_{knfsd,ganesha}
    syz_open_nfs_lane_profile$client{0,1}_{knfsd_v3,knfsd_v40,
        knfsd_v41,knfsd_v42,ganesha_v41}            # 0020, experimental

purpose:
    mounted NFS filesystem을 일반 syscall 경로로 조작

constraints:
    lane client는 0/1
    backend pair는 knfsd/Ganesha
    profile open은 fixture가 노출한 profile만 쓸 수 있다
        single: knfsd-<version>, v4.1 both에서는 ganesha-v41도
        broad-knfsd: knfsd-v3, knfsd-v40, knfsd-v41, knfsd-v42

verification_note:
    profile open(0020)과 broad-knfsd 노출은 이 명세가 참조할
    guest 검증 기록이 아직 없다.
```

source refs:

```text
bundle/patches/syzkaller/0015-*
bundle/patches/syzkaller/0017-*
bundle/patches/syzkaller/0020-*
bundle/lane/lane.sh
README.md
```

### HCAP-02 — Raw NFS/RPC request send

```text
id: HCAP-02
name: raw NFS/RPC request send
usable_stage: [stage1, stage2]
usable_by: [agent_stage1, agent_stage2]
status: validated

interface:
    syz_socket_connect_nfs*
    syz_socket_connect_nfs_pair*
    syz_send_nfs_fuzz$new
    syz_send_nfs_fuzz$new_final
    syz_send_nfs_fuzz$retry
    syz_send_nfs_fuzz$retry_final

purpose:
    C2S 방향의 protocol-shaped/raw NFS RPC 전송

constraints:
    raw request가 kernel NFS client가 만든 session/state를 자동으로 보유하지는 않음
    state-dependent operation은 별도 state setup이 필요할 수 있음
```

source refs:

```text
bundle/patches/syzkaller/0015-*
bundle/patches/syzkaller/0018-*
```

### HCAP-03 — Remote KCOV lane attribution

```text
id: HCAP-03
name: remote KCOV lane attribution
usable_stage: [stage1, stage2]
usable_by: [agent_stage1, agent_stage2]
status: validated

authority_refs:                     # digest 참조. artifact는 아직 없다 (§1.1)
    RemoteKcovSupportBoundary       # 귀속 execution context 목록 (06 §6.1)
    Q1AdmissibilityProfile          # Q1 JudgeProfile (06 §6.1)

purpose:
    knfsd server-side fs/nfsd 및 net/sunrpc coverage를
    executor proc/lane에 귀속

interface:
    experimental.remote_cover
    remote .extra coverage
    sunrpc_fuzz debugfs counters

constraints:
    knfsd campaign은 remote_cover=true
    lane ownership은 proc 단위
    Q1은 generation-attributed remote coverage만 사용
    KCOV_NFSD_OBSERVE global stream은 Q1에 사용하지 않음
    local KCOV / tracepoint / kprobe 결과는 Q1에 사용하지 않음
    PC 존재만으로 cross-thread ordering은 증명하지 못함
    귀속되는 execution context 목록은 RemoteKcovSupportBoundary가 소유하며
        이 entry에 복제하지 않는다 (authority_refs)
    lane NFS tracing(koov.nfs_trace=1)을 켜면 tracepoint 생성 코드의
        PC가 remote coverage에 섞인다. 기본은 꺼짐이며, 켠 실행은
        그 모드를 evidence에 기록해야 한다
```

source refs:

```text
README.md
docs/design/01-overview/01-overview.md
bundle/patches/kernel/0001-*
bundle/patches/kernel/0002-*
bundle/lane/lane.sh
```

### HCAP-04 — Four-lane execution topology

```text
id: HCAP-04
name: four-lane execution topology
usable_stage: [stage1, stage2]
usable_by: [agent_stage1, agent_stage2]
status: partially_validated

purpose:
    proc별 독립 NFS lane을 사용해 parallel fuzz attribution을 유지

constraints:
    manager procs=4
    manager snapshot=false for normal parallel operation
        (top-level snapshot fuzzing mode; issue #3)
    vm.snapshot (qemu -snapshot disk overlay) keeps its default
    nfs.localio_enabled=N
    koov.nfs_version=3|4.0|4.1|4.2 (single fixture)
    또는 koov.nfs_fixture=broad-knfsd (experimental)
        lane마다 knfsd v3/v4.0/v4.1/v4.2를 함께 마운트
        SERVER_IMPL=both 필요, knfsd lease 기본 90초
    koov.nfs_trace=0 (default) | 1 (lane NFS tracing opt-in)

verification_note:
    lane 구조 자체는 구현되어 있으나
    현재 문서에는 four-lane parallel manager topology의 미검증 범위가 남아 있음
```

source refs:

```text
README.md
bundle/corpus/nfs-normal/README.md
bundle/lane/lane.sh
bundle/lane/boot-fixture.sh
tools/prepare-live-lane-config.py
```

### HCAP-05 — Normal-flow scenario seeds

```text
id: HCAP-05
name: normal-flow scenario seeds
usable_stage: [stage1]
usable_by: [agent_stage1]
status: validated_subset
validated_scope:
    manifest.json의 seed별 oracle 중 그 seed의 evidence가 확인한 범위
    evidence가 측정하지 않았다고 적은 부분은 scope 밖
        (예: async-copy-v42의 callback attribution)

evidence_refs:
    bundle/corpus/nfs-normal/manifest.json (programs[].evidence)
    report/normal-flow-corpus.md

authority_refs:
    bundle/corpus/nfs-normal/manifest.json    # seed 목록과 seed별 oracle

purpose:
    이미 준비된 정상 NFS 상태/흐름을 Stage 1 scenario의 기반으로 재사용

interface:
    bundle/corpus/nfs-normal/manifest.json (schema 3, native profile별 seed)
    tools/build-normal-corpus.py --fixture broad-knfsd
    tools/audit-normal-corpus.py

available scenarios (native profile별):
    knfsd-v3:    basic, procedures, create retry
    knfsd-v40:   delegation recall, state namespace
    knfsd-v41:   basic, delegation recall, session state
    knfsd-v42:   async COPY, remote-KCOV max, remote-KCOV gaps
    ganesha-v41: basic (Ganesha campaign only)
```

위 목록은 설명용 요약이다. seed 목록, 각 seed의 기능 oracle, 실행 상태와 검증 한계는 `manifest.json`이
authority이고 `bundle/corpus/nfs-normal/README.md`가 설명한다. machine-readable HCAP은 seed 목록을 복제하지
않고 manifest를 참조한다(§1.1).

source refs:

```text
bundle/corpus/nfs-normal/
bundle/corpus/nfs-normal/manifest.json
tools/build-normal-corpus.py
tools/audit-normal-corpus.py
```

### HCAP-06 — Flow-transition observation

```text
id: HCAP-06
name: flow transition tracing
usable_stage: [stage1]
usable_by: [agent_stage1]
status: validated_subset
validated_scope:
    report/normal-flow-threads.md가 측정 결과를 기록한 scenario
    (tools/flow-trace/scenarios/의 S1, S2, S3, S3b, S4, S5, S5b)

evidence_refs:
    report/normal-flow-threads.md

purpose:
    PC만으로 증명할 수 없는 thread handoff / ordering을 trace event로 관측
    Candidate Analysis 및 진단에 사용
    Q1 oracle로는 사용하지 않음

interface:
    tools/flow-trace/capture.py
    tools/flow-trace/handoffs.py
    tools/flow-trace/scenarios/*.json

constraints:
    일반 fuzz feedback channel이 아니라 보조 observability
    trace loss가 있으면 missing verdict를 신뢰하지 않음
    trace 결과는 Q1 reached/not_reached를 변경하지 않음
```

source refs:

```text
tools/flow-trace/README.md
report/normal-flow-threads.md
```

### HCAP-07 — Fixed-width proxy mutation

```text
id: HCAP-07
name: NFSPARM1 fixed-width proxy mutation
usable_stage: [stage2]
usable_by: [manual_legacy_campaigns]  # Agent Stage 2 아님 (issue #8)
status: validated

interface:
    syz_arm_nfs_proxy$scoped
    NFSPARM1

purpose:
    C2S/S2C RPC record의 확인된 byte region을 same-width replacement

matching:
    direction
    backend
    client
    first opcode
    optional literal anchor

constraints:
    patch width <= 16 bytes
    original bytes verify-before-patch
    proxy ACK는 mutation 적용 증거가 아님
```

source refs:

```text
tools/nfs-proxy/README.md
tools/nfs-proxy/src/control.h
tools/nfs-proxy/src/delta.h
bundle/patches/syzkaller/0017-*
```

### HCAP-08 — Variable-length proxy mutation

```text
id: HCAP-08
name: NFSPARM2 variable-length proxy mutation
usable_stage: [stage2]
usable_by: [manual_legacy_campaigns]  # Agent Stage 2 아님 (issue #8)
status: partially_validated

interface:
    syz_arm_nfs_proxy_v2$scoped
    NFSPARM2

edits:
    REPLACE
    INSERT
    DELETE
    OP_APPEND
    OP_PREPEND

purpose:
    NFSv4 COMPOUND op array 내부의 variable-length edit

constraints:
    original-coordinate edit semantics
    overlap refused
    verify-before-patch
    op-array body 범위

verification_note:
    OP_APPEND와 variable-length REPLACE는 guest에서 검증됨.
    4-lane syz-execprog REPLACE도 검증됨.
    INSERT/DELETE, S2C variable-length edit, long syz-manager 운용은 미검증.
```

source refs:

```text
tools/nfs-proxy/README.md
tools/nfs-proxy/src/edit.h
bundle/patches/syzkaller/0019-*
```

### HCAP-09 — Mutation delta replay

```text
id: HCAP-09
name: mutation delta record/replay
usable_stage: [stage2]
usable_by: [manual_legacy_campaigns]  # Agent Stage 2 아님 (issue #8)
status: validated

purpose:
    실제 적용된 mutation을 durable delta로 기록하고
    같은 apply implementation으로 replay

outputs:
    arm-N.delta
    application counters

distinguishes:
    mutation reapplied
    predicate matched but original bytes differed
    predicate never matched
```

source refs:

```text
tools/nfs-proxy/src/delta.h
tools/nfs-proxy/README.md
```

### Target Proxy Architecture와의 관계

HCAP-07/08/09는 현재 `tools/nfs-proxy`에서 검증된 concrete capability를 기록한다.
목표 semantic Proxy architecture는
[`../03-nfs-proxy/01-architecture.md`](../03-nfs-proxy/01-architecture.md)에 별도로 정의한다.

Semantic decoder, Transaction Context, runtime field resolver 같은 목표 기능은
구현과 guest/runtime 검증이 끝나기 전에는 새 HCAP으로 지원된다고 간주하지 않는다.
구현이 검증되면 Harness Capability Specification을 갱신한다.

HCAP-07/08/09는 사람이 작성한 legacy/manual campaign만 쓴다. Agent의 Stage 2 pipeline은
MutationRuleSet을 NFSPARM anchor/offset/original bytes로 낮추지 않으며 semantic→legacy adapter도 없다
(issue #8). Agent가 쓰는 semantic mutation capability는 M7 promotion gate
(`../03-nfs-proxy/06-implementation-gap-analysis.md` §30)를 통과한 subset만 등록한다. 그 subset의 세부
범위는 아래 semantic capability registry가 소유한다.

### Semantic capability registry

semantic mutation의 세부 지원 범위는 HCAP entry에 나열하지 않는다(issue #14). Proxy build가 다음 registry를
결정적으로 생성한다.

```text
semantic capability registry
    semantic_runtime_version
    schema_id
    지원 semantic path / WireRef part
    predicate operator
    transform_id + type 계약
    mutation kind / structure_policy
    ValueRef source / context dependency 지원
    implementation / build identity
```

- build가 생성한 registry는 그 build가 *구현한* 범위를 기술할 뿐이며 그대로는 Agent가 쓸 수 없다.
- subset이 M7 gate를 통과하면 그 registry digest와 subset scope를 promotion한다. semantic mutation HCAP
  entry는 promoted registry를 `authority_refs`로, 검증된 subset을 `validated_scope`로 참조한다.
- Agent와 Mutation Rule Compiler는 promoted scope만 쓴다. 실행 중인 binary가 runtime에 광고하는 범위만으로는
  쓰지 않는다(§7.1).
- path, operator, transform 목록을 이 문서나 Agent·Proxy 설계 문서에 복제하지 않는다.

promotion된 subset이 아직 없으므로 semantic mutation HCAP entry도 아직 없다.

## 5. Stage별 사용 범위

```text
STAGE 1
    HCAP-01 lane filesystem access
    HCAP-02 raw NFS/RPC send
    HCAP-03 remote KCOV
    HCAP-04 lane topology
    HCAP-05 normal-flow seeds
    HCAP-06 flow tracing

STAGE 2
    Stage 1에서 선택된 scenario
    HCAP-02 raw NFS/RPC send
    HCAP-03 remote KCOV
    HCAP-04 lane topology
    semantic mutation capability (M7 promotion을 통과한 registry scope만, §4)

MANUAL / LEGACY CAMPAIGN (Agent pipeline 아님)
    HCAP-07 NFSPARM1 mutation
    HCAP-08 NFSPARM2 mutation (partially validated)
    HCAP-09 delta replay
```

promotion된 semantic subset이 없으면 Agent Stage 2의 semantic 요청은 `unsupported_by_current_harness`로
처리하고 `HarnessGapIssue(gap_class=mutation_engine)`를 semantic runtime 구현·검증 작업에 연결한다.
legacy 경로를 manual 실험에 쓰더라도 Controller는 Agent intent가 지원된다고 주장하지 않는다(issue #8).

Stage 1은 mutation capability를 Q1을 만들기 위한 우회 수단으로 사용하지 않는다.
Stage 1은 정상 또는 protocol-valid reachability scenario를 먼저 확보하는 것을 목표로 한다.

## 6. Agent 사용 규칙

Candidate Analysis과 Reachability Planning은 다음 순서로 판단한다.

```text
CandidateAnalysis
      |
      v
Harness Capability Specification
      |
      +-- 필요한 capability 존재
      |       |
      |       v
      |   Reachability Planning
      |
      +-- 필요한 capability 없음
              |
              v
      unsupported_by_current_harness
              |
              v
       HarnessGapIssue 생성/연결
              |
              v
       blocked_harness_gap
```

Agent는 없는 capability를 있다고 가정하지 않는다.
candidate 실행 중에 즉석에서 source를 바꾸지 않는다.
대신 별도 Harness Extension Work에서 syzlang, pseudo-syscall/executor, fixture/tool,
mutation-engine capability를 확장할 수 있다.

Linux kernel source를 바꾸는 observability extension은 자동 수행하지 않고 human decision issue로 관리한다.
자세한 계약은 `07-harness-gap-issue.md`를 따른다.

## 7. 갱신 책임

이 명세는 다음 변경과 함께 갱신해야 한다.

```text
new/changed pseudo-syscall
syzlang capability change
lane topology change
KCOV attribution change
new corpus scenario
proxy mutation ABI change
flow-trace capability change
runtime verification status change
```

### 7.1 runtime과 HCAP이 다를 때

어느 쪽도 조용히 우선하지 않는다(issue #14).

```text
runtime / build identity와 promoted registry가 pin된 HCAP 참조와 일치
    -> validated scope 안에서 사용

runtime이 pin된 authority보다 적거나 다르게 보고
    -> INCONCLUSIVE(infra) / 차단
    -> repository maintenance defect

runtime이 promotion되지 않은 capability를 더 노출
    -> 사용하지 않는다
    -> validation / promotion이 authority를 갱신하기 전에는 Agent capability가 아니다
```

### 7.2 drift guard

machine-readable HCAP을 도입할 때 `tools/test-lane-inputs.py`와 같은 형식의 host test가 다음을 확인한다.

```text
patch manifest가 가리키는 파일이 모두 존재
series에 들어가야 할 patch가 orphan으로 남지 않음
HCAP interface가 pin되어 적용된 syzlang build에서 resolve됨
참조한 corpus seed가 canonical manifest에 존재
promoted semantic registry digest가 runtime / build identity와 일치
rendered HCAP 문서가 machine data와 일치
```

같은 사실을 담은 목록 두 개를 계속 손으로 맞추지 않는다. 한 manifest를 authority로 정하고 나머지는 그것을
읽는다. 예를 들어 syzkaller patch 적용 순서의 authority는 `bundle/patches/syzkaller/series`다.
`tools/fport-apply.sh`는 지금 `*.patch` glob으로 patch를 적용하므로, 이후 tooling은 glob 대신 `series`(또는
그것에서 생성한 목록)를 읽어야 한다. `4f10720`(series에서 빠진 0021)과 `8c43771`(HCAP 수동 재동기화)이 손으로
고친 drift가 이 guard의 대상이다.
