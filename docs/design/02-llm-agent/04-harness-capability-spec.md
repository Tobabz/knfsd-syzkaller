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
    Read by:     Agent SDK / Controller
    Generated per job: NO
```

이 문서는 Agent의 출력이 아니다.

`knfsd-syzkaller` 구현이 바뀌었을 때 함께 갱신하는 **harness의 capability catalog**다.

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

    usable_stage[]
        stage1
        stage2

    interface
    inputs
    outputs
    constraints[]

    status
        validated
        partially_validated
        experimental

    source_refs[]
```

`status`는 기능 존재 여부와 runtime 검증 수준을 구분한다.
Agent는 기본적으로 `validated` capability를 우선 사용하고,
`partially_validated` / `experimental` 사용은 plan에 명시한다.

## 4. 현재 capability catalog

### HCAP-01 — Lane filesystem access

```text
id: HCAP-01
name: NFS lane filesystem access
usable_stage: [stage1]
status: validated

interface:
    syz_open_nfs_lane$client0
    syz_open_nfs_lane$client1
    syz_open_nfs_lane_pair$client{0,1}_{knfsd,ganesha}

purpose:
    mounted NFS filesystem을 일반 syscall 경로로 조작

constraints:
    lane client는 0/1
    backend pair는 knfsd/Ganesha
```

source refs:

```text
bundle/patches/syzkaller/0015-*
bundle/patches/syzkaller/0017-*
README.md
```

### HCAP-02 — Raw NFS/RPC request send

```text
id: HCAP-02
name: raw NFS/RPC request send
usable_stage: [stage1, stage2]
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
status: validated

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
```

source refs:

```text
README.md
docs/design/01-overview/01-overview.md
bundle/patches/kernel/0001-*
bundle/patches/kernel/0002-*
```

### HCAP-04 — Four-lane execution topology

```text
id: HCAP-04
name: four-lane execution topology
usable_stage: [stage1, stage2]
status: partially_validated

purpose:
    proc별 독립 NFS lane을 사용해 parallel fuzz attribution을 유지

constraints:
    manager procs=4
    manager snapshot=false for normal parallel operation
        (top-level snapshot fuzzing mode; issue #3)
    vm.snapshot (qemu -snapshot disk overlay) keeps its default
    nfs.localio_enabled=N
    koov.nfs_version=3|4.0|4.1|4.2

verification_note:
    lane 구조 자체는 구현되어 있으나
    현재 문서에는 four-lane parallel manager topology의 미검증 범위가 남아 있음
```

source refs:

```text
README.md
bundle/corpus/nfs-normal/README.md
tools/prepare-live-lane-config.py
```

### HCAP-05 — Normal-flow scenario seeds

```text
id: HCAP-05
name: normal-flow scenario seeds
usable_stage: [stage1]
status: validated_per_scenario

purpose:
    이미 준비된 정상 NFS 상태/흐름을 Stage 1 scenario의 기반으로 재사용

available scenarios:
    NFSv3 basic
    NFSv4.0 delegation recall
    NFSv4.1 basic
    NFSv4.1 delegation recall
    NFSv4.2 async COPY
```

각 seed의 실제 기능 oracle과 검증 한계는
`bundle/corpus/nfs-normal/README.md`가 authoritative detail이다.

source refs:

```text
bundle/corpus/nfs-normal/
bundle/corpus/nfs-normal/manifest.json
```

### HCAP-06 — Flow-transition observation

```text
id: HCAP-06
name: flow transition tracing
usable_stage: [stage1]
status: validated_for_documented_scenarios

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
    HCAP-07 NFSPARM1 mutation
    HCAP-08 NFSPARM2 mutation (partially validated)
    HCAP-09 delta replay
```

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

구현과 명세가 다르면 runtime의 실제 검증 결과가 우선하며,
명세 불일치는 repository maintenance defect로 취급한다.
