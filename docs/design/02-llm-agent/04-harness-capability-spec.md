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
        +-- CallAdmissionProfile (§3.1)

rendered Markdown (이 문서)
    설명용 view. machine data에서 생성하거나 machine data와 대조한다
```

- `hcap_revision`은 canonical machine-readable HCAP의 digest다. Controller가 job을 harness에 묶을 때 그
  harness를 기술하는 revision을 고르고, plan과 verdict가 이 값을 기록한다(`01` §11.2, issue #13).
- revision에는 두 status가 있다. promoted revision은 사람이 검토해 공유 HCAP으로 올린 것이고, staged revision은
  Harness Generation(`07` §5)이 만든 patch set이 Runner 검증을 통과해 생긴 것이다. staged revision은 그 gap key의
  job들이 쓰며, promoted revision을 바꾸지 않는다. plan과 verdict는 어느 쪽인지 기록한다.
- HCAP data는 `missing_capability_id`의 controlled vocabulary도 담는다(`07` §3, issue #13). 예:
  `state_lineage`, `remote_kcov.context.<context>`, `remote_kcov.kernel_revision.<commit>`,
  `neutral_control.<profile>`(`05` §11).
- Controller는 plan의 `required_capabilities`, `status`, `usable_by`를 이 데이터로 검증한다. Harness
  Materializer는 program의 call을 `CallAdmissionProfile`(§3.1)로 capability에 대조하고, Mutation Rule
  Compiler는 promoted semantic registry(§4)를 쓴다.
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

Harness Materializer는 Agent가 제안한 program의 각 call이 plan의 required capability에 admission되는지
확인한다(`05` §11, issue #12). admission의 authority는 §3.1의 `CallAdmissionProfile`이다.

`interface`에서 `interface.syz_calls`는 syz program 안에서 실행되는 call이고, `interface.host_tooling`은
repository maintainer가 host에서 쓰는 command와 file이다. 그 밖의 `interface` 항목(HCAP-03의 manager 설정과
counter 등)도 program call이 아니다. `host_tooling`은 실행 가능한 syz interface가 아니며 program call이나
runtime 입력이 될 수 없다. program call admission에는 `CallAdmissionProfile`만 쓴다.

### 3.1 CallAdmissionProfile

program call admission의 authority는 하나다(issue #18 F5).

```text
CallAdmissionProfile              # repository authority artifact, HCAP authority_refs로 digest 참조
    syzkaller_build               # ExecutionHarnessIdentity의 syzkaller build와 같아야 한다
    target                        # 예: linux/amd64
    entries[]
        call                      # pinned build가 resolve하는 정확한 syzlang 이름(variant 포함)
        capability_id             # 이 call을 admission하는 HCAP entry
        resource_constraints[]    # 예: lane resource에서 온 fd/path만 인자로 받는다
```

- profile은 pinned syzkaller build의 call table에서 생성하고, 그 build에서 resolve되지 않는 이름을 담지 않는다.
  drift guard(§7.2)가 이를 확인한다.
- profile에 없는 call은 admission되지 않는다. "일반 syscall은 예외" 같은 permissive fallback은 없다.
- 한 call이 여러 capability에 admission될 수 있다. Materializer는 그 중 하나가 plan의
  `required_capabilities`에 있고 `usable_by`에 `agent_stage1`이 있을 때만 받아들인다.
- seed provenance(HCAP-05)는 program bytes가 manifest의 seed와 같고 그 seed의 recorded oracle/evidence가
  있다는 것만 보증한다. seed 안의 call도 제안 program의 call과 똑같이 profile로 검사한다. seed라는 이유로
  검사를 건너뛰지 않는다.
- 첫 profile의 내용은 HCAP-01과 HCAP-02의 `validated_scope`에서 시작한다. 예: HCAP-01은 lane acquisition
  pseudo-call과, lane resource에 대해 validated seed가 실제로 쓰는 filesystem syscall을 admission한다.
  목록은 profile이 소유하며 이 문서에 복제하지 않는다.
- artifact는 첫 Stage 1 Materializer 통합에서 도입한다(§1.1의 milestone 규칙).

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

interface.syz_calls:
    lane acquisition
        syz_open_nfs_lane$client0
        syz_open_nfs_lane$client1
        syz_open_nfs_lane_pair$client{0,1}_{knfsd,ganesha}
        syz_open_nfs_lane_profile$client{0,1}_{knfsd_v3,knfsd_v40,
            knfsd_v41,knfsd_v42,ganesha_v41}        # 0020, experimental
    lane filesystem syscalls
        lane resource를 인자로 받는 일반 syscall.
        목록은 CallAdmissionProfile이 소유한다 (§3.1)

authority_refs:
    CallAdmissionProfile            # §3.1. artifact는 아직 없다

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

interface.syz_calls:
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

interface.syz_calls:
    없음. seed program의 call은 그 call을 admission하는 capability
    (HCAP-01, HCAP-02 등)로 검사한다 (§3.1)

interface.host_tooling:             # 실행 가능한 syz interface가 아니다
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

interface.host_tooling:
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

interface.syz_calls:
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

interface.syz_calls:
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

### HCAP-11 — Bounded NFSv4.1 client lifecycle recovery

```text
id: HCAP-11
name: bounded NFSv4.1 client lifecycle recovery
usable_stage: [stage1]
usable_by: [agent_stage1]
status: validated
scope: [client0_confirmed_expiry_recovery]

interface:
    syz_nfsd_client_ctl$expire_client0(0x0)  # exact admitted invocation

purpose:
    lane 0의 확정된 NFSv4.1 클라이언트 하나를 만료시키고
    일반 client0 profile I/O로 EXCHANGE_ID -> CREATE_SESSION 복구를 유도

constraints:
    single NFSv4.1 fixture와 SERVER_IMPL=both를 사용
    client0 selector 인자는 반드시 고정값 0x0을 사용하며 expiry는 정확히 한 번 수행
    expiry 뒤에 client0 profile을 획득하고 client1 획득이나 선행 client0 획득은 거부
    lifecycle broker가 정확히 하나의 confirmed minor-version-1 owner를 해석
    owner는 Linux NFSv4.1 frozen-phase9-lane0-client0/<UTS hostname>과 정확히 일치
    syz 호출은 client selector만 전달하며 client path, owner, ctl payload를 전달하지 않음
    broker만 /proc/fs/nfsd/clients/<client>/ctl을 선택하고 literal expire를 기록
    broker reply의 clientid, minorversion=1, session_count>0을 executor가 검사
    한 번의 expiry 뒤 client0 profile도 정확히 한 번 획득하고,
    parser가 client0 FD origin을 증명한 ordinary profile I/O를 수행
    profile 획득만 하거나 close/lseek만 수행한 프로그램은 recovery I/O로 인정하지 않음
```

executor ABI에는 lane 1용 `syz_nfsd_client_ctl$expire_client1`도 존재하지만, HCAP-11과
CallAdmissionProfile은 실제 KVM에서 검증된 client0만 공개한다. client1은 별도의 runtime 증거가 생기기 전까지
Agent가 사용할 수 없다. 2026-10-19 실 KVM 검증에서는 neutral control 3회가 승인된 target mapping을 실행하지
않았고, expiry stimulus 3회는 모두 그 mapping을 실행했다. 각 실행은 remote-KCOV generation begin/publish 1회,
abort/overflow/truncation 0회, 종료 시 outstanding token 및 remote ref 0을 기록했다. HCAP-03은 이 실행의
generation attribution을 계속 담당하며 HCAP-11이 이를 대체하지 않는다. 공유 증거는 실행 descriptor와
target mapping의 digest 및 전체 mapping identity를 기록하고 후보 source metadata와 target 주소는 포함하지
않는다. Host generator는 이 typed evidence의 execution harness, kernel/instrumentation/vmlinux/KASLR identity와
guest lane script digest를 새 descriptor에 대해 다시 검사한 뒤에만 HCAP-11을 promotion한다. fixture status는
lifecycle broker의 PID start time, server mount/net namespace, 명령행과 정확한 UNIX socket inode 소유권을 함께
검사하여 stale pathname이나 재사용된 PID를 broker로 인정하지 않는다.

source refs:

```text
bundle/patches/syzkaller/0027-*
bundle/lane/lane.sh
tools/nfs-proxy/src/lifecycle.c
tools/nfs-lifecycle/run.py
agent_pipeline/stage1/host/template/capability-evidence/hcap11-kvm.json
```

### HCAP-12 — Bounded nfsdcld reconnect during NFSv4.1 client recovery

```text
id: HCAP-12
name: bounded nfsdcld reconnect during NFSv4.1 client recovery
usable_stage: [stage1]
usable_by: [agent_stage1]
status: validated (KVM evidence 전까지 generator가 template을 거부)
scope: [client0_recovery_cld_reconnect]

interface:
    syz_nfsd_cld_ctl$reconnect(0x2)  # exact admitted invocation

purpose:
    HCAP-11 복구 중 fresh client0의 Cld_Create upcall이 rpc_pipefs CLD pipe reader 교체와
    겹치도록 하여, nfsd request context의 -EAGAIN 재시도와 reader-less 재queue 경로를 실행

constraints:
    HCAP-11 sequence 안에서 expire_client0 뒤, client0 profile 획득 전에 reconnect를 정확히 한 번 호출
    syz_nfsd_cld_ctl$daemon_down은 어떤 HCAP에서도 admit되지 않음 (fixture 검증 전용)
    syz 호출은 고정 op enum만 전달하며 path, PID, mount option, CLD payload, xid, command를 전달하지 않음
    broker만 nfsdcld를 netns/mntns, PID start time, comm/cmdline, 실행 파일, 소유한 rpc_pipefs CLD pipe
    dev:inode로 선택하고, 그 identity가 직전 transaction 종료 시점과 다르면 ESTALE로 거부
    reconnect는 daemon을 bounded 시간 동안 SIGSTOP한 뒤 SIGKILL과 재시작으로 교체; 겹치는 CLD 작업과
    그 동안의 client expiry는 EBUSY
    실패한 transaction은 daemon을 한 번 복구하고, 복구도 실패하면 broker가 failed 상태로 남아 모든 CLD 작업을
    EIO로 거부하며 lane status가 fixture를 unhealthy로 판정
```

CLD 작업의 실행 context와 귀속:

| CLD 작업 | 실행 context | remote-KCOV |
|---|---|---|
| RECLAIM_COMPLETE/OPEN_CONFIRM의 `nfsd4_cld_create(_v2)`, `cld_pipe_upcall` 재시도, `rpc_queue_upcall`, completion 대기 | nfsd request (`svc_process`) | 귀속됨 (`request`) |
| DESTROY_CLIENTID/EXCHANGE_ID/CREATE_SESSION의 `nfsd4_cld_remove` | nfsd request | 귀속됨 (`request`) |
| broker의 admin expire가 부른 `nfsd4_cld_remove` | broker 프로세스 | 귀속 안 됨 |
| laundromat의 expiry/remove, grace 종료 | workqueue | 귀속 안 됨 |
| `rpc_pipe_read`, `cld_pipe_downcall`, pipe open/release와 -EAGAIN purge | nfsdcld syscall | 귀속 안 됨 |
| `rpc_timeout_upcall_queue` (-ETIMEDOUT) | rpciod workqueue | 귀속 안 됨 |
| tracking init, version 확인, rpc_pipefs mount notifier | nfsd 시작/관리 | 귀속 안 됨 |

귀속되지 않는 context를 요구하는 Q1 target은 `remote_kcov.context.cld` gap으로 남으며, 이 capability는 그
범위를 지원한다고 주장하지 않는다. 그 context를 귀속하려면 커널 패치가 필요하며 owner 승인 전에는 적용하지
않는다. trace, dmesg, daemon log는 진단 정보일 뿐 Q1 근거가 아니다.

Broker 카운터(`server/cld.state`, broker 소유):
`reconnect_attempts/ok/fail`, `down_attempts/ok/fail`, `daemon_stop_ok/fail`, `daemon_start_ok/fail`,
`refused_busy`(겹친 요청), `refused_identity`(stale identity), `restore_ok/fail`(실패 뒤 복구). 실행 증거는 run별
delta를 기록한다.

KVM 증거(`capability-evidence/hcap12-kvm.json`, `Hcap12KvmEvidence`)는 run마다 하나의 귀속 generation과 공개
CLD probe(`cld_create`, `cld_create_error`, `pipe_wait_for_open`) hit 수를 담는다. promotion 조건은 다음과 같다.

- neutral control은 모든 probe를 miss하고 broker를 쓰지 않는다.
- 시나리오 A(normal)는 create를 hit하고 reader-less 재queue와 오류 경로는 miss한다.
- 시나리오 C(reconnect)는 create와 reader-less 재queue를 hit하고 오류 경로는 miss하며, run마다
  `reconnect_ok`가 1이다.
- 시나리오 B(daemon-down)는 fixture 증거로만 쓰며, run마다 `down_ok`가 1이고 daemon이 복구되어야 한다.
- 모든 run 뒤에 lane status가 통과하고, broker 실패·거부·복구 카운터는 모두 0이어야 한다.

Probe는 공개 커널 함수와 줄 범위에서 계산하며 후보 metadata를 쓰지 않는다. Host generator는 HCAP-11과 같은
identity 결합을 검사한 뒤에만 HCAP-12를 promotion한다.

source refs:

```text
bundle/patches/syzkaller/0028-*
bundle/lane/lane.sh
tools/nfs-proxy/src/cld.c
tools/nfs-lifecycle/run.py
agent_pipeline/stage1/host/template/capability-evidence/hcap12-kvm.json
```

### HCAP-13 — NLM lane locking and raw NLM RPC

```text
id: HCAP-13
name: NLM lane locking and raw NLM RPC
usable_stage: [stage1]
usable_by: [agent_stage1]
status: validated (KVM evidence 전까지 generator가 template을 거부)
scope: [nlm_lane_lock_rpc]

interface:
    syz_open_nlm_lane_file(lane fd, name, mode)       # lane 아래 regular file
    fcntl$lock(fd, 0x5 F_GETLK | 0x6 F_SETLK, flock)  # kernel NFS client의 NLM 호출
    syz_nlm_lane_fh(lane fd, name) -> nlm_lane_fh_id   # server file handle의 가변 word
    syz_socket_connect_nlm$client0/1                    # lane client netns -> server lockd TCP 4045
    syz_send_nlm_rpc(sock, rpc_nlm_call, len)           # record-marked raw NLM call
    recvfrom$inet_nlm_tcp(sock, ...)                    # reply

purpose:
    nlm-knfsd fixture(NFSv3 single lane)에서 server lane lockd의 LOCK/TEST/UNLOCK/CANCEL/SHARE와
    blocked lock의 GRANTED callback을 Stage 1 program으로 실행
```

Fixture (`NFS_FIXTURE=nlm-knfsd`, `koov.nfs_fixture=nlm-knfsd`):

- single NFSv3 fixture에 `SERVER_IMPL=both`가 필요하고, Ganesha mount는 계속 `nolock`이다.
- root namespace rpcbind를 멈추고, lane마다 server와 두 client network namespace에 각자의 rpcbind와
  `rpc.statd`(고정 port 662/2020, `/run`과 `/var/lib/nfs`는 namespace별)를 실행한다. kernel lockd의
  rpcbind 등록은 mount한 namespace의 `127.0.0.1:111`로 간다.
- `fs.nfs.nlm_tcpport`/`nlm_udpport`는 4045, `nlm_grace_period`는 10초다. setup은 두 knfsd mount에서
  공유 lock을 한 번 잡아 grace 종료와 lockd·statd 응답을 확인한다.
- lane status는 세 namespace의 nlockmgr v4와 status v1 등록, server의 4045 listen, knfsd mount에
  `nolock`이 없음을 확인한다.

Program 제약과 Materializer 계약:

- NLM 호출(`syz_socket_connect_nlm$*`, `syz_send_nlm_rpc`, `recvfrom$inet_nlm_tcp`,
  `syz_open_nlm_lane_file`, `syz_nlm_lane_fh`)은 HCAP-13을 요구한 scenario에서만 admit되고, neutral
  control은 이를 가질 수 없다(`nlm_without_hcap13`). HCAP-13 scenario는 `nlm-knfsd` selection을 써야
  한다(`fixture_not_nlm`).
- `fcntl$lock`은 knfsd-v3 lane origin FD와 cmd 5..6만 admit한다. collector는 non-threaded로 한
  program을 실행하므로 F_SETLKW와 OFD lock은 admit되지 않는다. blocked lock은 raw `LOCK`(block=1)으로
  만든다.
- `syz_open_nlm_lane_file`의 결과 FD는 lane directory 인자의 origin을 이어받는다(openat2
  RESOLVE_BENEATH/NO_XDEV/NO_SYMLINKS/NO_MAGICLINKS와 NFS superblock 확인).
- raw NLM 메시지의 `len` field는 정확해야 한다. 파일 핸들은 `@lane` 형태로 `syz_nlm_lane_fh` 결과를
  쓰며, executor가 lane export handle의 상수 word를 모두 확인한다.

NLM 작업의 실행 context와 귀속:

| NLM 작업 | 실행 context | remote-KCOV |
|---|---|---|
| server lockd가 TCP NLM 요청을 처리 (`nlmsvc_lock/testlock/unlock/cancel_blocked`, `nlmsvc_share_file`, GRANTED_RES의 `nlmsvc_grant_reply`) | lockd `svc_recv` (server lane netns) | 귀속됨 (`request`) |
| client0 lockd가 GRANTED_MSG callback을 처리 (`nlmclnt_grant`) | lockd `svc_recv` (client lane netns) | 귀속됨 (`request`) |
| UDP NLM 요청 | lockd `svc_udp_recvfrom` 뒤 `svc_process` | 귀속됨 (`request`, 0006). Stage 1에는 UDP NLM을 보내는 호출이 없다 |
| blocked lock grant (`nlmsvc_grant_blocked`) | lockd thread 자체 (`nlmsvc_retry_blocked`) | 귀속됨 (`lockd`, 0006). LOCK으로 block을 만든 program |
| GRANTED_MSG 송신과 완료 (`nlmsvc_grant_callback`), `*_MSG` 처리 중 보낸 `*_RES` reply | rpciod | 귀속됨 (`lockd`, 0006). grant는 block의 program, reply는 그 요청의 program |
| kernel client가 syscall에서 보내는 async UNLOCK/CANCEL (`nlmclnt_async_call`) | rpciod | 귀속 안 됨 |
| kernel client의 동기 NLM 호출 | executor 프로세스 | executor 자체 KCOV |

kernel patch 0006은 0004의 callback owner를 lockd에 쓴다. block의 owner는 그 block을 만든 LOCK 요청의
program이며, block이 사라질 때까지 바뀌지 않는다. owner의
generation이 closing, committed, aborted이면 section은 거부되고 `cb_section_owner_none`으로 센다. 이
lockd 작업을 요구하는 Q1 target의 `expected_context`는 `lockd`이고, Q1 profile은 `callback_v41`과 같은
counter를 본다. 위 표에서 귀속 안 됨으로 남은 작업을 요구하는 target은 이 boundary 밖이다.

KVM 증거(`capability-evidence/hcap13-kvm.json`, `Hcap13KvmEvidence`)는 `v3-nlm-lock` campaign의 run마다
하나의 귀속 generation과 공개 lockd probe(`svc_lock`, `svc_unlock`, `svc_testlock`, `svc_share`,
`clnt_grant`, `svc_grant_blocked`, `svc_grant_callback`) hit 수를 담는다. promotion 조건은 다음과 같다.

- neutral control은 모든 probe를 miss한다.
- lock(kernel client F_SETLK/F_GETLK/unlock)은 `svc_lock`, `svc_unlock`을 hit하고 grant probe
  (`clnt_grant`, `svc_grant_blocked`, `svc_grant_callback`)는 miss한다.
- rpc(raw LOCK/TEST/UNLOCK/SHARE/UNSHARE)는 `svc_lock`, `svc_unlock`, `svc_testlock`, `svc_share`를 hit한다.
- blocked(client1 lock 뒤의 raw blocking LOCK, client1 unlock)는 `svc_lock`, `svc_unlock`, `clnt_grant`,
  `svc_grant_blocked`, `svc_grant_callback`을 hit한다. 마지막 둘은 0006의 `lockd` context 귀속을 보인다.
- 모든 run 뒤에 lane status가 통과하고 crash와 artifact 오류가 없어야 한다.

`nlmsvc_grant_reply`는 진단으로만 기록한다.

source refs:

```text
bundle/patches/syzkaller/0030-*
bundle/lane/lane.sh
tools/nfs-lifecycle/run.py
agent_pipeline/stage1/host/template/capability-evidence/hcap13-kvm.json
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

promotion된 subset이 아직 없으므로 semantic mutation HCAP entry도 아직 없다. registry 생성과 promotion gate는
구현됐다(`../03-nfs-proxy/06-implementation-gap-analysis.md` §30, issue #51). 첫 subset이 gate를 통과하면 gate가
HCAP-10 entry를 가진 새 revision을 만든다. 그 entry는 `usable_by: [agent_stage2]`, `status: validated_subset`,
`validated_scope`에 promoted subset id, `authority_refs`에 `PromotedSemanticCapabilityRegistry` digest를 둔다.
subset 내용은 그 authority에만 있고 Agent는 `lookup_semantic_scope` 도구로 읽는다. vocabulary에는 어느 promoted
subset에도 맞지 않는 intent의 gap id `semantic_mutation.unpromoted`가 더해진다.

## 5. Stage별 사용 범위

```text
STAGE 1
    HCAP-01 lane filesystem access
    HCAP-02 raw NFS/RPC send
    HCAP-03 remote KCOV
    HCAP-04 lane topology
    HCAP-05 normal-flow seeds
    HCAP-06 flow tracing
    HCAP-11 bounded NFSv4.1 client lifecycle recovery
    HCAP-12 bounded nfsdcld reconnect during NFSv4.1 client recovery
    HCAP-13 NLM lane locking and raw NLM RPC

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
처리하고 `HarnessGapIssue(gap_class=mutation_engine)`를 연결한 뒤 Harness Generation(`07` §5)이 semantic
runtime capability를 생성·검증한다.
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
       Harness Generation (07 §5)
              |
              v
       staged HCAP revision -> Reachability Planning 재개
              |
              +-- 생성 실패 -> blocked_harness_gap
```

Agent는 없는 capability를 있다고 가정하지 않는다.
Stage 1/2 Agent는 candidate 실행 중에 즉석에서 source를 바꾸지 않는다.
없는 capability는 Harness Generation이 syzlang, pseudo-syscall/executor, fixture/tool,
mutation-engine, remote-KCOV 계측으로 생성하고 검증한다.

Linux kernel source를 바꾸는 observability extension도 Harness Generation이 생성한다. target kernel 동작을 바꾸지
않는 계측만 허용하고, `07` §5.2의 검증을 통과해야 쓴다. 공유 HCAP으로의 promotion은 사람이 검토한다.
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
CallAdmissionProfile의 모든 call이 같은 build에서 resolve되고 HCAP entry를 가리킴
참조한 corpus seed가 canonical manifest에 존재
promoted semantic registry digest가 runtime / build identity와 일치
rendered HCAP 문서가 machine data와 일치
```

같은 사실을 담은 목록 두 개를 계속 손으로 맞추지 않는다. 한 manifest를 authority로 정하고 나머지는 그것을
읽는다. 예를 들어 syzkaller patch 적용 순서의 authority는 `bundle/patches/syzkaller/series`다.
`tools/fport-apply.sh`는 지금 `*.patch` glob으로 patch를 적용하므로, 이후 tooling은 glob 대신 `series`(또는
그것에서 생성한 목록)를 읽어야 한다. `4f10720`(series에서 빠진 0021)과 `8c43771`(HCAP 수동 재동기화)이 손으로
고친 drift가 이 guard의 대상이다.
