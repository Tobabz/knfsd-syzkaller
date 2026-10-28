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
  `neutral_control.<profile>`(`05` §11). vocabulary 항목은 `gap_contracts`로 contract(§3.3)를 가질 수 있고,
  그 gap을 채우는 capability는 그 contract를 선언한다(#100).
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
    validated_layout            # 증거가 돈 실행 배치 (#99)
        procs                   # 생략하면 Stage 1 배치: procs=1, lanes=[0]
        lanes[]
    contract                    # 승격이 판정하는 범위 (§3.3, #100)

    evidence_refs[]             # 검증 기록
    authority_refs[]            # 세부 authority artifact의 digest 참조 (§1.1)
    source_refs[]
```

`status`는 기능 존재 여부와 runtime 검증 수준을 구분한다. 검증된 범위는 status 값에 넣지 않고
`validated_scope`에 데이터로 둔다(issue #14).
Agent는 기본적으로 `validated` capability와 `validated_subset`의 scope 안을 우선 사용하고,
`partially_validated` / `experimental` 사용과 scope 밖 사용은 plan에 명시한다.

`validated_layout`은 검증이 성립한 proc 수와 proc lane이다(proc i는 lane i). Stage 1 plan은 lane 0에서
실행되므로 그 배치를 덮지 않는 capability를 쓰면 거부된다(`layout_not_validated`). Stage 1보다 넓은 배치는
typed capability evidence의 `layout`이 같은 값일 때만 선언할 수 있다. Stage 2 manager의 `procs`는 runtime
selection capability(HCAP-04)의 배치를 넘지 못한다. 그 `procs`를 덮는 capability가 없는 admitted call은
enable하지 않으며, 조용히 빼지도 않는다. host spec이 `stage2.enable_syscalls`에서 그 call을 이름으로 빼지 않았으면
generation이 거부한다. 빠진 call은 candidate program에서도 잘려 나가기 때문이다(pinned syzkaller가 비활성 call을
seed에서 지운다). `stage2.procs`를 비워 두면 모든 admitted call이 enable되는 가장 큰 `procs`를 쓴다. 지금 HCAP-11,
HCAP-13, HCAP-14는 lane 0에서만 검증됐으므로 template과 live spec은 `procs=1`이다(#124 검토). typed evidence는
그것을 수집한 execution harness에 묶인다. 다른 빌드에서 수집한 evidence는 운영자가 host spec의
`evidence_carryover`에 원래 harness id와 사유를 적어야 받아들여진다. 그 사실은 capability의 `evidence_refs`에
`carried-capability-evidence.v1` record로 남는다. guest lane script는 이월되지 않는다. 사람이 만든
capability와 생성된 capability에 똑같이 적용한다.

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

### 3.2 트리거 기준

capability는 실제 위협 모델 안의 시나리오만 지원한다(결정 기록 `../decisions/2026-10-25-natural-trigger.md`).

- **트리거**는 Q1에서 대상 커널 코드를 실행시키려고 프로그램이 실행 중에 일으키는 행위다. 실행 전 환경
  구성(fixture 설정, 포트, lease·grace 시간, 데몬 기동)은 트리거가 아니다.
- 트리거는 NFS 클라이언트의 행위여야 한다(요청, syscall, 요청 중단, 연결 끊기. 여러 클라이언트의 조합 포함).
- 클라이언트의 행위 때문에 서버가 하는 동작(callback, lease 만료와 laundromat 처리, blocked lock grant, 서버
  데몬으로 가는 upcall)은 허용한다.
- 실행 중에 harness나 helper가 서버를 직접 조작하는 행위(서버 관리 인터페이스 쓰기, 서버 데몬 정지·종료·재시작,
  서버 설정 변경)는 허용하지 않는다.
- 같은 대상에 도달하는 자연 경로가 있으면 그 경로를 쓴다. 자연 경로가 RemoteKcovSupportBoundary 밖이면
  `remote_kcov_attribution` gap으로 계측을 생성한다(`07` §5). 귀속되지 않는다는 이유로 부자연스러운 트리거로
  우회하거나 대상을 포기하지 않는다.
- 이 기준은 사람이 만든 capability와 Harness Generation이 만든 capability에 똑같이 적용한다.
- Proxy 변조는 중간자 행위가 아니다. C2S 변조는 악의적인 클라이언트가, S2C 변조는 악의적인 서버가 보내는
  메시지를 대신 만든 것이다. Proxy는 변조를 정상 시나리오와 구분하려고 둔 구조다. 따라서 S2C 변조는 서버가
  protocol로 보낼 수 있는 응답·callback이면 허용하고, 그 대상은 서버 응답을 받는 쪽(kernel NFS client)이다.
  서버 관리 조작(서버 관리 인터페이스 쓰기, 데몬 정지·재시작)은 S2C 시나리오에서도 트리거가 아니다.

### 3.3 CapabilityContract

capability가 무엇을 도달시키는지는 후보와 상관없이 contract로 먼저 선언한다(#100). 승격 기준(`07` §5.3)은
contract를 기준으로 판정한다.

```text
CapabilityContract
    entry_points[]              # 프로그램이 capability에 들어오는 곳
        kind                    # syz_call | proxy_operation | fixture_action
        name
    boundary_functions[]        # 진입점이 도달시키는 공개 kernel 함수 (export·entry 함수, tracepoint 지점)
                                # Controller가 promotion probe로 고정한다
    fixed_arguments[]           # 진입점 syz call 인자 중 contract가 정한 고정값
        call
        path                    # 인자와 그 아래 field를 점으로 이은 이름 (client, buf.msg.proc)
        value | text            # 고정 숫자 또는 고정 문자열. 하나만 준다
    fixed_types[]               # protocol이 상수를 정한 syzlang type. 그 안의 상수는 모두 고정값이다
    time_dependent              # true면 KVM evidence로만 승격한다

GapContract                     # vocabulary 항목의 contract
    missing_capability_id
    contract

Capability.fills_gap?           # 이 capability가 채우는 gap ID
```

- contract의 `syz_call` 진입점은 capability `interface.syz_calls`와 같아야 한다.
- `fixed_arguments`는 진입점 call의 인자만 가리킨다. 한 값만 허용하는 인자 위치는 여기나 `fixed_types`에 있어야
  한다(`07` §5.3 기준 5). 후보 program에서 온 값을 고정값으로 올리지 않는다.
- contract의 목록은 집합이다. 순서와 상관없이 같은 contract는 digest가 같다.
- `fills_gap`이 있는 capability의 contract는 그 gap의 `GapContract`와 같다. HCAP은 이를 검증하고, gap
  contract가 없는 gap을 채운다는 capability도 거부한다. 후보에 맞춰 경계를 줄이면 다른 contract다.
- host spec의 `gap_contracts`는 spec을 승인한 operator의 진술이다. Harness Generation의 patch set은 spec을 바꿀 수
  있으므로 그 경로에서는 Controller가 gap과 contract, patch set이 시작한 base spec을 spec 밖에서 넘긴다(`generate
  --gap --base-spec`, `09` §3.2). 그러면 spec은 그 gap에 다른 contract를 줄 수 없고, patch set이 base spec에 추가하거나
  바꾼 capability는 모두 그 gap을 `fills_gap`으로 채워야 하고, base의 capability를 지울 수 없다. base에 이미 있던
  capability는 이 gap 판정의 대상이 아니다. 기준선 밖 capability는 승격 기준(evidence)을 generation마다 다시 거친다.
  evidence가 생성된 harness에 묶이기 때문이다.
- 기준이 생기기 전에 checked-in spec에 있던 항목의 digest(`validated_layout`과 evidence 참조를 뺀 spec 항목)는
  repository 코드 `LEGACY_CAPABILITY_BASELINES`에 고정한다. spec이 스스로 면제를 선언할 수 없다. digest가 같은
  동안은 contract 없이 남고, 내용이 바뀌면 새 capability와 같이 기준을 거친다(2026-10-26 사용자 결정). 지금은
  template의 HCAP-01, 03, 04, 11, 13과 `stage1-host-live`의 HCAP-01, 03, 04, 14가 여기에 있다. HCAP-14는 기준
  이전(2026-10-23)부터 live spec에 `experimental`로 있던 항목이다. 기준선은 그 status를 바꾸지 않으며, validated로
  올리거나 내용을 바꾸면 기준을 거친다.
- `contract`, `fills_gap`, `validated_layout`, `gap_contracts`는 `hcap.v1` 뒤에 생긴 field다. record가 그 field를
  가지고 만들어졌을 때만 직렬화해서, 그 전에 저장된 revision도 canonical bytes가 그대로 유지된다.

## 4. 현재 capability catalog

### HCAP-01 — Lane filesystem access

```text
id: HCAP-01
name: NFS lane filesystem access
usable_stage: [stage1]
usable_by: [agent_stage1]
status: validated_subset
validated_layout:
    procs=4, lanes=[0,1,2,3] (2026-10-27 lane-topology KVM evidence)
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
validated_layout:
    procs=4, lanes=[0,1,2,3] (2026-10-27 lane-topology KVM evidence)

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

validated_layout:
    procs=4, lanes=[0,1,2,3] (2026-10-27 KVM lane-topology evidence)
    Stage 2 manager procs의 상한 (#99). lane 0에서만 검증된 capability가
    있으면 그 call을 잃지 않는 procs까지만 쓴다(위 validated_layout 설명)

verification_note:
    2026-10-27 KVM campaign (agent_pipeline.stage2.topology)에서
    procs=4, lane별 최소 8 trusted executions, independent generation,
    Proxy ACK, healthy execution, lane journal 및 no foreign event를 확인했다.
    evidence: capability-evidence/hcap04-kvm.json (LaneTopologyEvidence)
    이 증거가 HCAP-01, HCAP-03, HCAP-04의 validated_layout을 함께 넓힌다
    lane.sh status는 manager VM 안에서 부를 수 없어 spool record의
    per-execution health 필드로 대신한다. Stage 1은 여전히 lane 0에서 실행된다.
    이 증거는 execution layout만 넓히며 HCAP-04의 나머지 partial scope를
    generic capability promotion으로 바꾸지 않는다.
```

source refs:

```text
README.md
bundle/corpus/nfs-normal/README.md
bundle/lane/lane.sh
bundle/lane/boot-fixture.sh
tools/prepare-live-lane-config.py
capability-evidence/hcap04-kvm.json
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

### HCAP-11 — Client-induced NFSv4.1 client expiry recovery

```text
id: HCAP-11
name: client-induced NFSv4.1 client expiry recovery
usable_stage: [stage1]
usable_by: [agent_stage1]
status: validated
scope: [client0_courtesy_expiry_recovery]

interface:
    syz_open_nlm_lane_file
    syz_nfs_lane_link$partition_client0(0x0, 0x0)
    syz_nfs_lane_link$heal_client0(0x0, 0x1)

purpose:
    lane 0의 client0이 lease보다 오래 서버와 끊겨 courtesy client가 된 뒤,
    client1의 충돌하는 OPEN으로 서버가 client0을 만료시키게 하고
    일반 client0 profile I/O로 EXCHANGE_ID -> CREATE_SESSION 복구를 유도

constraints:
    single NFSv4.1 fixture, SERVER_IMPL=both, 기본 NFSv4 lease 10 s
    모든 트리거는 NFS client 행위다(§3.2): client0은 자기 lane network namespace의
    자기 link에서 보내는 packet만 버리고, 만료는 client1의 OPEN에 대한 서버의 반응이다.
    서버 namespace에는 아무것도 하지 않는다.
    순서:
        r0 = syz_open_nfs_lane_profile$client0_knfsd_v41(0x2, 0x0)
        r1 = syz_open_nlm_lane_file(r0, name, 0x2)   # read-write, write delegation을 받는다
        syz_nfs_lane_link$partition_client0(0x0, 0x0) 정확히 한 번
            # link가 15 s(lease보다 김) 동안 보내는 packet을 모두 버리고, 버리는 채로 돌아온다
        r2 = syz_open_nfs_lane_profile$client1_knfsd_v41(0x2, 0x1)
        r3 = syz_open_nlm_lane_file(r2, 같은 name, 0x2)
        syz_nfs_lane_link$heal_client0(0x0, 0x1) 정확히 한 번
        parser가 client0 FD origin을 증명한 일반 I/O 하나 이상(statx, getdents64 등.
        close와 lseek는 인정하지 않음)
    partition과 heal 사이에는 client0 origin call이 없어야 한다(끊긴 link에서 기다린다)
    두 open이 같은 파일을 가리키는지는 parser fact가 아니다. 다른 파일을 열면 경로에 닿지 못할 뿐이다
    knfsd는 최근 30~60 s 안에 delegation을 회수한 파일에는 delegation을 주지 않는다. 반복 실행하는
    프로그램은 스스로 만든 파일에서 시작해야 하므로, 검증된 stimulus는 O_CREAT(mode 0x2)로 열고
    마지막에 client0이 그 파일을 unlinkat한다
    partition을 쓰는 프로그램은 syzkaller 기본 프로그램 예산(5 s)을 넘으므로 Stage 1 collector가
    syz-execprog -program-timeout을 올린다(KVM 90 s, TCG 270 s)
```

트리거는 knfsd의 courteous server 동작이다. NFSv4.1 client가 lease 동안 갱신하지 않아도 session이 있으면
서버는 바로 지우지 않고 `NFSD4_COURTESY`로 남긴다. 다른 client의 요청이 그 client의 state와 충돌할 때에만
`try_to_expire_client`가 만료시킨다. 검증된 경로에서는 client0이 read-write open으로 write delegation을 받아
두었고, client1의 OPEN이 그 delegation을 회수하는 `nfsd_break_deleg_cb`(client1 OPEN을 처리하는 nfsd
thread, 귀속됨)가 courtesy client0을 찾아 laundromat을 깨운다. laundromat의 `mark_client_expired`와 purge는
workqueue에서 돌아 귀속되지 않는다. client1의 OPEN은 `NFS4ERR_DELAY` 뒤 허가된다. heal 뒤 client0은
`BADSESSION`과 `STALE_CLIENTID`를 받고 새 clientid로 EXCHANGE_ID, CREATE_SESSION을 한다(nfsd request,
귀속됨). 첫 HCAP-11이 쓰던 서버 관리 인터페이스 `/proc/fs/nfsd/clients/<id>/ctl` 쓰기
(`syz_nfsd_client_ctl$expire_client0`)는 NFS client 행위가 아니므로(#96) materializer가 어떤 admission
authority가 허용하더라도 `syz_nfsd_client_ctl$` call을 `CALL_NOT_ADMITTED`(`<role>_server_admin_control`)로
거부한다. syzkaller patch 0027의 executor call과 `tools/nfs-proxy/src/lifecycle.c` broker는 fixture 작업용으로
남는다. `syz_nfs_lane_link$` call은 HCAP-11 scenario 밖에서(neutral control 포함) 거부된다.

KVM 증거는 `tools/nfs-lifecycle/run.py --scenario v41-courtesy-expiry --repeat 3`이 만든다. neutral control
(client0 lane I/O) 3회와 stimulus 3회를 같은 harness에서 돌린다. 각 실행은 remote-KCOV generation
begin/publish 1회, abort/overflow/truncation 0회, 종료 시 outstanding token 및 remote ref 0을 기록하고, 실행 뒤
`lane.sh status`가 fixture를 정상으로 보고하며 dmesg에 crash가 없어야 한다. public probe 세 개
(`nfsd_break_deleg_cb`, `nfsd4_exchange_id`, `nfsd4_create_session`)를 pinned vmlinux의 coverage callsite로
mapping하고, control은 셋 다 놓치고 stimulus는 매번 셋 다 실행해야 한다. stimulus의 서버 trace는
`nfsd_cb_recall` -> `nfsd_mark_client_expired` -> `nfsd_clid_purged` -> client1 `OP_OPEN` 허가 ->
`nfsd_clid_fresh` -> `OP_EXCHANGE_ID` -> `nfsd_slot_seqid_unconf` -> `nfsd_clid_confirmed` ->
`OP_CREATE_SESSION` 순서여야 하고 복구한 clientid는 만료된 것과 달라야 한다. HCAP-03은 이 실행의 generation attribution을 계속 담당한다. 공유 증거는
probe mapping digest와 전체 mapping identity를 기록하고 target 주소는 포함하지 않는다. Host generator는 이
typed evidence의 execution harness, kernel/instrumentation/vmlinux/KASLR identity와 guest lane script digest를
새 descriptor에 대해 다시 검사한 뒤에만 HCAP-11을 promotion한다.

2026-10-25 증거(`capability-evidence/hcap11-kvm.json`)는 KVM이 없는 host에서 TCG(`exec_slowdown` 10)로
얻었다. control 3회는 세 probe를 모두 놓쳤고, stimulus 3회는 매번 `nfsd_break_deleg_cb` 9개,
`nfsd4_exchange_id` 22개, `nfsd4_create_session` 55개 PC를 실행했으며 위 순서의 trace를 남겼다. 6회 모두
lane status 정상, crash 0이었다. 앞선 시도에서 확인한 두 가지가 설계에 반영되어 있다. link를 내리는
partition은 client에 `ENETUNREACH`를 돌려주고 lane의 정적 경로를 지워 복구가 멈췄으므로, 0032는 link를
유지한 채 blackhole root qdisc로 packet만 버린다. 같은 `lock0`을 다시 쓰는 반복 실행은 knfsd가 delegation을
주지 않아 충돌이 생기지 않았으므로, stimulus는 마지막에 `lock0`을 지운다.

source refs:

```text
bundle/patches/syzkaller/0032-*
bundle/lane/lane.sh
tools/nfs-lifecycle/run.py
tools/nfs-lifecycle/programs/v41-courtesy-expiry.prog
agent_pipeline/stage1/host/template/capability-evidence/hcap11-kvm.json
```

### HCAP-12 — 철회됨 (nfsdcld reconnect)

HCAP-12는 broker가 서버 데몬 nfsdcld를 SIGSTOP·SIGKILL·재시작해 rpc_pipefs CLD pipe reader 교체와 client0
복구를 겹치게 하는 capability였다. 어떤 NFS client 행위도 서버 데몬을 재시작시킬 수 없으므로 트리거 기준(§3.2)을
위반한다. 사람이 구현한 capability와 생성된 capability에 같은 기준을 적용하므로 manual 전용으로도 남기지 않고
카탈로그에서 삭제했다(#98). host generator template에는 HCAP-12 entry, KVM 증거, `syz_nfsd_cld_ctl$reconnect`
admission, 그 call을 켜는 runtime selection과 neutral control이 없고, materializer는 어떤 admission authority가
허용하더라도 `syz_nfsd_cld_ctl$` call을 `CALL_NOT_ADMITTED`(`<role>_server_daemon_control`)로 거부한다. 이전
`hcap_revision`에 묶인 job은 일반 `hcap_revision` 변경 경로로 다시 평가된다. syzkaller patch 0028의 executor
call과 `tools/nfs-proxy/src/cld.c` broker는 fixture 작업용으로 남는다.

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

귀속되지 않는 context를 요구하는 Q1 target은 `remote_kcov.context.cld` gap이며, 현재 harness는 그
범위를 지원하지 않는다. 그 context의 귀속 계측은 Harness Generation이 `remote_kcov_attribution`
gap으로 생성하고 검증한다(`07` §4, §5). trace, dmesg, daemon log는 진단 정보일 뿐 Q1 근거가 아니다.

### HCAP-13 — NLM lane locking and raw NLM RPC

```text
id: HCAP-13
name: NLM lane locking and raw NLM RPC
usable_stage: [stage1]
usable_by: [agent_stage1]
status: validated (KVM evidence 전까지 generator가 template을 거부)
scope: [nlm_lane_lock_rpc]
validated_layout:
    procs=1, lanes=[0] (Stage 1 only; Stage 2 재검증 전 lane 0으로 제한)

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
- 여기서 promoted는 M7 gate를 통과해 job이 binding한 `hcap_revision`에 pin됐다는 뜻이다. 그 revision은 promoted
  revision일 수도 있고 Harness Generation이 만든 staged revision(§1.1)일 수도 있다. staged revision이 semantic
  subset을 담으려면 M7 1단계(crash survival을 뺀 항목, `03-nfs-proxy/06` §30)를 통과해야 하고, pin은 crash survival
  pending으로 표시된다. crash survival은 자연 crash로만 확인하며 인위적으로 crash를 만들지 않는다. 공유 HCAP으로
  올리는 promotion은 그 확인(M7 2단계) 뒤에만 한다. subset을 사람이 구현했는지 생성했는지는 구분하지 않는다.
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
    HCAP-11 client-induced NFSv4.1 client expiry recovery
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
Planning은 자연 경로가 있으면 그 경로를 고르며, 그 경로가 귀속되지 않으면 서버 직접 조작으로 우회하지 않고
`remote_kcov_attribution` gap을 낸다(§3.2).
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

runtime이 pin된 authority에 없는 capability를 더 노출
    -> 사용하지 않는다
    -> validation / promotion(M7 gate나 Harness Generation 검증)이 binding한 revision의 authority를
       갱신하기 전에는 Agent capability가 아니다. staged revision에 pin된 것은 사용한다
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
