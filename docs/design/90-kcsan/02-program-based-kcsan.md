# Program-based-KCSAN

> 상태: 구현 검토 · 최종 확인: 2026-10-27 · 기준: Stage 2 campaign, syz-manager KCSAN overlay, KCSAN Policy Store
> 관련 패치: `bundle/patches/kcsan/{kernel,syzkaller}` 및 bootstrap/fport 연결 · 관련 게이트: Stage 1 Q1, Stage 2 gate와 campaign
> 목적: 후보 함수의 KCSAN 규칙을 퍼징 VM에 등록하고 해당 후보의 실행에만 연결하는 경계를 정의한다.

## 요약

후보 함수의 Policy payload는 Stage 1 실행에 넣지 않고, Stage 2 campaign 시작 시 job과 harness identity를 대조한 뒤 생성·선택한다. syz-manager는 각 VM에서 첫 runner 전에 payload를 등록하고, remote-coverage가 활성화된 각 program request에 manager의 `candidate_id`를 전달한다. executor는 그 ID로 KCOV generation을 시작하고 커널 KCSAN은 후보 규칙에 일치하는 접근만 샘플링한다. Stage 2 baseline gate와 replay는 기존 경로를 유지한다.

생성·등록·실행 선택·실제 watchpoint 적용은 서로 다른 성공 조건이다. 앞 단계의 성공이나 KCSAN 보고 부재만으로 다음 단계를 추론하면 안 된다. Stage 2는 syz-manager의 report artifact를 Q2 bundle에 보존하고 KCSAN을 nonfatal signal로 분류한다. KCSAN report가 있다는 사실만으로 guest가 종료됐다고 기록하지 않으며, host console에 KCSAN이 있지만 manager report가 없으면 Q2 internal error로 남긴다. Q2 report 수집·replay의 full runtime 검증은 아직 남아 있다.

## 해결하려는 문제

Stage 1의 `RunnerInput`에는 `job_id`와 하네스 참조만 있다. 이는 의도된 경계다. KCSAN Policy는 Stage 1 Q1 도달성에 영향을 주지 않으며, Stage 2 `campaign`에서 `_campaign_manager`가 Controller SQLite의 job, harness candidate ID, kernel commit, sanitizer를 대조한 후에만 `ProgramPolicyPipeline.manager_config()`로 payload를 만들고 선택한다. KASAN campaign은 이 Store를 열지 않고 KCSAN field도 받지 않는다.

Policy 생성 시점과 적용 시점도 구분해야 한다. Stage 1 poll이나 job 제출 때는 payload를 만들지 않는다. campaign 선택 시 같은 candidate ID의 기존 파일은 payload bytes가 같을 때만 재사용하고, 삭제된 파일은 동일한 내용으로 복원한다. payload 생성만으로 VM 등록이나 executor의 generation 연결이 끝났다고 간주할 수 없다.

## 구조

```text
+------------------------------ host ------------------------------+
| Stage 1 --Q1--> Stage 2 gate (baseline, unchanged)               |
| Stage 2 campaign --> execution.json(job_id,state_dir)             |
|                       |                                           |
|                       v                                           |
|                _campaign_manager --verify--> Job Store           |
|                       |                    candidate, kernel,     |
|                       |                    sanitizer match        |
|                       v                                           |
|          ProgramPolicyPipeline.manager_config                    |
|                       | payload file + kcsan_policy_file          |
|                       v                                           |
|                  syz-manager                                      |
|                  |            |                                  |
|        per VM boot            per program                         |
|        payload                candidate_id                        |
+--------|----------------------|---------------------------------+
         v                      v
+--------------------------- guest VM -----------------------------+
| policy-load --> Policy Store (R)                                  |
| ExecRequest --candidate_id--> executor --BEGIN_POLICY--> gen (B)  |
| gen --Policy ref--> candidate scope + matched-rule KCSAN (K)       |
+------------------------------------------------------------------+
```

위에서 아래로 읽는다. `(R)`은 VM별 등록, `(B)`는 실행별 generation 참조 연결, `(K)`는 실제 접근에서의 적용이다. payload는 campaign 시작 때 호스트에서 생성·검증되고, KASAN job은 이 경로에 들어오지 않는다. syz-manager에는 `job_id` 대신 선택된 payload 경로를 주며, 각 remote-coverage program request에는 manager가 가진 `candidate_id`를 전달한다.

| 연결 | 전달값·결과 | 소유 코드와 상태 |
|---|---|---|
| Stage 1 | 기존 `RunnerInput(job_id, harness refs)`; Policy payload 없음 | Q1 도달성 실행, 유지됨 |
| campaign 진입 | `job_id`, `state_dir`, harness candidate/kernel/sanitizer | `Stage2CommandEngine._prepare` → `_campaign_manager`, 구현됨 |
| 호스트 준비·선택 | job candidate → `kcsan-policies/<candidate_id>_policy.payload` → `kcsan_policy_file` | `ProgramPolicyPipeline.manager_config`, campaign에서 호출됨 |
| VM 부팅 | 선택한 payload → Policy Store 등록·조회 | syzkaller `loadKCSANPolicy` → executor `policy-load`, 구현됨 |
| 프로그램 실행 | manager candidate ID → `ExecRequest`/snapshot request → generation | syzkaller RPC/backend → executor, 구현됨 |
| KCSAN 적용 | generation Policy ref + function IP → matched-rule sampling | kernel overlay patch 0001–0004, host/VM evidence 일부 있음 |

## 설계

### 1. campaign 시작 때 후보를 Policy 파일로 준비한다

Stage 2의 campaign step은 `job_id`와 `state_dir`을 `execution.json`으로 전달한다. `_campaign_manager`는 Controller Store에서 job을 다시 읽어 harness의 `candidate_id`, descriptor의 kernel commit, job policy sanitizer와 일치하는지 확인한 뒤 `ProgramPolicyPipeline.manager_config()`를 호출한다. KASAN campaign은 이 경로를 타지 않는다.

```text
Stage2CommandEngine --job_id,state_dir--> _campaign_manager
                                                |
                                                v
                                           Controller Store
                                    candidate_id, location, kernel
                                                |
                                                v
                                     prepare_program_policy
                                                |
                                                v
        <state_dir>/kcsan-policies/<candidate_id>_policy.payload
                                                |
                                                v
                     manager.kcsan_policy_file = selected file
```

`JobPolicy.policy_id`는 job의 실행 방식을 선택한다. 커널 Policy의 키는 숫자 ID가 아니라 `candidate_id`다. 후보 ID, harness candidate ID, target kernel commit, KCSAN sanitizer 중 하나라도 맞지 않으면 campaign을 fail-closed로 중단한다.

현재 Program-based 규칙은 `location.kind=function` 및 `location.symbol`만 지원한다. 해당 함수에 `weight=4`, `delay_us=3000`을 주며, kernel overlay는 weight unit당 10%, 최대 40%를 직접 적용한다. payload 파일은 atomic하게 생성한다. 파일이 이미 있으면 같은 bytes인지 확인하고, 다른 내용으로 동일 candidate ID를 덮어쓰지 않는다. `source_range`와 인라인 심볼 해석은 지원하지 않는다.

payload는 job 제출·Stage 1 poll에서 만들지 않는다. campaign 재시도 시 파일이 없으면 같은 payload를 복원하고, 다른 bytes가 있으면 거부한다.

### 2. Stage 1 reachability와 Policy 적용을 분리한다

Stage 1에서는 Policy 파일을 준비하거나 등록하지 않는다. Controller가 Q1에 넘기는 Runner 입력 계약은 바뀌지 않으며, KCSAN delay가 도달성 증거를 바꾸지 않는다.

```text
candidate accepted
    |
    +-- Stage 1 RunnerInput(job_id, harness refs) --> Q1 reachability
                                                      |
                                                      +-- not REACHED: repair/stop
                                                      |
                                                      +-- REACHED: S1_REACHED
                                                              |
                                                              v
                                             Stage 2 gate (baseline, unchanged)
                                                              |
                                                              v
                                      campaign start --> prepare/register Policy
```

Stage 1이 종료된 뒤에도 Policy 파일은 아직 없다. Stage 2 gate와 replay 또한 기존 direct-VM 경로를 유지한다. Policy는 syz-manager campaign VM에서만 로드되며, 변이 프로그램·seed·corpus의 `Prog` 객체에는 candidate ID를 복사하지 않는다.

### 3. campaign 시작 시 파일 하나를 선택한다

실제 Stage 2 `campaign` step의 `_campaign_manager`가 `job_id`로 job을 조회해 identity를 검증한 뒤 `ProgramPolicyPipeline.manager_config(job_id, manager)`를 호출한다. 결과 config에 해당 후보의 `kcsan_policy_file` 하나만 추가하고, 그 뒤 syz-manager를 시작한다.

```text
Stage2 _campaign
      |
      | job_id + state_dir + harness/descriptor identity
      v
_campaign_manager --> Controller Store lookup + identity checks
      |
      v
ProgramPolicyPipeline.manager_config(job_id, manager)
      |
      +--prepare(job_id)--> candidate-specific payload
      |
      +--return manager.kcsan_policy_file = selected file
      v
syz-manager validates basename/header and reads selected file
```

syz-manager에는 `job_id`가 전달되지 않는다. manager config의 payload 경로와 파일 header의 `candidate_id`가 맞지 않으면 config validation에서 거부된다. 다른 후보 payload가 같은 폴더에 있어도 선택에 영향을 주지 않는다. 시드·코퍼스·변이 `Prog` 객체에는 candidate ID를 복사하지 않는다. `fport-apply.sh`와 bootstrap은 공통 syzkaller patch stack 다음에 KCSAN overlay를 적용하며, manifest/build record의 patch digest에는 두 stack이 모두 포함된다.

### 4. VM 등록과 프로그램 실행 선택을 분리한다

매니저가 선택한 후보는 서로 다른 두 경로로 VM에 전달된다.

```text
                        syz-manager
                         |         |
              per VM boot|         |per program execution
                         v         v
                    payload    candidate_id
                         |         |
                         v         v
             syz-executor policy-load   ExecRequest
                         |                    |
                         v                    v
                Policy Store (R)      syz-executor BEGIN
                         |                    |
                         +----Policy ref----> generation (B)
                                              |
                                              v
                                   NFS/RPC KCSAN access (K)
```

VM backend는 부팅할 때 payload와 executor를 복사하고 `policy-load`로 Store 등록·조회를 마친 뒤 runner를 시작한다. VM이 재부팅되면 다시 등록하지만, 프로그램이나 mutation마다 파일을 다시 등록하지 않는다. 일반 실행과 snapshot 실행 모두 매니저 설정의 `candidate_id`를 실행 요청에 넣는다. executor는 프로그램 실행 직전 새 generation을 시작하고 Store의 Policy 참조를 붙인다. 등록 `(R)`, 실행 연결 `(B)`, 실제 KCSAN 적용 `(K)`은 별개로 확인해야 한다.

### 5. 지원하지 않는 후보와 실행 경로

`location.kind=source_range`는 바로 등록할 함수 심볼이 없으므로 함수가 확정되기 전에는 payload 준비를 거부한다. 인라인되어 독립 실행 심볼이 없는 함수도 VM 등록에 실패할 수 있다. Kernel resolver는 `kallsyms_lookup_name()`을 사용하며 source path 기반 disambiguation이나 kernel-wide 동명 symbol uniqueness 검증은 제공하지 않는다. Pipeline의 candidate/kernel identity 검증도 이를 해결하지 않는다. 따라서 해석된 Store IP range를 정확한 `vmlinux`와 대조하기 전에는 특정 source function에 Policy가 적용됐다고 해석하지 않는다. 이름이 비슷한 함수나 부모 함수를 추측해 대체하지 않으며, 자동 uniqueness guard는 미결 사항이다. generation을 상속하지 않는 비동기 작업에는 이 Policy가 적용된다고 주장하지 않는다.

## 설계 근거

| 결정 | 근거 |
|---|---|
| campaign 시작 때 payload 준비 | Stage 1에서 쓰지 않는 파일을 미리 만들지 않고, campaign 직전 job/harness identity를 다시 검증한다. |
| Stage 1과 Stage 2 gate에는 Policy 미적용 | Q1와 baseline gate의 실행 조건을 보존하고 KCSAN candidate sampling을 fuzz campaign에만 제한한다. |
| campaign VM 시작 전에 등록 | campaign의 모든 program이 같은 등록된 Policy를 사용하고, 등록 실패 시 runner 시작을 막는다. |
| `job_id`로 후보·payload 조회 | Controller가 job의 후보를 찾되, Policy 자체는 `candidate_id`로 재사용한다. |
| 등록 상태를 VM 부팅 인스턴스별로 확인 | Policy Store는 커널 메모리에 있고 VM 재부팅 뒤에는 비어 있다. |

## 검토한 대안

| 선택지 | 얻는 것 | 비용·한계 | 채택 여부와 이유 |
|---|---|---|---|
| job 제출 시 미리 payload 생성 | campaign 준비 시간을 줄임 | Q1에서 중단되거나 KASAN만 실행하는 job에도 미사용 파일이 남음 | 채택 안 함. 실제 KCSAN campaign 진입 시 생성한다 |
| Stage 1 또는 gate부터 Policy 적용 | 모든 단계에서 동일한 sampling 설정 | delay가 Q1/baseline gate 조건을 바꾸고 비교 기준을 흐림 | 채택 안 함. Stage 1과 gate는 기존 경로를 유지한다 |
| 변이 프로그램마다 함수·payload 복사 | program 단독으로 설정을 확인 가능 | 반복 복사·등록 비용과 추가 identity 상태 | 채택 안 함. manager가 campaign candidate ID를 request에 넣는다 |
| VM 부팅 시 고정 payload만 등록 | 시작 절차가 단순함 | 잘못된 후보를 고정 선택할 위험 | 채택 안 함. campaign job/harness를 확인한 뒤 config 하나를 만든다 |

## 영향

**상류:** 후보 위치, 커널 commit 또는 실행 하네스 binding이 바뀌면 기존 payload의 적합성을 다시 확인해야 한다. Stage 2의 Q1 handoff 조건은 Agent 설계를 따른다.

**하류:** 다른 후보의 payload가 등록되거나 executor의 `candidate_id` 전달이 빠지면 KCSAN 비교 결과를 후보 함수의 탐지 효과로 해석할 수 없다.

**운영:** payload는 한 번 준비해 재사용하되 VM 재부팅마다 등록한다. 후보별 VM 격리는 필요하며, mutation마다 payload 생성·등록 비용을 지불하지 않는다.

## 신뢰성 요구

잘못된 Policy가 적용됐는데 성공으로 기록하는 거짓 양성이 가장 위험하다. 후보·binding 불일치, VM 등록 실패, executor 선택 실패는 Stage 2 적용 실험을 중단하고 원인을 기록한다. 같은 job과 binding의 재시도는 동일한 payload를 반환해야 한다. 등록·연결·실제 접근은 각각 별도로 관측하며, KCSAN 보고가 없다는 사실만으로 연결 실패나 race 부재를 단정하지 않는다.

## 검증 오라클

1. Host: KCSAN campaign에서 후보 함수의 `4/3000` rule을 만들고, 동일 candidate 재시도에서 payload bytes를 유지한다. Stage 1 poll/job 제출은 파일을 만들지 않는다. KASAN job은 KCSAN pipeline을 부르지 않는다.
2. Stage 1/gate: Policy 파일 등록과 generation bind 없이 기존 Q1 및 baseline gate 결과를 만든다.
3. Campaign start: job/harness candidate, kernel commit, sanitizer가 일치할 때만 manager config에 해당 후보의 `kcsan_policy_file`을 넣는다. VM 부팅 때 Store 등록·조회에 성공해야 runner가 시작된다.
4. 실행 중: request candidate ID, executor의 generation begin, `generation_policy_bind_ok`, 대상 함수의 `policy_rule_selected`, `policy_setup`, `policy_delay`를 각각 확인한다.

Host unit tests는 1–3의 계약을 다룬다. Kernel overlay patch 0004의 commit message는 KCSAN kernel build와 VM smoke test(후보 `nfsd_svc` 선택, 1100 접근 중 440 watchpoint setup)를 보고하지만, resolved base SHA와 원시 로그/evidence가 저장소에 없어 현재 pin에 대해 독립 재현된 검증으로 볼 수 없다. 이번 검토에서 재현 가능한 validation은 Python test suite와 clean-base syzkaller patch application이다. Controller에서 시작한 full Stage 2 two-server campaign 및 발견된 race의 replay는 아직 검증되지 않았다. 등록 성공은 실행 연결을, 카운터 증가는 실제 data race의 존재를 증명하지 않는다.

## 실패 양상과 진단

| 증상 | 가능한 원인 | 구분하는 관측 | 조치 |
|---|---|---|---|
| payload 준비 거부 | 후보 위치·binding 불일치, 범위 밖 함수 | job의 후보·하네스 identity와 준비 오류 | 입력을 바로잡고 동일 job의 재시도 계약 확인 |
| VM 등록 거부 | 독립 심볼 없음, 후보 ID 중복·payload 불일치 | register 결과와 Policy Store 조회 | 커널 빌드·함수 심볼·캠페인 설정 확인 |
| 등록됐으나 규칙 적용 없음 | executor 선택 누락, generation 미전파 | bind 카운터와 함수별 KCSAN 카운터 | 등록과 실행 연결 경계를 따로 점검 |
| Stage 1 결과에 Policy delay가 개입 | 준비와 등록 단계가 결합됨 | Stage 1의 등록·bind 로그 | Stage 1에서는 VM 등록을 금지 |

## 한계와 미결 사항

| 상태 | 항목 |
|---|---|
| 구현됨 | Stage 2 campaign이 job/harness/kernel/sanitizer identity를 확인하고 payload를 생성해 manager config에 선택한다. Stage 1, gate, replay는 Policy 없이 실행한다. |
| 구현됨 | KCSAN kernel 및 syzkaller overlay를 공통 patch stack 다음에 bootstrap/fport가 적용하고, build fingerprint에 두 stack을 기록한다. |
| 보고됨·독립 재현 안 됨 | Overlay patch 0004 commit message는 kernel build와 VM smoke test를 보고하지만 resolved base SHA와 raw evidence는 보존되지 않았다. 현재 pin 기준 재현 및 full Controller → Stage 2 two-server campaign/replay는 남아 있다. |
| 현재 범위 밖 | 한 manager에서 다중 candidate를 실행하는 방식. 현재 manager config는 후보 payload 하나만 허용한다. |
| 미결 | `source_range`에서 함수 해석, inline/동일 이름 심볼을 정확히 매핑하는 방법. |
| 미검증 | generation 경로를 상속하지 않는 asynchronous work의 Policy 전파와 서로 다른 candidate 간 VM 격리. |
| 미검증 | KCSAN race report의 Stage 2 full campaign 수집·replay 검증. |

## 참조

- `agent_pipeline/stage2/engine.py`: campaign execution에 `job_id`와 Controller `state_dir`을 기록.
- `agent_pipeline/stage2/kvm.py`: `_campaign_manager` identity 검증, `manager_config()` 연결, campaign 실행.
- `kcsan_pipeline/program_policy.py`, `kcsan_pipeline/pipeline.py`: 후보별 payload 생성·검증·보관.
- `bundle/patches/kcsan/kernel/series`, `bundle/patches/kcsan/syzkaller/series`: KCSAN kernel 및 syzkaller overlay.
- `tools/fport-apply.sh`, `tools/bootstrap-kcov-env.py`, `tools/syzkaller/build.py`: base series 뒤 overlay 적용 및 통합 build fingerprint.
- KCSAN overlay가 적용된 syzkaller의 `pkg/mgrconfig/load.go`: `kcsan_policy_file` 검증.
- syzkaller `pkg/execbackend/rpc.go`, `pkg/execbackend/snapshot.go`, `executor/executor_linux.h`: VM별 policy-load.
- syzkaller `pkg/rpcserver/rpcserver.go`, `pkg/rpcserver/runner.go`: manager candidate ID를 program request에 전달.
- `docs/design/02-llm-agent/01-two-stage-agent-architecture.md`: Stage 1 Q1, Stage 2 전략·gate·campaign.
- `docs/design/02-llm-agent/09-job-state-graph.md`: Runner task와 Stage 2 상태 계약.
- `docs/design/90-kcsan/01-architecture.md`: 커널 Policy Store와 generation 연결. 후보별 영속 ID 서술은 이 Program-based 설계로 재검토한다.

## Agent 사용 지침

**지원 범위:** `location.kind=function`이고 NFS/RPC 범위에 있는 후보 함수 하나의 고정 규칙을 준비한다. KCSAN job에만 적용한다.

**비지원 범위:** `source_range`를 함수로 추측하거나, 두 번째 함수를 임의로 추가하거나, VM 등록을 Stage 1 Q1의 일부로 간주하지 않는다.

**확장 절차:** 새 실행 경로를 추가할 때는 Stage 1/gate/replay의 baseline 경계를 유지하면서 job/harness/kernel identity, VM 등록, request candidate ID, generation bind를 각각 검증한다. `source_range`를 지원하려면 source path를 포함한 함수 해석 근거와 대상 빌드 symbol 검증을 먼저 추가한다.

**제약:** 다른 후보의 payload 파일을 선택한 매니저 설정을 재사용하지 않는다. VM 등록 성공과 실행 중 Policy 선택을 별도로 확인한다.

**검증 방법:** host 계약 검증 후 Stage 1/gate 비적용, campaign VM 등록·조회, request candidate ID, generation 연결, 함수별 KCSAN 카운터 순서로 확인한다.
