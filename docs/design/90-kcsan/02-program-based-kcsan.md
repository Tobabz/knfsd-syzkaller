# Program-based-KCSAN

> 상태: draft · 최종 확인: 2026-10-16 · 기준: Agent Controller, syz-manager, KCSAN Policy Store
> 관련 패치: Controller의 퍼징 시작 설정 연결 미구현 · 관련 게이트: Stage 1 Q1, Stage 2 baseline-with-rules gate
> 목적: 후보 함수의 KCSAN 규칙을 퍼징 VM에 등록하고 해당 후보의 실행에만 연결하는 경계를 정의한다.

## 요약

확정된 후보 함수로 KCSAN Policy payload를 미리 만들고, 퍼징 실행에 사용할 VM에 첫 프로그램 실행 전에 등록한다. Stage 1은 이 Policy 없이 도달성을 확인하며, Stage 2의 baseline 생성·전달 경로는 변경하지 않는다. 생성·등록·실행 선택을 혼동하면 Policy가 적용되지 않은 결과를 적용 실험으로 잘못 해석한다.

## 해결하려는 문제

코드상 Controller는 후보와 실행 설정을 job에 저장하지만, Stage 1의 `RunnerInput`에는 `job_id`와 하네스 참조만 있다. KCSAN pipeline은 채택된 후보를 `job_id`로 조회해 payload를 영속 파일로 만들고 `kcsan_policy_file`을 포함한 syz-manager 설정을 반환할 수 있다. 이 설정을 실제 퍼징 시작에 사용하는 Controller 연결은 아직 없다.

Policy 생성 시점과 적용 시점도 구분해야 한다. 후보 함수는 Stage 1의 Q1 판정에 따라 바뀌지 않으므로 payload 생성을 도달 성공 이후로 미룰 이유가 없다. 반면 후보 함수의 delay를 Stage 1에 적용하면 도달성을 확인하는 실행 조건이 바뀐다. payload를 만들었다는 사실만으로 VM의 Policy Store 등록이나 executor의 실행 선택을 완료했다고 간주할 수도 없다.

## 구조

```text
+------------------------------ host ------------------------------+
| Controller --job_id--> KCSAN pipeline --lookup--> Job Store      |
| KCSAN pipeline <--candidate_id------------------- Job Store      |
|                              +--payload (P)--> policy file       |
| Stage 1 --Q1--> Stage 2 --baseline/rules--> [M] fuzz launch      |
| Controller --job_id-------------------------> [M]                |
| [M] --job_id--> manager_config                                   |
| manager_config --kcsan_policy_file--> syz-manager                |
| syz-manager --payload--> VM backend (per boot)                   |
| syz-manager --candidate_id--> ExecRequest (per program)          |
+------------------------------|-------------------|---------------+
                               | payload           | ExecRequest
                               v                   v
+--------------------------- guest VM -----------------------------+
| Policy Loader --register payload--> Policy Store (R)             |
| ExecRequest --candidate_id--> syz-executor --BEGIN--> gen (B)    |
| gen --Policy ref--> NFS/RPC access --IP match--> KCSAN (K)       |
+------------------------------------------------------------------+
```

위에서 아래로 읽는다. `(P)`는 호스트 파일 준비, `(R)`은 VM별 등록, `(B)`는 실행별 참조 연결, `(K)`는 실제 접근의 적용 관측이다. `[M]`은 아직 없는 Stage 2 퍼징 시작 호출부다. `manager_config`가 Job Store에서 `job_id`에 연결된 `candidate_id`를 찾고 해당 파일 경로를 설정에 넣는다. syz-manager가 받는 것은 `job_id`가 아니라 이미 선택된 파일 경로다.

| 연결 | 전달값·결과 | 소유 코드와 상태 |
|---|---|---|
| 후보 접수 | `job_id`로 채택된 `candidate_id` 조회 | `Controller._prepare_candidate` → `ProgramPolicyPipeline.prepare`, 구현됨 |
| 호스트 준비 | 후보 함수 → `kcsan-policies/<candidate_id>_policy.payload` | `prepare_program_policy`, 구현됨 |
| 퍼징 시작 | `job_id` → Job Store의 `candidate_id` → `kcsan_policy_file` | `ProgramPolicyPipeline.manager_config`는 구현됨; 호출부 `[M]`은 미구현 |
| VM 부팅 | 선택한 payload → Policy Store 등록·조회 | `completeKCSANPolicies` → `loadKCSANPolicy` → `policy-load`, 구현됨 |
| 프로그램 실행 | 설정의 `candidate_id` → `ExecRequest` → generation | `rpcserver.Runner`·snapshot backend → `syz-executor`, 구현됨 |

## 설계

### 1. 후보를 Policy 파일로 준비한다

Controller가 후보를 채택하면 KCSAN 준비 함수에 `job_id`를 준다. 함수나 Policy 내용을 Stage 1 Runner에 싣지 않는다.

```text
Controller --job_id--> ProgramPolicyPipeline.prepare
                              |
                              | lookup(job_id)
                              v
                         Job Store
                              |
                              +-- JobPolicy.sanitizer
                              +-- candidate_id, location, kernel_commit
                              +-- harness binding (if present)
                              |
                              v
                     prepare_program_policy
                              |
                              | payload bytes
                              v
       <state_dir>/kcsan-policies/<candidate_id>_policy.payload
```

`JobPolicy.policy_id`는 실행 방식 선택에 쓰는 문자열이다. 커널 Policy의 키는 숫자 ID가 아니라 `candidate_id`다. KCSAN job만 파일을 만들며, KASAN job은 준비 함수를 통과해도 파일을 만들지 않는다. 후보와 하네스 binding의 커널 commit이 다르면 거부한다.

Program-based 규칙은 후보의 `location.kind=function`과 `location.symbol`만 사용한다. 해당 함수에 `weight=4`, `delay_us=3000`을 주고 기본값은 기존 NFS/RPC KCSAN 범위를 따른다. 파일이 이미 있으면 같은 bytes인지 확인한다. 다른 내용으로 후보 ID의 Policy를 덮어쓰지 않는다.

Stage 1의 `Controller.poll()`은 작업 상태와 누락된 응답을 확인하는 루프이지 Policy 갱신 주기가 아니다. 실행 중인 작업을 확인할 때마다 payload를 다시 읽지 않는다. 미전달 Agent 작업을 재시도하기 직전, Controller 재시작 후 복구할 때, 새 작업을 전달할 때 파일을 다시 확인한다. 퍼징 시작 설정을 만들 때도 `manager_config()`가 선택한 파일을 확인한다. 파일이 없으면 동일한 payload를 복원하고, 같은 후보 ID에 다른 내용이 있으면 거부한다.

### 2. 파일 준비와 Stage 1 실행을 분리한다

Policy 파일을 미리 만드는 것은 Stage 1 실행에 그 Policy를 적용한다는 뜻이 아니다.

```text
candidate accepted
    |
    +--KCSAN prepare--> payload file (not loaded in Stage 1)
    |
    +--Stage 1 RunnerInput(job_id, harness refs)--> Q1 reachability
                                                 |
                                                 +-- not REACHED: repair/stop
                                                 |
                                                 +-- REACHED: S1_REACHED
```

Stage 1 Runner의 입력 계약은 유지한다. Stage 1이 실패하면 준비된 파일은 남을 수 있지만, 퍼징 VM에 등록되지 않은 상태로 끝난다. Stage 2의 변이 전략은 도달성 결과를 사용하며, Policy 파일 자체를 프로그램이나 변이 규칙에 넣지 않는다.

### 3. 퍼징 시작 시 파일 하나를 선택한다

퍼징 시작 전에 `job_id`로 후보를 다시 조회하고 그 후보의 payload 파일을 선택한다. 이 변환은 `ProgramPolicyPipeline.manager_config`에 구현되어 있지만, Stage 2의 실제 퍼징 시작 호출부는 아직 없다.

```text
[미구현] Stage 2 fuzz launch
      |
      | job_id + base config
      v
ProgramPolicyPipeline.manager_config(job_id, config)
      |
      +--prepare(job_id)--> Job Store
      |                         |
      +<--Job(candidate_id)-----+
      |
      +--select--> <state_dir>/kcsan-policies/
      |             <candidate_id>_policy.payload
      |
      +--return config.kcsan_policy_file = selected file
      v
syz-manager --read selected file--> candidate_id + payload path
```

조회 책임은 KCSAN pipeline에 있다. `manager_config`는 `prepare(job_id)`를 통해 Job Store에서 `candidate_id`를 읽고, 그 ID로 파일명을 만든다. syz-manager에는 `job_id`를 전달하지 않는다. syz-manager는 설정의 `kcsan_policy_file`을 읽어 파일명과 payload에 기록된 `candidate_id`가 일치하는지만 확인한다. 다른 후보 파일이 같은 폴더에 있어도 선택에 영향을 주지 않는다. 선택한 파일이 없거나 ID가 다르면 시작을 거부한다. 시드·코퍼스·변이의 `Prog` 객체에는 후보 ID를 복사하지 않는다.

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

`location.kind=source_range`는 바로 등록할 함수 심볼이 없으므로 함수가 확정되기 전에는 payload 준비를 거부한다. 인라인되어 독립 실행 심볼이 없는 함수도 VM 등록에 실패할 수 있다. 이름이 비슷한 함수나 부모 함수를 추측해 대체하지 않는다. generation을 상속하지 않는 비동기 작업에는 이 Policy가 적용된다고 주장하지 않는다.

## 설계 근거

| 결정 | 근거 |
|---|---|
| 후보 접수 직후 payload 준비 | 후보와 binding을 확인할 수 있으며 Q1 결과와 무관하게 함수 규칙은 고정된다. |
| Stage 1에는 등록·실행 연결하지 않음 | 3000us delay가 도달성 판정의 실행 조건을 바꾸지 않게 한다. |
| Stage 2 gate 전에 해당 VM에 등록 | gate와 변이 퍼징이 동일한 관측 설정을 사용해야 한다. |
| `job_id`로 후보·payload 조회 | Controller가 job의 후보를 찾되, Policy 자체는 `candidate_id`로 재사용한다. |
| 등록 상태를 VM 부팅 인스턴스별로 확인 | Policy Store는 커널 메모리에 있고 VM 재부팅 뒤에는 비어 있다. |

## 검토한 대안

| 선택지 | 얻는 것 | 비용·한계 | 채택 여부와 이유 |
|---|---|---|---|
| Q1 통과 후에만 payload 생성 | 사용하지 않을 산출물을 줄임 | 후보가 바뀌지 않는데 준비를 실행 결과에 불필요하게 묶음 | 채택 안 함. 후보 위치가 Stage 1 결과로 달라지는 계약이 생기면 재검토 |
| Stage 1부터 Policy 적용 | 모든 단계의 KCSAN 설정이 같음 | delay가 Q1 도달성 검증에 개입 | 채택 안 함. Stage 1의 목적은 기본 조건에서의 도달 확인 |
| 변이 프로그램마다 함수·payload 복사 | 프로그램 단독으로 설정을 확인 가능 | 반복 복사·등록 비용과 VM 상태 관리가 필요 | 채택 안 함. 매니저가 실행 요청에 `candidate_id`를 넣는다 |
| VM 부팅 시 고정 payload만 등록 | 시작 절차가 단순함 | 어떤 후보를 실행할지 모르면 잘못된 payload를 선택할 수 있음 | 채택 안 함. 실행 VM의 job과 payload를 확인한다 |

## 영향

**상류:** 후보 위치, 커널 commit 또는 실행 하네스 binding이 바뀌면 기존 payload의 적합성을 다시 확인해야 한다. Stage 2의 Q1 handoff 조건은 Agent 설계를 따른다.

**하류:** 다른 후보의 payload가 등록되거나 executor의 `candidate_id` 전달이 빠지면 KCSAN 비교 결과를 후보 함수의 탐지 효과로 해석할 수 없다.

**운영:** payload는 한 번 준비해 재사용하되 VM 재부팅마다 등록한다. 후보별 VM 격리는 필요하며, mutation마다 payload 생성·등록 비용을 지불하지 않는다.

## 신뢰성 요구

잘못된 Policy가 적용됐는데 성공으로 기록하는 거짓 양성이 가장 위험하다. 후보·binding 불일치, VM 등록 실패, executor 선택 실패는 Stage 2 적용 실험을 중단하고 원인을 기록한다. 같은 job과 binding의 재시도는 동일한 payload를 반환해야 한다. 등록·연결·실제 접근은 각각 별도로 관측하며, KCSAN 보고가 없다는 사실만으로 연결 실패나 race 부재를 단정하지 않는다.

## 검증 오라클

1. Host: KCSAN job에서 후보 함수의 `4/3000` rule이 만들어지고, 같은 후보의 재시도는 동일한 payload를 사용한다. 일반적인 Stage 1 poll은 파일을 다시 만들지 않으며, 미전달 Agent 작업의 재시도와 퍼징 시작 설정 생성은 누락된 파일을 복원한다. KASAN job은 Policy 파일을 만들거나 설정에 넣지 않는다.
2. Stage 1: payload가 준비돼도 해당 실행의 Policy 등록·generation 연결이 발생하지 않는다. Q1 판정은 기존 도달성 증거로 수행한다.
3. 퍼징 시작: `[M]` 연결 후 Controller가 선택한 syz-manager 설정에 해당 후보의 `kcsan_policy_file`만 들어간다. VM 부팅 후 Store 조회 결과가 payload와 일치하고, 재부팅 뒤에는 다시 등록된다.
4. 실행 중: executor의 Policy 선택과 커널의 `generation_policy_bind_ok`를 확인하고, 대상 함수 접근에서 `policy_rule_selected`, `policy_setup`, `policy_delay`를 구분해 관측한다.

1은 host test 대상이다. 2~4는 실제 VM Runner와 Stage 2가 연결된 뒤 검증해야 한다. 등록 성공은 실행 연결을, 카운터 증가는 가설과 일치하는 race 탐지를 각각 증명하지 않는다.

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
| 결정됨 | 후보가 확정된 뒤 payload를 준비하고, Stage 1에는 적용하지 않으며 Stage 2 gate 전에 해당 VM에 등록한다. |
| 구현됨 | 후보 접수 후 KCSAN payload를 후보별 파일로 보관·재사용한다. Stage 1 Runner는 이 파일을 전달받지 않는다. KCSAN pipeline은 선택한 job의 `kcsan_policy_file` 설정을 반환한다. syz-manager에는 VM 부팅 시 등록하는 코드가 있다. |
| 미구현 | Stage 2 퍼징 시작 호출부의 `manager_config(job_id, config)` 연결과 실제 VM에서 등록·조회·executor 선택을 검증하는 경로. |
| 미구현 | Stage 2 Agent·Runner의 실제 실행 경로. VM을 새로 시작할지 재사용할지는 그 구현에서 결정한다. |
| 현재 범위 밖 | 다중 후보를 한 매니저 설정에서 실행하는 방식. 현재 설정은 후보 payload 하나만 허용한다. |
| 미결 | `source_range`의 함수 해석과 인라인 함수 처리. |
| 미검증 | 비동기 작업으로의 generation Policy 전파와 후보별 VM 격리. |

## 참조

- `agent_pipeline/controller/tasks.py`: `RunnerInput`, `Runner` 계약.
- `agent_pipeline/controller/service.py`: job 저장 및 `Controller._dispatch`의 Runner 호출.
- `agent_pipeline/stage1/cli.py`, `agent_pipeline/stage1/service.py`: KCSAN 준비 함수를 Controller에 연결.
- `kcsan_pipeline/program_policy.py`, `kcsan_pipeline/pipeline.py`: 후보별 payload 생성·보관과 `manager_config()`.
- `env/syzkaller/pkg/mgrconfig/load.go`: `kcsan_policy_file`로 지정된 payload 하나 검증.
- `env/syzkaller/pkg/execbackend/rpc.go`, `env/syzkaller/pkg/execbackend/snapshot.go`: VM 부팅 시 payload 복사·등록.
- `env/syzkaller/executor/executor_linux.h`: Policy Store 등록·조회.
- `env/syzkaller/pkg/rpcserver/rpcserver.go`, `env/syzkaller/pkg/rpcserver/runner.go`, `env/syzkaller/pkg/execbackend/snapshot.go`: 매니저 후보 ID를 실행 요청에 전달.
- `docs/design/02-llm-agent/01-two-stage-agent-architecture.md`: Stage 1 Q1, Stage 2 전략·gate·campaign.
- `docs/design/02-llm-agent/09-job-state-graph.md`: Runner task와 Stage 2 상태 계약.
- `docs/design/90-kcsan/01-architecture.md`: 커널 Policy Store와 generation 연결. 후보별 영속 ID 서술은 이 Program-based 설계로 재검토한다.

## Agent 사용 지침

**지원 범위:** `location.kind=function`이고 NFS/RPC 범위에 있는 후보 함수 하나의 고정 규칙을 준비한다. KCSAN job에만 적용한다.

**비지원 범위:** `source_range`를 함수로 추측하거나, 두 번째 함수를 임의로 추가하거나, VM 등록을 Stage 1 Q1의 일부로 간주하지 않는다.

**확장 절차:** 퍼징 시작 호출부가 구현되면 Controller에서 `manager_config()` 결과로 매니저를 시작하고, VM 등록·조회와 executor 선택을 gate 앞에서 검증한다. `source_range`를 지원하려면 함수 해석 근거와 대상 빌드 심볼 검증을 먼저 추가한다.

**제약:** 다른 후보의 payload 파일을 선택한 매니저 설정을 재사용하지 않는다. VM 등록 성공과 실행 중 Policy 선택을 별도로 확인한다.

**검증 방법:** host 계약 검증 후 Stage 1 비적용, Stage 2 gate 전 등록, generation 연결, 함수별 KCSAN 카운터 순서로 확인한다.
