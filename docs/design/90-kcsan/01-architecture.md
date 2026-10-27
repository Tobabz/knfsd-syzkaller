# KCSAN Policy 전체 구조

> 상태: 구현 개요 · 최종 확인: 2026-10-27
> 현재 기준: [`bundle/patches/BASE`](../../../bundle/patches/BASE) kernel `v7.3-rc6` (`a90ee4305c4a5df72c11b31dacfdc76e00fcf78a`) / syzkaller (`801f0966669a37e048adabf9e5f38ce52825ea82`)
> 검증 범위: KCSAN patch 0004의 커밋 메시지는 clean-base kernel build와 snapshot VM smoke를 기록하지만, resolved base SHA와 원시 evidence를 보존하지 않는다. 2026-10-14 문서의 `v7.3-rc5` 표기는 과거 기준이며 현재 pin의 최종 검증 근거로 취급하지 않는다. Full Controller→Stage 2 campaign/replay 검증은 미완료다.
> 2026-10-27 정정: 퍼징 시작 경계와 현재 Program-based 동작은 [02](02-program-based-kcsan.md)를 우선한다.

## 요약

KCSAN Policy는 NFS/RPC 커널 코드의 후보 함수에 watchpoint 설치 기회와 delay를 배분하는 실행별 설정이다. Policy를 VM 커널에 등록한 뒤 프로그램 실행의 KCOV generation에 참조를 연결하여, 그 실행에 귀속된 작업이 같은 규칙을 사용하도록 한다. 등록, 실행 연결, 실제 함수별 적용을 구분하지 않으면 Policy의 효과를 잘못 판단할 수 있다.

## 목적

목표는 **knfsd 관련 data race 후보를 시험할 때 KCSAN의 관측을 후보 함수와 그 관련 경로에 집중하는 것**이다. 기본 KCSAN은 많은 커널 접근을 샘플링하므로, 후보 함수에 도달하더라도 그 함수의 접근에 충분한 watchpoint가 설치된다는 보장은 없다. Policy는 후보별 함수 규칙을 제공해 이 관측 기회를 조정한다.

동일한 입력과 실행 조건에서 범위 제한만 있는 KCSAN, 후보 함수에 고정 규칙을 주는 방식, 호출 경로를 분석해 규칙을 만드는 방식을 비교할 수 있어야 한다. 개선 여부는 전체 KCSAN 보고 수만으로 판단하지 않는다. 목표 함수에서의 실제 적용, 후보와 관련된 보고, 실행 비용을 함께 본다. Policy는 취약점이나 race의 존재를 사전에 확정하지 않는다.

이 문서는 KCSAN Policy의 구성 요소와 그 경계만 정의한다. 후보를 찾는 절차, NFS 요청 변조, 도달성 및 최종 취약점 판정은 각각의 설계 계약을 따른다.

## 해결하려는 문제

기존 실험에서는 Policy가 Store에 등록됐거나 전역 KCSAN 카운터가 증가한 것만으로 **지정한 함수의 접근에 Policy가 적용됐는지** 설명하기 어려웠다. 프로그램에서 시작한 NFS 요청은 SUNRPC와 nfsd의 별도 작업으로 이어질 수 있으므로, 등록된 Policy를 현재 프로그램의 작업과 연결하는 경로도 필요하다.

이 구분 없이 KCSAN 보고가 없다는 결과만 보면 후보 접근의 미실행, Policy 전달 실패, watchpoint 미설치, 실제 충돌 부재가 섞인다. 따라서 이 설계는 Policy의 생성·등록·선택·적용을 별도 단계로 두고 각 단계의 성공을 확인할 수 있게 한다.

## 구조

```text
+---------------------------- host ----------------------------+
| candidate --> Policy preparation (P)  program + candidate_id  |
|                      |                         |              |
|                  payload                  syz-manager         |
+----------------------|-------------------------|--------------+
                       v                         v
+-------------------------- VM user --------------------------+
|                Policy Loader           syz-executor          |
|                     | register(key,rules)  | begin(key)       |
+---------------------|----------------------|------------------+
                      v                      v
+-------------------------- kernel ---------------------------+
|             Policy Store (R) --ref--> KCOV generation (B)    |
|                                         | bind/token          |
|                                         v                     |
|                            syscall / NFS-RPC work            |
|                                         | active Policy ref   |
|                                         v                     |
|                         KCSAN scope + rule decision (K)       |
|                                         | weight / delay      |
|                                         v                     |
|                               watchpoint setup              |
+-------------------------------------------------------------+
```

`(P)`는 생성 결과, `(R)`은 VM 등록, `(B)`는 실행별 참조 연결, `(K)`는 함수별 적용의 관측 지점이다. 읽는 순서는 Policy 준비·등록과 프로그램 실행·선택의 두 경로가 kernel의 generation에서 합쳐진 뒤 KCSAN 접근으로 이어진다.

그림은 구성 요소 사이의 책임 경계를 나타낸다. 현재 Program-based 경로는 단일 `function` 후보에서 고정 rule payload를 만들고 Stage 2 campaign config로 연결한다. 상세한 Controller handoff와 미검증 end-to-end 구간은 [02](02-program-based-kcsan.md)에 기록한다. `NFS-RPC work`에는 generation 귀속이 확인된 작업만 포함하며, 비동기 작업 전체에 적용된다고 가정하지 않는다.

## 설계

### 구성 요소의 책임

| 요소 | 책임 |
|---|---|
| Policy preparation | 후보 지점을 바탕으로 감시할 함수와 함수별 규칙을 선정하고, 검증 가능한 Policy 산출물을 만든다. |
| Policy Loader | VM이 사용할 payload를 커널에 등록하고 결과를 확인한다. |
| Policy Store | `candidate_id`별 Policy와 해석된 함수 IP 범위를 보관하고 참조를 제공한다. |
| syzkaller 실행 경로 | 프로그램 실행에 연결된 `candidate_id`를 executor까지 전달한다. |
| KCOV generation | 한 프로그램 실행에 선택된 Policy 객체의 참조를 보유한다. |
| KCSAN 접근 경로 | 활성 참조와 접근 IP로 규칙을 찾고 watchpoint 선택·delay에 사용한다. |

현재 payload는 **`candidate_id`, schema version, default settings, 함수별 symbol/subsystem/weight/delay**를 담는다. Kernel commit은 payload에 직렬화되지 않는다. 대신 Stage 2 `_campaign_manager`가 Controller job, harness candidate, descriptor kernel commit, sanitizer를 대조하고 pinned kernel artifacts를 사용한 뒤 payload를 선택한다. 지원 생성 경로는 accepted KCSAN candidate의 단일 `location.kind=function`에 고정 rule을 주는 방식(`weight=4`, `delay_us=3000`)뿐이다. LLM이 호출 경로에서 추가 함수를 선택하는 방식은 구현 범위가 아니다. Kernel resolver는 `kallsyms_lookup_name()`과 symbol size/offset으로 IP range를 얻지만, source path를 보존하거나 kernel-wide 동명 symbol의 유일성을 입증하지 않는다. 따라서 source-level에서 이름이 유일해 보인다는 사실만으로 target IP가 올바르다고 단정할 수 없다. Payload 및 kernel-side validation은 `kcsan_pipeline/program_policy.py`와 kernel overlay patch 0002에 있다.

커널 overlay patch 0001은 watchpoint 설치를 built-in NFS client, NFS common, lockd, SUNRPC, NFSD text scope로 제한한다. Policy 없는 실행은 이 공통 scope의 baseline sampling을 유지한다. Policy-bound generation에서는 patch 0003/0004가 선택한 candidate subsystem과 실제 rule IP에 맞는 접근만 새 watchpoint 후보로 샘플링한다. 현재 `weight=4`는 matched access마다 40% 선택 threshold를 뜻하며 unmatched access는 그 generation에서 새로운 watchpoint를 설치하지 않는다. 이미 설치된 watchpoint를 다른 접근이 관측할 수 있으므로, report의 stack만으로 후보 rule이 선택됐다고 단정하지 않는다.

Loader가 등록한 Policy는 VM의 Store에 유지된다. KCSAN Stage 2 campaign manager config가 payload 하나를 선택하고, syz-manager는 VM 부팅마다 runner 시작 전에 `policy-load`를 수행한다. VM 재부팅 뒤 Store는 비어 있으므로 동일 payload를 다시 등록한다. Store는 candidate별 immutable entry를 갖고 중복 ID를 거부한다. 등록 및 request selection 절차는 [02](02-program-based-kcsan.md)와 kernel overlay patch 0002에서 정의한다.

syz-manager는 program request마다 manager `candidate_id`를 executor로 전달한다. Remote-coverage executor는 첫 syscall 전에 `KCOV_REMOTE_GENERATION_BEGIN_POLICY`로 새 generation을 만들고, 커널은 Store에서 **키가 아닌 Policy 객체의 참조**를 generation에 붙인다. 이후 지원되는 request bind와 remote token paths는 같은 generation을 활성화한다. 매 syscall 또는 KCSAN memory access에서 Store를 다시 조회하지 않는다. generation 종료 시 참조를 반환한다. generation 밖의 task가 candidate Policy를 상속한다고 일반화하지 않는다.

KCSAN은 active Policy와 현재 access IP가 맞으면 rule의 delay를 적용하고 watchpoint 설치 기회를 weight로 정한다. Patch 0004의 확률은 weight unit당 10%, 최대 40%이며, 이는 직접 matched-rule sampling이지 기존 KCSAN baseline과 30/70 혼합하는 방식이 아니다. Policy는 KCSAN report를 직접 생성하거나 NFS 요청을 변조하지 않는다.

## 설계 근거

| 결정 | 근거 |
|---|---|
| 공통 NFS/RPC 범위를 유지 | Policy 방식이 달라도 같은 커널 영역에서 결과를 해석하고, 정책으로 감시 범위가 무심코 확대되지 않도록 한다. |
| Policy 등록과 실행 선택을 분리 | 하나의 VM에서 여러 프로그램이 실행되므로, 프로그램마다 규칙 전체를 다시 전달할 필요가 없다. |
| generation에 Policy 참조를 보유 | 한 프로그램의 syscall과 귀속 가능한 NFS/RPC 작업이 기존 generation 경로를 공유한다. |
| KCSAN은 활성 참조와 IP만 사용 | 메모리 접근마다 Policy 텍스트 파싱이나 `candidate_id` 기반 Store 조회를 하지 않는다. |
| 등록·bind·적용을 따로 관측 | 앞 단계의 성공이 다음 단계의 성공을 증명하지 않는다. |

## 검토한 대안

| 선택지 | 얻는 것 | 비용·한계 | 채택 여부와 이유 |
|---|---|---|---|
| 커널 전체에서 Policy 적용 | NFS/RPC 밖의 접근도 감시 | 실험 범위와 비용이 확대됨 | 비채택. 공통 범위 유지 |
| Policy payload를 프로그램마다 전달 | 사전 등록 불필요 | 반복 검증·복사와 실행 경계 관리가 필요 | 비채택. 등록 후 `candidate_id` 선택 |
| KCSAN 접근마다 Store 검색 | 실행 문맥 저장이 단순 | 매우 빈번한 접근에 조회 비용 추가 | 비채택. 활성 참조 사용 |
| 작업 객체마다 별도 후보 키 추가 | generation 밖의 작업도 식별 가능 | NFS/RPC 경계마다 전파 코드를 중복 구현 | 비채택. 기존 귀속 경로 우선 사용 |

generation 경로 밖의 작업이 목표 후보의 필수 실행 부분으로 확인되면 마지막 대안을 다시 검토한다.

## 영향

**상류:** 후보 지점과 대상 커널 빌드가 달라지면 Policy가 가리키는 함수와 IP 범위를 다시 검증해야 한다. 함수 선정 근거는 Policy 산출물과 함께 보존한다.

**하류:** 잘못된 `candidate_id` 연결이나 원격 귀속 누락은 다른 프로그램의 Policy가 적용되거나 대상 작업에 아무 규칙도 적용되지 않는 결과를 낳는다. 이는 KCSAN 결과의 비교 가능성을 해친다. 사용자 공간 NFS-Ganesha 서버 내부에는 커널 KCSAN Policy가 직접 적용되지 않는다.

**운영:** VM 등록·재등록과 Policy 참조 수명 관리가 필요하다. 높은 watchpoint 설치율과 delay는 실행 시간 및 race의 타이밍을 바꿀 수 있으므로 처리량을 별도로 기록한다.

## 신뢰성 요구

가장 위험한 거짓 양성은 Policy가 등록만 됐는데 특정 프로그램·함수에 적용됐다고 판단하는 것이다. 거짓 음성은 실제 적용됐지만 계측 또는 원격 귀속 관측이 빠져 적용되지 않았다고 판단하는 경우다. `candidate_id`가 지정된 실행의 등록·bind 실패는 기본 실행으로 조용히 바꾸지 않고, Policy 적용 실패로 드러내야 한다.

같은 Policy 산출물과 커널 빌드에서는 동일한 함수 규칙을 등록할 수 있어야 한다. KCSAN 보고 횟수는 샘플링과 스케줄링에 따라 달라질 수 있으므로, Policy 적용의 재현성과 race 보고 횟수의 결정론을 혼동하지 않는다.

## 검증 오라클

| 확인 단계 | 판정 가능한 관측 | 이것만으로 증명하지 않는 것 |
|---|---|---|
| 생성·선택 | job/harness candidate ID, descriptor kernel commit, sanitizer match, exact payload bytes | 대상 vmlinux에서 runtime symbol/IP가 올바르게 해석됨 |
| 등록 | Store에서 후보 키, 기본값, 모든 rule의 범위·가중치·delay 조회 | 특정 실행에 선택됨 |
| 실행 연결 | 요청의 `candidate_id`와 generation의 Policy bind 결과 대조 | 목표 함수에서 접근 발생 |
| 실제 적용 | 함수별 적격 접근·선택·설치·delay 증가 | 목표 race의 존재 또는 root cause |

범위 밖 함수와 미등록 후보 키는 음성 대조로 사용한다. 전역 `policy_rule_selected`, `policy_setup`, `policy_delay`의 증가만으로 특정 함수의 적용을 주장하지 않는다. KCSAN 보고는 최종 관측값이지만, 보고 부재만으로 Policy 실패 또는 race 부재를 결정하지 않는다.

## 실패 양상과 진단

| 증상 | 가능한 원인 | 구분하는 관측 | 조치 |
|---|---|---|---|
| 함수 rule 등록 실패 | 빌드 불일치, 심볼/범위 해석 실패 | 대상 빌드와 rule 해석 결과 | 추측 대체 금지, 대상 재확인 |
| Store에서 후보 키 조회 실패 | Loader 실패 또는 VM 재부팅 | VM별 등록·조회 결과 | 등록 복구 후 실행 |
| 등록은 됐지만 bind 없음 | 실행 요청의 `candidate_id` 누락 또는 generation 시작 실패 | 요청의 `candidate_id`와 generation 결과 | 해당 실행을 Policy 적용 결과에서 제외 |
| bind는 됐지만 rule 적용 없음 | 함수 미실행, IP 매핑 오류, 원격 귀속 누락 | 함수 접근·rule 선택·remote section 관측 | 원인을 분리해 수정 |
| 설치·delay는 증가했으나 보고는 없음 | 충돌 부재 또는 타이밍·샘플링 영향 | 함수별 적용 계측과 반복 실행 | 등록 실패로 단정하지 않음 |

## 한계와 미결 사항

| 상태 | 항목 |
|---|---|
| 결정됨 | 공통 NFS/RPC 범위 안에서 함수별 Policy를 적용한다. |
| 결정됨 | `candidate_id`는 실행 선택용이고, generation은 실제 Policy 참조를 보유한다. |
| 현재 범위 밖 | LLM이 호출 경로에서 추가 함수를 선정하는 Program policy generation; 현재는 후보 function 하나를 그대로 rule로 쓴다. |
| 결정됨 | Program-based 방식은 숫자 ID를 발급하지 않고 KCSAN pipeline이 후보 함수 규칙을 준비한다(`02-program-based-kcsan.md`). |
| 구현됨 / 미검증 | Stage 2 `_campaign_manager`가 identity를 확인해 manager config를 선택한다. Current full Stage 2 two-server campaign과 KCSAN report replay는 아직 재실행하지 않았다. |
| 결정됨 | Patch 0004는 matched rule weight에 직접 10%/unit, max 40% threshold를 적용한다. Default KCSAN baseline은 Policy 없는 scope-bound 실행에 남는다. |
| 미검증 | 모든 background·비동기 작업에 generation Policy가 전파된다는 주장. |
| 미검증 | Candidate symbol의 runtime IP가 source path에 지정한 함수와 일치한다는 보장. `kallsyms_lookup_name()`은 source path/동명 symbol disambiguation을 제공하지 않는다. |

Program-based 실행 경계와 현재 구현 상태는 `02-program-based-kcsan.md`에 정의한다. 이 디렉터리에는 현재 01/02 설계 문서만 있으며, 별도 generation, Store/Loader, watchpoint-selection 문서는 아직 없다. 새 세부 문서를 추가할 때는 patch와 테스트의 실제 계약을 먼저 확인하고, 이 개요와 상충하는 미래형 설명을 남기지 않는다.

## 참조

- `../02-llm-agent/02-vulnerability-candidate.md`: Policy 준비 단계에 전달될 후보 지점의 형식.
- `../02-llm-agent/01-two-stage-agent-architecture.md`: 후보 지점과 실행 가능한 프로그램이 만들어지는 단계의 계약.

## Agent 사용 지침

**지원 범위:** Stage 2 KCSAN campaign에서 정확한 kernel commit에 묶인 accepted candidate 하나의 `location.kind=function` rule을 만든다. Candidate/harness/descriptor commit identity는 campaign 진입 때 대조된다. `source_range`와 LLM이 추가하는 함수는 지원하지 않는다.

**비지원 범위:** 후보 하나가 자동으로 race 함수쌍이나 실행 심볼을 보장한다고 가정하지 않는다. KCSAN Policy는 NFS semantic mutation 규칙이나 사용자 공간 Ganesha 계측을 만들지 않는다.

**확장 절차:** 새 실행·함수 policy를 추가할 때는 candidate/kernel identity, serialized payload schema, symbol-to-IP disambiguation, VM Store registration, request candidate ID, generation bind, function-specific KCSAN counters를 각각 테스트한다. Baseline Stage 1/gate/replay에는 candidate policy를 적용하지 않는다.

**제약:** 공통 범위 밖 함수, 다른 빌드의 IP 범위, 출처가 불명확한 `candidate_id`를 정상 적용으로 취급하지 않는다.

**검증 방법:** Policy 산출물 확인, VM Store 조회, 실행 generation의 bind, 지정 함수의 watchpoint·delay 계측을 순서대로 확인한다. KCSAN 보고만으로 앞 단계의 성공을 역추론하지 않는다.
