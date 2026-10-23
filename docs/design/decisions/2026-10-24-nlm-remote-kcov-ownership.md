# NLM remote KCOV ownership contract

> 상태: 검토 결과 반영 중   ·   최종 확인: 2026-10-24   ·   기준: kernel 7.3 / c03c1a14507dfaf8b856c2608f9ac216021fc222
> 관련 패치: kernel 0001, 0004, 0006, 0007   ·   관련 게이트: HCAP-13, Stage 2

## 요약

이 문서는 NLM LOCK에서 시작한 비동기 GRANTED callback의 커널 실행과 remote KCOV를
같은 owner identity로 연결하기 위한 계약을 정의한다. 현재 패치는 owner 포인터와
generation 참조를 일부 전달하지만 callback 완료와 aggregate publish까지의 sealed
identity 증거는 아직 없다. 소스 대조에서 확인한 0006의 retry 경로 lifetime 결함은
0007에서 owner 접근 전에 선택된 블록의 임시 참조를 확보하도록 수정했다. 0001부터
0007까지의 최종 bzImage와 모듈 빌드는 통과했지만, 이 경로의 KASAN/KCSAN 동시성
실행은 아직 완료하지 않았다. typed lifecycle 계약과 런타임 검증을 만족하기 전
결과는 diagnostic_only로 남기고 Stage 2 ownership evidence로 승격하지 않는다.

## 해결하려는 문제

현재 KVM 진단에서는 host packet capture가 같은 LOCK과 GRANTED_MSG를 관찰해도 그
callback이 어느 generation의 커널 실행에서 처리되었는지 remote KCOV aggregate와
직접 연결할 수 없다. GRANTED_MSG는 원래 LOCK과 다른 비동기 RPC task와 rpciod
실행을 거치며, callback 시점에 최신 generation을 조회하면 늦은 callback이 다음
프로그램에 잘못 귀속될 수 있다.

이 연결이 없으면 callback 관련 PC가 aggregate에 없는 것을 실행되지 않았다고
읽거나, 다른 generation의 PC를 현재 LOCK의 실행 증거로 읽게 된다. 패치 0006은
nlmsvc_create_block, nlmsvc_retry_blocked, __nlm_async_call에서 owner를 보존하는
경로를 추가한다. 적용된 kernel checkout의 소스 대조에서 nlmsvc_retry_blocked()가
전역 리스트 락을 해제한 뒤 block->b_call->a_fuzz_owner를 읽는 것을 확인했다.
그 시점에 다른 cancel/traverse 경로가 리스트 참조를 해제할 수 있으므로 0006에는
owner 접근 전에 임시 nlm_block 참조가 필요했다. 0007은 이 참조를 리스트 락 해제
전에 확보하고 처리가 끝난 뒤 해제한다. 0001부터 0007까지의 최종 커널 bzImage와
모듈 빌드는 통과했지만, 이 경로의 KASAN/KCSAN 동시성 실행은 아직 완료하지 않았다.

## 구조

~~~text
+-------------------------- kernel --------------------------+
| LOCK -> owner(G,C) -> nlm_block                            |
|              | owner ref                                   |
|              v                                              |
| GRANT -> rpc_task -> rpciod                                 |
|                         | section(G,C)                       |
|                         v                                    |
|                  remote KCOV aggregate                      |
|                         | typed events                       |
+-------------------------+----------------------------------+
                          v
+---------------------- host verifier -----------------------+
| journal + pcap + aggregate identity                         |
| owned / diagnostic_only / owner_mismatch / incomplete        |
+-------------------------------------------------------------+
~~~

범례: G는 generation, C는 request cookie, owner ref는 수명 참조, typed events는
host가 검증할 lifecycle event다. LOCK에서 아래로 읽고 마지막에 kernel identity와
host 관찰을 교차 검증한다.

## 설계

### 1. 불변 owner identity

각 LOCK에서 sunrpc_fuzz_cb_owner를 한 번 만들고 callback 수명 동안 바꾸지
않는다. 객체는 generation 참조, common handle과 generation으로 된 owner,
request cookie, lane network namespace 참조, lane epoch, refcount를 가진다.

owner identity는 callback 시점의 최신 lane 상태로 재구성하지 않는다. 이미 owner를
가진 callback에 새 event가 합쳐지면 최초 owner를 유지하고 후발 owner는 별도로
귀속하지 않는다.

### 2. lockd에서 RPC task까지의 전달

blocked lock을 만드는 nlmsvc_create_block은 현재 실행 section에서 owner를
저장한다. nlmsvc_retry_blocked가 grant를 재개할 때 owner를 참조하고,
__nlm_async_call은 nlm_rqst.a_fuzz_owner를 rpc_task에 전달한다. 부모 section이
없으면 비동기 call은 ownerless로 남긴다.

보존해야 할 관계는 다음과 같다.

~~~text
LOCK -> nlm_block -> nlm_rqst -> rpc_task -> callback worker/rpciod
~~~

각 화살표는 owner identity와 generation reference를 함께 전달한다. 포인터 주소,
현재 thread, 현재 lane generation은 identity가 아니다.

### 3. callback 실행과 remote KCOV section

callback RPC task의 FSM step과 callback reply는 owner에서 section token을 발급받아
remote KCOV scratch에 기록한다. token은 generation이 OPEN일 때만 발급한다.
CLOSING, ABORTED, COMMITTED, identity 불일치, lane epoch 불일치, scratch 또는
ticket 실패는 다른 generation에 섞지 않고 실패 상태로 기록한다.

section 종료 시 scratch를 owner aggregate에 병합하고 callback 완료 뒤 aggregate
publish event를 남긴다. generation이 닫힌 뒤 실행된 늦은 callback은 PC를 폐기하고
outside_activation_window 또는 ownerless로 남긴다.

### 4. typed lifecycle event

커널 계측과 host verifier가 같은 identity를 비교하도록 다음 event를 generation,
cookie, lane epoch, monotonic sequence와 함께 기록한다.

owner_created, lock_owner_attached, grant_owner_attached, callback_task_queued,
callback_task_started, remote_section_started, callback_execution_entered,
remote_section_stopped, kcov_aggregate_published, callback_completed,
owner_invalidated, owner_released.

event stream은 sealed journal manifest, activation marker, VM instance identity와
연결한다. 누락되거나 순서가 역전되면 packet 관찰이 정상이어도 ownership을
인정하지 않는다.

### 5. 종료와 재시작 경계

generation 종료, lockd/rpciod 중단, Proxy 재시작, VM crash/reboot, lane epoch
변경은 owner continuity를 끊는다. 이전 owner를 새 generation에 재사용하지 않고,
종료 시 owner ref와 remote section ref가 0인지 확인한다. 확인하지 못하면
restart_continuity_unknown 또는 capture_incomplete로 분류한다.

## 설계 근거

| 결정 | 근거 |
|---|---|
| generation과 cookie를 immutable identity로 사용 | executor handle 재사용을 구분하고 늦은 callback 오귀속을 막는다. |
| owner 수명과 section token 수명을 분리 | callback retry가 FINISH drain을 무기한 연장하지 않으면서 실행 중 section은 배출한다. |
| lockd와 rpc_task 양쪽에 owner 저장 | grant와 RPC FSM이 다른 thread/workqueue에서 실행된다. |
| typed event와 sealed manifest 요구 | pcap의 LOCK/callback byte match는 kernel callback execution과 KCOV publish를 증명하지 않는다. |
| 실패 시 ownerless 유지 | 거짓 양성으로 Stage 2를 승격하는 비용이 거짓 음성보다 크다. |

패치 0001은 generation별 remote aggregate와 token 기반을, 0004는 SUNRPC owner
helper와 RPC task section을, 0006은 lockd blocked grant와 NLM async call 전달을,
0007은 retry 중 선택된 blocked lock의 lifetime pinning을 제공한다. 이는 설계
방향과 한정된 lifetime 수정의 근거이며 typed event stream과 host 검증의 완성을
의미하지 않는다.

## 검토한 대안

| 선택지 | 얻는 것 | 비용·한계 | 채택 여부와 이유 |
|---|---|---|---|
| callback 시점의 최신 generation 조회 | 구현이 짧다 | 늦은 callback을 다음 프로그램에 섞는다 | 기각. immutable owner를 쓴다. |
| 전역 KCOV handle 하나로 수집 | callback PC를 볼 수 있다 | 동시 lane과 generation이 섞인다 | 기각. identity 없는 aggregate는 근거가 아니다. |
| packet LOCK/callback match만 사용 | 커널 변경이 없다 | callback worker와 KCOV를 연결하지 못한다 | 기각. diagnostic_only 경계만 유지한다. |
| callback work 전체를 FINISH가 기다림 | 늦은 PC를 더 모은다 | retry가 종료를 막고 generation abort를 유발한다 | 기각. owner ref와 token을 분리한다. |
| owner propagation + sealed lifecycle events | 수명·실행·aggregate를 교차 검증한다 | kernel ABI, journal, verifier, KVM negative control이 필요하다 | 채택. 모든 게이트 전에는 승격하지 않는다. |

## 영향

### 상류

kernel 0001의 generation/token ABI, 0004의 SUNRPC owner helper, 0006의 lockd
전달 필드에 의존한다. rpc_task 수명, nlm_rqst 해제, blocked lock 재시도,
lane epoch 또는 journal schema가 바뀌면 owner release와 event 순서를 재검토한다.

### 하류

ownership 검증 전의 .extra, packet callback match, CapabilityProposal 및 Stage 2
readiness는 진단 자료로만 사용한다. verifier가 owner mismatch, event gap,
aggregate digest 불일치를 놓치면 다른 generation의 coverage를 현재 후보의 Q1
증거로 오인할 수 있으므로 최종 상태는 fail-closed여야 한다.

### 운영

owner object, generation reference, event journal, aggregate tag와 KVM negative
campaign이 추가된다. callback section과 journal 저장 비용이 있고 scratch 포화나
worker 재시작으로 PC가 누락될 수 있다. 누락은 counter와 결과 상태로 노출한다.

## 신뢰성 요구

| 항목 | 요구 |
|---|---|
| 오류 방향 | 거짓 양성이 더 위험하다. 다른 generation의 PC를 소유 증거로 인정하면 Stage 2 판단을 오염시킨다. |
| 실패 방식 | owner allocation, token, section, event sealing, capture, digest, restart continuity 중 하나라도 실패하면 diagnostic_only 또는 명시적 실패를 반환한다. |
| 관측 가능성 | owner 생성·부착·queue·start·stop·publish·complete·invalidate·release와 거부 사유별 counter를 남긴다. 종료 시 live owner와 remote ref가 0인지 확인한다. |
| 재현성 | 동일 VM instance, kernel·syzkaller digest, 후보, generation, lane epoch, event sequence를 사용한다. 재시작·재전송·동시 generation은 별도 negative control로 분리한다. |

## 검증 오라클

owned는 다음 조건을 모두 만족할 때만 사용할 수 있다.

1. host capture가 activation open 전에 시작되고 callback completion과 close 뒤까지
   이어지며 drop, hole, unresolved TCP record가 없다.
2. sealed journal이 하나의 FORWARD_COMPLETE LOCK을 확인하고 packet evidence가
   유일한 GRANTED_MSG를 같은 VM instance와 session/lane/generation에 연결한다.
3. owner_created에서 callback_completed까지 owner key
   (generation, request_cookie, lane_epoch)가 변하지 않는다.
4. callback task start, remote section start/stop, kcov_aggregate_published가
   순서대로 있고 aggregate identity가 owner key와 일치한다.
5. duplicate/retransmission, callback after close, VM crash, Proxy 또는
   lockd/rpciod restart, owner mismatch가 없다.
6. 종료 시 owner ref, callback ref, remote section ref가 0이고 manifest와 result
   digest가 일치한다.

이 오라클은 callback 실행과 remote KCOV aggregate 연결을 판정한다. 함수 PC만으로
LOCK 순서, packet 유일성, crash 전후 continuity, 취약점 영향, Stage 2 readiness를
증명하지 않는다.

## 실패 양상과 진단

| 증상 | 가능한 원인 | 구분하는 관측 | 조치 |
|---|---|---|---|
| LOCK과 callback은 보이나 owner가 없음 | 부모 section 없음, allocation 실패, 늦은 callback | owner와 section 거부 counter, event stream | diagnostic_only; 새 generation에 재귀속하지 않는다. |
| aggregate generation이 owner와 다름 | task 전달 누락, stale owner, epoch 교차 | owner key와 aggregate tag, owner_mismatch event | campaign을 reject하고 propagation을 조사한다. |
| section start 없이 callback 완료 | token 거부, closing/abort, lane unhealthy | token rejection 사유와 lifecycle event | PC ownership을 인정하지 않는다. |
| publish는 있으나 callback completion 없음 | retry, task free race, crash, journal truncation | task/callback event, close marker, crash record | capture_incomplete 또는 restart_continuity_unknown. |
| ref가 0이 되지 않음 | release 누락, retry work, namespace teardown race | live owner/ref counter와 종료 event | leak 수정 전 승격하지 않는다. |
| packet parser만 실패 | drop, TCP hole/overlap, connection reuse | pcap stats, stream issue, sealed manifest | capture_incomplete; kernel ownership을 추정하지 않는다. |

## 한계와 미결 사항

- 확인됨: 적용된 kernel source checkout에서 nlm_block, nlm_rqst, rpc_task,
  nlmsvc_grant_blocked, nlmsvc_grant_callback, nlmclnt_grant의 실제 경로와 패치
  적용 결과를 대조했다. nlmsvc_retry_blocked()의 owner 접근 전 block pinning
  수정은 0007 patch로 분리했고, 0001부터 0007까지 series 적용과 최종 bzImage 및
  모듈 빌드를 통과했다.
- 미구현: 패치 텍스트에는 NLM typed lifecycle event의 안정된 schema와 aggregate
  identity를 교차 검증하는 host verifier가 없다.
- 미검증: callback completion과 KCOV publish가 같은 owner key로 sealed 되는지,
  crash/restart/epoch에서 stale owner가 거부되는지 KVM campaign을 다시 수행하지
  않았다.
- 미결: event 저장 위치, 최대 크기, overflow quarantine 여부와 aggregate digest의
  canonical encoding을 정해야 한다.
- 미결: 하나의 blocked lock이 여러 callback 또는 retry를 만들 때 owner를 callback
  completion과 일대일로 묶는 규칙을 정해야 한다.
- 범위 밖: HCAP-13 승인, Stage 2 승격, 취약점 영향 판정, raw pcap 공개.

## 참조

- bundle/patches/kernel/0001-kcov-attribute-remote-coverage-to-per-program-reques.patch — generation, remote token, aggregate 기반.
- bundle/patches/kernel/0004-sunrpc-attribute-NFSv4.1-server-callbacks-to-the-pro.patch — sunrpc_fuzz_cb_owner, RPC task와 callback section 전달.
- bundle/patches/kernel/0006-lockd-attribute-blocked-lock-grants-NLM-async-calls-.patch — blocked NLM grant, nlm_rqst.a_fuzz_owner, async NLM call 전달.
- docs/design/decisions/2026-10-05-callback-attribution.md — callback owner의 generation 수명과 기존 NFSv4 callback 검증·한계.
- docs/design/decisions/2026-10-23-nlm-callback-attribution-contract.md — packet 및 host journal 기반 NLM diagnostic attribution 경계.
- agent_pipeline/stage2/nlm_callback_contract.py — normalized contract.

## Agent 사용 지침

### 지원 범위

Agent는 LOCK, GRANTED_MSG, activation window, packet/journal completeness를
진단적으로 비교할 수 있다. kernel owner identity와 위 오라클을 만족하는 외부
증거가 있을 때만 owned 후보를 계산하며 최종 verdict는 Controller가 낸다.

### 비지원 범위

packet byte match, callback 수신, fcntl 완료, 일반 remote KCOV PC 존재만으로 owner를
주장하지 않는다. raw pcap, raw coverage, target PC, lock tuple, 후보 위치를
issue·PR·repo에 복사하지 않는다. typed event, sealed manifest, VM identity가
없으면 결과는 diagnostic_only 또는 fail-closed다.

### 확장 절차

1. kernel patch에 owner key와 lifecycle event 생성·전달·release 지점을 추가하고
   실제 심볼과 lifetime을 checkout에서 확인한다.
2. event schema와 canonical digest를 고정하고 agent_pipeline/stage2 normalized
   input 및 verifier에 필드를 추가한다.
3. 기존 encoding과 digest를 보존하는 replay test와 누락·중복·재시작 negative
   test를 추가한다.
4. 독립 KVM에서 positive, deactivate-before-grant, duplicate/retransmission,
   Proxy restart, lockd/rpciod restart, VM crash/reboot, concurrent generation을
   실행한다.
5. typed evidence와 owner 승인을 받은 뒤에만 HCAP-13 또는 Stage 2 gate를 갱신한다.

### 제약

owner key는 (generation, request_cookie, lane_epoch)로 immutable해야 한다.
현재 generation 조회, thread ID, pointer address, wall-clock timestamp로 owner를
재구성하지 않는다. CLOSING, ABORTED, COMMITTED, epoch mismatch, event gap, drop,
ref leak은 모두 ownership을 차단한다.

### 검증 방법

문서·패치 대조는 git diff --check와 kernel patch 적용·빌드로 시작한다. KVM 결과에서
lifecycle event sequence, aggregate tag, host journal/pcap manifest, drop counter,
owner/ref 종료 counter를 함께 확인하고 기존 NLM diagnostic contract의
diagnostic_only 결과와 분리해 보고한다. 실패 시 raw 증거를 공개하지 않고 실패
상태와 원인 counter만 보고한다.
