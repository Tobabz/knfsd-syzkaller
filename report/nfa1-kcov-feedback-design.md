# NF-A1 transport KCOV: 관측과 fuzzing 피드백의 간극

> **기록 안내 (2026-10-01).** 이 문서의 수집기(`nfa1-kcov-observer.c`)와 실행 어댑터(`nfa1-kcov-presence.py`)는
> 커밋 `7833ed3`에서 제거되었고, 커널 패치(`bundle/patches/kernel/0013-*`)만 시리즈에 남아 있습니다.
> 설계 기록으로만 보존합니다.

## 현재 상태와 문제

기존 요청별 remote KCOV는 RPC 레코드와 소유권을 확인한 뒤
`svc_process`에서 시작한다. 그 전에 실행되는 softirq
`svc_data_ready`/`svc_xprt_enqueue`와 nfsd 스레드의
`svc_xprt_dequeue`는 요청별 `.extra`에 들어가지 않았다. R2 실행의
물리적 handoff trace는 이 경로의 실행을 보여 주지만, 해당 세 함수의
요청별 PC는 0개였다. PC 부재를 미실행으로 해석할 수 없는 이유다.

현재 작업 전용 커널은 NFSD 전역 관측 핸들
`0x0200000000000001`로 이 두 구간을 별도 수집한다.
`svc_process`는 기존 checked request ticket에만 맡긴다.
이미 실행 중인 KCOV나 관리 중인 ticket이 있으면 관측을 건너뛰며,
관측 결과를 요청의 generation 또는 executor `.extra`에 합치지 않는다.
소스는 `bundle/patches/kernel/series`의 마지막 NF-A1 패치,
수집기는 `bundle/corpus/nfs-normal/nfa1-kcov-observer.c`,
실행 어댑터는 같은 디렉터리의 `nfa1-kcov-presence.py`에 있다.

v4.2/TCP COPY 페어 VM 결과는
`/home/idealinsane/normal-flow-evidence/NF-A1-KCOV-V2-20260928/`에
보존한다. OFF는 비포화 관측 PC 16,053개와 요청별 PC 0개,
ON은 비포화 관측 PC 13,065개와 요청별 PC 721,547개였다.
양쪽 모두 data-ready/enqueue/dequeue 함수 영역의 PC가 있고,
`svc_process` 요청별 PC는 ON에서만 확인됐다. ON의 관리 중인
요청 시작/종료는 68/68이며 기능적 COPY와 cleanup이 통과했다.
각 모드의 KCSAN 보고 2건은 그대로 남아 있다. 관측 PC는 게스트
전체의 **구간 도달** 증거이지 같은 요청의 handoff나 순서 증거가 아니다.
원본 VM 이미지는 변경하지 않았다.

이 결과는 계측 공백을 *볼 수 있게* 만들었지만 해당 PC를
coverage-guided fuzzing의 *피드백으로 쓰게* 하지는 않는다.
어댑터는 작업 전후 관측 파일을 별도로 읽어 판정하고,
executor의 `coverage/` 및 요청별 `.extra` 밖에 보관한다.
따라서 현재 fuzzer가 입력을 보존하거나 변이의 가치를 계산하는
신호에는 새 transport PC가 반영되지 않는다. 기존 요청별
`svc_process` 등의 피드백은 그대로 유지된다.

## 단순 합치기가 잘못되는 이유

전역 핸들은 소켓, 네임스페이스, nfsd 스레드에 걸친 PC를 모은다.
동시에 실행된 다른 클라이언트나 background 작업의 PC를 현재
프로그램의 새 coverage로 계산하면 입력 선택이 오염된다.
특히 `svc_data_ready` 시점에는 RPC 레코드와 요청 소유자가 아직
확정되지 않아 PC 하나를 특정 요청에 귀속할 근거가 없다.
`svc_xprt_dequeue`도 나중에 처리될 레코드와 무조건 일대일이 아니다.

관측 시작을 요청별 ticket보다 앞으로 옮기거나 전역 PC를 기존
generation에 합치는 방식은 소유권 검사를 우회할 수 있다.
반대로 관측 누락도 가능하다. task 문맥의 data-ready callback은
현재 훅 대상이 아니며, softirq가 관리 중인 ticket을 중단하거나
scratch가 없으면 관측은 수동적으로 건너뛴다. disable 당시
진행 중인 section은 폐기될 수 있고 버퍼 포화도 가능하다.
따라서 PC 부재를 입력의 미도달 판정으로 사용해서는 안 된다.

## 선택지와 판단 기준

| 선택지 | 얻는 것 | 비용과 한계 |
| --- | --- | --- |
| 현재 방식 유지: 별도 전역 관측 | 기존 요청별 generation을 보존하면서 실행 구간을 진단 | 새 transport PC는 fuzzing 신호가 아니며 입력별 귀속 불가 |
| 실행 단위로 격리해 별도 signal 제공 | 격리가 성립하면 요청보다 거친 *프로그램 실행 단위*의 탐색 신호 가능 | 실행마다 관측기 reset/stop/drain과 외부 트래픽 통제 필요; background 잔여 작업과 진행 중 section은 여전히 혼입·누락 가능, 처리량 감소 |
| 연결/레코드의 소유권을 전송 경계부터 전달 | 동시 실행 환경의 정확한 입력별 피드백으로 확장 가능 | 커널과 executor의 ABI·수명주기 변경이 큼; 레코드 전 소켓 콜백에는 요청별 소유권을 정의할 수 없어 별도 귀속 단위가 필요 |

단기 후보는 기존 `.extra`에 합치지 않는 **실행 단위의 별도 signal**
실험이다. 한 실행에서 생성된 PC만 그 실행에 연결할 수 있는지
먼저 입증해야 한다. 다른 클라이언트의 트래픽을 넣어도 현재
입력의 새 signal이 늘지 않는 음성 대조, 종료 후 in-flight
section/drain 확인, 포화·누락 판정, 동일 입력 재실행의 안정성,
처리량 비용을 함께 측정한다. 통과 전에는 이 신호를 corpus 선택에
연결하지 않는다. 다중 클라이언트와 background 작업이 필요한
일반 fuzzing에서 이 격리를 보장하지 못하면 세 번째 선택지를
검토한다. 그때도 요청 이전 callback의 귀속 단위는 요청 ID가
아닌 연결 또는 실행 창일 수 있음을 명시해야 한다.

**아직 결정되지 않은 사항:** fuzzing에 필요한 최소 단위가
실행별 신호인지 요청별 신호인지, 허용할 격리·처리량 비용,
그리고 동시 실행의 다른 트래픽을 어떻게 배제하거나 표시할지.
현재 PC 존재와 기능 성공만으로 이 결정을 대신하지 않는다.
구간 관측의 재현 방법과 기존 정상 흐름의 나머지 공백은
`bundle/corpus/nfs-normal/README.md`와
`report/normal-flow-corpus.md`에 있다.
