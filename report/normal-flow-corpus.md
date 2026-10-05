# 정상 NFS 실행 흐름: 지원 범위와 완료 기준

현재 코퍼스는 TCP 입력 여섯 개를 포함한다. NFSv3 입력 하나, NFSv4.0 입력 하나, NFSv4.1·v4.2 입력 네 개이다.
v4.1 기본 파일 연산 퍼징은 knfsd와 Ganesha가 각각 별도 syz-manager와 `corpus.db`를 사용한다.
두 서버는 한 번에 한 서버씩 실행한다.
입력·마운트·실행 명령의 기준은
[코퍼스 운영 문서](../bundle/corpus/nfs-normal/README.md)와
[시드 manifest](../bundle/corpus/nfs-normal/manifest.json)이다.

아래 NF 식별자는 Linux 커널의 NFS 서버·클라이언트 실행 흐름을 가리킨다.
실행 주체의 전체 목록, 시나리오별 전환 규칙, 측정 결과는
[실행 주체와 스레드 전환](normal-flow-threads.md)이 소유한다.
이 문서는 흐름의 정의와 완료 상태만 소유한다.
Ganesha 기본 입력은 기능 비교용이다. 현재 피드백은 클라이언트 커널 KCOV이다.
Ganesha 사용자 공간 서버 내부 커버리지는 수집하지 않는다.

## 완료 기준

1. 대상 입력이 고정된 syzkaller에서 파싱되고 실제 VM에서 실행되어야 한다.
   기대 errno와 파일 효과를 확인한다. 파싱 성공만으로 NFS 실행을 인정하지 않는다.
2. 스레드 전환을 주장하려면 요청·작업의 제출과 실행을 같은 대상으로
   연결한 관측이 필요하다. PC 존재나 최종 파일 효과만으로 전환을 인정하지 않는다.
   연결 키로 묶은 관측은 `LINKED`이다. 연결 키가 없고 시간 순서만 확인한 관측은 `ORDERED`이다.
   `ORDERED`는 같은 일이라는 증명이 아니다.
3. KCOV 수집 여부를 흐름의 실행 여부와 구분해 기록한다. 원격 KCOV가
   비어 있어도 미실행을 뜻하지 않는다. 수집된 PC만으로 요청별 귀속을 증명하지 않는다.
4. 버전·전송방식·서버·fixture 조건을 고정해 결과를 해석한다. 고정한 조건에서
   입력과 직접 관측이 없는 흐름은 미검증으로 남긴다.

## 목표 흐름과 현재 상태

`전환 규칙`은 [실행 주체와 스레드 전환](normal-flow-threads.md)의 전환 ID이다.
`판정`의 날짜는 증거 실행 `run2`의 날짜(2026-10-05)이다.

### 서버 흐름

| 흐름 | 정상 트리거와 실행 주체 | 전환 규칙 | 판정 |
| --- | --- | --- | --- |
| NF-A1 TCP 요청 수신 | 소켓 data-ready(softirq)가 nfsd 스레드를 깨운다. nfsd 스레드가 요청을 실행한다 | S1-01–03, S2-01, S3-01–02 | `LINKED`: 소켓 주소 쌍과 xid로 연결했다(v3, v4.0, v4.1, v4.2). KCOV 귀속은 이 판정과 별개이다 |
| NF-A2 동기 실행·응답 캐시 | 같은 nfsd 스레드가 캐시 판단과 NFS 연산을 실행한다 | 없음 | knfsd 기본 입력의 34개 호출이 완료됐다. 중복 응답 캐시 분기는 미검증이다 |
| NF-B1 인증·export 캐시 재방문 | nfsd 스레드가 캐시 miss에서 upcall을 보낸다. `rpc.mountd`가 응답한다 | S1-08, S4-01 | `ORDERED`: upcall 3개 뒤 mountd가 `cache_revisit_request`를 실행했다. 서버는 `svc_defer`를 쓰지 않았다(0건). 대기 중인 nfsd 스레드가 깨어나는 순간은 미검증이다 |
| NF-B2 SUNRPC 캐시 정리 | 타이머가 `do_cache_clean`을 제출한다. kworker가 실행한다 | S4-06 | `LINKED` |
| NF-C1 비동기 COPY | nfsd 스레드가 `copy thread` kthread를 만든다 | S3-03 | `LINKED`: `client=` 값으로 연결했다(v4.2) |
| NF-D1 서버 발신 callback | nfsd 스레드 또는 copy 스레드가 `nfsd4_callbacks` workqueue에 제출한다. rpciod가 CB RPC를 보낸다 | S2-03–04, S2-10–12, S3-04–05, S3-09–10, S3b-02–03, S3b-10–11 | `LINKED`와 `ORDERED`: v4.0, v4.1, v4.2에서 관측했다 |
| NF-D2 세션 backchannel | 클라이언트 소켓 수신 worker가 요청을 `sv_cb_list`에 넣는다. callback 스레드가 실행한다 | S3-06–08, S3b-04–06 | `LINKED`와 `ORDERED`: v4.1, v4.2에서 관측했다. v4.0에서는 backchannel이 없다(`MISSING`을 확인했다) |
| NF-D3 delegation recall | 충돌한 OPEN을 실행하는 nfsd 스레드가 `nfsd_break_deleg_cb`를 실행한다 | S2-02–03, S3b-01–02 | `ORDERED`와 `LINKED`: grant, recall, CB 응답, 반환의 순서를 v4.0과 v4.1에서 관측했다 |
| NF-E1/E2 상태 수명·회수 | 타이머가 laundromat을 제출한다. 메모리 압력이 shrinker worker를 제출한다 | S4-02–03 | `LINKED`. 미관측: lease 만료로 인한 client 만료. 25초 링크 단절에서 만료 이벤트가 0건이었다. 이유는 미검증이다 |
| NF-E3/E3b 파일 캐시 정리·처분 | filecache laundrette가 실행된 뒤 nfsd 스레드가 처분한다 | S4-04 | `ORDERED`: v3 실행에서만 관측했다. v4.x 실행에서는 관측하지 못했다 |
| NF-E4 클라이언트 추적 | `nfsdcld`가 downcall을 쓴다. 서버를 시작한 제어 태스크가 grace를 끝낸다 | S4-05 | `ORDERED`: 새 서버에서 grace가 시작 직후 끝난다. laundromat은 grace를 끝내지 않는다 |
| NF-E5 pNFS layout recall·fence | layout 충돌·타임아웃 → callback·fence 작업 | 없음 | pNFS export와 fence 백엔드가 없다 |

### 클라이언트와 보조 서비스 흐름

이 절의 흐름은 [실행 주체와 스레드 전환](normal-flow-threads.md)이 처음 정의한다.

| 흐름 | 정상 트리거와 실행 주체 | 전환 규칙 | 판정 |
| --- | --- | --- | --- |
| NF-F1 클라이언트 동기 RPC | syscall 태스크가 송신하고 대기한다. 소켓 콜백(softirq)이 xprtiod 수신 worker를 제출한다. worker가 대기 태스크를 깨운다 | S1-04–05 | `LINKED` |
| NF-F2 클라이언트 비동기 RPC와 해제 | syscall 태스크가 rpciod에 제출한다. 완료 뒤 nfsiod가 `rpc_release`를 실행한다 | S1-06–07 | `LINKED` |
| NF-F3 state manager | CB_RECALL이나 에러가 state manager kthread를 만든다 | S2-07, S3b-07 | `ORDERED` |
| NF-F4 lease 갱신 | 타이머가 `nfs4_renew_state`를 제출한다 | S4-07 | `LINKED` |
| NF-F5 NFSv4.0 callback 서버 | 서버가 client의 callback 리스너에 별도 TCP 연결을 연다 | S2-05–06, S2-13 | `LINKED`와 `ORDERED`: v4.0에서만 관측했다. v4.1에서는 `UNPAIRED`와 `MISSING`을 확인했다 |
| NF-F6 delegation 반환 | state manager가 DELEGRETURN을 rpciod에 제출한다. nfsd 스레드가 실행한다 | S2-08–09, S3b-08–09 | `LINKED` |
| NF-G1 NFSv3 서버 기동 | 제어 태스크가 nfsd 스레드와 lockd를 시작한다. lockd grace 타이머가 `grace_ender`를 제출한다 | S1-09–11 | `ORDERED`와 `LINKED` |
| NF-G2 NLM 잠금 대기, GRANTED, NSM, reclaim | 서버 로컬 잠금의 해제가 `lm_notify`를 실행한다. lockd가 `GRANTED_MSG`를 rpciod에 제출한다. `SM_NOTIFY`가 reclaimer kthread를 만든다 | S5-01–07, S5b-01–03 | `LINKED`와 `ORDERED`: loopback 잠금 마운트에서 관측했다(셸 스크립트, 시드 아님). lane 마운트는 `nolock`이고 lane에 `rpc.statd`가 없어서 lane 구성에서는 도달하지 못한다. 호스트 간 NLM은 관측하지 못했다 |
| NF-G3 mount와 umount | `mount.nfs`, `umount` 태스크가 동기 RPC를 보낸다. umount 뒤 해제 work가 실행된다 | 없음 | 부분 측정: client 쪽 RPC와 해제 work만 관측했다. MOUNT 프로토콜 서버는 사용자 공간 `rpc.mountd`이므로 서버 쪽 전환은 추적 대상이 아니다 |

## 프로토콜과 계측 경계

현재 입력의 대상은 NFSv3, NFSv4.0, NFSv4.1, NFSv4.2의 TCP이다.
NFSv3 입력은 `basic-v3-tcp.prog`이고 NFSv4.0 입력은 `deleg-recall-v40-tcp.prog`이다.
두 입력은 2026-10-05에 추가했다. 두 입력의 모든 호출이 errno 0으로 끝났다.
NFSv3 입력은 `flock`을 쓰지 않는다. `nolock` 마운트에서 `flock`은 client 로컬 잠금이다(코드상).
NFSv2, UDP, RPC-over-RDMA, LOCALIO, NAT에 대한 실행 완료나 스레드 전환은 주장하지 않는다.
NLM 잠금은 시드로 만들 수 없다. lane 마운트가 `nolock`이기 때문이다. NLM은 셸 스크립트 S5, S5b가 별도 구성으로 다룬다.
LOCALIO의 probe work는 `nfs.localio_enabled=N`에서도 실행한다(측정됨). LOCALIO의 I/O 경로는 실행하지 않는다.

knfsd의 요청별 원격 KCOV는 `svc_process` 부근에서 시작한다.
그러므로 그보다 앞선 소켓 수신·큐 삽입 단계의 PC가 없다는 사실만으로 미실행을 단정하지 않는다.
전역으로 관측한 전송 단계 PC는 특정 프로그램의 피드백으로 바로 합칠 수 없다.
corpus 선택 신호로 쓰기 전에 세 가지를 확인한다: 실행별 격리, 남은 작업의 배출, 외부 트래픽 배제.
callback과 주기적 작업은 별도 관측 없이 요청에 귀속하지 않는다.
현재 검증 결과의 범위와 실행 방법은
[코퍼스 운영 문서](../bundle/corpus/nfs-normal/README.md)를 따른다.
