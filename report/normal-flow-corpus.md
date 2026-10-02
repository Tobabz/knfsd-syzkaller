# 정상 NFS 실행 흐름: 지원 범위와 완료 기준

현재 코퍼스는 NFSv4.1·v4.2/TCP 입력 네 개를 포함한다. v4.1 기본 파일 연산
퍼징은 knfsd와 Ganesha가 각각 별도 syz-manager와 `corpus.db`를 사용하며
한 번에 한 서버씩 실행한다. 입력·마운트·실행 명령의 기준은
[코퍼스 운영 문서](../bundle/corpus/nfs-normal/README.md)와
[시드 manifest](../bundle/corpus/nfs-normal/manifest.json)다.

아래 NF 식별자는 Linux 커널의 NFS 서버·클라이언트 실행 흐름을 가리킨다.
Ganesha 기본 입력은 기능 비교용이며, 현재 피드백은 클라이언트 커널
KCOV다. Ganesha 사용자 공간 서버 내부 커버리지는 수집하지 않는다.

## 완료 기준

1. 대상 입력이 고정된 syzkaller에서 파싱되고 실제 VM에서 실행되어야 한다.
   기대 errno와 파일 효과를 확인한다. 파싱 성공만으로 NFS 실행을 인정하지 않는다.
2. 스레드 전환을 주장하려면 요청·작업의 제출과 실행을 같은 대상으로
   연결한 관측이 필요하다. PC 존재나 최종 파일 효과만으로 전환을 인정하지 않는다.
3. KCOV 수집 여부를 흐름의 실행 여부와 구분해 기록한다. 원격 KCOV가
   비어 있어도 미실행을 뜻하지 않으며, 수집된 PC만으로 요청별 귀속을 증명하지 않는다.
4. 버전·전송방식·서버·fixture 조건을 고정해 결과를 해석한다. 해당 조건의
   입력과 직접 관측이 없는 흐름은 미검증으로 남긴다.

## 목표 흐름과 현재 공백

| 흐름 | 정상 트리거와 실행 문맥 | 현재 입력과 판정 |
| --- | --- | --- |
| NF-A1 TCP 요청 수신 | 소켓 data-ready 작업 → nfsd 서비스 스레드의 요청 처리 | 기본·COPY 입력이 있다. 현재 시드 실행의 원격 KCOV만으로 수신부터 서비스 스레드까지의 물리적 전환을 확인하지 않는다. |
| NF-A2 동기 처리·응답 캐시 | 같은 nfsd 스레드에서 캐시 판단과 NFS 연산 처리 | knfsd 기본 입력의 34개 호출이 완료됐다. 중복 응답 캐시 분기는 별도 미검증이다. |
| NF-B1 인증·export 캐시 재방문 | 캐시 보류 → 갱신 → nfsd 재방문 | 재방문을 정상 조건으로 유발하는 입력과 관측 fixture가 없다. |
| NF-B2 SUNRPC 캐시 정리 | 만료 항목 → 전역 지연 작업 실행 | 작업 실행을 직접 확인하는 입력·관측이 없다. |
| NF-C1 비동기 COPY | NFSv4.2 COPY 요청 → 서버 copy 스레드 | COPY 입력은 32 MiB 반환과 커버리지를 확인했다. 현재 fixture에서 스레드 전환을 별도로 재확인하지 않았다. |
| NF-D1 서버 발신 callback | COPY 완료·delegation 충돌 → callback 작업·RPC 실행 | COPY와 delegation 입력이 있다. callback 작업의 제출·실행을 현재 fixture에서 직접 연결하지 않았다. |
| NF-D2 세션 backchannel | 클라이언트 소켓 수신 작업 → callback 서비스 스레드 | delegation 입력이 있다. 수신부터 서비스 스레드까지의 전체 전환은 미검증이다. |
| NF-D3 delegation recall | 다른 클라이언트의 충돌 → recall callback | delegation 입력이 있다. 현재 fixture에서 grant·recall·ACK·return의 순서를 직접 확인하지 않았다. |
| NF-E1/E2 상태 수명·회수 | lease 만료 또는 메모리 압력 → laundromat·reaper 작업 | 이벤트를 유발하고 작업 실행을 관측하는 fixture가 없다. |
| NF-E3/E3b 파일 캐시 정리·처분 | 캐시 GC 또는 shrinker → 정리 작업·nfsd 깨우기 | GC 작업과 처분 후 서비스 스레드 복귀를 확인하는 입력·관측이 없다. |
| NF-E4 클라이언트 추적 | grace 시작 → nfsdcld 사용자 공간 upcall | nfsdcld를 선택·검증하는 fixture가 없다. |
| NF-E5 pNFS layout recall·fence | layout 충돌·타임아웃 → callback·fence 작업 | pNFS export와 fence 백엔드가 없다. |

## 프로토콜과 계측 경계

현재 입력의 대상은 NFSv4.1·v4.2/TCP다. 기존 NFSv3 시드와 별도 fixture는
제거되었다. 현재 공통 lane fixture는 NFSv3·v4.0의 기본 마운트와 교차 I/O를
검증했지만, 해당 버전의 정상 흐름 시드와 스레드 전환 오라클은 없다.
NFSv2, UDP, RPC-over-RDMA, LOCALIO, NAT에 대한 실행 완료나 스레드 전환은 주장하지 않는다. NF-B1/B2와 NF-E1–E5는
현재 코퍼스의 실행 시나리오 수에 포함하지 않는다.

knfsd의 요청별 원격 KCOV는 `svc_process` 부근에서 시작하므로 그보다
앞선 소켓 수신·큐잉 단계의 PC가 없다는 사실만으로 미실행을 단정하지
않는다. 전역으로 관측한 전송 단계 PC는 특정 프로그램의 피드백으로 바로
합칠 수 없다. 실행별 격리, 남은 작업의 배출, 외부 트래픽 배제를 확인하기
전에는 corpus 선택 신호로 사용하지 않는다. callback과 주기적 작업도
별도 관측 없이 요청에 귀속하지 않는다.
현재 검증 결과의 범위와 실행 방법은
[코퍼스 운영 문서](../bundle/corpus/nfs-normal/README.md)를 따른다.
