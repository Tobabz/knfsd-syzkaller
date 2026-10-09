# NFSD trace.c의 KCOV 수집 설계

> 상태: draft · 최종 확인: 2026-10-10 · 기준: 저장소 `f2b3814`
> 대상: Linux `fs/nfsd/trace.c` 번역 단위에서 생성되는 코드
> 코드 조사: kernel `2f0acf4dc463c972b38a82c362d4a187276c3013`, syzkaller `01fa50721727a4cbcd2a79a2c69b4b56d472b858`
> 범위: 기존 커널 계측을 사용하는 NFSD 이벤트 활성화. 커널 계측 코드 변경과 재빌드는 없다.

## 요약

목표는 `fs/nfsd/trace.c`에서 생성되는 tracepoint 코드의 실제 PC를 KCOV로 수집하는 것이다.
기존 KASAN 게스트의 정상 NFS 입력에서 이벤트 활성화만으로 대상 PC가 수집됨을 확인했다.
`bundle/lane/lane.sh`의 setup이 tracefs를 준비하고 NFSD 이벤트와 `tracing_on`을 활성화하며, bootstrap이 부팅 상태를 확인한다.

실측 조건과 원시 증거는 [수동 활성화 비교](../../../report/validation-history.md#nfsd-tracec-kcov-activation-2026-10-10)와
[자동 활성화 결과](../../../report/validation-history.md#nfsd-tracec-automatic-activation-2026-10-10)에 기록한다.

## 해결하려는 문제

`fs/nfsd/trace.c`의 본문은 다음과 같다.

```c
#define CREATE_TRACE_POINTS
#include "trace.h"
```

이 파일을 컴파일하면 `fs/nfsd/trace.h`와 공통 trace 매크로가 실제 함수와 tracepoint 정의를 생성한다.
`fs/nfsd/Makefile`은 `trace.o`를 `nfsd.o`에 포함한다. 따라서 조사 단위는 `trace.c`의 소스 줄 수가 아니라
`trace.o`에 생성된 코드와 그 코드의 런타임 실행이다.

사전 정적 조사에서 확인한 사실:

- 저장된 KASAN·KCSAN 설정은 `CONFIG_KCOV_INSTRUMENT_ALL=y`이며, NFSD Makefile에는 KCOV 제외 설정이 없다.
- KASAN `vmlinux`의 `trace_event_raw_event_nfsd_compound`와 `trace_event_raw_event_nfsd_io_class`에
  `__sanitizer_cov_trace_pc` 호출이 존재한다. 전체 생성 함수의 계측 여부를 전수 확인한 것은 아니다.
- `env/manifest.json`의 kernel·syzkaller 리비전은 조사한 소스 HEAD와 다르다. 먼저 빌드 기준을 맞춰야 한다.

계측 호출이 존재해도 tracepoint 기록 경로가 비활성이거나 실행 스레드에 유효한 KCOV 수집 구간이 없으면
원하는 PC를 얻지 못한다. 이 두 원인을 구분하는 것이 계획의 출발점이다.

## 구조

```text
 build:
   fs/nfsd/trace.c + trace.h + common trace macros
                  |
                  v
              trace.o --KCOV instrumentation--> vmlinux

 runtime:
 +------------------- guest kernel --------------------+
 | NFSD request / async work                           |
 |       | trace_nfsd_*() call site                    |
 |       v                                            |
 | enabled tracepoint                                 |
 |       | dispatch / event recording                  |
 |       v                                            |
 | code generated in trace.o (T)                       |
 |       | compiler-inserted KCOV calls                |
 |       v                                            |
 | active KCOV area of the executing task (K)          |
 +-----------------------|----------------------------+
                         | raw PCs
                  host: symbol/object mapping
```

(T)는 대상 코드, (K)는 수집 문맥이다. 빌드 경로와 런타임 경로를 각각 위에서 아래로 읽는다.

## 설계

### 1. trace.o의 생성 코드와 빌드 계측 확인

소스·시리즈·설정·바이너리 해시를 일치시킨 뒤 `trace.o`의 컴파일 명령과 디스어셈블 결과를 확인한다.
대상 함수 목록은 해당 빌드의 심볼과 디버그 정보에서 얻는다. 예시는 `__traceiter_nfsd_*`,
`trace_event_raw_event_*`이며, 최적화로 함수가 합쳐지거나 인라인될 수 있음을 반영한다.

생성 코드를 tracepoint 디스패치, 이벤트 기록, 출력 포맷·관리 코드로 분류한다.
NFS 요청 중 실행되는 부분과 trace를 읽거나 설정하는 태스크에서 실행되는 부분을 같은 결과로 합치지 않는다.
계측 누락이 확인된 경우에만 해당 빌드 설정이나 함수의 제외 속성을 검토한다.
저장된 설정과 일부 바이너리에서 이미 계측이 확인됐으므로 Makefile 설정을 우선 추가하지 않는다.

### 2. 대상 코드의 실행 조건 확인

tracefs가 준비된 계측 대상 게스트에서 기존 이벤트 활성화 인터페이스를 사용한다.

```sh
echo 1 | sudo tee /sys/kernel/tracing/events/nfsd/enable
```

이 설정은 NFSD 이벤트 기록 콜백을 등록·활성화한다. 해당 콜백이 기존 remote KCOV 구간에서 실행되면
이미 삽입된 KCOV 호출이 PC를 수집한다. 이 명령 자체가 KCOV 수집 세션을 시작하는 것은 아니다.
세션과 remote 구간은 기존 executor·커널 패치가 담당한다.

호스트에서 실행하면 호스트 커널의 설정이 바뀌므로 fuzz VM의 계측에는 게스트 안에서 실행한다.
이벤트 기록 본문까지 실행하려면 `tracing_on`과 필터 상태도 확인한다.
정상 NFS 요청으로 비활성·활성 결과를 비교하고, 필요할 때 `trace.o`의 어느 코드가 실행되는지 조사한다.
단순히 `trace_nfsd_*()` 호출 지점을 지났다는 사실과 이벤트 기록 콜백이 실행됐다는 사실을 구분한다.

`CONFIG_HAVE_STATIC_CALL`과 probe 구성에 따라 디스패치 경로가 달라질 수 있다.
모든 실행에서 `__traceiter_nfsd_*`가 반드시 호출된다고 가정하지 않고 실제 빌드와 활성화 상태를 기준으로 판정한다.

### 3. 생성 코드의 PC가 KCOV로 수집되는지 확인

프로그램별 원시 KCOV PC를 저장하고 `trace.o`의 함수·주소 범위와 대조한다.
매크로에서 생성된 코드의 소스 위치는 `trace.h`나 공통 헤더로 표시될 수 있으므로,
`addr2line` 결과에서 `fs/nfsd/trace.c` 문자열만 찾는 방식으로 수집 여부를 판정하지 않는다.

원시 PC 대조가 필요하면 기존 `syz-execprog`의 `-coverfile` 기능을 사용한다.
`capture.py`는 VM과 trace 수집을 자동화하는 선택 도구이며, 수정하거나 사용할 필요가 있는 것은 아니다.
초기 비교는 동기 요청으로 제한하여 기존 수집 구간과 대상 함수의 관계를 확인한다.

### 4. 수집되지 않는 실행 문맥의 원인 분류

동기 요청은 `svc_process`의 기존 remote 구간을 확인한다. COPY와 callback은 기존 saved-work·callback owner 구간을 확인한다.
대상 코드가 구간 밖에서 실행될 때만 누락된 귀속 경계를 검토한다.
수집 구간의 시작·종료를 공용 tracepoint 매크로에 일괄 삽입하지 않는다.

비동기 작업은 발생 원인이 된 프로그램의 generation을 유지한다.
주기적 작업이나 owner가 없는 작업을 이벤트 발생 시점의 프로그램에 임의로 연결하지 않는다.
동기 수집을 확인한 뒤 정상 입력의 비동기·병렬 실행으로 구간의 혼입과 지연 작업을 검사한다.

### 5. 소비 경로와 비용 확인

원시 PC가 수집된 뒤 syzkaller의 필터·심볼화·신호 처리가 그 PC를 어떻게 소비하는지 확인한다.
`trace.o`에서 생성된 코드의 커버리지로 표시하며, 이를 NFSD의 모든 파일 연산 코드 커버리지로 확대 해석하지 않는다.
tracepoint 활성화에 따른 처리량·버퍼 사용량과 커버리지의 반복 안정성을 측정한다.

### 변경 범위

- 적용: `bundle/lane/lane.sh`의 setup에서 NFSD 이벤트를 활성화한다. tracefs 준비나 활성화에 실패하면 setup이 실패한다.
- 부팅 검사: `tools/bootstrap-kcov-env.py`의 `stage_verify_variant`가 NFSD 이벤트와 `tracing_on`의 활성 상태를 확인한다.
- 배포: 호스트 주입 lane 스크립트를 사용하므로 이미지 재생성은 필요 없다. 기존 manager 설정은 `prepare-live-lane-config.py`로 새 스크립트를 고정해야 한다.
- 조사·측정: 필요한 경우 기존 정상 입력과 `syz-execprog`의 원시 PC 출력을 사용한다.
- 빌드 설정: `fs/nfsd/Makefile`과 KCOV 설정은 누락 원인이 확인된 경우에만 변경한다.
- 귀속: 기존 NFSD/SUNRPC 수집 구간에서 원인이 확인된 부분만 변경 후보로 삼는다.
- 전달: 커널 변경이 필요하면 `bundle/patches/kernel/`에 새 패치로 남긴다.
- 결과: 별도 `report/` 문서에 기록하며 README에는 진행 기록을 넣지 않는다.

## 설계 근거

`CREATE_TRACE_POINTS`는 선언된 tracepoint의 정의와 콜백 코드를 생성한다.
이 코드의 계측 여부는 컴파일 결과로, 실행 여부는 tracepoint 활성화와 호출 경로로,
수집 여부는 실행 태스크의 KCOV 상태로 각각 확인해야 한다.

KCOV는 컴파일러가 삽입한 호출로 PC를 수집하고, remote coverage는 다른 실행 문맥에 수집 구간을 지정한다.
tracepoint probe는 호출자의 문맥에서 실행된다.
[KCOV 문서](https://docs.kernel.org/dev-tools/kcov.html), [tracepoint 문서](https://docs.kernel.org/trace/tracepoints.html)

서브시스템의 `events/<system>/enable`은 해당 시스템의 이벤트를 함께 활성화하는 기존 인터페이스다.
[이벤트 활성화 문서](https://docs.kernel.org/trace/events.html#via-the-enable-toggle)

## 검토한 대안

| 선택지 | 얻는 것 | 비용·한계 | 판단 |
|---|---|---|---|
| 기존 trace.o 계측과 trace 활성화 활용 | 대상 코드의 실제 PC를 기존 경로로 수집 | 실행 문맥별 귀속을 확인해야 함 | 우선 접근 |
| trace.o의 명시적 KCOV 빌드 설정 추가 | 전체 계측 설정이 꺼져도 대상을 지정 가능 | 이미 계측된 구성에서는 효과가 중복됨 | 누락 또는 선택 계측 요구가 확인될 때 검토 |
| 모든 tracepoint 콜백에서 remote KCOV 시작·종료 | 대상 실행 지점에 수집 제어를 모음 | 중첩·잠금 문맥·잘못된 owner 문제가 생김 | 채택하지 않음 |
| 이벤트별 marker 또는 별도 이벤트 ID 신호 | 이벤트 이름을 구분하는 별도 피드백 제공 | trace.c 생성 코드의 실제 PC 수집과 다른 목표 | 이 계획의 범위에서 제외 |

## 영향

- **상류:** 커널의 trace 생성 매크로·최적화·컴파일러가 바뀌면 함수와 주소 범위가 달라진다. 빌드별로 대응을 다시 구한다.
- **하류:** 공유 이벤트 클래스는 같은 기록 코드를 사용한다. 코드 커버리지를 이벤트별 발생 횟수·순서로 읽지 않는다.
- **운영:** trace 활성화가 추가 실행과 버퍼 비용을 만든다. 동일한 활성화 조건을 유지하고 비용을 비교한다.

## 신뢰성 요구

거짓 음성을 줄이기 위해 계측 누락, 비활성 tracepoint, 미실행, 수집 구간 부재, 버퍼 포화를 분리한다.
거짓 양성을 줄이기 위해 `trace.o` 외부의 공용 tracing 코드와 다른 태스크·lane의 PC를 대상 결과에 섞지 않는다.
실행 기준과 원시 결과를 함께 보관하고, 프로그램 owner를 확인할 수 없는 결과는 별도로 표시한다.

## 검증 오라클

| 확인 | 통과 조건 |
|---|---|
| 빌드 | 기준이 일치하는 trace.o에서 대상 생성 함수와 KCOV 호출의 대응을 확인 |
| 실행 | 선택한 tracepoint 활성화와 정상 요청으로 대상 경로의 실행을 확인 |
| 수집 | 프로그램별 원시 PC를 trace.o의 계측 지점으로 대응시킬 수 있음 |
| 음성 대조 | 이벤트 비활성 또는 해당 정상 요청이 없는 조건의 결과 차이를 설명할 수 있음 |
| 귀속 | 비동기·병렬 실행에서 다른 lane과 다음 프로그램의 결과에 잘못 섞이지 않음 |
| 소비 | 수집한 PC의 필터·심볼화·manager 신호 처리가 의도한 계약과 일치 |
| 비용 | 활성화 전후 처리량·버퍼 사용량·반복 안정성을 같은 조건에서 비교 |

코드 변경이 필요한 경우 KASAN·KCSAN과 KCOV 비활성 구성의 빌드도 확인한다.
PC 수집 성공은 `trace.c`에서 생성된 해당 코드의 실행 근거이며, NFSD 전체 경로나 이벤트 간 인과관계의 증명은 아니다.

## 실패 양상과 진단

| 증상 | 가능한 원인 | 구분하는 관측 | 조치 |
|---|---|---|---|
| trace.o에 KCOV 호출이 없음 | 컴파일 옵션 또는 함수 제외 속성 | 실제 컴파일 명령·디스어셈블 | 해당 빌드 조건 확인 |
| tracepoint 호출 경로는 지났으나 기록 콜백이 실행되지 않음 | 이벤트 비활성, 조건 불충족, 필터 | 이벤트 활성화 상태·호출 경로 | 실행 조건 확인 |
| 이벤트 기록은 있으나 PC가 없음 | 수집 구간 부재·owner 부재·포화 | 원시 PC와 기존 수집 카운터 | 누락 문맥 분류 |
| trace.c 파일명으로 PC를 찾을 수 없음 | 매크로의 헤더 위치로 심볼화됨 | 오브젝트·컴파일 단위·함수 범위 | 파일명 필터를 보완 |
| 원시 PC는 있으나 manager 결과에 없음 | 필터·중복 제거·신호 변환 | 원시 PC와 소비 결과 | 기존 소비 경로 확인 |

## 한계와 미결 사항

- **확정:** 계측 대상은 `fs/nfsd/trace.c` 번역 단위의 생성 코드다.
- **미검증:** 모든 대상 함수의 계측 여부, 활성화 조건별 실제 수집 범위, 계측 비용.
- **범위 밖:** 이벤트별 marker-PC 추가, 이벤트 인자 기반 상태 피드백, 전체 NFSD 코드의 새 계측 체계.
- 기존 COPY·callback 귀속 결정은 유지한다. 구간 밖 PC가 관측되면 해당 원인을 근거로 별도 변경을 검토한다.

## Agent 사용 지침

기본 활성화는 lane setup에서 제공한다. 추가 범위를 다룰 때 `trace.c`의 생성 코드와 수집 문맥을 조사하며, 확인된 누락 없이 계측 패치를 추가하지 않는다.
seed·Mutation Engine의 동작 변경과 새로운 취약점 시나리오 작성은 이 계획에 포함하지 않는다.

## 참조

- [설계 작성 지침](../00-writing-guidelines.md)
- [lane 귀속 결정](../decisions/2026-10-01-lane-attribution.md), [callback 귀속 결정](../decisions/2026-10-05-callback-attribution.md)
- [trace 수집 도구](../../../tools/flow-trace/README.md)
- 커널 생성 경로: `fs/nfsd/trace.c`, `fs/nfsd/trace.h`, `fs/nfsd/Makefile`, `include/trace/define_trace.h`, `include/trace/trace_events.h`.
- 빌드·수집: `scripts/Makefile.lib`, `kernel/kcov.c`의 `__sanitizer_cov_trace_pc`.
- 귀속: `net/sunrpc/svc.c`의 `svc_process`, `fs/nfsd/nfs4proc.c`의 `nfsd4_do_async_copy`, `net/sunrpc/fuzz.c`의 `sunrpc_fuzz_cb_section_start`.
- 소비: syzkaller `executor/executor.cc`의 `write_signal`, `pkg/cover/backend/elf.go`와 `dwarf.go`.
