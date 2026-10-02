# 프록시 길이 변경 편집 구현 지시서

> **임시 인계 문서다. 아래 "삭제 조건"을 모두 만족하면 이 디렉터리 전체를 삭제한다.**
> 작성: 2026-10-01 · 기준: `main` (`1f3af0b` 이후), 커널 `v7.3-rc5` + 새 시리즈(0001~0003), syzkaller 0001~0018

> **진행 상황 (2026-10-02): Phase 1(6절) 구현 완료, 호스트 검증만 통과, 아직 `main`에 병합 안 함.**
> `tools/nfs-proxy/src/edit.{c,h}`(새 모듈), `control.c`의 arm v2 디코드·적용·체이닝, 프록시 arm v2
> 패킷(`NFSPARM2`)과 delta v2(`NFSPDLT2`), syzkaller 패치 `0019`(`syz_arm_nfs_proxy_v2`). `tools/nfs-proxy/build.sh`
> 전체(클랑 + gcc ASan/UBSan, `test_edit` 추가)와 syzkaller `go test ./sys/linux/...` 통과. **8절의 게스트
> 검증은 하지 않았다** — lane 귀속이 길이 변경 편집에서 유지되는지, 실제 게스트에서 OP_APPEND/INSERT/DELETE/REPLACE가
> 적용되는지는 미확인. 삭제 조건 1~5는 아직 하나도 충족되지 않았다(아래 조건 그대로 유효). 다음 단계와 남은 미검증
> 항목은 세션 보고(완료 보고)를 참조.

## 0. 이 문서의 성격과 삭제 조건

이 문서는 대화 컨텍스트가 길어져 새 세션에서 구현을 이어 가기 위해 만든 **작업 지시서**다. 설계의 영구 기록이 아니다.
영구 기록은 구현이 끝난 뒤 `docs/design/05-wire-mutation/`의 설계 문서로 옮긴다
(`docs/design/00-writing-guidelines.md`의 형식을 따른다).

**삭제 조건 (모두 만족해야 삭제한다):**

1. 구현 단계(아래 6절)의 **Phase 1이 `main`에 병합**되었다. Phase 2, 3은 이 문서를 계속 쓸지, 별도 이슈로 옮길지 결정하고 결과를
   커밋 메시지에 남긴다. Phase 2, 3을 하지 않기로 했다면 그 사실과 이유를 05 문서에 적는다.
2. `docs/design/05-wire-mutation/`에 설계 문서가 있고, 이 문서의 **2절(확정된 결정)과 3절(불변 조건)이 그 문서에 옮겨졌다.**
   이 두 절의 내용은 다른 곳에서 복원할 수 없으므로 옮기지 않고 삭제하지 않는다.
   6절의 Phase 2, 3 계획(스키마 생성 방법, 자체 검증 오라클)도 아직 하지 않았다면 05 문서나 이슈로 옮긴다.
3. 호스트 테스트(`tools/nfs-proxy/build.sh`)와 게스트 검증(8절)의 통과 결과가 구현 커밋 메시지에 기록되었다.
4. `verify-lane.py`, `mkinputs.py`, `run-verify.sh`는 (a) `tools/`로 옮겨 정식 도구로 채택했거나 (b) 더 이상 필요 없음을 확인했다.
   이 스크립트들은 지워진 A/B 러너를 대신해 임시로 만든 것이다.
5. 이 문서에 적힌 **미검증 항목**(5.3절)이 해소되었거나 05 문서의 "한계와 미결 사항"으로 옮겨졌다.

**삭제 방법:** `git rm -r docs/handoff/proxy-variable-length-edits` 후 커밋한다. 커밋 메시지에 위 다섯 조건의 충족 근거를 적는다.
삭제한 문서는 `git log -- docs/handoff/proxy-variable-length-edits`로 복원할 수 있다.

## 1. 목표

NFS wire 프록시(`tools/nfs-proxy/`)가 지금은 **같은 위치를 같은 폭(최대 16바이트)으로 덮어쓰는** 변조만 한다
(`nfsp_apply_rule`의 `memcpy`). 취약점 시나리오가 요구하는 다음 변조를 지원하도록 만든다.

- NFSv4 COMPOUND에 **operation을 추가**한다.
- **가변 길이 필드**를 바꾼다 (길이가 달라지는 편집).

이 변조는 syzkaller 프로그램에 담긴 arm 규칙으로 지정되고, 프록시에는 난수가 없어 같은 프로그램이 같은 변조를 재현해야 한다.

## 2. 확정된 결정 (사용자 결정, 2026-09-30 ~ 10-01)

| 결정 | 내용 |
|---|---|
| 지원 범위 | operation 추가와 가변 길이 필드 변경을 **지원해야 한다** |
| 응답 보정 | 요청을 편집해도 **응답은 보정하지 않는다.** 클라이언트가 어떻게 반응하는지 관찰한다. 클라이언트 취약점 시나리오에서 필요해지면 XID 기반 짝 편집을 나중에 추가한다 |
| 스키마 범위 | 0층: 스키마 없이 가능한 편집(op 배열 앞·뒤 추가, raw 바이트 편집). 1층: 요청 op 74개의 경계 계산(syzlang `socket_inet_nfs.txt`에서 생성하고 RFC 8881로 op마다 대조). 2층: 응답 result 구조는 필요한 op만 손으로 작성. 범위 밖: `attrvals` 내부(속성별 중첩 구조) |
| 편집 모드 | **구조 보존**(본문의 `opcount`, XDR 길이·패딩을 맞춘다)과 **raw**(본문은 지정한 편집만 하고 보정하지 않는다). 취약점이 길이 필드와 실제 길이의 불일치 자체를 요구할 수 있어 둘 다 필요하다. **fragment 헤더(레코드 마커)는 두 모드 모두 항상 다시 만든다.** 마커가 틀리면 그 레코드뿐 아니라 이후 스트림 전체의 경계가 어긋나므로, 의도적 불일치는 RPC·XDR 본문 안에서만 만든다 |
| 한 레코드의 여러 편집 | **모든 offset과 앵커는 원본 레코드 기준이다.** 적용 구간이 겹치는 편집은 거부한다. 적용은 원본 기준 offset 순서로 한 번에 재구성한다(앞 편집이 뒤 편집의 위치를 밀지 않는다). `walk` 결과(slot, `header_end`)도 원본 기준이다. 도구를 쓰다 문제가 생기면 조정한다 (2026-10-01 결정) |
| 알 수 없는 op | op 경계를 알아야 하는 편집에서 표에 없는 op를 만나면 **편집을 거부하고(fail-closed) 카운터를 올린다** |
| 개수 변경 | RPC 삭제, 복제, 삽입, 순서 바꿈처럼 **레코드 개수를 바꾸는 변조는 이번 범위 밖**이다 |
| 귀속 | remote KCOV 귀속은 lane 단위(netns)라서 프록시 변조가 귀속에 영향을 주지 않는다. 귀속 때문에 프록시를 고칠 일은 없다 |

## 3. 불변 조건 (구현이 깨면 안 되는 것)

기존 코드 주석이 근거다. 새 구현이 이 원칙을 바꿔야 하면 구현 전에 사용자에게 알린다.

1. **규칙에 매칭되지 않은 레코드는 바이트 그대로 통과한다.** `framing.h`는 "프록시는 wire를 다시 쓰면 안 된다"고 적고 있다.
   길이를 바꾸려면 매칭된 레코드는 재구성해야 하므로, 이 원칙을 "매칭되지 않은 레코드는 바이트 동일"로 정제하고 문서에 남긴다.
2. **원본을 검증한 뒤에만 적용한다** (verify-before-patch). 원본이 기록과 다르면 적용하지 않고 `refused_orig`를 센다.
3. **프록시에 난수를 넣지 않는다.** 변조는 전부 arm 패킷의 바이트로 결정된다.
4. **프로듀스 경로와 `--replay` 경로가 같은 적용 함수를 쓴다.** 새 편집 종류도 한 함수에서 처리한다.
5. **변조 기록(`arm-N.delta`)은 적용될 때마다 O_SYNC로 남긴다.** 커널 oops 직전의 마지막 변조가 남아야 한다.
6. **ACK는 등록 완료만 뜻한다.** 적용 성공이나 서버 도달을 뜻하지 않는다.
7. **레코드 개수를 바꾸지 않는다.** 한 입력 레코드는 정확히 한 출력 레코드가 된다.
8. **실패는 연결을 닫는다.** 검증되지 않은 바이트를 내보내지 않는다 (`on_record`가 음수를 반환하면 닫는다).
9. 컴파일러 경고는 오류다 (`-Werror -Wconversion ...`). 새니타이저 빌드(gcc ASan+UBSan)를 건너뛸 수 없다.
10. **잘못된 arm 패킷은 등록하지 않는다.** syzkaller가 arm 구조체를 무작위로 변이하므로 길이, 편집 목록, 편집 종류가 틀린 패킷이
    자주 온다. 지금처럼 `decode()`에서 거부하고 `invalid_arms`를 올리며 ACK를 보내지 않는다. 잘못된 패킷 때문에 프록시가 죽거나
    다른 arm에 영향을 주면 안 된다.

## 4. 현재 코드 (확인한 사실)

`tools/nfs-proxy/src/`. 줄 번호 대신 함수 이름으로 적는다.

| 위치 | 사실 | 이번 변경과의 관계 |
|---|---|---|
| `proxy.c` `feed()` | 읽은 바이트를 `nfsp_framing`에 넣고 완성된 레코드마다 `on_record(client, backend, dir, f->buf, len, arg)`를 부른다. 반환이 0이 아니면 `mutation_errors`를 올리고 연결을 닫는다. 이어서 **`enqueue(q, f->buf, len, ...)`로 같은 버퍼를 그대로** 큐에 넣고 `nfsp_framing_consume(f, len)`으로 원래 길이만큼 버린다 | 길이가 바뀌면 `enqueue`가 새 바이트와 새 길이를 받아야 한다. `consume`은 **원래** 길이를 써야 한다. 지금은 `f->buf`(framing 버퍼)를 제자리에서 고치므로, 길이가 늘면 **별도 출력 버퍼**가 필요하다(할당 상한 = 메시지 상한). 큐 상한은 `ceiling + NFSP_READ_CHUNK`(`ceiling = limit + 4`)라서 늘어난 레코드가 여기에 걸리면 `relay_errors`로 연결이 닫힌다 |
| `proxy.h` `on_record` | 주석: "콜백은 **길이를 보존해야 한다.** 음수는 이 레코드를 거부하고 연결을 닫는다. NULL은 순수 중계" | 이 계약이 바뀐다. 콜백이 출력 버퍼와 새 길이를 돌려주는 형태가 필요하다 |
| `control.c` `nfsp_control_record()` | arm 중 `client`, `backend`, `dir`이 맞는 것이 있을 때만 `nfsp_walk`로 레코드를 해석한다. 해석이 안 되면 `unknown_layout`을 올리고 그대로 통과. 규칙마다 `patch_allowed()`를 거친 뒤 `nfsp_apply_rule()`을 부른다 | 편집 종류별 허용 검사와 적용이 여기를 지난다 |
| `control.c` `patch_allowed()` | 덮어쓸 위치가 `walk`의 **타입이 확실한 4바이트 slot**이거나 `TRAILER`가 아닌 **raw 영역 안**일 때만 허용 | 삽입·삭제용 허용 규칙을 새로 정해야 한다 |
| `control.c` `decode()` | arm 패킷은 정확히 **140바이트**: 8바이트 magic `NFSPARM1`, 32비트 big-endian 9개(방향, 백엔드, 클라이언트, 첫 opcode, 앵커 위치·길이, 패치 위치·폭, 0이어야 하는 예약), 앵커 64바이트, 원본 16바이트, 대체 16바이트. `patch_off >= 4`, 원본 != 대체여야 한다 | 가변 길이 편집을 담을 새 패킷 버전이 필요하다 |
| `control.c` | arm 슬롯 `NFSP_ARM_SLOTS = 64`. 등록 후 1바이트 ACK. `arm-N.delta`를 O_SYNC로 기록. fd가 닫히면 규칙이 사라진다 | 슬롯 수와 수명 관리는 유지한다 |
| `delta.h` | 규칙 구조체: `dir, backend, client, first_opcode, match_index, anchor_off, anchor_len, patch_off, patch_w, applied_count` + `anchor[64]`, `orig[16]`, `repl[16]`. 상수 `NFSP_DELTA_ANCHOR_MAX 64`, `NFSP_DELTA_PATCH_MAX 16`. 파일 magic `NFSPDLT1`, 버전 1, 레코드 헤더 u32 10개 | 가변 길이 데이터를 담는 새 파일 버전이 필요하다. 기존 버전 읽기를 유지할지 정한다 |
| `delta.c` `nfsp_apply_rule()` | 방향·백엔드·클라이언트·첫 opcode를 맞추고 앵커를 확인한 뒤, 패치 구간이 메시지 안인지 보고(`refused_out_of_range`), 원본 바이트를 비교하고(`refused_orig_diff`), `memcpy`로 덮어쓴다 | 이 함수를 편집 종류 전체를 처리하는 단일 구현으로 확장한다 |
| `walk.h` `nfsp_walk()` | 입력은 fragment 헤더를 포함한 완전한 메시지. 헤더 층(RPC, COMPOUND)만 타입이 확실한 slot(`NFSP_SR_OPCOUNT`, `TAG_LEN`, `FIRST_OPCODE` 등)으로 내고, 그 뒤는 구조를 주장하지 않는 raw 영역(`NFSP_RR_OP_BODY`)으로 낸다. `header_end`, `msg_len`을 알려 준다. 해석 실패 시 prefix만 주고 호출자가 통과시킨다 | 0층 편집은 이 정보만으로 가능하다. 스키마 층은 "region에 붙는 후속 계층"으로 자리가 남아 있다 |
| `framing.h` | 한 레코드는 1개 이상의 fragment다. `nfsp_framing_peek()`이 돌려주는 길이는 fragment 헤더를 포함한다. 메시지 상한 `NFSP_MSG_LIMIT_DEFAULT` 16 MiB, fragment 4096개 상한 | 편집된 레코드는 fragment 헤더를 다시 만들어야 한다(5.1절) |
| syzkaller `sys/linux/fs_nfs_fuzz.txt` | `nfs_proxy_arm` 구조체가 위 140바이트 패킷을 그대로 기술한다. `sys/linux/nfs_fuzz_test.go`의 `TestNFSFourRoutesAndScopedArm`이 **패킷 크기 140과 magic**을 단언한다 | 패킷을 바꾸면 이 기술과 테스트를 같이 고친다 |
| syzkaller `executor/common_linux.h` `syz_arm_nfs_proxy()` | 규칙 포인터에서 **140바이트를 고정으로** 보내고 1바이트 ACK를 기다린다 | 가변 길이 패킷이면 길이를 인자로 받아야 한다 |

## 5. 설계 제안 (구현자가 확정한다)

아래는 지금까지의 논의에서 나온 **제안**이다. 구현 전에 코드로 타당성을 확인하고, 바꿔야 하면 이유와 함께 사용자에게 알린다.

### 5.1 편집 종류와 모드

| 편집 | 스키마 | 비고 |
|---|---|---|
| `OVERWRITE` (기존) | 불필요 | 같은 폭. 현재 동작을 유지한다 |
| `INSERT` (offset, bytes) | 불필요 (raw) | 지정 위치에 바이트 삽입 |
| `DELETE` (offset, len) | 불필요 (raw) | 지정 구간 삭제. 원본 바이트 검증 |
| `REPLACE` (offset, old_len, new bytes) | 불필요 (raw) | 길이가 달라지는 교체. 원본 검증 |
| `OP_APPEND` (op bytes) | 불필요 | op 배열 뒤에 추가. `opcount` slot 갱신. 추가 위치는 메시지 끝 |
| `OP_PREPEND` (op bytes) | 불필요 | `header_end`에 삽입. 단 NFSv4.1은 SEQUENCE가 첫 op여야 한다 |
| op 중간 삽입, op 삭제, 가변 필드 변경 | **필요 (1층)** | op 경계를 알아야 한다 |

- **구조 보존 모드:** 편집 후 `opcount`, XDR 4바이트 패딩 등 본문 구조를 맞춘다(범위는 아래). fragment 헤더(길이, last-fragment 비트)는 모드와 무관하게 다시 만든다.
- **raw 모드:** 본문은 지정한 편집만 하고 보정하지 않는다(마커는 다시 만든다). 의도적 불량(길이 필드와 실제의 불일치)을 만들기 위한 모드다.
- **Phase 1(0층)에서 구조 보존이 실제로 보정하는 범위:** 스키마가 없으면 op 본문 안의 XDR 길이 필드 위치를 모른다. 그래서
  - `OP_APPEND`, `OP_PREPEND`: 마커와 `opcount` slot을 보정한다. 추가하는 op 바이트는 4바이트 배수여야 한다(아니면 arm 거부).
  - `INSERT`, `DELETE`, `REPLACE`: 마커만 보정한다. 구조 보존과 raw의 차이가 없으므로 이 셋은 모드를 받지 않거나 같은 동작으로 둔다.
  - op 본문 안의 XDR 길이·패딩 보정은 1층(Phase 2)의 몫이다.
- 편집한 레코드는 **fragment 하나, last-fragment 비트 켜짐**으로 다시 만드는 안을 제안한다. 여러 fragment로 온 레코드를 편집하면 합쳐서
  내보낸다. 이 선택이 서버·클라이언트 동작에 주는 영향은 확인하지 못했다.
- `OP_APPEND`가 메시지 끝에 붙는 근거는 COMPOUND4args와 COMPOUND4res에서 op 배열이 마지막 필드라는 RFC 5661 정의다.
  `walk.c`는 헤더 뒤의 op 본문을 `add_region(out, c->off, c->len - c->off, NFSP_RR_OP_BODY)`로 **메시지 끝까지** 영역으로 낸다(확인함).

### 5.2 인터페이스 변경

- **arm 패킷 v2:** magic을 `NFSPARM2`처럼 버전으로 구분하고 가변 길이 편집 목록을 담는다. `NFSPARM1` 수용 여부를 정한다.
  syzkaller 쪽은 `nfs_proxy_arm` 기술을 가변 길이 구조로 바꾸고(`len[]`, `array`), executor의 `syz_arm_nfs_proxy`가 길이를 받게 하고,
  `nfs_fuzz_test.go`를 고친다. 이 변경은 `bundle/patches/syzkaller/`에 **새 번호의 패치**(0019)로 만든다. 기존 패치를 고치지 않는다.
- **delta 파일 v2:** `NFSPDLT2`처럼 버전으로 구분하고 편집 종류와 가변 길이 데이터를 담는다. `--replay`가 v1과 v2를 모두 읽을지 정한다.
- **`on_record` 계약:** 길이 보존 조건을 없애고, 콜백이 (출력 버퍼, 출력 길이)를 돌려주도록 한다. 출력 길이는 `msg_limit` 이하여야 한다.
- **편집 데이터 상한:** arm 패킷 하나에 담는 편집 바이트 합의 상한을 정한다(SEQPACKET 한 번 전송 크기, syzkaller가 만드는 큰 값 대비).
  값은 **미정**이다(제안 4 KiB, 사용자 결정 대기). 상한을 넘는 arm은 거부한다.
- **통계:** 편집 적용 횟수, 길이 변화량 합, `refused_unknown_op`(알 수 없는 op로 거부), `refused_limit`(상한 초과)을 추가한다.

### 5.3 미검증 항목 (구현 중 확인하고 결과를 기록한다)

| 항목 | 확인 방법 |
|---|---|
| 요청에 op를 추가하면 응답의 `resarray`가 길어지는데, 리눅스 NFS 클라이언트가 뒤에 붙은 결과를 어떻게 처리하는가 | 게스트에서 OP_APPEND를 켜고 클라이언트 동작과 `dmesg` 관찰. 응답은 보정하지 않는 것이 결정이다 |
| 앞 op가 실패하면 뒤 op는 실행되지 않으므로, 추가한 op가 실제로 실행되는가 | 서버 쪽 `.extra`에서 추가 op의 처리 함수(예: `nfsd4_getattr`) 도달 여부 |
| 여러 fragment로 온 레코드를 한 fragment로 합쳐 내보내도 서버가 문제없이 받는가 | 큰 WRITE 등으로 다중 fragment 레코드를 만들어 편집 |
| 길이가 바뀐 레코드에서도 lane 귀속이 유지되는가 | 편집을 켠 상태에서 `.extra` 30/30 확인 |
| 서버의 최대 요청 크기와 프록시 `msg_limit`의 관계 | 상한 근처 편집으로 거부·연결 종료 동작 확인 |

## 6. 단계

**Phase 1 (이번에 구현한다): 0층.** `INSERT`, `DELETE`, `REPLACE`, `OP_APPEND`, `OP_PREPEND`를 구조 보존·raw 두 모드로 지원한다.
스키마는 만들지 않는다. 포함: 프록시 코드, arm 패킷 v2와 delta v2, syzkaller 패치 0019, 호스트 단위 테스트, **v2 arm을 쓰는 게스트 검증 프로그램**, 게스트 검증.
저장소의 `tools/nfs-proxy/test/guest-syzkaller-mutate.prog`는 140바이트 v1 arm용이라 그대로 쓸 수 없다. 편집 종류마다
(`OP_APPEND`, `INSERT` 등) 실제로 적용되는 프로그램을 새로 만들어 `run-verify.sh`의 `WORKLOAD`로 넘긴다.
**Phase 1을 끝내면 멈추고 사용자에게 보고해 검토를 받는다.** 검토 전에 Phase 2로 넘어가지 않는다.

**Phase 2: 1층.** 요청 op 74개의 인자 레이아웃을 `socket_inet_nfs.txt`에서 생성해 op 경계 표를 만들고, RFC 8881로 op마다 대조한다.
`attrvals`는 불투명으로 둔다. 자체 검증: 기술 파일로 만든 메시지를 워커가 끝까지 파싱해 소비한 바이트가 메시지 길이와 같은지 확인하고,
실제 클라이언트 트래픽(프록시로 캡처)으로도 같은 검사를 한다. 표에 없는 op는 거부한다.

**Phase 3: 2층.** 응답 result 구조를 필요한 op부터 추가한다.

## 7. 범위 밖

- 레코드 개수를 바꾸는 변조(삭제, 복제, 삽입, 순서 바꿈)
- 응답 보정, RPCSEC_GSS 무결성 모드(현재 마운트는 `sec=sys`이고 GSS는 지원하지 않는다고 05 문서에 적는다)
- 커널 변경 (귀속은 lane 단위라 프록시 변조와 무관하다)
- `attrvals` 내부의 속성별 편집

## 8. 검증

### 8.1 호스트 (먼저, 반드시)

```sh
tools/nfs-proxy/build.sh          # clang 빌드 + 단위 테스트 + gcc ASan/UBSan 빌드·테스트
```

새 모듈이 있으면 `build.sh`의 `UNITS` 목록에 추가해 새니타이저 빌드가 자동으로 포함되게 한다.
`test_delta.c`, `test_control.c`, `test_proxy.c`에 편집 종류별 테스트(정상, 원본 불일치, 범위 초과, 상한 초과, 레코드 하나당
출력 하나, 매칭되지 않은 레코드의 바이트 동일성)를 추가한다. **호스트 테스트가 통과하기 전에는 게스트에 올리지 않는다.**

### 8.2 게스트

지워진 A/B 러너를 대신해 이 디렉터리의 스크립트를 쓴다.

| 파일 | 용도 |
|---|---|
| `mkinputs.py` | 검증 입력(VM 도우미, lane fixture 세 종, 워크로드, 프록시를 넣은 deps)을 `~/prune-evidence/inputs`에 다시 만든다. VM 도우미는 `git show ab353b0:bundle/ab-runner/phases/run_frozen_phase1_vm.py`에서 복원한다. deps는 `tools/assemble-guest-deps.py`로 `bundle/src/guest-deps-ganesha-v15.6.tar.gz`와 프록시(`NFSP_PROXY`, 기본 `bundle/src/nfs-proxy-lane`)를 합쳐 만든다 |
| `verify-lane.py` | VM 한 대를 띄워 fixture, `syz-execprog`(원격 커버리지 켬), 카운터와 `.extra`, `dmesg`를 확인하고 `result.json`을 쓴다 |
| `run-verify.sh` | 위를 부트스트랩 산출물 기준으로 감싼 실행 스크립트 (`kasan`/`kcsan` × `direct`/`proxy`/`raw`/`copy`) |

필요한 것: 부트스트랩이 만든 환경(`env/images/<variant>/{bzImage,vmlinux}`, `env/syzkaller/bin`,
버전 중립 이미지 `env/images/bookworm-kcov-fresh.qcow2`의 raw 사본), Ganesha deps(`tools/build-ganesha-v15.sh`),
프록시 게스트 빌드(Docker 필요: `tools/nfs-proxy/build-guest.sh`).

`build-guest.sh`는 출력 파일이 이미 있으면 덮어쓰지 않고 실패한다(`output already exists`). 새 프록시는 다른 경로로 빌드하고
그 경로를 `mkinputs.py`에 넘겨 deps를 다시 만든다.

```sh
tools/nfs-proxy/build-guest.sh --out ~/nfsp-build/nfs-proxy-v2
NFSP_PROXY=~/nfsp-build/nfs-proxy-v2 python3 docs/handoff/proxy-variable-length-edits/mkinputs.py
WORKLOAD=<v2 arm 프로그램> docs/handoff/proxy-variable-length-edits/run-verify.sh <ENV_DIR> kasan raw
```

**통과 기준 (프록시 경유, 편집 규칙을 켠 상태):**

- `.extra` 파일 수가 프로그램 수와 같다 (30/30). lane 귀속이 길이 변경 편집에서도 유지된다.
- `generation_aborted` 0, `outstanding_tokens` 0, 프록시 통계의 `framing_errors`, `relay_errors`, `mutation_errors` 0.
- `arm-N.delta`에 적용 횟수가 남고, `--replay`가 같은 결과를 재현한다. 원본 불일치 규칙은 `refused_orig`를 올리고 `--replay`가 실패한다.
- 편집 규칙이 **없는** 프로그램의 결과(1,800개 안팎의 fs/nfsd PC, 34콜 워크로드)가 변경 전과 같다 (회귀 없음).

## 9. 환경 주의사항

- **부팅 인자 `nfs.localio_enabled=N`이 필수다.** 없으면 이미지의 lane fixture가 시작을 거부해 NFS에 닿지 않는다(`README.md`에 기재됨).
- **저장소 `env/`가 낡았을 수 있다.** 다른 작업으로 병합 전 시리즈(커널 14개)로 빌드됐을 수 있으니, 새 시리즈로 쓰려면 부트스트랩을 다시 돌린다.
  2026-10-02 기준 저장소 `env/`는 버전 중립 이미지(`bookworm-kcov-fresh.qcow2`)를 쓰는 구조다.
- **`env/syzkaller/bin`의 `syz-manager`와 `syz-executor`의 리비전이 다를 수 있다.** manager 실행이 필요하면 같은 소스에서 따로 빌드한다.
  이 작업은 `syz-execprog`만 쓰므로 영향이 없다.
- **A/B 러너, `evidence/`, 이전 실험 하네스(`~/q1-harness`)는 없다.** 검증은 8.2의 스크립트로 한다.
- 이 저장소의 `bundle/src/nfs-proxy-lane`은 gitignore 대상 빌드 산출물이다. 프록시를 고치면 다른 경로로 다시 빌드한다.
- **VM 도우미는 lane 스크립트 주입(9P, `koov.lane_sha256`)을 하지 않는다.** 그래서 이미지의 부팅 fixture는 시작을
  거부하고, `mkinputs.py`가 만든 실행별 fixture가 lane을 직접 띄운다. 이 조합으로 게스트를 돌려 본 적은 아직 없다
  (2026-10-02, 스크립트 수정 후 미실행). 처음 실행할 때 fixture 단계 로그를 먼저 확인한다.
- **lane 병렬 운용이 필수다.** 이 스크립트는 `--procs 1`로 lane 하나만 검증한다. 편집 규칙이 lane 여러 개에서 동시에
  쓰일 때의 검증은 `vm.snapshot`을 끈 syz-manager로 따로 한다.
- WSL 안에서 작업한다 (`/home/idealinsane/projects/knfsd-syzkaller`). KVM(`/dev/kvm`)이 필요하다.

## 10. 완료 보고

Phase 1을 끝내면 다음을 보고한다.

- 바뀐 파일과 새 패치 번호, 호스트 테스트 결과(clang, ASan+UBSan)
- 게스트 검증 표 (8.2의 통과 기준 각각)
- 5.3절 미검증 항목 중 확인한 것과 결과
- 3절 불변 조건 중 바꾼 것이 있으면 그 이유
- 이 문서의 삭제 조건 중 아직 남은 것
