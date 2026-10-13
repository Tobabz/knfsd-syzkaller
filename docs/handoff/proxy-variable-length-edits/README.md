# NFS-specific Mutation Engine: variable-length edits

이 디렉터리는 프록시 기반의 NFS 특화 Mutation Engine에서 사용하는 길이 변경 편집의
인계 자료와 게스트 검사 도구를 포함합니다.

- 현재 인터페이스와 빌드 방법: [Mutation Engine 사용 안내](../../../tools/nfs-proxy/README.md)
- 설계·구현 인계 자료: [handoff.md](handoff.md)
- 실행 결과와 증거 위치: [검증 기록](../../../report/validation-history.md)

M0 레거시 replay gate는 호스트 빌드가 끝난 뒤 다음처럼 실행한다. 세 arm은
각각 v1 4-route/delta replay, v2 resize/delta replay, v2 live original-byte
거부를 검사하며 하나라도 실패하면 `run-verify.sh` 자체도 실패한다.

```sh
NFSP_PROXY=/path/to/bookworm-amd64-relay python3 mkinputs.py
OUT=/path/to/evidence IMAGE=/path/to/bookworm.raw \
  ./run-verify.sh /path/to/env kasan \
  legacy-v1 legacy-v2 legacy-v2-refusal
```
