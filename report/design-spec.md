# knfsd-fuzz 설계 명세 (DESIGN-SPEC)

> 버전: 1.2 · 2026-10-01
> 활성 검사: Ψ1, Ψ2, R1 (bootstrap manifest 기반). R2, R4, R5, Ψ3, Ψ4 철회.

이 문서는 **패치가 아니라 계약**이다. 패치는 계약의 "이 버전 구현 후보"일 뿐이다.
계약은 bootstrap이 환경을 만들 때 기계적으로 확인하는 부분(아래)만 활성 상태다.

---

## 1. 전제조건 Ψ(T)

| Ψ | 요구 | 오라클 | 상태 |
|---|---|---|---|
| Ψ1 | KCOV 컴파일 | `env/build/<variant>/.config`에 `CONFIG_KCOV=y` 또는 `env/images/<variant>/vmlinux` 심볼 | 활성 |
| Ψ2 | KASAN 또는 KCSAN | `manifest.verify.variants.<variant>.mem_sanitizer ∈ {kasan, kcsan}` | 활성 |
| Ψ3 | NFSv4 서버 디스패치 경로 존재 | `nfsd4_proc_compound` on_only > 0 (A/B 증거 필요) | 철회 |
| Ψ4 | remote_cover/cover_edges 모델 유지 | R5 증거 일관성 | 철회 |

---

## 2. 요구사항

### R1 부팅·빌드 무결성 (활성)
- 판정: `manifest.status == "pass"` 이고 모든 variant의 `mem_sanitizer ∈ {kasan, kcsan}`
- 오라클: `env/manifest.json` — bootstrap이 variant마다 부팅해 lane 상태와 sanitizer를 확인한 결과

### 철회된 요구사항
- **R2** 원격 커버리지 기여, **R4** 원격 커버리지 심도, **R5** 관측 연결·증거 연쇄:
  A/B 하네스가 만든 `evidence/`를 읽는 게이트였다. 하네스와 판정 스크립트(`fport-design-gate.sh`)를
  커밋 `7833ed3`에서 제거하면서 함께 철회했다. 시드는 stock syz-manager로 실행하며, 원격 커버리지는
  `experimental.remote_cover` 설정으로 켜고 끈다.
- **R3** (2026-09-26): 스루풋 회귀 상한. 환경 잡음으로 인해 계약 범위 밖.
- **R6** (2026-09-27): SHA256 기반 apply-audit. 부가 감사 메커니즘으로 폐기.

---

## 3. 시리즈를 다시 적용해야 할 때

1. `fport-variant.sh`로 rc 변형을 기록하고 `fport-apply.sh`로 재적용한다.
2. `bootstrap-kcov-env.py`를 다시 실행해 빌드와 variant별 검증(R1)이 통과하는지 확인한다.

---

## 4. 번들 스코프

- `fport-apply.sh`: `kernel|syzkaller` 시리즈 적용.
- SHA256SUMS 자기 일치 검증은 2026-09-27에 폐기.

---

## 5. 메모리 새니타이저

KASAN 또는 KCSAN 중 하나를 지원. bootstrap의 `--variant kasan|kcsan`으로 선택(기본: 둘 다 빌드·검증).
KCSAN 리포트는 치명 panic이 아니므로 실행 결과를 볼 때 구분 필요.
