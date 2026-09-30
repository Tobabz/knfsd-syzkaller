# knfsd-fuzz 설계 명세 (DESIGN-SPEC)

> 버전: 1.1 · 2026-09-27
> 활성 게이트: R1, R2, R4, R5 (R3, R6 retired)

이 문서는 **패치가 아니라 계약**이다. 패치는 계약의 "이 버전 구현 후보"일 뿐이다.
`tools/fport-design-gate.sh`가 계약을 기계적으로 판정한다.

---

## 1. 전제조건 Ψ(T)

| Ψ | 요구 | 오라클 |
|---|---|---|
| Ψ1 | KCOV 컴파일 | `.config`에 `CONFIG_KCOV=y` 또는 vmlinux 심볼 |
| Ψ2 | KASAN 또는 KCSAN | `manifest.verify.mem_sanitizer ∈ {kasan, kcsan}` |
| Ψ3 | NFSv4 서버 디스패치 경로 존재 | `nfsd4_proc_compound` on_only > 0 |
| Ψ4 | remote_cover/cover_edges 모델 유지 | R5 증거 일관성 |

Ψ가 false면 판정은 **UNSUPPORTED**.

---

## 2. 활성 요구사항 R1,R2,R4,R5

### R1 부팅·빌드 무결성
- 게이트: `manifest.status == "pass"` and `mem_sanitizer ∈ {kasan,kcsan}`
- 오라클: `env/manifest.json`

### R2 원격 커버리지 기여 (인과 귀속)
- 게이트: `off fs/nfsd == 0` and `on fs/nfsd > 0` and `converged` and `controls_eq`
- 오라클: `evidence/analysis_summary.json`

### R4 원격 커버리지 심도
- 게이트: `fs/nfsd.on_only ≥ 100` and `net/sunrpc.on_only > 0` and `nfsd4_proc_compound` 존재
- 오라클: `evidence/analysis_summary.json` + `evidence/coverage_sets/`

### R5 관측 연결·증거 연쇄
- 게이트: `status == PASS` and `integrity_pass` and `remote_contribution_share ≥ 95%` and 커버리지 셋 6종 존재
- 오라클: `evidence/analysis_summary.json` + `evidence/coverage_sets/`

### 철회된 게이트
- **R3** (2026-09-26): 스루풋 회귀 상한. 환경 잡음으로 인해 계약 범위 밖.
- **R6** (2026-09-27): SHA256 기반 apply-audit. 부가 감사 메커니즘으로 폐기.

---

## 3. 계약 위반 시 행동

1. `fport-design-gate.sh -v`로 실패한 게이트 확인.
2. 해당 계약의 설계 의도를 보고 새 패치 텍스트로 재생성.
3. `fport-variant.sh` → `fport-apply.sh`로 재적용.
4. 게이트 전체 재실행. 전부 pass 전까지 "미적용".

---

## 4. 게이트 실행

```sh
bash tools/fport-design-gate.sh -v     # 0=HOLDS, 1=FAIL, 2=UNSUPPORTED
```

---

## 5. 번들·파이프라인 스코프

- 파이프라인: `kernel|syzkaller` 포워드포트.
- SHA256SUMS 자기 일치 검증은 2026-09-27에 폐기.
- `env/` 빌드 산출물은 신규 rc 포팅(full 모드)에서 신선 환경으로 교첸됨.

---

## 6. 메모리 새니타이저

KASAN 또는 KCSAN 중 하나를 지원. bootstrap의 `--variant kasan|kcsan`으로 선택(기본: 둘 다 빌드·검증).
KCSAN 리포트는 치명 panic이 아니므로 trial 판정 시 구분 필요.
