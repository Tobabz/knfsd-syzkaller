# T1–T7 Remote KCOV Instrumentation Verification — Results

본 문서는 일반 코퍼스 AB 배터리 결과다.

Host: WSL2 Ubuntu 26.04 (nested virt), `~/work/env` env, handoff `~/work/bundle`
Date: 2026-09-23

## Environment gates (check_port_env.py)
| Check | Result |
|---|---|
| repo layout / syzkaller tree / /dev/kvm / qemu / qemu-img / ssh / addr2line / gcc / go | OK |
| cpus >= 8 | OK (16) |
| ram >= 16GB | OK (25.3GB) |
| debian mirror | OK |
| /tmp >= 20GB | **MISS** (12.6GB; tmpfs — host flow uses /home, 898GB free) |

## Bootstrap pins (~/work/env/manifest.json)
- kernel base 93f51579…, syz base 801f0966…, syzkaller 시리즈 15패치
- bzImage sha256: 3e8a518acaccceba0d573b350f243c52b680a15d84cd7076f99aca78ec9e1367
- vmlinux sha256: d70f8a49eb20caa3c56e897fb2cee3eb55f16bab8d323b10e8cdfaee763599a7
- bake: bookworm-kcov-fresh-v1.qcow2 sha256 f2c7ab9e… (821MB, minor 1)
- **verify: mode base** ✅ (lane status; KASAN 확인 단계는 미포함)

## Porting adaptations (harness-level, no checkpoint edits)
- **AB 러너 래인 픽스처 충돌 해결**: 베이크 이미지의 `frozen-phase9-fixture.service`가 부팅 시 `/tmp/frozen-phase9.manager`로 4레인을 구성하고 `/syz-nfs-lanes`를 싱글 테넌트로 소유합니다. AB 러너(디스포저블 모델)는 자체 root(`mktemp`)로 신선 레인을 구성하려다 `lane.sh setup`의 선행 `cleanup_fixture`에서 마커 소유권 불일치(source_tree_leaks:1, rc=1 silent)로 실패. → `--lane-fixture` 래퍼(`tools/ab-lane-fixture.sh` = prelude 16행 + 원본 `frozen_phase9_lane.sh` 694행 verbatim, diff로 동일성 확인)가 `setup` 시 부팅 픽스처를 `systemctl stop`(ExecStop=자기 root cleanup, 마커 일치 → 완전 retire)으로 정리 후 원본 로직 실행. 핀된 러너/이미지/커널 수정 없음.
- **마커-히든 레이아웃 적응 (AB 워크로드 + BIND_RE)**: 핀된 syz 패치 0014(`00abb5f executor: hide fixed lane marker from fuzz programs`, 체크포인트 `fixed_lane_marker_isolation_2026-09-18.md` PASS)가 `/nfs-lane`에 client0/client1 마운트만 노출("clients-only", `.lane_id`는 `/syz-nfs-lanes/proc-N` 숨김 트리에 보존). 체크인된 워크로드(`open('nfs-lane/.lane_id')`)와 러너 BIND_RE(`clients-only` 없는 형식)는 **숨김 이전 기준**이라 실패 확인: call 0 errno 2(ENOENT)×30, call 1/2 EBADF(9)×30, 매핑 검증 실패. → `tools/nfs_remote_kcov_ab_workload_markerhidden.prog`(34콜, call 0~2를 `open$dir(client0)/getdents64/close`로 교체, 나머지 31콜 원본 verbatim: diff 검증) + `tools/run_ab_adapted.py`(BIND_RE를 `(?:clients-only )?` 허용으로 수정, 실제 로그에서 bindings {(0,0),(1,1)} 매칭 확인). call 14 flock은 30/30 모두 예상 EAGAIN(11) 관측.

## T-matrix
| # | Test | Command | Result | Evidence |
|---|---|---------|--------|----------|
| T1 | Deterministic attribution (ON) | tools/run-ab.sh | ✅ PASS | evidence/remote_on/trial_{01,02}: remote_start_positive, remote_result_valid 31/31, extra_files_exact 30==30 |
| T2 | Plain-send control (OFF) | tools/run-ab.sh | ✅ PASS | evidence/remote_off: extra_files_zero, remote_start/publish/merge/scratch_zero, fs/nfsd PCs 0 |
| T3 | Counter integrity / drain | tools/run-ab.sh | ✅ PASS | diagnostics: gauges drained 0, ordinal_mismatch 0, pair_miss 0, double_complete 0, lane_epoch_collision 0, cleanup leaks 전부 0 |
| T4 | Cross-lane isolation | tools/run-ab.sh | ✅ PASS | cross_lane_attribution==0 (ON/OFF 모두), bindings {(0,0),(1,1)} |
| T5 | Retry / generation lifecycle | tools/run-ab.sh | ✅ PASS | call 14 flock EAGAIN(11) 30/30, remote_stop_exact, coverage_loss_zero |
| T6 | Async work attribution | tools/run-ab.sh | ✅ PASS | phase6 merge_positive, publish_positive, aggregate buffers 31, managed_generations_positive |
| T7 | Handler coverage gate | tools/analyze-ab.sh | ✅ PASS | fs/nfsd PCs OFF 0 vs ON 1,748 (+1,748, share 100%), ON-only ranked CSV 15개 핸들러(nfsd4_proc_compound 42 등) |

## Artifacts
- evidence/  (experiment_manifest.json, trial dirs 4개 pass, coverage_sets/, diagnostics/, images/*.svg, analysis_summary.json, nfs_remote_kcov_on_off_coverage_report.md, on_off_{trials,samples}.csv)

## AB phase counters (T3/T6 증거, trial_01/02 동일)
| counter | OFF | ON |
|---|---:|---:|
| phase3 ordinal rx/tx (c2s+s2c) | 1590/1590 | 1590/1590, ordinal_mismatch 0 |
| phase4 generation begin=committed | 0 | 31 = 31 (aborted 0, double_complete 0) |
| phase5 remote_start granted=ok | 0 | 1406 = 1406 (incomplete/nested 0) |
| phase5 mapping exact owner match | 0 | 1406 (mismatch 0, cross-lane 0) |
| phase5 remote_result_valid | 0 | 31/31 (incomplete/invalid 0) |
| phase5 scratch reserved=returned | 0 | 1406 = 1406 (overflow 0) |
| phase6 aggregate committed=published | 0 | 31 = 31 (aborted/incomplete/invalid 0) |
| phase6 entries merged=published | 0 | 5,041,632 = 5,041,632 (truncated 0) |
| coverage_export raw_pc_records | 3,794,381 | 9,070,234 (extra 30 files) |

## Evidence integrity (sha256, key artifacts)
| artifact | sha256 |
|---|---|
| evidence/experiment_manifest.json | d1cec7ea232183f8f0264f6c34cd5550050ebe65738f0729b9dcf1a7376bb50a |
| evidence/nfs_remote_kcov_on_off_coverage_report.md | 89fcfbe1a28a1b8987d6a2300f02d9aac9ebf65b091ae1c443054f3b87d9fa92 |
| evidence/coverage_sets/fs_nfsd_on_only_ranked.csv | 9e02a41858215fa3f5f235cd554a25e1201dc37b03d21228ab3175bc6f8bc4f0 |
| tools/ab-lane-fixture.sh | e91f0f40f003be7039e2f7599b0df0ba6e21d276ad39eda6513b03a68ed625bf (매니페스트 lane_fixture 일치) |
| tools/nfs_remote_kcov_ab_workload_markerhidden.prog | 59e1d766a9a15c8e1700ce055674d9d1b06dccc9167d567e06985d8d9cf69f02 (매니페스트 workload 일치) |
| tools/run_ab_adapted.py | abff1b310e4eb6e512d2f69484c59f26b7b4f360481c42407d149123f100b249 |