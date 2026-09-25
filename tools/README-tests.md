# T1-T7 remote KCOV instrumentation verification — execution checklist

본 체크리스트는 일반 코퍼스 AB 배터리만 다룬다.

Environment: WSL2 (Ubuntu 26.04, nested virt), kcov env at `~/work/env`,
handoff at `~/work/bundle`, prep scripts in `~/work/tools`.

## Test -> command -> evidence mapping

| T | Test | Command (prep script) | Primary evidence |
|---|------|----------------------|------------------|
| T1 | Deterministic attribution (ON) | `run-ab.sh` (mode=on trials) | `evidence/remote_on/trial_*/trial_evidence.json`: remote_start_ok>0, extra_files==executions, functional/local/raw gates |
| T2 | Plain-send control (OFF) | `run-ab.sh` (mode=off trials) | `evidence/remote_off/trial_*/...`: extra_files_zero, remote_start_zero, remote counters all 0 |
| T3 | Counter integrity / leak-free drain | `run-ab.sh` both | diagnostics deltas; all_gauges_drained, live_resources_drained, no_incomplete/invalid/aborted_publish, double_complete_zero |
| T4 | Cross-lane isolation | `run-ab.sh` | cross_lane_attribution==0, ordinal_mismatch==0, connection_pair_miss==0, lane_epoch_collision_zero |
| T5 | Retry / generation lifecycle | `run-ab.sh` | conflict call (idx 14) errno 11 exact; remote_stop_exact==remote_start_ok; generations drained |
| T6 | Async (post-handler) work | `run-ab.sh` | phase6: remote_section_completed, aggregate_merge_completed>0, aggregate_published>0, scratch_overflow==0 |
| T7 | Handler coverage gate (symbolized) | `analyze-ab.sh` | `evidence/`: coverage report; ranked ON-only fs/nfsd CSV; per-handler (GETATTR/OPEN/WRITE/READ/LOCK/REMOVE/RENAME/COMMIT) coverage growth |

## Execution order (post-build)

1. `bash tools/convert-ab-image.sh`          # qcow2 -> raw twin (A/B runner uses format=raw)
2. `bash tools/run-ab.sh`                    # 4 trials (off/on x 2), fresh snapshots
3. `bash tools/analyze-ab.sh`                # symbolize + report + CSV (T7)