# flow-trace

Records kernel trace events in a lane guest and judges thread transitions.
The design, the rules and the recorded results are in
[report/normal-flow-threads.md](../../report/normal-flow-threads.md).

## Run

Record all runs (about 20 minutes; each run boots a fresh guest):

```sh
tools/flow-trace/run-all.sh ~/flow-trace-evidence/run3
```

Record one run, for example the NFSv4.2 COPY seed:

```sh
python3 tools/flow-trace/capture.py --version 4.2 --restart-fixture --stop-fixture \
    --seed bundle/corpus/nfs-normal/async-copy-v42-tcp.prog --settle 3 --out /tmp/s3
```

Judge one trace against one scenario:

```sh
python3 tools/flow-trace/handoffs.py /tmp/s3/trace.txt.gz \
    tools/flow-trace/scenarios/s3-v42-async-copy.json
```

Add `--control` to run a negative control (every `specific` transition must be absent).
Add `--only S3-03,S3-04` to judge selected transitions.

Judge all runs and count the execution subjects:

```sh
tools/flow-trace/summarize.sh ~/flow-trace-evidence/run3
```

## Files

| File | Role |
|---|---|
| `capture.py` | Boots a guest, enables the events, runs a seed or a shell script, saves the trace |
| `events.txt` | Tracepoints (`event group:pattern`) and kprobes (`kprobe label symbol`) |
| `handoffs.py` | Pairs submit and execute events and prints one verdict per transition |
| `scenarios/*.json` | Transition rules for S1, S2, S3, S3b and S4 |
| `subjects.json`, `subjects.py` | One marker event per execution subject; counts per trace |
| `stimulus/s4-state-lifetime.sh` | Shell stimulus for state-lifetime work |
| `run-all.sh`, `summarize.sh` | Record every run; judge every run |

## Notes

- The evidence stays outside the repository. Cite its directory and the commit of these tools.
- `--restart-fixture` rebuilds all four lanes inside the traced window.
- A probe that fails to attach is listed in `meta.json` as `kprobe_failed`.
  `receive_cb_reply`, `__cld_pipe_upcall` and `svc_revisit_deferred` fail on kernel `25456a766`.
- Check the judge output line `[no loss]`. If it says `LOSS`, a `MISSING` verdict is not trustworthy.
