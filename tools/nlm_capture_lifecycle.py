"""Disposable lane instrumentation, never used by the production harness."""

from pathlib import Path
import re


CAPTURE = "/tmp/nlm-callback-diagnostic.pcap"
STATS = "/tmp/nlm-callback-diagnostic.stats"
READY = "/tmp/nlm-callback-diagnostic.ready"
COMPLETE = "/tmp/nlm-callback-diagnostic.complete"
STOP = "/tmp/nlm-callback-diagnostic.stop"
PID = "/tmp/nlm-callback-diagnostic.pid"
EVENT_LOG = "/tmp/nlm-callback-diagnostic.events"
MARKER_SOCKET = "/tmp/nlm-callback-diagnostic.marker"
DEFAULT_VM_INSTANCE_ID = "nlm-smoke-vm"


def instrument_lane(path: Path, vm_instance_id: str = DEFAULT_VM_INSTANCE_ID) -> None:
    """Start before client setup; stop last when the server namespace retires."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", vm_instance_id):
        raise ValueError("invalid diagnostic VM instance ID")
    source = path.read_text()
    start = '    kill -0 "$setup_server_pid"\n'
    stop = '    stop_pids=$(namespace_pids "$stop_ns")\n'
    if (source.count(start) != 1 or source.count(stop) != 2
            or 'diagnostic_capture_pid=' in source):
        raise ValueError("diagnostic capture lane instrumentation boundary changed")
    setup = f'''
    if [ "$setup_lane_id" = 0 ]; then
        ! pgrep -x nlm-pcap >/dev/null
        rm -f {CAPTURE} {STATS} {READY} {COMPLETE} {STOP} {PID} \
            {EVENT_LOG} {MARKER_SOCKET} /tmp/nlm-pcap.log
        nsenter -t "$setup_server_pid" -n -- /tmp/nlm-pcap \
            {CAPTURE} {STATS} {READY} {COMPLETE} {STOP} \
            {EVENT_LOG} {MARKER_SOCKET} {vm_instance_id} \
            >/tmp/nlm-pcap.log 2>&1 < /dev/null &
        diagnostic_capture_pid=$!
        diagnostic_capture_start=$(awk '{{print $22}}' \
            "/proc/$diagnostic_capture_pid/stat")
        case "$diagnostic_capture_pid:$diagnostic_capture_start" in
            *[!0-9:]*|:*|*:) return 1 ;;
        esac
        printf '%s %s\n' "$diagnostic_capture_pid" \
            "$diagnostic_capture_start" > {PID}
        diagnostic_capture_wait=0
        while ! test -f {READY}; do
            kill -0 "$diagnostic_capture_pid"
            diagnostic_capture_wait=$((diagnostic_capture_wait + 1))
            test "$diagnostic_capture_wait" -lt 100
            sleep 0.1
        done
        test "$(cat "/proc/$diagnostic_capture_pid/comm")" = nlm-pcap
        test "$(awk '{{print $22}}' "/proc/$diagnostic_capture_pid/stat")" = \
            "$diagnostic_capture_start"
    fi
'''
    # Cleanup stops clients and nfsd before the server namespace. Preserve the
    # recorder while other server processes close, then require its stats.
    filtering = f'''    if test -s {PID}; then
        read diagnostic_capture_pid diagnostic_capture_start < {PID} || return 1
        case "$diagnostic_capture_pid:$diagnostic_capture_start" in
            *[!0-9:]*|:*|*:) return 1 ;;
        esac
        test "$(cat "/proc/$diagnostic_capture_pid/comm")" = nlm-pcap || \
            return 1
        test "$(awk '{{print $22}}' \
            "/proc/$diagnostic_capture_pid/stat")" = \
            "$diagnostic_capture_start" || return 1
        diagnostic_capture_net=$(stat -Lc '%d:%i' \
            "/proc/$diagnostic_capture_pid/ns/net") || return 1
        diagnostic_stop_net=$(stat -Lc '%d:%i' \
            "/run/netns/$stop_ns") || return 1
        if [ "$diagnostic_capture_net" = "$diagnostic_stop_net" ]; then
        diagnostic_other_pids=
        diagnostic_has_capture=0
        for diagnostic_pid in $stop_pids; do
            if [ "$diagnostic_pid" = "$diagnostic_capture_pid" ]; then
                diagnostic_has_capture=1
            else
                diagnostic_other_pids="$diagnostic_other_pids $diagnostic_pid"
            fi
        done
        test "$diagnostic_has_capture" = 1 || return 1
        if [ "$diagnostic_has_capture" = 1 ]; then
            if [ -n "$diagnostic_other_pids" ]; then
                kill $diagnostic_other_pids 2>/dev/null || true
            fi
            diagnostic_cleanup_wait=0
            while [ -n "$diagnostic_other_pids" ] && \
                    [ "$diagnostic_cleanup_wait" -lt 20 ]; do
                diagnostic_cleanup_wait=$((diagnostic_cleanup_wait + 1))
                sleep 0.1
                diagnostic_other_pids=
                diagnostic_has_capture=0
                for diagnostic_pid in $(namespace_pids "$stop_ns"); do
                    if [ "$diagnostic_pid" = "$diagnostic_capture_pid" ]; then
                        diagnostic_has_capture=1
                    else
                        diagnostic_other_pids="$diagnostic_other_pids $diagnostic_pid"
                    fi
                done
                test "$diagnostic_has_capture" = 1 || return 1
            done
            if [ -n "$diagnostic_other_pids" ]; then
                kill -KILL $diagnostic_other_pids 2>/dev/null || true
                diagnostic_cleanup_wait=0
                while [ -n "$diagnostic_other_pids" ]; do
                    diagnostic_cleanup_wait=$((diagnostic_cleanup_wait + 1))
                    test "$diagnostic_cleanup_wait" -lt 50 || return 1
                    sleep 0.1
                    diagnostic_other_pids=
                    diagnostic_has_capture=0
                    for diagnostic_pid in $(namespace_pids "$stop_ns"); do
                        if [ "$diagnostic_pid" = "$diagnostic_capture_pid" ]; then
                            diagnostic_has_capture=1
                        else
                            diagnostic_other_pids="$diagnostic_other_pids $diagnostic_pid"
                        fi
                    done
                    test "$diagnostic_has_capture" = 1 || return 1
                done
            fi
            test "$(cat "/proc/$diagnostic_capture_pid/comm")" = nlm-pcap || \
                return 1
            test "$(awk '{{print $22}}' \
                "/proc/$diagnostic_capture_pid/stat")" = \
                "$diagnostic_capture_start" || return 1
            # A stop file avoids the check-then-kill PID reuse race. The
            # collector polls it with a bounded socket timeout.
            : > {STOP}
            diagnostic_capture_wait=0
            while :; do
                diagnostic_capture_live=0
                if test -r "/proc/$diagnostic_capture_pid/stat" && \
                        test "$(awk '{{print $22}}' \
                            "/proc/$diagnostic_capture_pid/stat")" = \
                            "$diagnostic_capture_start"; then
                    diagnostic_capture_live=1
                fi
                if test "$diagnostic_capture_live" = 0 && \
                        test -s {STATS} && test -e {COMPLETE}; then
                    break
                fi
                diagnostic_capture_wait=$((diagnostic_capture_wait + 1))
                test "$diagnostic_capture_wait" -lt 100 || return 1
                sleep 0.1
            done
            # Refresh after the recorder exits; never retain numeric PIDs from
            # before the cleanup waits.
            stop_pids=$(namespace_pids "$stop_ns")
            rm -f {PID}
        fi
        fi
    fi
'''
    # Only the first enumeration owns graceful shutdown, not the KILL fallback.
    source = source.replace(start, start + setup, 1)
    source = source.replace(stop, stop + filtering, 1)
    path.write_text(source)
