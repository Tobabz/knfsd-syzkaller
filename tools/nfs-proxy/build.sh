#!/usr/bin/env bash
# tools/nfs-proxy/build.sh -- build the proxy and run the host test suite.
#
# No cmake, no ninja, no root.  Native Linux needs only clang/gcc + libc.
#
# Two runtime tests need Linux behaviour that other hosts, notably Darwin, lack:
# test_control needs AF_UNIX/SOCK_SEQPACKET, the legacy arm transport, and
# test_proxy needs its loopback address topology (see test/test_proxy.c).  On
# such a host both are still compiled natively, and then the script requires
# Docker to run the whole suite in a Linux container -- the Linux gate below --
# rather than substitute another socket type or topology, or skip the test.
#
# Usage:
#   tools/nfs-proxy/build.sh            build + run every test
#   tools/nfs-proxy/build.sh --test     run the existing binaries without
#                                       rebuilding them; the Linux gate, when
#                                       needed, still builds from source
#   tools/nfs-proxy/build.sh --clean
#
# WHY THE TESTS COME FIRST
#
#   The proxy sits on the critical path of every RPC and is fed by a fuzzer, so
#   its failures are indistinguishable from the servers' failures unless it is
#   verified in isolation.  On this axis a guest boot has already been spent
#   learning that lesson more than once.  Nothing here may reach a guest until
#   this script is green.
#
# WHY TWO COMPILER VARIABLES
#
#   clang is the primary build.  SANCC defaults to `gcc` because some Linux
#   hosts have the sanitizer runtime there even when clang cannot link it.
#   On Darwin `/usr/bin/gcc` is Apple clang; the probe below, not the command
#   name, is the authority for whether the sanitizer runtime is usable.
#
#   LeakSanitizer is not supported by Apple's ASan runtime.  On Darwin only we
#   disable leak detection while keeping the ASan+UBSan compile AND execution
#   mandatory.  Other hosts keep leak detection enabled.
#
#   THE SANITIZER PASS MUST NOT BE SKIPPABLE.  An earlier revision of this
#   script wrapped the sanitizer build in an `if` with its stderr sent to
#   /dev/null; the compiler could not find the runtime, the branch was skipped,
#   and the script reported success while the check had not run at all.  That
#   is the exact failure mode this project keeps paying for -- a gate that
#   reports PASS without looking.  Here the sanitizer build is REQUIRED: if it
#   cannot be produced, this script fails.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
SRC="$HERE/src"
TEST="$HERE/test"
BUILD="$HERE/build"
CC=${CC:-clang}
SANCC=${SANCC:-gcc}
HOST_OS=$(uname -s)
ASAN_DETECT_LEAKS=1
[ "$HOST_OS" = Darwin ] && ASAN_DETECT_LEAKS=0
LINUX_TEST_IMAGE=${NFSP_LINUX_TEST_IMAGE:-debian:bookworm}

# -Werror on purpose: a proxy that is fed hostile input cannot afford warnings
# that are "probably fine".
WARN="-Wall -Wextra -Werror -Wshadow -Wconversion -Wsign-conversion \
	-Wpointer-arith -Wcast-qual -Wwrite-strings -Wmissing-prototypes \
	-Wstrict-prototypes -Wformat=2"
CFLAGS="-std=c11 -O2 -g -pthread $WARN"
SANFLAGS="-std=c11 -O1 -g -fsanitize=address,undefined \
	-fno-omit-frame-pointer -pthread $WARN"

MODE=${1:-all}
[ "$MODE" = "--clean" ] && { rm -rf "$BUILD"; echo "cleaned"; exit 0; }
mkdir -p "$BUILD"

# A unit is a name plus the sources that make it up.  Add new modules here; the
# build and the sanitizer build then both pick them up automatically, which is
# how a module cannot accidentally be tested without sanitizers.
UNITS="test_framing:$TEST/test_framing.c:$SRC/framing.c\
       test_walk:$TEST/test_walk.c:$SRC/walk.c\
       test_delta:$TEST/test_delta.c:$SRC/delta.c\
       test_edit:$TEST/test_edit.c:$SRC/edit.c:$SRC/walk.c:$SRC/framing.c\
       test_golden:$TEST/test_golden.c:$SRC/delta.c:$SRC/edit.c:$SRC/walk.c:$SRC/framing.c\
       test_proxy:$TEST/test_proxy.c:$SRC/proxy.c:$SRC/framing.c\
       test_control:$TEST/test_control.c:$SRC/control.c:$SRC/delta.c:$SRC/walk.c:$SRC/edit.c"
# Units whose runtime test this host cannot run; the Linux gate runs them.
DEFERRED=

# Fail early and loudly if a compiler is missing, rather than at the first use.
for c in "$CC" "$SANCC"; do
	command -v "$c" >/dev/null 2>&1 || {
		echo "FATAL: compiler '$c' not found" >&2
		exit 2
	}
done

# Prove the sanitizer toolchain works BEFORE relying on it, with the error
# visible.  A sanitizer pass that silently does not happen is worse than no
# sanitizer pass, because it is counted as coverage that does not exist.
if [ "$MODE" != "--test" ]; then
	echo "=== sanitizer toolchain probe ($SANCC) ==="
	probe_src="$BUILD/sanprobe.c"
	cat > "$probe_src" <<'EOF'
#include <stdlib.h>
int main(void) { char *p = malloc(4); p[0] = 1; free(p); return 0; }
EOF
	if ! "$SANCC" -std=c11 -fsanitize=address,undefined \
		-o "$BUILD/sanprobe" "$probe_src" 2>"$BUILD/sanprobe.err"; then
		echo "FATAL: $SANCC cannot build with -fsanitize=address,undefined:" >&2
		cat "$BUILD/sanprobe.err" >&2
		echo "Install the sanitizer runtime, or set SANCC to a compiler" >&2
		echo "that has one.  Do NOT weaken this check." >&2
		exit 3
	fi
	if ! ASAN_OPTIONS="detect_leaks=$ASAN_DETECT_LEAKS:abort_on_error=1" \
	     UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
	     "$BUILD/sanprobe"; then
		echo "FATAL: sanitizer runtime probe failed" >&2
		exit 3
	fi
	echo "  $SANCC -fsanitize=address,undefined: usable (detect_leaks=$ASAN_DETECT_LEAKS)"
fi

# The legacy arm endpoint is AF_UNIX/SOCK_SEQPACKET.  Linux implements it;
# Darwin defines the constant but socket(2) returns EPROTONOSUPPORT.  Probe the
# runtime so a platform mismatch cannot become either a false failure or a
# stream-socket compatibility path that never exists in the real guest.
seqprobe="$BUILD/seqpacket-probe"
if [ "$MODE" != "--test" ]; then
	seqprobe_src="$BUILD/seqpacket-probe.c"
	cat > "$seqprobe_src" <<'EOF'
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
int main(void) {
	int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (fd < 0) return 1;
	close(fd);
	return 0;
}
EOF
	"$CC" -std=c11 -Wall -Wextra -Werror -o "$seqprobe" "$seqprobe_src"
fi
[ -x "$seqprobe" ] || { echo "FATAL: $seqprobe missing" >&2; exit 4; }
NATIVE_SEQPACKET=0
if "$seqprobe"; then
	NATIVE_SEQPACKET=1
	echo "  AF_UNIX/SOCK_SEQPACKET runtime: native"
else
	echo "  AF_UNIX/SOCK_SEQPACKET runtime: unavailable; Linux gate required"
fi

# ASAN_OPTIONS: abort on the first error so a finding cannot be lost in a long
# log.  detect_leaks is on wherever LeakSanitizer exists -- a proxy that leaks
# per connection would only show up after many trials -- and off only on
# Darwin, whose ASan runtime has none (see the header).
run_sanitized() {
	ASAN_OPTIONS="detect_leaks=$ASAN_DETECT_LEAKS:abort_on_error=1" \
	UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 "$@"
}

# test_proxy refuses to run when its address topology does not work on this
# host, before any thread exists (main() in test/test_proxy.c).  That refusal
# is what keeps such a host out of the watchdog, so it is exercised on every
# host: a refusal that stopped working must not pass for a host that has the
# topology.
check_proxy_guard() {
	rc=0
	out=$("$@" --simulate-unusable-addresses 2>&1) || rc=$?
	case $out in
	"FAIL: fixture addresses unusable: simulated; no test thread was started")
		[ "$rc" -eq 3 ] && return 0 ;;
	esac
	echo "FATAL: $* did not refuse a simulated unusable topology (exit $rc):" >&2
	printf '%s\n' "$out" >&2
	return 1
}

run_unit() {
	name=$1
	shift
	primary="$BUILD/$name"
	asan="$BUILD/$name.asan"

	if [ "$MODE" != "--test" ]; then
		echo "=== build: $name ($CC) ==="
		# shellcheck disable=SC2086
		if ! $CC $CFLAGS -I"$SRC" -o "$primary" "$@" -lm; then
			echo "FATAL: primary build failed: $name" >&2
			return 1
		fi
		echo "=== build: $name + ASan/UBSan ($SANCC) ==="
		# shellcheck disable=SC2086
		if ! $SANCC $SANFLAGS -I"$SRC" -o "$asan" "$@" -lm; then
			echo "FATAL: sanitizer build failed: $name" >&2
			return 1
		fi
	fi

	[ -x "$primary" ] || { echo "FATAL: $primary missing" >&2; return 1; }
	[ -x "$asan" ] || { echo "FATAL: $asan missing" >&2; return 1; }
	defer=
	if [ "$name" = test_control ] && [ "$NATIVE_SEQPACKET" -eq 0 ]; then
		defer="no AF_UNIX/SOCK_SEQPACKET"
	fi
	if [ "$name" = test_proxy ]; then
		check_proxy_guard "$primary" || return 1
		check_proxy_guard run_sanitized "$asan" || return 1
		rc=0
		why=$("$primary" --check-addresses) || rc=$?
		case $rc in
		0) ;;
		3) defer=${why#fixture addresses unusable: } ;;
		*) echo "FATAL: $name --check-addresses exited $rc: $why" >&2
		   return 1 ;;
		esac
	fi
	if [ -n "$defer" ]; then
		DEFERRED="$DEFERRED $name"
		echo "  DEFERRED: $name compiled natively; runtime test goes to the Linux gate ($defer)"
		return 0
	fi

	if ! "$primary"; then
		echo "TEST FAILED: $name" >&2
		return 1
	fi
	if ! run_sanitized "$asan"; then
		echo "SANITIZER FAILED: $name" >&2
		return 1
	fi
	echo "  OK: $name (primary + sanitizer)"
}

# THE LINUX GATE runs when a unit was deferred above.  It copies this directory
# into a fresh container (debian:bookworm unless NFSP_LINUX_TEST_IMAGE is set),
# installs the toolchains with apt-get -- so it needs network access to a
# Debian mirror -- and runs the full build.sh there, every unit included.  It
# always builds from source, even under --test, because the host binaries are
# not Linux binaries.  The container runs on Docker's native platform (e.g.
# linux/arm64 on Apple silicon): it checks Linux socket behaviour, not the guest
# architecture, which build-guest.sh pins.
#
# Packages: clang and gcc are the two strict toolchains (gcc also brings the
# ASan/UBSan runtimes); libc6-dev supplies the C headers and crt objects, which
# gcc only recommends; ca-certificates matters only if the image's apt sources
# use HTTPS.
run_linux_gate() {
	[ -n "$DEFERRED" ] || return 0
	command -v docker >/dev/null 2>&1 || {
		echo "FATAL: the Linux gate must run$DEFERRED, and Docker is unavailable" >&2
		return 1
	}
	docker info >/dev/null 2>&1 || {
		echo "FATAL: the Linux gate must run$DEFERRED, and the Docker daemon is not running" >&2
		return 1
	}
	echo
	echo "=== Linux gate ($LINUX_TEST_IMAGE) for:$DEFERRED ==="
	docker run --rm --init \
		--mount "type=bind,src=$HERE,dst=/src,readonly" \
		"$LINUX_TEST_IMAGE" bash -lc '
			set -eu
			apt-get update -qq
			apt-get install -qq -y --no-install-recommends clang gcc libc6-dev ca-certificates \
				>/tmp/nfsp-apt.log 2>&1 || { tail -80 /tmp/nfsp-apt.log >&2; exit 1; }
			cp -a /src /tmp/nfs-proxy
			# build/ holds the host binaries; build everything here.
			rm -rf /tmp/nfs-proxy/build
			cd /tmp/nfs-proxy
			echo "Linux gate platform: $(uname -sm)"
			./build.sh
		'
	echo "=== Linux gate: PASS ==="
}

# The guest replay probe is not runnable on the host -- it connects to the
# fixed guest lane address -- but it is part of the legacy reproduction path.
# Build it with both strict toolchains so semantic refactors cannot silently
# leave the guest smoke source uncompilable.  Actual guest execution remains a
# VM smoke test, not a host unit test.
build_guest_replay_probe() {
	primary="$BUILD/guest-delta-replay"
	asan="$BUILD/guest-delta-replay.asan"
	source="$TEST/guest-delta-replay.c"

	if [ "$MODE" != "--test" ]; then
		echo "=== build-only: guest-delta-replay ($CC) ==="
		# shellcheck disable=SC2086
		$CC $CFLAGS -I"$SRC" -o "$primary" "$source" -lm
		echo "=== build-only: guest-delta-replay + ASan/UBSan ($SANCC) ==="
		# shellcheck disable=SC2086
		$SANCC $SANFLAGS -I"$SRC" -o "$asan" "$source" -lm
	fi

	[ -x "$primary" ] || { echo "FATAL: $primary missing" >&2; return 1; }
	[ -x "$asan" ] || { echo "FATAL: $asan missing" >&2; return 1; }
	if [ "$MODE" = "--test" ]; then
		echo "  OK: guest-delta-replay binaries present (--test does not rebuild them)"
	else
		echo "  OK: guest-delta-replay compiles (host build-only gate)"
	fi
}

if [ "$MODE" != "--test" ]; then
	echo
	for unit in $UNITS; do
		name=${unit%%:*}
		rest=${unit#*:}
		# shellcheck disable=SC2086
		run_unit "$name" $(echo "$rest" | tr ':' ' ')
		echo
	done
else
	for unit in $UNITS; do
		run_unit "${unit%%:*}"
	done
fi

build_guest_replay_probe
run_linux_gate

if [ "$MODE" != "--test" ]; then
	echo "=== build: scoped nfs-proxy executable ($CC) ==="
	# shellcheck disable=SC2086
	$CC $CFLAGS -I"$SRC" -o "$BUILD/nfs-proxy" \
		"$SRC/main.c" "$SRC/proxy.c" "$SRC/framing.c" \
		"$SRC/control.c" "$SRC/delta.c" "$SRC/walk.c" "$SRC/edit.c"
fi

echo "=== host test suite: PASS ==="
