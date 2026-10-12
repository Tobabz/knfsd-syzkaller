#!/usr/bin/env bash
# tools/nfs-proxy/build.sh -- build the proxy and run the host test suite.
#
# No cmake, no ninja, no root.  Native Linux needs only clang/gcc + libc.  A
# host whose AF_UNIX implementation lacks SOCK_SEQPACKET (notably Darwin)
# cannot execute the legacy control transport faithfully; on that host the
# script requires Docker for an exact Linux runtime gate rather than substituting
# a different socket type or silently skipping the test.
#
# Usage:
#   tools/nfs-proxy/build.sh            build + run every test
#   tools/nfs-proxy/build.sh --test     run tests only (assumes built)
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
       test_proxy:$TEST/test_proxy.c:$SRC/proxy.c:$SRC/framing.c\
       test_control:$TEST/test_control.c:$SRC/control.c:$SRC/delta.c:$SRC/walk.c:$SRC/edit.c"

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
	if [ "$name" = test_control ] && [ "$NATIVE_SEQPACKET" -eq 0 ]; then
		echo "  OK: $name compiled natively; exact runtime test deferred to Linux gate"
		return 0
	fi

	if ! "$primary"; then
		echo "TEST FAILED: $name" >&2
		return 1
	fi
	# ASAN_OPTIONS: abort on the first error so a finding cannot be lost in a
	# long log; detect_leaks=1 because a proxy that leaks per connection would
	# only show up after many trials.
	if ! ASAN_OPTIONS="detect_leaks=$ASAN_DETECT_LEAKS:abort_on_error=1" \
	     UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 "$asan"; then
		echo "SANITIZER FAILED: $name" >&2
		return 1
	fi
	echo "  OK: $name (primary + sanitizer)"
}

run_linux_seqpacket_gate() {
	[ "$NATIVE_SEQPACKET" -eq 0 ] || return 0
	command -v docker >/dev/null 2>&1 || {
		echo "FATAL: host lacks AF_UNIX/SOCK_SEQPACKET and Docker is unavailable" >&2
		return 1
	}
	docker info >/dev/null 2>&1 || {
		echo "FATAL: host lacks AF_UNIX/SOCK_SEQPACKET and Docker daemon is not running" >&2
		return 1
	}
	echo
	echo "=== Linux SOCK_SEQPACKET compatibility gate ($LINUX_TEST_IMAGE) ==="
	docker run --rm --init \
		--mount "type=bind,src=$HERE,dst=/src,readonly" \
		"$LINUX_TEST_IMAGE" bash -lc '
			set -eu
			apt-get update -qq
			apt-get install -qq -y --no-install-recommends clang gcc libc6-dev ca-certificates \
				>/tmp/nfsp-apt.log 2>&1 || { tail -80 /tmp/nfsp-apt.log >&2; exit 1; }
			cp -a /src /tmp/nfs-proxy
			cd /tmp/nfs-proxy
			./build.sh
		'
	echo "=== Linux SOCK_SEQPACKET compatibility gate: PASS ==="
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
	echo "  OK: guest-delta-replay compiles (host build-only gate)"
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
run_linux_seqpacket_gate

if [ "$MODE" != "--test" ]; then
	echo "=== build: scoped nfs-proxy executable ($CC) ==="
	# shellcheck disable=SC2086
	$CC $CFLAGS -I"$SRC" -o "$BUILD/nfs-proxy" \
		"$SRC/main.c" "$SRC/proxy.c" "$SRC/framing.c" \
		"$SRC/control.c" "$SRC/delta.c" "$SRC/walk.c" "$SRC/edit.c"
fi

echo "=== host test suite: PASS ==="
