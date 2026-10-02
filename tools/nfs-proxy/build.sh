#!/usr/bin/env bash
# tools/nfs-proxy/build.sh -- build the proxy and run the host test suite.
#
# No cmake, no ninja, no root: clang and libc only.  That is not a preference,
# it is the constraint this repository operates under (see
# tools/build-ganesha-deps.sh for the same reasoning applied to the guest side).
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
# WHY TWO COMPILERS
#
#   clang is the primary build.  clang 21's ASan runtime is NOT installed on
#   this host (libclang_rt.asan.a is absent and the package is not in the
#   distribution index), so the sanitizer pass is built with gcc, whose
#   libasan.so is present.  gcc accepts the identical strict flag set and the
#   module is plain C11 + libc, so the two builds exercise the same source.
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
	echo "  $SANCC -fsanitize=address,undefined: usable"
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

	if ! "$primary"; then
		echo "TEST FAILED: $name" >&2
		return 1
	fi
	# ASAN_OPTIONS: abort on the first error so a finding cannot be lost in a
	# long log; detect_leaks=1 because a proxy that leaks per connection would
	# only show up after many trials.
	if ! ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 \
	     UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 "$asan"; then
		echo "SANITIZER FAILED: $name" >&2
		return 1
	fi
	echo "  OK: $name (primary + sanitizer)"
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

if [ "$MODE" != "--test" ]; then
	echo "=== build: scoped nfs-proxy executable ($CC) ==="
	# shellcheck disable=SC2086
	$CC $CFLAGS -I"$SRC" -o "$BUILD/nfs-proxy" \
		"$SRC/main.c" "$SRC/proxy.c" "$SRC/framing.c" \
		"$SRC/control.c" "$SRC/delta.c" "$SRC/walk.c" "$SRC/edit.c"
fi

echo "=== host test suite: PASS ==="
