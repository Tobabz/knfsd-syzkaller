#!/usr/bin/env bash
# tools/nfs-proxy/build.sh -- build the proxy and run the host test suite.
#
# No cmake, no ninja, no root: clang and libc only.  That is not a preference,
# it is the constraint this repository operates under (see
# tools/build-ganesha-deps.sh for the same reasoning applied to the guest side).
# python3 (standard library only) runs the ProtocolSchema normalizer's tests
# and proves the pinned XDR files and committed schema tables are fresh; the C
# build never needs it, so the guest build container does not either.
#
# Linux only.  test_control needs AF_UNIX/SOCK_SEQPACKET, the legacy arm
# transport, and test_proxy binds 127.0.0.2/.3 and 127.0.0.10/.11, which Linux
# routes to loopback without setup.  No other host is supported.
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
       test_golden:$TEST/test_golden.c:$SRC/delta.c:$SRC/edit.c:$SRC/walk.c:$SRC/framing.c\
       test_rpc_record:$TEST/test_rpc_record.c:$SRC/rpc_record.c:$SRC/framing.c\
       test_rpc_decode:$TEST/test_rpc_decode.c:$SRC/rpc_decode.c:$SRC/rpc_record.c:$SRC/walk.c\
       test_nfs_decode:$TEST/test_nfs_decode.c:$SRC/nfs_decode.c:$SRC/schema.c:$SRC/rpc_decode.c:$TEST/schema_tproto.c:$TEST/schema_tflat.c:$TEST/schema_tedge.c\
       test_nfs4_decode:$TEST/test_nfs4_decode.c:$SRC/nfs_decode.c:$SRC/schema.c:$SRC/rpc_decode.c:$SRC/schema_nfs4.c\
       test_nfs3_decode:$TEST/test_nfs3_decode.c:$SRC/nfs_decode.c:$SRC/schema.c:$SRC/rpc_decode.c:$SRC/schema_nfs3.c:$SRC/schema_nfs4.c\
       test_txn:$TEST/test_txn.c:$SRC/txn.c\
       test_activation:$TEST/test_activation.c:$SRC/activation.c\
       test_rule:$TEST/test_rule.c:$SRC/rule.c:$SRC/schema.c:$SRC/schema_nfs4.c:$TEST/schema_tproto.c:$TEST/schema_tflat.c:$TEST/schema_tedge.c\
       test_resolver:$TEST/test_resolver.c:$SRC/resolver.c:$SRC/nfs_decode.c:$SRC/schema.c:$SRC/rpc_decode.c:$TEST/schema_tproto.c\
       test_mutation_apply:$TEST/test_mutation_apply.c:$SRC/mutation_apply.c:$SRC/resolver.c:$SRC/edit.c:$SRC/nfs_decode.c:$SRC/schema.c:$SRC/rpc_decode.c:$SRC/rpc_record.c:$SRC/walk.c:$SRC/framing.c:$TEST/schema_tproto.c\
       test_semantic:$TEST/test_semantic.c:$SRC/semantic.c:$SRC/txn.c:$SRC/nfs_decode.c:$SRC/schema.c:$SRC/rpc_decode.c:$SRC/schema_nfs4.c:$SRC/schema_nfs3.c\
       test_proxy:$TEST/test_proxy.c:$SRC/proxy.c:$SRC/framing.c:$SRC/rpc_record.c:$SRC/rpc_decode.c\
       test_journal:$TEST/test_journal.c:$SRC/journal.c:$SRC/jsonw.c:$SRC/sha256.c\
       test_control:$TEST/test_control.c:$SRC/control.c:$SRC/delta.c:$SRC/walk.c:$SRC/edit.c"

# Generated ProtocolSchema tables and the annotation file each comes from.
# A table is committed so the C build (and the guest build container) needs
# no Python; this list is how a stale one is caught.
SCHEMAS="$TEST/schema/tproto.ann:$TEST/schema_tproto.c\
	 $TEST/schema/tflat.ann:$TEST/schema_tflat.c\
	 $TEST/schema/tedge.ann:$TEST/schema_tedge.c\
	 $HERE/schema/nfs4/nfs4.ann:$SRC/schema_nfs4.c\
	 $HERE/schema/nfs3/nfs3.ann:$SRC/schema_nfs3.c"

# Pinned RFC XDR: every file here must still hash to its SOURCES pin.  The
# offline check only; `schema/rfc_xdr.py SOURCES --verify` re-extracts from
# the RFCs themselves and needs the network.
XDR_SOURCES="$HERE/schema/nfs4/SOURCES $HERE/schema/nfs3/SOURCES"

# Fail early and loudly if a compiler is missing, rather than at the first use.
for c in "$CC" "$SANCC" python3; do
	command -v "$c" >/dev/null 2>&1 || {
		echo "FATAL: '$c' not found" >&2
		exit 2
	}
done

# The decoder trusts structural properties the normalizer proves (acyclic
# types, non-empty array elements, bounded depth), so its tests run first, and
# every committed table must be exactly what the normalizer produces today.
echo "=== schema normalizer tests (python3) ==="
for t in test_normalize.py test_rfc_xdr.py; do
	if ! out=$(python3 "$HERE/schema/$t" -q 2>&1); then
		printf '%s\n' "$out" >&2
		echo "FATAL: schema/$t failed" >&2
		exit 1
	fi
done
for m in $XDR_SOURCES; do
	python3 "$HERE/schema/rfc_xdr.py" "$m" --check || {
		echo "FATAL: XDR source differs from its pin in $m" >&2
		exit 1
	}
done
for pair in $SCHEMAS; do
	python3 "$HERE/schema/normalize.py" "${pair%%:*}" --check "${pair#*:}" || {
		echo "FATAL: stale schema table ${pair#*:}" >&2
		exit 1
	}
done
echo "  OK: normalizer tests, XDR pins, $(echo $SCHEMAS | wc -w) schema tables fresh"

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

# test_proxy refuses to start, before any thread exists, when its loopback
# topology does not work on this host (main() in test/test_proxy.c), so a
# broken host fails at once with the cause instead of in the watchdog.  The
# refusal is forced here on every run, so that it cannot stop working unseen.
check_proxy_guard() {
	rc=0
	out=$(ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 \
	      UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
	      "$1" --simulate-unusable-addresses 2>&1) || rc=$?
	case $out in
	"FAIL: fixture addresses unusable: simulated; no test thread was started")
		[ "$rc" -eq 3 ] && return 0 ;;
	esac
	echo "FATAL: $1 did not refuse a simulated unusable topology (exit $rc):" >&2
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
	if [ "$name" = test_proxy ]; then
		check_proxy_guard "$primary" || return 1
		check_proxy_guard "$asan" || return 1
	fi

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

if [ "$MODE" != "--test" ]; then
	echo "=== build: scoped nfs-proxy executable ($CC) ==="
	# shellcheck disable=SC2086
	$CC $CFLAGS -I"$SRC" -o "$BUILD/nfs-proxy" \
		"$SRC/main.c" "$SRC/proxy.c" "$SRC/framing.c" "$SRC/rpc_record.c" \
		"$SRC/control.c" "$SRC/delta.c" "$SRC/walk.c" "$SRC/edit.c" \
		"$SRC/semantic.c" "$SRC/resolver.c" "$SRC/mutation_apply.c" \
		"$SRC/txn.c" "$SRC/activation.c" "$SRC/nfs_decode.c" \
		"$SRC/schema.c" "$SRC/schema_nfs4.c" "$SRC/schema_nfs3.c" \
		"$SRC/rpc_decode.c" "$SRC/rule.c" "$SRC/target.c" \
		"$SRC/journal.c" "$SRC/jsonw.c" "$SRC/sha256.c" -lm
	# The fault hook the live tests build in must stay warning-free too.
	# shellcheck disable=SC2086
	$CC $CFLAGS -DNFSP_TARGET_FAULT_INJECT -I"$SRC" -c "$SRC/target.c" \
		-o "$BUILD/target-faults.o"
fi

echo "=== host test suite: PASS ==="
