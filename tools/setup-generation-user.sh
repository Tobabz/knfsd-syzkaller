#!/usr/bin/env bash
# tools/setup-generation-user.sh — the Harness Generation OS user (07 §5.1).
#
# The generation Agent's commands and a patch set's validation build run as
# a separate OS user without network.  This sets that up once per host, for
# the user who runs the Stage 1 service (SUDO_USER):
#
#   - system user and group `harness-gen` (home /var/lib/harness-gen,
#     no login shell); SUDO_USER joins the group (next login) so it can
#     clean up what the generation user wrote;
#   - /usr/local/libexec/knfsd-harness-gen (root:root 0755): runs its
#     arguments in a new network namespace as harness-gen, with
#     no_new_privs, umask 002, its own HOME and SIGKILL when sudo dies;
#   - /etc/sudoers.d/knfsd-harness-gen: SUDO_USER may run only that
#     wrapper as root, without a password (checked with visudo);
#   - <state_dir>/generation-worktrees and <state_dir>/validation-work,
#     owned by SUDO_USER, group harness-gen, setgid 2775;
#   - ACLs, where needed, so harness-gen reads the clone: traverse
#     (u:harness-gen:x) on its parents, read (rX) on the clone.
#
# The spec's `generation.launcher` defaults to this wrapper, so `generate`
# needs nothing more.  Running it again changes nothing that is already
# right.
#
# Usage:
#   sudo bash tools/setup-generation-user.sh [--spec PATH] [--user NAME]
#     --spec  host spec whose state_dir gets the directories
#             (default: stage1-host/host-spec.json)
#     --user  generation user (default: harness-gen); give the same
#             `generation.user` in the spec
set -eu

TOOLS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$TOOLS")"
SPEC="$REPO/stage1-host/host-spec.json"
GEN=harness-gen

while [ $# -gt 0 ]; do
    case "$1" in
        --spec) SPEC=$2; shift 2 ;;
        --user) GEN=$2; shift 2 ;;
        *) echo "usage: $0 [--spec PATH] [--user NAME]" >&2; exit 2 ;;
    esac
done

[ "$(id -u)" = 0 ] || { echo "ERROR: run with sudo" >&2; exit 1; }
OPERATOR="${SUDO_USER:-}"
[ -n "$OPERATOR" ] && [ "$OPERATOR" != root ] || {
    echo "ERROR: run through sudo as the user of the Stage 1 service" >&2
    exit 1; }
case "$GEN" in
    *[!a-z0-9_-]*|"") echo "ERROR: bad user name: $GEN" >&2; exit 1 ;;
esac
[ -f "$SPEC" ] || { echo "ERROR: no host spec at $SPEC" >&2; exit 1; }
SPEC="$(cd "$(dirname "$SPEC")" && pwd)/$(basename "$SPEC")"
STATE="$(python3 -c '
import json, os, sys
spec = sys.argv[1]
print(os.path.normpath(os.path.join(os.path.dirname(spec),
                                    json.load(open(spec))["state_dir"])))
' "$SPEC")"
HOME_DIR="/var/lib/$GEN"
WRAPPER="/usr/local/libexec/knfsd-$GEN"
SUDOERS="/etc/sudoers.d/knfsd-$GEN"

# 1. User and group.
if ! id -u "$GEN" >/dev/null 2>&1; then
    useradd --system --user-group --create-home --home-dir "$HOME_DIR" \
        --shell /usr/sbin/nologin "$GEN"
    echo "created user $GEN"
fi
install -d -o "$GEN" -g "$GEN" -m 0750 "$HOME_DIR"
if ! id -nG "$OPERATOR" | tr ' ' '\n' | grep -qx "$GEN"; then
    usermod -aG "$GEN" "$OPERATOR"
    echo "added $OPERATOR to group $GEN (takes effect at the next login)"
fi

# 2. The launcher.  Fixed paths only: it runs as root.
install -d -m 0755 "$(dirname "$WRAPPER")"
TMP="$(mktemp)"
cat >"$TMP" <<EOF
#!/bin/sh
# Installed by knfsd-syzkaller tools/setup-generation-user.sh: run the
# arguments as $GEN without network (Harness Generation, 07 section 5.1).
set -eu
[ "\${1-}" = "--" ] && shift
[ \$# -gt 0 ] || { echo "usage: \$0 [--] COMMAND..." >&2; exit 2; }
umask 002
HOME=$HOME_DIR
export HOME
exec /usr/bin/unshare --net -- /usr/bin/setpriv --reuid=$GEN --regid=$GEN \\
    --init-groups --no-new-privs --pdeathsig KILL -- "\$@"
EOF
install -o root -g root -m 0755 "$TMP" "$WRAPPER"
rm -f "$TMP"

# 3. sudoers: only the wrapper, and the caller's environment (the Agent's
# commands get only PATH, HOME, the locale and generation.env).
TMP="$(mktemp)"
cat >"$TMP" <<EOF
# Installed by knfsd-syzkaller tools/setup-generation-user.sh
Defaults!$WRAPPER !env_reset
$OPERATOR ALL=(root) NOPASSWD: $WRAPPER
EOF
visudo -cqf "$TMP" || { rm -f "$TMP"; echo "ERROR: bad sudoers" >&2; exit 1; }
install -o root -g root -m 0440 "$TMP" "$SUDOERS"
rm -f "$TMP"

# 4. Directories the generation user writes in.
install -d -o "$OPERATOR" -m 0755 "$STATE"
for d in generation-worktrees validation-work; do
    install -d -o "$OPERATOR" -g "$GEN" -m 2775 "$STATE/$d"
    # The group is the boundary here: an ACL inherited from a clone that
    # holds state_dir (step 5) would leave harness-gen read-only.
    ! command -v setfacl >/dev/null || setfacl -b "$STATE/$d"
done

# 5. harness-gen reads the clone (worktrees share its .git): traverse on
# the parents, from / down, then read on the clone if it lacks it.
command -v setfacl >/dev/null || need_acl=1
parents=()
dir="$(dirname "$REPO")"
while [ "$dir" != / ]; do parents=("$dir" "${parents[@]}"); dir="$(dirname "$dir")"; done
for dir in "${parents[@]}"; do
    if ! runuser -u "$GEN" -- test -x "$dir"; then
        [ -z "${need_acl:-}" ] || {
            echo "ERROR: $GEN cannot enter $dir and setfacl is missing" >&2
            exit 1; }
        setfacl -m "u:$GEN:x" "$dir"
        echo "granted $GEN traverse on $dir"
    fi
done
if ! runuser -u "$GEN" -- sh -c 'test -r "$1" -a -x "$1" -a -r "$1/.git/HEAD"' _ "$REPO"; then
    [ -z "${need_acl:-}" ] || {
        echo "ERROR: $GEN cannot read $REPO and setfacl is missing" >&2
        exit 1; }
    setfacl -R -m "u:$GEN:rX" -m "d:u:$GEN:rX" "$REPO"
    echo "granted $GEN read on $REPO"
fi

# 6. Check: as the operator, through sudo, the user and no network.
got="$(runuser -u "$OPERATOR" -- sudo -n "$WRAPPER" -- /bin/sh -c \
    'id -un; tail -n +3 /proc/net/dev | grep -cv "^ *lo:" || true')"
[ "$got" = "$GEN
0" ] || { echo "ERROR: launcher check failed: $got" >&2; exit 1; }
echo "ok: generation launcher $WRAPPER runs as $GEN without network"
