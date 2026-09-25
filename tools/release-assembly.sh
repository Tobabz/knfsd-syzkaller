#!/usr/bin/env bash
# tools/release-assembly.sh — optional maintainer snapshot (NOT a release
# distribution since 2026-09-26: asset-free model — the base image and
# keypair are generated per site by tools/make-base-image.sh, upstream
# sources are cloned by bootstrap at pinned refs).
#
# 배포(스냅샷) 정의 = `bundle/SHA256SUMS`의 고정 3항목(커밋된 부트스트랩 입력):
#   - `src/bookworm-base.img[.gz]`·`src/bookworm.id_rsa[.pub]`는 사이트 생성물이므로
#     SHA256SUMS에 포함되지 않는다. 이 스크립트는 raw 베이스 이미지를 절대
#     아카이브하지 않으며, 자체 점검으로 raw 유출 시 실패(어보트)한다.
#   - `--minimal`: 정확히 SHA256SUMS 3항목 + SHA256SUMS만 아카이브.
#   - 기본: 3항목 + 패치 시리즈(`patches/{kernel,syzkaller}`, 각 디렉토리
#     SHA256SUMS로 검증) + `LICENSE`·`THIRD-PARTY-LICENSES.md`.
#
# 출력: $WORK_ROOT/dist/knfsd-syzkaller-forward-port-<stamp>.tar.gz (+ dist/SHA256SUMS)
# 경로 관례: 자기 위치 유도 + KOOV_WORK_ROOT 오버라이드 (tools/README.md 환경 변수 표).
set -eu

MINIMAL=0
[ "${1:-}" = "--minimal" ] && MINIMAL=1
SUFFIX=""
[ "$MINIMAL" -eq 1 ] && SUFFIX="-minimal"

TOOLS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_ROOT="${KOOV_WORK_ROOT:-$(dirname "$TOOLS")}"
BUNDLE="$WORK_ROOT/bundle"
DIST="${KOOV_DIST_DIR:-$WORK_ROOT/dist}"
STAMP="$(date +%Y%m%d)"
ARCHIVE="$DIST/knfsd-syzkaller-forward-port-$STAMP$SUFFIX.tar.gz"
mkdir -p "$DIST"

echo "=== 1) verify bundle/SHA256SUMS (fixed items) ==="
( cd "$BUNDLE" && sha256sum -c SHA256SUMS --quiet ) || {
  echo "FAIL: bundle/SHA256SUMS verification failed — aborting." >&2; exit 1; }
N=$(awk 'NF==2' "$BUNDLE/SHA256SUMS" | wc -l)
echo "bundle/SHA256SUMS: $N/$N verified"

mapfile -t ENTRIES < <(awk 'NF==2 {print $2}' "$BUNDLE/SHA256SUMS")

echo "=== 2) assembling archive ==="
if [ "$MINIMAL" -eq 0 ]; then
  echo "--- verifying patch series manifests (per-dir SHA256SUMS) ---"
  ( cd "$BUNDLE/patches/kernel"  && sha256sum -c SHA256SUMS --quiet ) || {
    echo "FAIL: patches/kernel series verification failed." >&2; exit 1; }
  ( cd "$BUNDLE/patches/syzkaller" && sha256sum -c SHA256SUMS --quiet ) || {
    echo "FAIL: patches/syzkaller series verification failed." >&2; exit 1; }
  tar czf "$ARCHIVE" \
      -C "$BUNDLE" "${ENTRIES[@]}" SHA256SUMS patches/kernel patches/syzkaller \
      -C "$WORK_ROOT" LICENSE THIRD-PARTY-LICENSES.md
else
  tar czf "$ARCHIVE" -C "$BUNDLE" "${ENTRIES[@]}" SHA256SUMS
fi

echo "=== 3) self-check: raw image must NOT be in the archive ==="
if tar tzf "$ARCHIVE" | grep -qx 'src/bookworm-base.img'; then
  echo "FAIL: raw base image leaked into the release archive!" >&2
  rm -f "$ARCHIVE"; exit 1
fi
echo "raw excluded (no base image / keys shipped): OK"

echo "=== 4) record archive checksums (all in dist/) ==="
( cd "$DIST" && sha256sum knfsd-syzkaller-forward-port-*.tar.gz | tee SHA256SUMS )

echo
echo "release archive: $ARCHIVE"
echo "release checksum manifest: $DIST/SHA256SUMS"
du -h "$ARCHIVE" | sed 's|^|size: |'
