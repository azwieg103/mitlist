#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$ROOT/work"
TOP="$ROOT/rpmbuild"
DIST="$ROOT/dist"
VERSION="$(sed -n 's/^#define MITLIST_VERSION "\([^"]*\)".*/\1/p' "$ROOT/src/mitlist.c" | head -n1)"
RPM_RELEASE="${RPM_RELEASE:-ZWIEGNET.1.el10}"

if [[ -z "$VERSION" ]]; then
  echo "ERROR: could not determine mitlist version." >&2
  exit 1
fi
if [[ ! "$RPM_RELEASE" =~ ^ZWIEGNET\.[1-9][0-9]*\.el10$ ]]; then
  echo "ERROR: invalid RPM_RELEASE '$RPM_RELEASE'." >&2
  exit 1
fi

for cmd in gcc make krb5-config rpmbuild tar; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "ERROR: required build command not found: $cmd" >&2
    exit 1
  }
done

rm -rf "$WORK" "$TOP" "$DIST"
mkdir -p "$WORK/mitlist" "$TOP/BUILD" "$TOP/BUILDROOT" "$TOP/RPMS" \
  "$TOP/SOURCES" "$TOP/SPECS" "$TOP/SRPMS" "$DIST"
cp -a "$ROOT/Makefile" "$ROOT/src" "$ROOT/README.md" "$WORK/mitlist/"
tar -czf "$TOP/SOURCES/mitlist-$VERSION.tar.gz" -C "$WORK" mitlist

rpmbuild -ba "$ROOT/packaging/mitlist.spec" \
  --define "_topdir $TOP" \
  --define "rpm_release $RPM_RELEASE"

find "$TOP/RPMS" "$TOP/SRPMS" -type f -name '*.rpm' -exec cp -v {} "$DIST/" \;
echo "RPM build complete:"
find "$DIST" -maxdepth 1 -type f -printf '%f\n' | sort
