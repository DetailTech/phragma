#!/usr/bin/env bash

manifest_sha256_verify() {
  local root="$1"
  shift
  local manifest="$root/manifest.sha256"
  local rel path digest entry expected actual
  local tmp_dir tmp_expected tmp_manifest tmp_files tmp_nonregular
  local start_failures="$failures"

  if [ -z "$root" ]; then
    fail "manifest.sha256 root is required"
    return 1
  fi
  if [ -L "$manifest" ]; then
    fail "manifest.sha256 must not be a symlink: $manifest"
    return 1
  fi
  if [ ! -s "$manifest" ]; then
    fail "manifest.sha256 missing or empty: $manifest"
    return 1
  fi

  tmp_dir="$(mktemp -d)" || {
    fail "manifest.sha256 could not create temporary workspace"
    return 1
  }
  tmp_expected="$tmp_dir/expected"
  tmp_manifest="$tmp_dir/manifest"
  tmp_files="$tmp_dir/files"
  tmp_nonregular="$tmp_dir/nonregular"
  : > "$tmp_manifest"

  for rel in "$@"; do
    printf '%s\n' "$rel"
  done | LC_ALL=C sort > "$tmp_expected"

  while IFS= read -r line || [ -n "$line" ]; do
    [ -z "$line" ] && continue
    case "$line" in
      \#*) continue ;;
    esac
    digest="${line%%[[:space:]]*}"
    entry="${line#"$digest"}"
    entry="${entry#"${entry%%[![:space:]]*}"}"
    entry="${entry#\*}"
    case "$digest" in
      [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
      *)
        fail "manifest.sha256 has invalid digest for entry: $line"
        continue
        ;;
    esac
    if [ -z "$entry" ] || [ "$entry" = "$line" ]; then
      fail "manifest.sha256 entry missing path: $line"
      continue
    fi
    case "$entry" in
      /*|../*|*/../*|*/..|.|..|manifest.sha256)
        fail "manifest.sha256 entry path is not allowed: $entry"
        continue
        ;;
    esac
    if grep -Fxq "$entry" "$tmp_manifest"; then
      fail "manifest.sha256 duplicate entry: $entry"
      continue
    fi
    printf '%s\n' "$entry" >> "$tmp_manifest"
    path="$root/$entry"
    if [ -L "$path" ]; then
      fail "manifest.sha256 entry must not be a symlink: $entry"
      continue
    fi
    if [ ! -f "$path" ]; then
      fail "manifest.sha256 entry missing file: $entry"
      continue
    fi
    actual="$(manifest_sha256_file "$path")" || {
      fail "manifest.sha256 could not hash entry: $entry"
      continue
    }
    if [ "$actual" != "$digest" ]; then
      fail "manifest.sha256 mismatch for $entry"
    fi
  done < "$manifest"

  LC_ALL=C sort -o "$tmp_manifest" "$tmp_manifest"
  while IFS= read -r rel; do
    if ! grep -Fxq "$rel" "$tmp_manifest"; then
      fail "manifest.sha256 missing required entry: $rel"
    fi
  done < "$tmp_expected"
  while IFS= read -r rel; do
    if ! grep -Fxq "$rel" "$tmp_expected"; then
      fail "manifest.sha256 has unexpected entry: $rel"
    fi
  done < "$tmp_manifest"

  (cd "$root" && find . ! -type f ! -type d -print 2>/dev/null | sed 's#^\./##' | LC_ALL=C sort) > "$tmp_nonregular"
  while IFS= read -r rel; do
    fail "evidence bundle contains unsupported non-regular file: $rel"
  done < "$tmp_nonregular"

  (cd "$root" && find . -type f ! -name manifest.sha256 -print 2>/dev/null | sed 's#^\./##' | LC_ALL=C sort) > "$tmp_files"
  while IFS= read -r rel; do
    if ! grep -Fxq "$rel" "$tmp_expected"; then
      fail "evidence bundle contains unexpected file outside manifest policy: $rel"
    fi
  done < "$tmp_files"

  if [ "$failures" -eq "$start_failures" ]; then
    ok "manifest.sha256 verified exact file set"
  fi
  rm -rf "$tmp_dir"
}

manifest_sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    return 1
  fi
}
