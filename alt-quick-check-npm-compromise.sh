#!/usr/bin/env bash
set -euo pipefail

packages_json='[
  {"name":"backslash","version":"0.2.1"},
  {"name":"chalk-template","version":"1.1.1"},
  {"name":"supports-hyperlinks","version":"4.1.1"},
  {"name":"has-ansi","version":"6.0.1"},
  {"name":"simple-swizzle","version":"0.2.3"},
  {"name":"color-string","version":"2.1.1"},
  {"name":"error-ex","version":"1.3.3"},
  {"name":"color-name","version":"2.0.1"},
  {"name":"is-arrayish","version":"0.3.3"},
  {"name":"slice-ansi","version":"7.1.1"},
  {"name":"color-convert","version":"3.1.1"},
  {"name":"wrap-ansi","version":"9.0.1"},
  {"name":"ansi-regex","version":"6.2.1"},
  {"name":"supports-color","version":"10.2.1"},
  {"name":"strip-ansi","version":"7.1.1"},
  {"name":"chalk","version":"5.6.1"},
  {"name":"debug","version":"4.4.2"},
  {"name":"ansi-styles","version":"6.2.2"}
]'

if ! command -v jq >/dev/null 2>&1; then
  echo "Error: 'jq' is required (to parse the JSON array-of-objects)."
  exit 1
fi

names=$(printf '%s\n' "$packages_json" | jq -r '.[].name' | tr '\n' ' ')

echo "Running 'npm cache ls' for given packages..."
npm_output="$(npm cache ls $names 2>/dev/null || true)"

echo
echo "Packages found in npm cache:"
tmpfile=$(mktemp)
trap 'rm -f "$tmpfile"' EXIT

# loop through package/version
printf '%s\n' "$packages_json" | jq -r '.[] | "\(.name)\t\(.version)"' | \
while IFS=$'\t' read -r name version; do
  if [ -n "$name" ] && printf '%s\n' "$npm_output" | grep -q "${name}-${version}"; then
    echo "• $name@$version"
    echo 1 >> "$tmpfile"
  fi
done

if ! grep -q 1 "$tmpfile"; then
  echo "(none)"
fi