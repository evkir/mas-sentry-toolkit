#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SPDX_LINE="# SPDX-License-Identifier: AGPL-3.0-or-later"
added=0; skipped=0
while IFS= read -r -d '' file; do
    if grep -q "SPDX-License-Identifier" "$file"; then
        skipped=$((skipped + 1)); continue
    fi
    first_line="$(head -n 1 "$file" 2>/dev/null || true)"
    tmp="$(mktemp)"
    if [[ "$first_line" == "#!"* ]]; then
        { printf '%s\n' "$first_line"; printf '%s\n' "$SPDX_LINE"; tail -n +2 "$file"; } > "$tmp"
    else
        { printf '%s\n' "$SPDX_LINE"; cat "$file"; } > "$tmp"
    fi
    mv "$tmp" "$file"
    added=$((added + 1))
done < <(find "$ROOT/mas_sentry" "$ROOT/tests" "$ROOT/scripts" -type f -name '*.py' -print0 2>/dev/null)
printf 'SPDX headers: %d added, %d already present.\n' "$added" "$skipped"
