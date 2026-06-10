#!/usr/bin/env bash
set -euo pipefail

profile="${COVERAGE_PROFILE:-coverage.out}"
text_report="${COVERAGE_TEXT:-coverage.txt}"
html_report="${COVERAGE_HTML:-coverage.html}"
package_report="${COVERAGE_PACKAGES:-coverage-packages.txt}"
low_report="${COVERAGE_LOW_FUNCTIONS:-coverage-low-functions.txt}"
min_coverage="${COVERAGE_MIN:-85.0}"
summary_file="${GITHUB_STEP_SUMMARY:-}"

module_path="$(go list -m)"

go test -v -covermode=atomic -coverpkg=./... -coverprofile="$profile" ./...
go tool cover -func="$profile" > "$text_report"
go tool cover -html="$profile" -o "$html_report"

total_coverage="$(awk '/^total:/ { gsub(/%/, "", $3); print $3 }' "$text_report")"
if [[ -z "$total_coverage" ]]; then
  echo "Unable to read total coverage from $text_report" >&2
  exit 1
fi

awk -v module="$module_path" '
  BEGIN { module_prefix = module "/" }
  NR == 1 { next }
  {
    key = $1
    path = key
    sub(/:.*/, "", path)
    pkg = path
    sub(/\/[^\/]+$/, "", pkg)
    display = pkg
    if (index(display, module_prefix) == 1) {
      display = substr(display, length(module_prefix) + 1)
    }
    segment_pkg[key] = display
    segment_statements[key] = $2
    if ($3 > 0) {
      segment_covered[key] = 1
    }
  }
  END {
    for (key in segment_statements) {
      pkg = segment_pkg[key]
      statements[pkg] += segment_statements[key]
      if (segment_covered[key]) {
        covered[pkg] += segment_statements[key]
      }
    }
    for (pkg in statements) {
      pct = statements[pkg] == 0 ? 0 : covered[pkg] * 100 / statements[pkg]
      printf "%.1f\t%s\t%d/%d\n", pct, pkg, covered[pkg], statements[pkg]
    }
  }
' "$profile" | sort -n > "$package_report"

awk -v module="$module_path" '
  BEGIN { module_prefix = module "/" }
  $1 != "total:" && $NF ~ /%$/ {
    pct = $NF
    gsub(/%/, "", pct)
    if (pct < 50) {
      location = $1
      if (index(location, module_prefix) == 1) {
        location = substr(location, length(module_prefix) + 1)
      }
      printf "%06.2f\t%s\t%s\n", pct, location, $2
    }
  }
' "$text_report" | sort -n > "${low_report}.sorted"
head -20 "${low_report}.sorted" > "$low_report"
rm -f "${low_report}.sorted"

if awk -v total="$total_coverage" -v min="$min_coverage" 'BEGIN { exit !(total + 0 >= min + 0) }'; then
  gate_status="PASS"
else
  gate_status="FAIL"
fi

if [[ -n "$summary_file" ]]; then
  {
    echo "### Go CLI coverage"
    echo
    echo "| Metric | Value |"
    echo "| --- | ---: |"
    echo "| Gate | $gate_status |"
    echo "| Minimum total statements | ${min_coverage}% |"
    echo "| Current total statements | ${total_coverage}% |"
    echo
    echo "#### Source Package Coverage"
    echo
    echo "| Package | Coverage | Covered statements |"
    echo "| --- | ---: | ---: |"
    awk -F '\t' '{ printf "| %s | %s%% | %s |\n", $2, $1, $3 }' "$package_report"
    echo
    echo "<details>"
    echo "<summary>Lowest-covered functions under 50%</summary>"
    echo
    if [[ -s "$low_report" ]]; then
      echo '```'
      awk -F '\t' '{ printf "%s%%\t%s\t%s\n", $1 + 0, $2, $3 }' "$low_report"
      echo '```'
    else
      echo "No functions below 50% coverage."
    fi
    echo "</details>"
    echo
    echo "<details>"
    echo "<summary>Full function coverage</summary>"
    echo
    echo '```'
    cat "$text_report"
    echo '```'
    echo "</details>"
  } >> "$summary_file"
fi

if [[ "$gate_status" != "PASS" ]]; then
  echo "Go coverage ${total_coverage}% is below required floor ${min_coverage}%." >&2
  exit 1
fi

echo "Go coverage ${total_coverage}% meets required floor ${min_coverage}%."
