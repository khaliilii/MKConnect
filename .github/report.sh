# Sourced by CI steps (BASH_ENV): report <log> emits the log tail as an error annotation.
report() {
  local body
  body=$(grep -v '^go: downloading' "$1" | tail -n 80 | sed -e 's/%/%25/g' -e 's/\r/%0D/g' | sed ':a;N;$!ba;s/\n/%0A/g')
  echo "::error title=$1::${body}"
}
