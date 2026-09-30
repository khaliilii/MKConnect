# Sourced by CI steps (BASH_ENV): report <log> emits the interesting part of a
# failed log as an error annotation (annotations are cut at ~4 KB, so drop
# overlong lines like linker command lines and lead with the error lines).
report() {
  local lines body
  lines=$(grep -v -e '^go: downloading' -e 'Pulling fs layer' -e 'Waiting$' -e 'Verifying Checksum' \
    -e 'Download complete' -e 'Pull complete' "$1" | cut -c1-300)
  body=$( { echo "$lines" | grep -i -E 'error|undefined|cannot|failed|not found|fatal' | tail -n 25; \
            echo '----- tail -----'; echo "$lines" | tail -n 15; } \
    | sed -e 's/%/%25/g' -e 's/\r/%0D/g' | sed ':a;N;$!ba;s/\n/%0A/g')
  echo "::error title=$1::${body}"
}
