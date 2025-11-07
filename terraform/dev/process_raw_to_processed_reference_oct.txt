#!/usr/bin/env bash
set -euo pipefail

BUCKET="bhavana-p11-logs-dev-bhv123"
RAW_PREFIX="raw"
PROC_PREFIX="processed"
TMPDIR="$(mktemp -d)"
echo "Temp dir: $TMPDIR"

# check dependencies
if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: 'jq' not found. Install it (sudo apt install -y jq) and re-run."
  exit 1
fi
if ! command -v gzip >/dev/null 2>&1; then
  echo "ERROR: 'gzip' not found. Install it (sudo apt install -y gzip) and re-run."
  exit 1
fi

# list objects and process each key
aws s3 ls "s3://$BUCKET/$RAW_PREFIX/" --recursive | awk '{print $4}' | while read -r key; do
  # skip empty lines
  if [[ -z "$key" ]]; then
    continue
  fi

  # skip directory markers (keys that end with '/')
  if [[ "${key: -1}" == "/" ]]; then
    echo "Skipping directory marker: $key"
    continue
  fi

  echo "Processing s3://$BUCKET/$key"
  base="$(basename "$key")"
  localfile="$TMPDIR/$base"

  # download
  aws s3 cp "s3://$BUCKET/$key" "$localfile"

  # handle .gz files by streaming decompression into jq
  ndjsonfile="$localfile.ndjson"
  if [[ "$localfile" == *.gz ]]; then
    # decompress and extract Records[] if exists, otherwise compact whole JSON
    if gzip -dc "$localfile" | jq -e '.Records' >/dev/null 2>&1; then
      gzip -dc "$localfile" | jq -c '.Records[]' > "$ndjsonfile"
    else
      gzip -dc "$localfile" | jq -c '.' > "$ndjsonfile"
    fi
  else
    # non-gz case
    if jq -e '.Records' "$localfile" >/dev/null 2>&1; then
      jq -c '.Records[]' "$localfile" > "$ndjsonfile"
    else
      jq -c '.' "$localfile" > "$ndjsonfile"
    fi
  fi

  # upload to processed/
  out_key="$PROC_PREFIX/$base.ndjson"
  echo "Uploading to s3://$BUCKET/$out_key"
  aws s3 cp "$ndjsonfile" "s3://$BUCKET/$out_key"

  # cleanup
  rm -f "$localfile" "$ndjsonfile"
done

rmdir "$TMPDIR" || true
echo "Done. Processed files uploaded to s3://$BUCKET/$PROC_PREFIX/"
