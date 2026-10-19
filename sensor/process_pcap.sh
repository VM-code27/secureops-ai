#!/usr/bin/env sh
# Turn a packet capture (Wireshark / tcpdump) into Zeek + Suricata logs, then optionally upload them.
#   ./process_pcap.sh capture.pcap                 -> logs in ./out/
#   API_URL=... API_TOKEN=... ./process_pcap.sh capture.pcap   -> also uploads to the API
set -eu
PCAP="$1"
DIR="$(cd "$(dirname "$PCAP")" && pwd)"; FILE="$(basename "$PCAP")"
mkdir -p "$DIR/out/zeek" "$DIR/out/suricata"
docker run --rm -v "$DIR":/data -w /data/out/zeek zeek/zeek:lts zeek -C -r "/data/$FILE" LogAscii::use_json=T
docker run --rm -v "$DIR":/data --entrypoint /bin/sh jasonish/suricata:latest -c \
  "suricata-update --no-test >/dev/null 2>&1 || true; suricata -r /data/$FILE -l /data/out/suricata"
echo "Logs written to $DIR/out/"
if [ -n "${API_URL:-}" ] && [ -n "${API_TOKEN:-}" ]; then
  for f in conn ssh software; do
    [ -f "$DIR/out/zeek/$f.log" ] && curl -sS -X POST -H "X-API-Token: $API_TOKEN" \
      --data-binary @"$DIR/out/zeek/$f.log" "$API_URL/ingest/zeek?sensor=pcap&filename=$f.log" && echo
  done
  curl -sS -X POST -H "X-API-Token: $API_TOKEN" --data-binary @"$DIR/out/suricata/eve.json" \
    "$API_URL/ingest/suricata?sensor=pcap" && echo
else
  echo "Upload them on the dashboard's Live data -> Upload logs tab, or set API_URL and API_TOKEN."
fi
