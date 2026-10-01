#!/bin/sh
# X2: one run per scenario, then read the monitor state (per-task completed-job
# counter n) over the ST-LINK before the next reset. No firmware change.
set -u
cd "$(dirname "$0")"
OUT=../data/raw/overload_x2
ST_ADDR=0x2000c168   # static mon_state_t st[8] in build 3f31aafddd356da1 (16 B each)
for SC in X2_p13_l500_ctrl X2_p13_l600 X2_p13_l700 X2_p13_l800; do
  for REP in 0 1; do
    D=$OUT/rep$REP; mkdir -p $D
    ../.venv/bin/python -u orchestrator.py overload_x2.toml --out $D --only $SC
    st-flash read $D/overload_x2/${SC}_st.bin $ST_ADDR 128 >/dev/null 2>&1 \
      && echo "$SC rep$REP: counters read" || echo "$SC rep$REP: COUNTER READ FAILED"
    date -Is > $D/overload_x2/${SC}_st.time
  done
done
echo X2_DONE
