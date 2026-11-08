#!/bin/bash
# Sample the bridge's memory on a connected device.
#
# The number that matters is the guest arena: one big anonymous VMA the size of
# the reserved guest address space. Its growth IS the leak, without the noise of
# dalvik/scudo/GL in the process total.
#
# Rss alone lies: zram swaps out cold leaked pages, so the arena's Rss can *fall*
# in the middle of a growing leak. Rss+Swap is monotonic; that is what is summed.
#
# No root needed as long as the app is debuggable -- run-as gives full /proc access.
#
# usage: DEV=<serial> PKG=<package> ./memcheck.sh [samples] [interval_sec] [outfile]
D=${DEV:?set DEV to the adb serial}
PKG=${PKG:?set PKG to the application id}
N=${1:-24}
IV=${2:-5}
OUT=${3:-mem_log.csv}

PID=$(adb -s "$D" shell pidof "$PKG" | tr -d '\r')
[ -z "$PID" ] && { echo "not running"; exit 1; }
echo "pid=$PID  interval=${IV}s  samples=$N"
echo "t_s,rss_kb,arena_kb,jit_kb,vmsize_kb,threads" > "$OUT"

for i in $(seq 0 $((N-1))); do
  T=$((i*IV))
  S=$(adb -s "$D" shell "run-as $PKG sh -c 'grep -E \"^VmRSS|^VmSize|^Threads\" /proc/$PID/status; echo ===; cat /proc/$PID/smaps'" 2>/dev/null | tr -d '\r')
  [ -z "$S" ] && { echo "$T,DEAD"; break; }
  echo "$S" | awk -v t="$T" '
    /^VmRSS:/{rss=$2} /^VmSize:/{vsz=$2} /^Threads:/{thr=$2}
    /^[0-9a-f]+-[0-9a-f]+ /{
      split($1,r,"-"); sz=(strtonum("0x" r[2])-strtonum("0x" r[1]))/1024
      # 4 GiB guest arena; use ~2097152 instead if the fallback mapping was taken
      arena=(sz>=4194000 && sz<=4194400); jit=($2=="rwxp" && sz>=65536)
      next
    }
    /^Rss:/ { if(arena) a+=$2; if(jit) j+=$2 }
    /^Swap:/{ if(arena) a+=$2 }
    END{ printf "%s,%s,%s,%s,%s,%s\n", t, rss, a, j, vsz, thr }'
  sleep "$IV"
done | tee -a "$OUT"

# Reading the result:
#   flat arena          -> no leak
#   rising and settling -> free lists / asset caches warming up; measure a second window
#   rising linearly     -> real leak. Send the app to the background (input keyevent
#                          KEYCODE_HOME) and re-measure: zero means it is render-driven.
#                          Then attribute it by guest LR from inside the malloc thunks.
