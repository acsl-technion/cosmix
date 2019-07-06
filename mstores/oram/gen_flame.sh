#!/usr/bin/env sh

FLAMEGRAPH=${HOME}/Downloads/FlameGraph/flamegraph.pl
STACKCOLLAPSE=${HOME}/Downloads/FlameGraph/stackcollapse-perf.pl

perf record -i -g -e cycles:u -- $1
perf script | ${STACKCOLLAPSE} > out.perf-folded
${FLAMEGRAPH} out.perf-folded > $2

