#!/bin/sh

set -e

PRELOAD_LIB=$1 TARGET=$2 OUT_PWD=$3
echo -e "\n ==== Preload Test begins. Using lib at $PRELOAD_LIB."
echo -e " ---- Running strace on $OUT_PWD/${TARGET}..."
export LD_PRELOAD=$PRELOAD_LIB

strace -E LD_DEBUG=symbols,statistics,bindings -f -o $OUT_PWD/strace-preload.log    $OUT_PWD/${TARGET} 2> $OUT_PWD/strace-preload.err \
    || echo " ---- Preload Test FAILED"

export NO_PM_PRELOAD=1;
strace -E LD_DEBUG=symbols,statistics,bindings -f -o $OUT_PWD/strace-nopreload.log  $OUT_PWD/${TARGET} 2> $OUT_PWD/strace-nopreload.err \
    || echo " ---- Preload Test FAILED";

unset NO_PM_PRELOAD;
export LD_BIND_NOW=1;
strace -E LD_DEBUG=symbols,statistics,bindings -f -o $OUT_PWD/strace-bindnow.log  $OUT_PWD/${TARGET} 2> $OUT_PWD/strace-bindnow.err \
    || echo " ---- Preload Test FAILED";

echo -e " ==== Preload Test completed. Log files at $OUT_PWD.";
exit 0
