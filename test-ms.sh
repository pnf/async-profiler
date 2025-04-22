#!/ms/dist/fsf/PROJ/bash/4.3/bin/bash -vx

source paths-ms.sh
# Skip tests that require elevated permissions or perf access
export SKIP=fdtransfer,perfEventsTargetCpuWithFdtransferEventsCount,perfEventsTargetCpuEventsCount,cycles,cacheMisses
# skip tests that are too flaky when running on jenkins
export SKIP=${SKIP},raceToLocks,cpuWall

make test
