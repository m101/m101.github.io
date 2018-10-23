#!/bin/sh

start=`date`
echo "Start: "$start

echo 'MemCheck ... '
valgrind --leak-check=full --show-reachable=yes --track-origins=no -v $1 $2 1>run-valgrind.txt 2>valgrind-memcheck.txt
echo 'Done'
# end of memcheck
end=`date`
echo $end

# start_cache=`date`
# echo $start_cache
# echo 'CacheGrind ... '
# valgrind --tool=cachegrind $1 $2 1>run-cachegrind.txt 2>valgrind-cache.txt
# echo 'Done'
# end=`date`
# echo $end

start_call=`date`
echo $start_call

echo 'CallGrind ... '
valgrind --tool=callgrind --dump-instr=yes --trace-jump=yes --cacheuse=yes --cache-sim=yes $1 $2 1>run-callgrind.txt 2>valgrind-call.txt
echo 'Done'

end=`date`
echo "End: "$end

start=`date -d "'"$start"'" '+%s'`
end=`date -d "'"$end"'" '+%s'`
counter=`python -c 'print '"$end-$start"''`

python -c 'print "It took '$counter' seconds to run the valgrind profiling tools (memcheck, cachegrind and callgrind)"'
