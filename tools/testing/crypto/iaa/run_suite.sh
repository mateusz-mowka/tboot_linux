#!/usr/bin/env bash
#
# Runs a suite of tests, placing results in a specified directory.
#
# Arguments:
#
#     testsuite - File containing a list of test names to be run
#     basedir   - New directory under which to store the results
#                 (if not provided, current [date-time] will be used)
#
# testsuite format:
#
#     One test name per line.  The test name will have "test-" prepended to it
#     to form the name of the file (in the current directory) which will be
#     executed.
#
#     Optional: a space separated list of [key]=[value] pairs can be supplied
#     after the test name to specify test parameters.  This will result in
#     [key] being available as an exported environment variable, with a value
#     of [value] (for each provided pair).
#

testsuite=$1
basedir=$2

if [ -z "${testsuite}" ]; then
    echo "No test suite specified"
    exit 1
fi

if [ -z "${basedir}" ]; then
    basedir=$(date '+%Y%m%d-%H%M%S')
fi

mkdir -p "${basedir}"

while read -a words; do
    test="${words[0]}"

    # Skip blank lines and comments (lines starting with "#")
    if [ -z "${test}" -o "${test:0:1}" = "#" ]; then
	continue
    fi

    # Set title
    ifs="${IFS}"
    IFS='+'
    title="${words[*]}"
    IFS="${ifs}"

    # Export parameters
    for param in ${words[@]:1}; do
	key="${param%%=*}"
	value="${param#*=}"

	export "${key}"="${value}"
    done

    script=./test-"${test}"
    dir="${basedir}"/"${title}"
    out="${dir}"/out
    trace="${dir}"/"${title}".trace

    echo "========================================"
    echo "Test: ${title}"
    echo "Results directory: ${dir}"
    echo "========================================"
    echo "Test: ${title}" >/dev/kmsg

    mkdir -p "${dir}"

    echo "----------------------------------------"
    echo "teardown-zswap"
    echo "----------------------------------------"
    ./teardown-zswap

    echo "----------------------------------------"
    echo "Run ${script}"
    echo "----------------------------------------"
    "${script}" > "${out}"

    echo "----------------------------------------"
    echo "dump-zswap-hists-all"
    echo "----------------------------------------"
    ./dump-zswap-hists-all >> "${out}"

    echo "----------------------------------------"
    echo "calcpercent.py"
    echo "----------------------------------------"
    ./calcpercent.py "${out}" 98 >> "${out}"

    echo "----------------------------------------"
    echo "cp /sys/kernel/debug/tracing/trace"
    echo "----------------------------------------"
    cp /sys/kernel/debug/tracing/trace "${trace}"

    echo "----------------------------------------"
    echo "trace_to_lat_csv.py"
    echo "----------------------------------------"
    ./trace_to_lat_csv.py -d "${dir}" -e load
    ./trace_to_lat_csv.py -d "${dir}" -e store

    echo "----------------------------------------"
    echo "trace_to_comp_avg.py"
    echo "----------------------------------------"
    ./trace_to_comp_avg.py -d "${dir}" -e load
    ./trace_to_comp_avg.py -d "${dir}" -e store

done <"${testsuite}"
