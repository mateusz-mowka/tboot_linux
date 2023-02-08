#!/usr/bin/env bash
#
# Summarize a testsuite results directory into tables.
#
# Argument:
#
#     basedir - Directory containing results from running a testsuite
#     data_file_suffix   - Summarize data in files with names ending in this.
#                          Defaults to "_lat_stats.csv", which will summarize
#                          the latency values.
#                          Use "_size_stats.csv" for compressed size values.
#

basedir=$1
data_file_suffix=$2

if [ -z "${data_file_suffix}" ]; then
    data_file_suffix="_lat_stats.csv"
fi

targets=$(echo $(seq 0.05 0.05 0.95)" 0.98 0.99")

function extract_from_csv () {
    file=$1
    gawk 'BEGIN { \
             FS = ","; \
             split("'"${targets}"'", targets, " "); \
         } \
         NR > 1 { \
             a[NR] = $2; \
         } \
         END { \
             asort(a, a, "@val_num_asc"); \
             n = NR-1; \
	     printf("%d ", n); \
             for (i in targets) { \
                 printf("%g ", a[int(n * targets[i])]); \
             } \
         }' "${file}"
}

head_tformats=$(echo "${targets}" | sed 's/[^ ]*/%6s/g')
data_tformats=$(echo "${targets}" | sed 's/[^ ]*/%6d/g')

for event in store load; do
    printf '\n%-55s %10s '"${head_tformats}"' %10s\n' "${event}" count ${targets} comp_ratio
    echo '----------------------------------------------------------------------------------------------'

    for dir in "${basedir}"/*; do
        title=$(basename "${dir}")
        values=$(extract_from_csv "${dir}"/*_"${event}${data_file_suffix}")
        comp_ratio=$(cut -d' ' -f3 "${dir}"/*_"${event}"_comp_avg.csv)

        printf '%-55s %10d '"${data_tformats}"' %10.2f\n' "${title}" ${values} "${comp_ratio}"
    done
done
