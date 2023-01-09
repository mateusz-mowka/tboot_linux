#!/usr/bin/env bash
#
# Summarize a testsuite results directory into tables.
#
# Argument:
#
#     basedir - Directory containing results from running a testsuite
#     short   - If set to anything, produce short summary
#

basedir=$1
short=$2

# Start with short list of targets:
targets="0.50 0.75 0.98 0.99"

# If short mode is not set, use long list:
if [ -z "${short}" ]; then
    targets=$(echo $(seq 0.50 0.05 0.95)" 0.98 0.99")
fi

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
             for (i in targets) { \
                 printf("%g ", a[int(n * targets[i])]); \
             } \
         }' "${file}"
}

head_tformats=$(echo "${targets}" | sed 's/[^ ]*/%6s/g')
data_tformats=$(echo "${targets}" | sed 's/[^ ]*/%6d/g')

for event in store load; do
    printf '\n%-55s '"${head_tformats}"' %10s\n' "${event}" ${targets} comp_ratio
    echo '----------------------------------------------------------------------------------------------'

    for dir in "${basedir}"/*; do
        title=$(basename "${dir}")

        ptiles=$(extract_from_csv "${dir}"/*"${event}"_lat_stats.csv)

        comp_ratio=$(cut -d' ' -f3 "${dir}"/"${title}"_store_comp_avg.csv)

        printf '%-55s '"${data_tformats}"' %10.2f\n' "${title}" ${ptiles} "${comp_ratio}"
    done
done
