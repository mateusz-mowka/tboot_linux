#ifndef __INTEL_PMT_H_
#define __INTEL_PMT_H_

#include <stdbool.h>

#define PMT_METRIC_ARR_TO_PTR	(struct pmt_metric *)&(struct pmt_metric [])

enum pmt_metric_index {
	PMT_XTAL,
	PMT_SOCN_XTAL,
	PMT_DIE_LLC,
	PMT_DIE_C2p1,
	PMT_DIE_C2p2,
	PMT_DIE_C3p1,
	PMT_DIE_C3p2,
	PMT_DIE_C6,
	PMT_PC2_RES,
	PMT_PC2R_RES,
	PMT_PC3_RES,
	PMT_PC6_RES,
	PMT_PC7_RES,
	PMT_PC8_RES,
	PMT_PC9_RES,
	PMT_PC10_RES,
	PMT_METRIC_END,
};

struct pmt_metric {
	enum pmt_metric_index index;
	int q_offset;
	int lsb;
	int num_bits;
};

struct pmt_guids {
	char guid[10];
	struct pmt_metric *metric;
};

struct pmt_table {
	struct pmt_metric	*metric;
	unsigned long long	*addr;
	int			offset;
	int			map_size;
	int			fd;
};

int pmt_create_table(struct pmt_guids *g);
bool pmt_table_has(enum pmt_metric_index metric_index);
void pmt_destroy_table(void);
void pmt_read_metric(enum pmt_metric_index metric_idx, unsigned long long *val);
extern struct pmt_guids pmt_guids_mtl[];
#endif
