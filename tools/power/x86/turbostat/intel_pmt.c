#include <dirent.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>

#include "intel_pmt.h"

#define PMT_DIR "/sys/class/intel_pmt"

static struct pmt_table *table = NULL;

static void *pmt_find_and_mmap_guid(const char *guid, int *size, int *offset, int *fd)
{
	struct dirent *dir;
	void *addr;
	DIR *d;

	d = opendir(PMT_DIR);
	if (!d)
		return NULL;

	while ((dir = readdir(d)) != NULL) {
		FILE *fptr;
		char this_guid[10];
		char buffer[50] = { '\0' };
		char dir_name[8] = { '\0' };

		if (strncmp("telem", dir->d_name, 5))
			continue;

		strcpy(dir_name, dir->d_name);
		snprintf(buffer,  50, "%s/%s/guid", PMT_DIR, dir_name);
		fptr = fopen(buffer, "r");
		if (!fptr)
			return NULL;

		if (fscanf(fptr, "%s", this_guid) == 0)
			return NULL;

		fclose(fptr);
		if (strcmp(guid, this_guid))
			continue;

		snprintf(buffer,  50, "%s/%s/offset", PMT_DIR, dir_name);
		fptr = fopen(buffer, "r");
		if (!fptr)
			return NULL;

		if (fscanf(fptr, "%d", offset) == 0)
			return NULL;

		fclose(fptr);

		snprintf(buffer,  50, "%s/%s/size", PMT_DIR, dir_name);
		fptr = fopen(buffer, "r");
		if (!fptr)
			return NULL;

		if (fscanf(fptr, "%d", size) == 0)
			return NULL;

		fclose(fptr);

		snprintf(buffer,  50, "%s/%s/telem", PMT_DIR, dir_name);
		*fd = open(buffer, O_RDONLY);
		if (*fd == -1)
			return NULL;

		addr = mmap(NULL, *size + *offset, PROT_READ, MAP_SHARED, *fd, 0);
		if (addr == MAP_FAILED) {
			close(*fd);
			return NULL;
		}

		return addr;
	}

	return NULL;
}

/*
 * From an array of platform guids, create a table to be indexed by metric name,
 * allowing for quick lookup and reads. Discover the guids, mmap the telemetry
 * file it exists, and add the information to the table.
 *
 * Example entry
 * 	pmt_table[PMT_DIE_C6] = {
 * 	  .metric = {
 *	  	.index = PMT_DIE_C6,
 *	  	.q_offset = 140,	// qword offset were metric is located
 *	  	.lsb = 32,		// Least significant bit of metric in qword
 *	  	.num_bits = 32		// Size of the metric in bits,
 *	  }
 *	  .addr = the mmap addr,
 *	  .offset = the offset in page where the telemetry starts,
 * 	}
 */
int pmt_create_table(struct pmt_guids *g)
{
	if (!g)
		return -1;

	table = malloc(sizeof(struct pmt_table) * (PMT_METRIC_END));
	if (!table)
		return -1;

	memset(table, 0, sizeof(struct pmt_table) * (PMT_METRIC_END));

	do {
		struct pmt_metric *m = g->metric;
		int fd, size, offset;
		void *addr;

		addr = pmt_find_and_mmap_guid(g->guid, &size, &offset, &fd);
		if (addr == NULL) {
			++g;
			continue;
		}

		while (m->index != PMT_METRIC_END) {
			if (table[m->index].addr != NULL) {
				/* Should not happen if table added correctly */
				++m;
				continue;
			}
			table[m->index].metric = m;
			table[m->index].addr = addr;
			table[m->index].offset = offset;
			table[m->index].map_size = size + offset;
			table[m->index].fd = fd;
			++m;
		}

		++g;
	} while (strcmp(g->guid, ""));

	return 0;
}

bool pmt_table_has(enum pmt_metric_index metric_index)
{
	if (table ==  NULL)
		return false;

	if (table[metric_index].fd)
		return true;

	return false;
}

void pmt_destroy_table(void)
{
	struct pmt_table *entry = table;

	if (entry == NULL)
		return;

	while (entry->addr) {
		munmap(entry->addr, table->offset + table->map_size);
		close(entry->fd);
		++entry;
	}

	free(table);
}

void pmt_read_metric(enum pmt_metric_index metric_idx, unsigned long long *val)
{
	unsigned long long mask = (unsigned long long)-1;
	unsigned long long sample;
	int offset, lsb, num_bits;

	/*
	 * The metric is at:
	 * 	page offset (where telemetry starts in page) +
	 * 	q_offset (where the metric is relative to the page offset)
	 */
	offset = table[metric_idx].offset + table[metric_idx].metric->q_offset;

	num_bits = table[metric_idx].metric->num_bits;
	lsb = table[metric_idx].metric->lsb;

	sample = *(unsigned long long *)&(table[metric_idx].addr[offset]);

	mask >>= 64 - num_bits;
	*val = (sample >> lsb) & mask;
}
