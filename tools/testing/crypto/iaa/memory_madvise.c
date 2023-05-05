#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <linux/mman.h>

#ifndef MADV_PAGEOUT
#define MADV_PAGEOUT	21	/* force pages out immediately */
#endif

#define PG_SZ		4096

int main(int argc, char **argv)
{
	int i, nr_pages = 1;
        int64_t *dump_ptr;
	char *addr, *a;
        int loop = 1;

	if (argc > 1)
		nr_pages = atoi(argv[1]);

        printf("Allocating %d pages to swap in/out\n", nr_pages);

        /* allocate pages */
        addr = mmap(NULL, nr_pages * PG_SZ, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        *addr = 1;

        /* initialize data in page to all '*' chars */
        memset(addr, '*', nr_pages * PG_SZ);

        printf("Swapping out %d pages\n", nr_pages);

        /* Tell kernel to swap it out */
        madvise(addr, nr_pages * PG_SZ, MADV_PAGEOUT);

        while (loop > 0) {
                /* Wait for swap out to finish */
                sleep(5);

		a = addr;

		printf("Swapping in %d pages\n", nr_pages);

                /* Access the page ... this will swap it back in again */
		for (i = 0; i < nr_pages; i++) {
			if (a[0] != '*') {
				printf("Bad data from decompress!!!\n");

				dump_ptr = (int64_t *)a;
				for (int j = 0; j < 100; j++) {
					printf("  page %d data: %#llx\n", i, *dump_ptr);
					dump_ptr++;
				}
			}

			a += PG_SZ;
		}

                loop --;
        }

        printf("Swapped out and in %d pages\n", nr_pages);
}

