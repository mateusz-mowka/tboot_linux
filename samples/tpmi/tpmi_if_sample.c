// SPDX-License-Identifier: GPL-2.0
/*
 * Sample TPMI in-kernel interface
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/intel_tpmi.h>

MODULE_LICENSE("GPL");

int tpmi_get_info(int package_id, int tpmi_id, int *num_entries, int *entry_size);
void __iomem *tpmi_get_mem(int package_id, int tpmi_id, int *size);
void tpmi_free_mem(void __iomem *mem);

static int __init tpmi_if_module_init(void)
{
	int entry_size, num_entries;
	void __iomem *mem;
	int ret, size;


	pr_info("%s\n", __func__);

	/* TPMI_ID for RAPL is 0 */
	ret = tpmi_get_info(0, 0, &num_entries, &entry_size);
	if (ret) {
		pr_info("tpmi_get_info failed\n");
		return -1;
	}

	pr_info("num_entries :%d entry_size:%d\n", num_entries, entry_size);
	mem = tpmi_get_mem(0, 0, &size);
	if (!mem) {
		pr_info("tpmi_get_mem failed\n");
		return -1;
	}

	pr_info("mapped mem size:%d\n", size);

	pr_info("rapl_header_info 0x%x\n", readb(mem));

	msleep(10000);

	/*
	 *  Simulate mem_write via debugfs while sleep here,
	 *  for example:  echo "0:0x01" > mem_write for tpmi-id-0
	 */

	pr_info("AFter sleep rapl_header_info 0x%x\n", readb(mem));

	tpmi_free_mem(mem);

	return 0;
}

static void __exit tpmi_if_module_exit(void)
{
	pr_info("%s\n", __func__);
}

MODULE_IMPORT_NS(INTEL_TPMI);
module_init(tpmi_if_module_init);
module_exit(tpmi_if_module_exit);
