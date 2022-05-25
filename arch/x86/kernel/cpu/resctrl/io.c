// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/acpi.h>

#define IORDT_RCS_AQ	(1 << 0)
#define IORDT_RCS_RTS	(1 << 1)
#define IORDT_RCS_CTS	(1 << 2)
#define IORDT_RCS_REGW	(1 << 3)
#define IORDT_RCS_REF	(1 << 4)
#define IORDT_RCS_CEF	(1 << 5)

/*
 * iordt_rcs - Describe RCS
 * @channels_type:		0: PCIe or CXL.IO	1: CXL.cache
 * @rcs_enumeration_id: 	ID for this RCS under this RMUD
 * @channel_count:		Number of channels under this link
 * @flags:			flags under this link
 * @rmid_block_offset:		RMID offset from the MMIO location
 * @clos_block_offset:		CLOS offset from the MMIO location
 * @rcs_block_bdf:		I/O block BDF
 * @rcs_block_bar_number:	IO/ block BAR number
 * @rcs_block_mmio_location:	I/O block MMIO BAR location
 */
struct iordt_rcs {
	u16 channels_type;
	u8  rcs_enumeration_id;
	u8  channel_count;
	u64 flags;
	u16 rmid_block_offset;
	u16 clos_block_offset;
	u16 rcs_block_bdf;
	u8  rcs_block_bar_number;
	u64 rcs_block_mmio_location;
} *iordt_rcs;

struct iordt_chms_vc {
	u8   channel;
	bool shared;
};

/*
 * iordt_chms - Describe CHMS
 * @rcs_enumeration_id: RCS enumeration ID
 * @vc[8]:		Index into the RCS configuration table for VC0-8
 */
struct iordt_chms {
	u8  rcs_enumeration_id;
	struct iordt_chms_vc  vc[8];
};

/*
 * iordt_dss - Describe DSS
 * @device_type:	1: Root Complext Integrated Endpoint (RCEIP)
 *			2: PCI sbu-hierarchy
 * @enumeration_id:	BDF
 * @chms_num:		Number of CHMS entries under this DSS
 * @chms:		Pointer to an CHMS array under this DSS
 */
struct iordt_dss {
	u8  device_type;
	u16 enumeration_id;
	u16 chms_num;
	struct iordt_chms *chms;
};

/*
 * iordt_rmud - Describe RMUD
 * @min_closid:	Minimum CLOSID
 * @min_rmid:	Minimum RMID
 * @max_closid:	Maximum CLOSID
 * @max_rmid:	Maximum RMID
 * @segment:	Segment
 * @rcs_num:	Number of RCS entries under this RMUD
 * @rcs:	Pointer to an RCS array under this RMUD
 * @dss_num:	Number of DSS entries under this RMUD
 * @dss:	Pointer to an DSS array under this RMUD
 */
static struct iordt_rmud {
	u32 min_closid;
	u32 min_rmid;
	u32 max_closid;
	u32 max_rmid;
	u16 segment;
	int rcs_num;
	struct iordt_rcs *rcs;
	int dss_num;
	struct iordt_dss *dss;
} *iordt_rmud;

int iordt_rmud_num;

bool irdt_parsed;

static bool __init iordt_cpu_has_cat_l3(void)
{
	return rdt_cpu_has(X86_FEATURE_CAT_L3) &&
	       rdt_cpu_has(X86_FEATURE_CAT_L3_IO);
}

static bool __init iordt_cpu_has_cmt_l3(void)
{
	return rdt_cpu_has(X86_FEATURE_CQM_OCCUP_LLC) &&
	       rdt_cpu_has(X86_FEATURE_CQM_OCCUP_LLC_IO);
}

static bool __init iordt_cpu_has_mbm_l3(void)
{
	return (rdt_cpu_has(X86_FEATURE_CQM_MBM_TOTAL) ||
	       rdt_cpu_has(X86_FEATURE_CQM_MBM_LOCAL)) &&
	       rdt_cpu_has(X86_FEATURE_CQM_MBM_IO);
}

static bool __init irdt_enabled(void)
{
	return cpu_feature_enabled(X86_FEATURE_CQM_OCCUP_LLC_IO)	|
	       cpu_feature_enabled(X86_FEATURE_CQM_MBM_IO)	|
	       cpu_feature_enabled(X86_FEATURE_CAT_L3_IO);
}

#define IORDT_DEV_TYPE_DSS		0
#define IORDT_DEV_TYPE_RCS		1
#define IORDT_CHMS_SIZE			16
#define IORDT_VC_NUM			8
#define IORDT_CHMS_CHANNEL_VALID	(1 << 7)
#define IORDT_CHMS_CHANNEL_SHARED	(1 << 6)
#define IORDT_CHMS_CHANNEL_VAL		~(IORDT_CHMS_CHANNEL_VALID |	\
					IORDT_CHMS_CHANNEL_SHARED)
#define IORDT_RCS_NUM			64
#define IORDT_DSS_NUM			64
#define IORDT_RMUD_NUM			32
struct iordt_rmud init_rmud[IORDT_RMUD_NUM] __initdata;
struct iordt_dss init_dss[IORDT_DSS_NUM] __initdata;
struct iordt_rcs init_rcs[IORDT_RCS_NUM] __initdata;

static int __init
dss_enumerate(struct acpi_table_dss *acpi_dss, struct iordt_dss *dss,
	      int dss_rcs_num, u16 *length)
{
	void *acpi_chms = (void *)acpi_dss + sizeof(struct acpi_table_dss);
	struct iordt_chms *chms;
	int chms_num, chms_idx;

	chms_num = (acpi_dss->length - sizeof(struct acpi_table_dss))/
		   IORDT_CHMS_SIZE;

	chms = kzalloc(sizeof(struct iordt_chms) * chms_num, GFP_KERNEL);
	if (!chms)
		return -ENOSPC;

	for (chms_idx = 0; chms_idx < chms_num; chms_idx++) {
		u8 *p = acpi_chms + chms_idx * IORDT_CHMS_SIZE;
		int vc_idx;

		chms[chms_idx].rcs_enumeration_id = p[0];
		for (vc_idx = 0; vc_idx < IORDT_VC_NUM; vc_idx++) {
			u8 channel_byte, channel;
			int shared;

			channel_byte = p[vc_idx + 1];
			/* Only enumerate valid channel */
			if (!(channel_byte & IORDT_CHMS_CHANNEL_VALID))
				continue;

			channel = channel_byte & IORDT_CHMS_CHANNEL_VAL;
			shared = channel_byte & IORDT_CHMS_CHANNEL_SHARED;

			chms[chms_idx].vc[vc_idx].shared = shared;
			chms[chms_idx].vc[vc_idx].channel = channel;
		}
	}
	dss->chms_num = chms_num;
	dss->chms = chms;

	*length = acpi_dss->length;

	return 0;
}

static int __init
rcs_enumerate(struct acpi_table_rcs *acpi_rcs, struct iordt_rcs *rcs,
	      int dss_rcs_num, u16 *length)
{
	*length = acpi_rcs->length;

	return 0;
}

static int __init
dss_rcs_enumerate(struct iordt_rmud *rmud, struct acpi_table_rmud *acpi_rmud)
{
	int dss_num = 0,rcs_num = 0, ret = 0;
	void *dss_rcs, *rmud_end;

	dss_rcs = (void *)acpi_rmud + sizeof(struct acpi_table_rmud);
	rmud_end = (void *)acpi_rmud + acpi_rmud->length - 1;
	while ((rmud_end + 1) > (void *)dss_rcs) {
		unsigned char type;
		u16 length = 0;

		/* This DSS/RCS table must be inside the RMUD table space */
		if (((void *)dss_rcs + length - 1) > rmud_end )
			break;

		/* type: 0 (DSS)      1 (RCS) */
		type = *(char *)dss_rcs;
		if (type == IORDT_DEV_TYPE_DSS) {
			ret = dss_enumerate(dss_rcs, &init_dss[dss_num],
					    dss_num, &length);
			if (ret)
				return ret;
			dss_num++;
		} else if (type == IORDT_DEV_TYPE_RCS) {
			ret = rcs_enumerate(dss_rcs, &init_rcs[rcs_num],
					    rcs_num, &length);
			if (ret)
				return ret;
			rcs_num++;
		} else {
			continue;
		}

		dss_rcs = (void *)dss_rcs + length;
	}

	if (rcs_num) {
		struct iordt_rcs *rcs;

		rcs = kzalloc(sizeof(struct iordt_rcs) * rcs_num, GFP_KERNEL);
		if (!rcs)
			return -ENOSPC;

		/* Set up this RCS in RMUD. */
		memcpy(rcs, init_rcs, sizeof(struct iordt_rcs) * rcs_num);
		rmud->rcs = rcs;
		rmud->rcs_num = rcs_num;
	}

	if (dss_num) {
		struct iordt_dss *dss;

		dss = kzalloc(sizeof(struct iordt_dss) * dss_num, GFP_KERNEL);
		if (!dss)
			return -ENOSPC;

		/* Set up this DSS in RMUD. */
		memcpy(dss, init_dss, sizeof(struct iordt_dss) * dss_num);
		rmud->dss = dss;
		rmud->dss_num = dss_num;
	}

	return 0;
}

static void iordt_rmud_free(struct iordt_rmud *rmud, int rmud_num)
{
	int i, j;

	/* Free all allocated RCS and DSS memory. */
	for (i = 0; i < rmud_num; i++) {
		kfree(rmud->rcs);
		for (j = 0; j < rmud->dss_num; j++)
			kfree(rmud->dss[j].chms);
		kfree(rmud->dss);
	}

	/* Free the iordt_rmud array. */
	if (rmud == iordt_rmud) {
		kfree(rmud);
		iordt_rmud_num = 0;
	}
}

void __exit iordt_free(void)
{
	iordt_rmud_free(iordt_rmud, iordt_rmud_num);
}

static void
rmud_copy(struct iordt_rmud *rmud, struct acpi_table_rmud *acpi_rmud)
{
	rmud->min_closid = acpi_rmud->min_clos;
	rmud->min_rmid = acpi_rmud->min_rmid;
	rmud->max_closid = acpi_rmud->max_clos;
	rmud->max_rmid = acpi_rmud->max_rmid;
	rmud->segment = acpi_rmud->segment;
}

static int __init rmud_enumerate(struct acpi_table_irdt *acpi_irdt)
{
	struct acpi_table_rmud *acpi_rmud = NULL;
	int ret, rmud_num = 0;
	void *irdt_end = NULL;

	acpi_rmud = (void *)acpi_irdt + sizeof(struct acpi_table_irdt);
	irdt_end = (void *)acpi_irdt + acpi_irdt->header.length -1;
	while ((irdt_end + 1) > (void *)acpi_rmud) {
		/* type 0 for "RMUD" */
		if (acpi_rmud->type)
			break;

		/* This RMUD table must be inside the IRDT table space */
		if (((void *)acpi_rmud + acpi_rmud->length - 1) > irdt_end )
			break;

		rmud_copy(&init_rmud[rmud_num], acpi_rmud);
		ret = dss_rcs_enumerate(&init_rmud[rmud_num], acpi_rmud);
		if (ret) {
			pr_err("Cannot allocate IORDT device\n");
			iordt_rmud_free(init_rmud, rmud_num);

			return ret;
		}

		rmud_num++;
		acpi_rmud = (void *)acpi_rmud + acpi_rmud->length;
	}

	iordt_rmud = kzalloc(rmud_num * sizeof(struct iordt_rmud), GFP_KERNEL);
	if (!iordt_rmud) {
		pr_err("Cannot allocate IORDT channels array\n");
		iordt_rmud_free(iordt_rmud, rmud_num);

		return -ENOSPC;
	}
	/* Set up RMUD array. */
	iordt_rmud_num = rmud_num;
	memcpy(iordt_rmud, init_rmud, sizeof(struct iordt_rmud) * iordt_rmud_num);

	return 0;
}

static int __init irdt_enumerate(struct acpi_table_irdt *irdt)
{
	return rmud_enumerate(irdt);
}

static int __init acpi_parse_irdt(struct acpi_table_header *table)
{
	struct acpi_table_irdt *irdt = NULL;
	int ret = 0;

	if (!irdt_enabled())
		return -EINVAL;

	irdt = (struct acpi_table_irdt *)table;
	if (!irdt) {
		pr_warn("Unable to map IRDT\n");

		return -ENODEV;
	}

	ret = irdt_enumerate(irdt);

	return ret;
}

bool iordt_enabled(void)
{
	return io_enabled ? true : false;
}

void __init iordt_show(void)
{
	if (io_enabled & IO_CAT_L3_ENABLED)
		pr_info("CAT L3 IO detected\n");
	if (io_enabled & IO_CMT_L3_ENABLED)
		pr_info("CMT L3 IO detected\n");
	if (io_enabled & IO_MBM_L3_ENABLED)
		pr_info("MBM L3 IO detected\n");
}

void __init iordt_init(void)
{
	if (!iordt_cpu_has_cat_l3() && !iordt_cpu_has_cmt_l3() &&
	    !iordt_cpu_has_mbm_l3())
		return;

	if (acpi_disabled)
		return;

	irdt_parsed = acpi_table_parse(ACPI_SIG_IRDT, acpi_parse_irdt);
	if (irdt_parsed) {
		pr_warn("Unable to parse IRDT table\n");

		return;
	}
}
