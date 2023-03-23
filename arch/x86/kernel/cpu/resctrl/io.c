// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt)	"iordt: " fmt

#include <linux/seq_file.h>
#include <linux/acpi.h>
#include "internal.h"

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

#define IORDT_RCS_AQ	(1 << 0)
#define IORDT_RCS_RTS	(1 << 1)
#define IORDT_RCS_CTS	(1 << 2)
#define IORDT_RCS_REGW	(1 << 3)
#define IORDT_RCS_REF	(1 << 4)
#define IORDT_RCS_CEF	(1 << 5)

/*
 * iordt_rcs - Describe RCS
 * @channel_type:		0: PCIe or CXL.IO	1: CXL.cache
 * @rcs_enumeration_id: 	ID for this RCS under this RMUD
 * @channel_count:		Number of channels under this link
 * @flags:			flags under this link
 * @regw:			Register width 2B or 4B
 * @rmid_block_offset:		RMID offset from the MMIO location
 * @clos_block_offset:		CLOS offset from the MMIO location
 * @rcs_block_bdf:		I/O block BDF
 * @rcs_block_bar_number:	IO/ block BAR number
 * @rcs_block_mmio_location:	I/O block MMIO BAR location
 * @closid_base:		Mapped CLOSID MMIO base
 * @rmid_base:			Mapped RMID MMIO base
 */
struct iordt_rcs {
	u16 channel_type;
	u8  rcs_enumeration_id;
	u8  channel_count;
	u64 flags;
	u8  regw;
	u16 rmid_block_offset;
	u16 clos_block_offset;
	u16 rcs_block_bdf;
	u8  rcs_block_bar_number;
	u64 rcs_block_mmio_location;
	void __iomem *closid_base;
	void __iomem *rmid_base;
} *iordt_rcs;

/*
 * iordt_chms - Describe CHMS
 * @rcs_enumeration_id: RCS enumeration ID
 * @vc_num:		Number of VC
 * @vc[8]:		Index into the RCS configuration table for VC0-7
 */
struct iordt_chms {
	u8  rcs_enumeration_id;
	u8  vc_num;
	struct iordt_vc vc[IORDT_VC_NUM];
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

int iordt_channel_num;
struct iordt_chan iordt_channel[IORDT_CHANNEL_NUM];

static u64 io_enabled;

static u64 l3_io_qos_cfg(void)
{
	u64 l3_mon = io_enabled & (IO_CMT_L3_ENABLED | IO_MBM_L3_ENABLED) ?
		     L3_IOM_ENABLE : 0;
	u64 l3_cat = io_enabled & IO_CAT_L3_ENABLED ?  L3_IOA_ENABLE : 0;

	return l3_mon | l3_cat;
}

/* Set up L3_IO_QOS_CFG MSR. */
void l3_io_qos_cfg_update(void *enable)
{
	bool iordt_enable = *(bool *)enable;
	u64 val;

	if (!iordt_enabled())
		return;

	val = iordt_enable ? l3_io_qos_cfg() : 0;
	wrmsrl(MSR_IA32_L3_IO_QOS_CFG, val);
}

#define io_enabled_valid(flag) (flag & (IO_CAT_L3_ENABLED |		\
				IO_CMT_L3_ENABLED | IO_MBM_L3_ENABLED))

void __init iordt_enable(u64 flag)
{
	if (io_enabled_valid(flag))
		io_enabled |= flag;
}

static bool __init irdt_enabled(void)
{
	return cpu_feature_enabled(X86_FEATURE_CQM_OCCUP_LLC_IO)	|
	       cpu_feature_enabled(X86_FEATURE_CQM_MBM_IO)	|
	       cpu_feature_enabled(X86_FEATURE_CAT_L3_IO);
}

struct iordt_rmud init_rmud[IORDT_RMUD_NUM] __initdata;
struct iordt_dss init_dss[IORDT_DSS_NUM] __initdata;
struct iordt_rcs init_rcs[IORDT_RCS_NUM] __initdata;

static int __init
dss_enumerate(struct acpi_table_dss *acpi_dss, struct iordt_dss *dss,
	      int dss_rcs_num, u16 *length, int rmud_idx)
{
	void *acpi_chms = (void *)acpi_dss + sizeof(struct acpi_table_dss);
	struct iordt_chms *chms;
	int chms_num, chms_idx;

	chms_num = (acpi_dss->length - sizeof(struct acpi_table_dss))/
		   IORDT_CHMS_SIZE;

	chms = kzalloc(sizeof(struct iordt_chms) * chms_num, GFP_KERNEL);
	if (!chms)
		return -ENOSPC;

	dss->enumeration_id = acpi_dss->id;
	for (chms_idx = 0; chms_idx < chms_num; chms_idx++) {
		u8 *p = acpi_chms + chms_idx * IORDT_CHMS_SIZE;
		int vc_idx;

		chms[chms_idx].rcs_enumeration_id = p[0];
		for (vc_idx = 0; vc_idx < IORDT_VC_NUM; vc_idx++) {
			u8 vc_channel_byte, vc_channel;
			struct iordt_vc *vc;
			int shared;

			vc_channel_byte = p[vc_idx + 1];
			/* Only enumerate valid channel */
			if (!(vc_channel_byte & IORDT_CHMS_CHANNEL_VALID))
				continue;

			vc_channel = vc_channel_byte & IORDT_CHMS_CHANNEL_VAL;
			shared = vc_channel_byte & IORDT_CHMS_CHANNEL_SHARED;

			vc = & chms[chms_idx].vc[vc_idx];
			vc->valid = true;
			vc->shared = shared;
			vc->vc_channel = vc_channel;
			vc->channel = vc_channel | (p[0] << 8) | \
				      (rmud_idx << 16);
			vc->bdf = dss->enumeration_id;
			INIT_LIST_HEAD(&vc->list);

			chms[chms_idx].vc_num++;
		}
	}
	dss->chms_num = chms_num;
	dss->chms = chms;

	*length = acpi_dss->length;

	return 0;
}

static int rcs_setup(struct iordt_rcs *rcs, struct acpi_table_rcs *acpi_rcs)
{
	void __iomem *base;
	unsigned long addr;
	int size;

	rcs->channel_type = acpi_rcs->channel_type;
	rcs->rcs_enumeration_id = acpi_rcs->rcs_enumeration_id;
	rcs->channel_count = acpi_rcs->channel_count;
	rcs->flags = acpi_rcs->flags;
	rcs->regw = rcs->flags & IORDT_RCS_REGW ? 2 : 4;
	rcs->rmid_block_offset = acpi_rcs->rmid_block_offset;
	rcs->clos_block_offset = acpi_rcs->clos_block_offset;
	rcs->rcs_block_bdf = acpi_rcs->rcs_block_bdf;
	rcs->rcs_block_bar_number = acpi_rcs->rcs_block_bar_number;
	rcs->rcs_block_mmio_location = acpi_rcs->rcs_block_mmio_location;

	size = rcs->channel_count * rcs->regw;
	addr = rcs->rcs_block_mmio_location + rcs->clos_block_offset;
	base = ioremap(addr, size);
	if (!base) {
		pr_err("Cannot map RCS CLOS block MMIO location %lx\n",
		       (unsigned long)rcs->rcs_block_mmio_location);
		return -ENOMEM;
	}
	rcs->closid_base = base;
	addr = rcs->rcs_block_mmio_location + rcs->rmid_block_offset;
	base = ioremap(addr, size);
	if (!base) {
		pr_err("Cannot map RCS RMID block MMIO location %lx\n",
		       (unsigned long)rcs->rcs_block_mmio_location);
		return -ENOMEM;
	}
	rcs->rmid_base = base;

	return 0;
}

static int __init
rcs_enumerate(struct acpi_table_rcs *acpi_rcs, struct iordt_rcs *rcs,
	      int dss_rcs_num, u16 *length)
{
	*length = acpi_rcs->length;

	return rcs_setup(rcs, acpi_rcs);
}

static int __init
dss_rcs_enumerate(struct iordt_rmud *rmud, struct acpi_table_rmud *acpi_rmud,
		  int rmud_idx)
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
					    dss_num, &length, rmud_idx);
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
		for (j = 0; j < rmud->rcs_num; j++) {
			iounmap(rmud->rcs[j].closid_base);
			iounmap(rmud->rcs[j].rmid_base);
		}
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

	/* Free iordt_channel->name. */
	for (i = 0; i < iordt_channel_num; i++)
		kfree(iordt_channel[i].file.name);
	iordt_channel_num = 0;
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

static int rcs_find(struct iordt_rmud *rmud, u8 rcs_enumeration_id,
		    struct iordt_rcs **rcs)
{
	int i;

	for (i = 0; i < rmud->rcs_num; i++) {
		if (rmud->rcs[i].rcs_enumeration_id == rcs_enumeration_id) {
			/* Find RCS that matches rcs_enumeration_id. */
			*rcs = &rmud->rcs[i];

			return 0;
		}
	}

	return -EINVAL;
}

#define for_each_iordt_rmud(rmud, rmud_idx, iordt_rmud)			\
	for (rmud = iordt_rmud, rmud_idx = 0;				\
	     rmud < iordt_rmud + iordt_rmud_num; rmud++, rmud_idx++)

#define for_each_iordt_dss(dss, dss_idx, rmud)				    \
	for (dss = rmud->dss, dss_idx = 0; dss < rmud->dss + rmud->dss_num; \
	     dss++, dss_idx++)

#define for_each_iordt_chms(chms, dss)				\
	for (chms = dss->chms; chms < dss->chms + dss->chms_num; chms++)

#define for_each_iordt_vc(vc, chms)				\
	for (vc = chms->vc; vc < chms->vc + chms->vc_num; vc++)

#define for_each_iordt_rcs(rcs, rcs_idx, rmud)				    \
	for (rcs = rmud->rcs, rcs_idx = 0; rcs < rmud->rcs + rmud->rcs_num; \
	     rcs++, rcs_idx++)

static void get_rcs_closid_addr(struct iordt_rcs *rcs, int channel,
				void __iomem **addr)
{
	*addr = (void *)(rcs->closid_base + channel * rcs->regw);
}

static void get_rcs_rmid_addr(struct iordt_rcs *rcs, int channel,
			      void __iomem **addr)
{
	*addr = (void *)(rcs->rmid_base + channel * rcs->regw);
}

static void iordt_closid_rmid_write(void __iomem *addr, u32 val, u8 regw)
{
	if (regw == 2)
		*(u16 *)addr = (u16)val;
	else
		*(u32 *)addr = val;
}

void iordt_closid_write(struct iordt_chan *c, u32 val)
{
	iordt_closid_rmid_write(c->closid_addr, val, c->regw);
	c->closid = val;
}

void iordt_rmid_write(struct iordt_chan *c, u32 val)
{
	iordt_closid_rmid_write(c->rmid_addr, val, c->regw);
	c->rmid = val;
}

struct iordt_chan *iordt_channel_find(u32 channel)
{
	struct iordt_chan *pchannel;

	for_each_iordt_channel(pchannel) {
		if (pchannel->channel == channel)
			return pchannel;
	}

	return NULL;
}

static int _iordt_channel_setup(struct iordt_chms *chms, struct iordt_dss *dss,
				struct iordt_rmud *rmud, int rmud_idx)
{
	void __iomem *closid_addr, *rmid_addr;
	u8 rcs_enumeration_id, vc_channel;
	struct iordt_chan *pchannel;
	struct iordt_rcs *rcs;
	struct iordt_vc *vc;
	u32 channel;
	int ret;

	rcs_enumeration_id = chms->rcs_enumeration_id;
	for_each_iordt_vc(vc, chms) {
		vc_channel = vc->vc_channel;
		channel = vc->channel;

		pchannel = iordt_channel_find(channel);
		if (pchannel) {
			list_add_tail(&vc->list, &pchannel->list);
			continue;
		}

		ret = rcs_find(rmud, rcs_enumeration_id, &rcs);
		if (ret) {
			pr_warn("Cannot read RCS from channel %d\n", channel);

			return ret;
		}

		get_rcs_closid_addr(rcs, vc_channel, &closid_addr);
		get_rcs_rmid_addr(rcs, vc_channel, &rmid_addr);


		pchannel = &iordt_channel[iordt_channel_num];
		pchannel->channel = channel;
		pchannel->closid_addr = closid_addr;
		pchannel->rmid_addr = rmid_addr;
		pchannel->rdtgrp = &rdtgroup_default;
		pchannel->regw = rcs->regw;
		iordt_closid_write(pchannel, 0);
		iordt_rmid_write(pchannel, 0);
		ret = rdtgroup_channel_info_files_setup(pchannel);
		if (ret)
			return ret;

		pchannel->segment = rmud->segment;

		INIT_LIST_HEAD(&pchannel->list);
		list_add_tail(&vc->list, &pchannel->list);

		iordt_channel_num++;
	}

	return 0;
}

static int iordt_channel_setup(void)
{
	int rmud_idx, dss_idx,ret;
	struct iordt_rmud *rmud;
	struct iordt_chms *chms;
	struct iordt_dss *dss;

	for_each_iordt_rmud(rmud, rmud_idx, iordt_rmud) {
		for_each_iordt_dss(dss, dss_idx, rmud) {
			for_each_iordt_chms(chms, dss) {
				ret = _iordt_channel_setup(chms, dss, rmud,
							   rmud_idx);
				if (ret)
					return ret;
			}
		}
	}

	return 0;
}

static void iordt_closid_rmid_setup(u32 closid, u32 rmid)
{
	struct iordt_chan *pchannel;

	for_each_iordt_channel(pchannel) {
		/* Initilize CLOSID and RMID to 0. */
		iordt_closid_write(pchannel, closid);
		iordt_rmid_write(pchannel, rmid);
	}
}

int iordt_channel_config(bool enable)
{
	int ret = 0;

	if (!iordt_rmud)
		return -ENOSPC;

	if (enable) {
		/* Clear CLOSIDs and RMIDs when mounting resctrl. */
		iordt_closid_rmid_setup(0, 0);
	} else {
		/* Restore to default values when unmounting resctrl. */
		iordt_closid_rmid_setup(0xf, 0xffff);
	}

	return ret;
}

#ifdef RESCTRL_DEBUG
static void iordt_channel_show(struct seq_file *s, struct iordt_chms *chms,
			       struct iordt_rmud *rmud, int rmud_idx)
{
	void __iomem *closid_addr, *rmid_addr;
	int channel, ret, vc_channel;
	u8 rcs_enumeration_id;
	struct iordt_rcs *rcs;
	struct iordt_vc *vc;
	u32 closid, rmid;

	rcs_enumeration_id = chms->rcs_enumeration_id;
	for_each_iordt_vc(vc, chms) {
		vc_channel = vc->vc_channel;
		channel = vc->channel;

		ret = rcs_find(rmud, rcs_enumeration_id, &rcs);
		if (ret) {
			pr_warn("Cannot read RCS frm channel %d\n", channel);
			continue;
		}

		get_rcs_closid_addr(rcs, vc_channel, &closid_addr);
		get_rcs_rmid_addr(rcs, vc_channel, &rmid_addr);

		closid = rcs->regw == 2 ? *(u16 *)closid_addr :
			 *(u32 *)closid_addr;
		rmid = rcs->regw == 2 ? *(u16 *)rmid_addr : *(u32 *)rmid_addr;

		seq_printf(s, "\t\tChannel %x: CLOSID=%d @ 0x%lx, RMID=%d @ 0x%lx\n",
			   channel, closid, (unsigned long)closid_addr,
			   rmid, (unsigned long)rmid_addr);
	}
}

static void iordt_rmud_show(struct seq_file *s, struct iordt_rmud *rmud,
			   int rmud_idx)
{
	seq_printf(s, "RMUD[%d]:\n", rmud_idx);
	seq_printf(s, "\tmin CLOSID: %d\n", rmud->min_closid);
	seq_printf(s, "\tmax CLOSID: %d\n", rmud->max_closid);
	seq_printf(s, "\t  min RMID: %d\n", rmud->min_rmid);
	seq_printf(s, "\t  max RMID: %d\n", rmud->max_rmid);
	seq_printf(s, "\t   segment: %d\n", rmud->segment);
}

static void iordt_dss_show(struct seq_file *s, struct iordt_dss *dss,
			   int dss_idx)
{
	seq_printf(s, "\tDSS[%d]:\n", dss_idx);
	seq_printf(s, "\t\tBDF: %x\n", dss->enumeration_id);
}

static void iordt_rcs_show(struct seq_file *s, struct iordt_rcs *rcs,
			   int rcs_idx)
{
	void __iomem *p;
	int vc_channel;

	seq_printf(s, "\tRCS[%d]:\n", rcs_idx);
	seq_printf(s, "\t\t     channel type: %d\n", rcs->channel_type);
	seq_printf(s, "\t\t   enumeration id: %d\n", rcs->rcs_enumeration_id);
	seq_printf(s, "\t\t    channel count: %d\n", rcs->channel_count);
	seq_printf(s, "\t\t            flags: 0x%lx\n",
		   (unsigned long)rcs->flags);
	seq_printf(s, "\t\tRMID block offset: 0x%x\n", rcs->rmid_block_offset);
	seq_printf(s, "\t\tCLOS block offset: 0x%x\n", rcs->clos_block_offset);
	seq_printf(s, "\t\t    RCS block BDF: 0x%x\n", rcs->rcs_block_bdf);
	seq_printf(s, "\t\tRCS block bar num: %d\n", rcs->rcs_block_bar_number);
	seq_printf(s, "\t\t   RCS block MMIO:0x%llx\n",
		   rcs->rcs_block_mmio_location);

	seq_printf(s, "\t\t      CLOSID base: 0x%p\n", rcs->closid_base);
	for (vc_channel = 0; vc_channel < rcs->channel_count; vc_channel++) {
		p = (void *)(rcs->closid_base + vc_channel * rcs->regw);
		if (rcs->regw == 2) {
			seq_printf(s, "\t\t0x%p: closid[%d]=0x%x\n", p,
				   vc_channel, *(u16 *)p);
		} else {
			seq_printf(s, "\t\t0x%p: closid[%d]=0x%x\n", p,
				   vc_channel, *(u32 *)p);
		}
	}

	seq_printf(s, "\t\t        RMID base: 0x%p\n", rcs->rmid_base);
	for (vc_channel = 0; vc_channel < rcs->channel_count; vc_channel++) {
		p = (void *)(rcs->rmid_base + vc_channel * rcs->regw);
		if (rcs->regw == 2) {
			seq_printf(s, "\t\t0x%p: rmid[%d]=0x%x\n", p,
				   vc_channel, *(u16 *)p);
		} else {
			seq_printf(s, "\t\t0x%p: rmid[%d]=0x%x\n", p,
				   vc_channel, *(u32 *)p);
		}
	}
}

void iordt_misc_show(struct seq_file *s)
{
	int rmud_idx, dss_idx, rcs_idx;
	struct iordt_rmud *rmud;
	struct iordt_chms *chms;
	struct iordt_dss *dss;
	struct iordt_rcs *rcs;

	for_each_iordt_rmud(rmud, rmud_idx, iordt_rmud) {
		iordt_rmud_show(s, rmud, rmud_idx);

		for_each_iordt_dss(dss, dss_idx, rmud) {
			iordt_dss_show(s, dss, dss_idx);
			for_each_iordt_chms(chms, dss)
				iordt_channel_show(s, chms, rmud, rmud_idx);
		}

		for_each_iordt_rcs(rcs, rcs_idx, rmud)
			iordt_rcs_show(s, rcs, rcs_idx);
	}
}
#endif

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
		ret = dss_rcs_enumerate(&init_rmud[rmud_num], acpi_rmud,
					rmud_num);
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

	ret = iordt_channel_setup();
	if (ret) {
		iordt_rmud_free(iordt_rmud, rmud_num);

		return ret;
	}

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

bool iordt_feature_enabled(u64 flag)
{
	return io_enabled & flag;
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
