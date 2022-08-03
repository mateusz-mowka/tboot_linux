// SPDX-License-Identifier: GPL-2.0-only
/*
 * isst_tpmi.c: SST TPMI interface core
 *
 * Copyright (c) 2022, Intel Corporation.
 * All Rights Reserved.
 *
 * This information will be useful to understand flows:
 * In the current generation of platforms, TPMI is supported via OOB
 * PCI device. This PCI device has one instance per CPU package.
 * There is a unique TPMI ID for SST. Each TPMI ID also has multiple
 * entries, representing per power domain information.
 * There is one dev file for complete SST information and control same as the
 * prior generation of hardware. User space need not be aware of the SST
 * information and control is presented by the hardware. User space just need
 * to be aware of which CPU package they want to control and for which CPU.
 * User space has full information to map CPU to power domain and package.
 */
#define DEBUG
#include <linux/auxiliary_bus.h>
#include <linux/delay.h>
#include <linux/intel_tpmi.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pm_runtime.h>
#include <uapi/linux/isst_if.h>

#include "isst_tpmi_core.h"
#include "isst_if_common.h"
#include "../tpmi_power_domains.h"

/* Supported SST hardware version by this driver */
#define ISST_HEADER_VERSION		1

/**
 * struct sst_header -	SST main header
 * @interface_version:	Version number for this interface
 * @cap_mask:		Bitmask of the supported sub features. 1=the sub feature is enabled.
 *			0=disabled.
 *			Bit[8]= SST_CP enable (1), disable (0)
 *			bit[9]= SST_PP enable (1), disable (0)
 *			other bits are reserved for future use
 * @cp_offset:		Qword (8 bytes) offset to the SST_CP register bank
 * @pp_offset:		Qword (8 bytes) offset to the SST_PP register bank
 *
 * This register allows SW to discover SST capability and the offsets to SST-CP
 * and SST-PP register banks.
 */
struct sst_header {
	u8 interface_version;
	u8 cap_mask;
	u8 cp_offset;
	u8 pp_offset;
};

/**
 * struct cp_header -	SST-CP (core-power) header
 * @feature_id:		0=SST-CP, 1=SST-PP, 2=SST-BF, 3=SST-TF
 * @feature_rev:	Interface Version number for this SST feature
 * @ratio_unit:		Frequency ratio unit. 00: 100MHz. All others are reserved
 * @resd:		Reserved for future use
 *
 * This structure is used store SST-CP header. This is packed to the same
 * format as defined in the specifications.
 */
struct cp_header {
	u64 feature_id :4;
	u64 feature_rev :8;
	u64 ratio_unit :2;
	u64 resd :50;
};

/**
 * struct pp_header -	SST-PP (Perf profile) header
 * @feature_id:		0=SST-CP, 1=SST-PP, 2=SST-BF, 3=SST-TF
 * @feature_rev:	Interface Version number for this SST feature
 * @level_en_mask:	SST-PP level enable/disable fuse mask
 * @allowed_level_mask:	Allowed level mask used for dynamic config level switching
 * @resd0:		Reserved for future use
 * @ratio_unit:		Frequency ratio unit. 00: 100MHz. All others are reserved
 * @block_size:		Size of PP block in Qword unit (8 bytes)
 * @dynamic_switch:	If set (1), dynamic switching of SST PP is supported
 * @resd1:		Reserved for future use
 *
 * This structure is used store SST-PP header. This is packed to the same
 * format as defined in the specifications.
 */
struct pp_header {
	u64 feature_id :4;
	u64 feature_rev :8;
	u64 level_en_mask :8;
	u64 allowed_level_mask :8;
	u64 resd0 :4;
	u64 ratio_unit :2;
	u64 block_size :8;
	u64 dynamic_switch :1;
	u64 resd1 :21;
};

/**
 * struct feature_offset -	Offsets to SST-PP features
 * @pp_offset:		Qword offset within PP level for the SST_PP register bank
 * @bf_offset:		Qword offset within PP level for the SST_BF register bank
 * @tf_offset:		Qword offset within PP level for the SST_TF register bank
 * @resd:		Reserved for future use
 *
 * This structure is used store offsets for SST features in the register bank.
 * This is packed to the same format as defined in the specifications.
 */
struct feature_offset {
	u64 pp_offset :8;
	u64 bf_offset :8;
	u64 tf_offset :8;
	u64 resd :40;
};

/**
 * struct levels_offset -	Offsets to each SST PP level
 * @sst_pp_level0_offset:	Qword offset to the register block of PP level 0
 * @sst_pp_level1_offset:	Qword offset to the register block of PP level 1
 * @sst_pp_level2_offset:	Qword offset to the register block of PP level 2
 * @sst_pp_level3_offset:	Qword offset to the register block of PP level 3
 * @sst_pp_level4_offset:	Qword offset to the register block of PP level 4
 * @resd:			Reserved for future use
 *
 * This structure is used store offsets of SST PP levels in the register bank.
 * This is packed to the same format as defined in the specifications.
 */
struct levels_offset {
	u64 sst_pp_level0_offset :8;
	u64 sst_pp_level1_offset :8;
	u64 sst_pp_level2_offset :8;
	u64 sst_pp_level3_offset :8;
	u64 sst_pp_level4_offset :8;
	u64 resd :24;
};

/**
 * struct pp_control_offset -	Offsets for SST PP controls
 * @perf_level:		A SST-PP level that SW intends to switch to
 * @perf_level_lock:	SST-PP level select lock. 0 - unlocked. 1 - locked till next reset
 * @resvd0:		Reserved for future use
 * @current_state:	Bit mask to control the enable(1)/disable(0) state of each feature
 *			of the current PP level, bit 0 = BF, bit 1 = TF, bit 2-7 = reserved
 * @resd:		Reserved for future use
 *
 * This structure is used store offsets of SST PP controls in the register bank.
 * This is packed to the same format as defined in the specifications.
 */
struct pp_control_offset {
	u64 perf_level :3;
	u64 perf_level_lock :1;
	u64 resvd0 :4;
	u64 current_state :8;
	u64 resd :48;
};

/**
 * struct pp_status_offset -	Offsets for SST PP status fields
 * @sst_pp_level:	Returns the current SST-PP level
 * @sst_pp_lock:	Returns the lock bit setting of perf_level_lock in pp_control_offset
 * @error_type:		Returns last error of SST-PP level change request. 0: no error,
 *			1: level change not allowed, others: reserved
 * @feature_state:	Bit mask to indicate the enable(1)/disable(0) state of each feature of the
 *			current PP level. bit 0 = BF, bit 1 = TF, bit 2-7 reserved
 * @resd0:		Reserved for future use
 * @feature_error_type: Returns last error of the specific feature. Three error_type bits per
 *			feature. i.e. ERROR_TYPE[2:0] for BF, ERROR_TYPE[5:3] for TF, etc.
 *			0x0: no error, 0x1: The specific feature is not supported by the hardware.
 *			0x2-0x6: Reserved. 0x7: feature state change is not allowed.
 * @resd1:		Reserved for future use
 *
 * This structure is used store offsets of SST PP status in the register bank.
 * This is packed to the same format as defined in the specifications.
 */
struct pp_status_offset {
	u64 sst_pp_level :3;
	u64 sst_pp_lock :1;
	u64 error_type :4;
	u64 feature_state :8;
	u64 resd0 :16;
	u64 feature_error_type : 24;
	u64 resd1 :8;
};

/**
 * struct perf_level -	Used to store perf level and mmio offset
 * @mmio_offset:	mmio offset for a perf level
 * @level:		perf level for this offset
 *
 * This structure is used store final mmio offset of each perf level from the
 * SST base mmio offset.
 */
struct perf_level {
	int mmio_offset;
	int level;
};

/**
 * struct tpmi_per_power_domain_info -	Store per power_domain SST info
 * @package_id:		Package id for this power_domain
 * @power_domain_id:	Power domain id, Each entry from the SST-TPMI instance is a power_domain.
 * @max_level:		Max possible PP level possible for this power_domain
 * @ratio_unit:		Ratio unit for converting to MHz
 * @avx_levels:		Number of AVX levels
 * @pp_block_size:	Block size from PP header
 * @sst_header:		Store SST header for this power_domain
 * @cp_header:		Store SST-CP header for this power_domain
 * @pp_header:		Store SST-PP header for this power_domain
 * @perf_levels:	Pointer to each perf level to map level to mmio offset
 * @feature_offsets:	Store feature offsets for each PP-level
 * @control_offset:	Store the control offset for each PP-level
 * @status_offset:	Store the status offset for each PP-level
 * @sst_base:		Mapped SST base IO memory
 * @auxdev:		Auxiliary device instance enumerated this instance
 * @saved_sst_cp_control: Save SST-CP control configuration to store restore for suspend/resume
 * @saved_clos_configs:	Save SST-CP CLOS configuration to store restore for suspend/resume
 * @saved_clos_assocs:	Save SST-CP CLOS association to store restore for suspend/resume
 * @saved_pp_control:	Save SST-PP control information to store restore for suspend/resume
 *
 * This structure is used store complete SST information for a power_domain. This information
 * is used to read/write request for any SST IOCTL. Each physical CPU package can have multiple
 * power_domains. Each power domain describes its own SST information and has its own controls.
 */
struct tpmi_per_power_domain_info {
	int package_id;
	int power_domain_id;
	int max_level;
	int ratio_unit;
	int avx_levels;
	int pp_block_size;
	struct sst_header sst_header;
	struct cp_header cp_header;
	struct pp_header pp_header;
	struct perf_level *perf_levels;
	struct feature_offset feature_offsets;
	struct pp_control_offset control_offset;
	struct pp_status_offset status_offset;
	void __iomem *sst_base;
	struct auxiliary_device *auxdev;
	u64 saved_sst_cp_control;
	u64 saved_clos_configs[4];
	u64 saved_clos_assocs[4];
	u64 saved_pp_control;
};

/**
 * struct tpmi_sst_struct -	Store sst info for a package
 * @package_id:			Package id for this aux device instance
 * @number_of_power_domains:	Number of power_domains pointed by power_domain_info pointer
 * @power_domain_info:		Pointer to power domains information
 *
 * This structure is used store full SST information for a package.
 * Each package has a unique OOB PCI device, which enumerates TPMI.
 * Each Package will have multiple power_domains.
 */
struct tpmi_sst_struct {
	int package_id;
	int number_of_power_domains;
	struct tpmi_per_power_domain_info *power_domain_info;
};

/* Max instances. This will be supported max packages */
#define	SST_MAX_INSTANCES	16

#define SST_MUL_FACTOR_NONE	1

/* Since there is no other value other than 100MHz, just use define */
#define SST_MUL_FACTOR_FREQ	100

/* All SST regs are 64 bit size */
#define SST_REG_SIZE	8

/**
 * struct tpmi_sst_common_struct -	Store all SST instances
 * @max_index:		Maximum instances currently present
 * @sst_inst:		Pointer to per package instance
 *
 * Stores every SST Package instance.
 */
struct tpmi_sst_common_struct {
	int max_index;
	struct tpmi_sst_struct *sst_inst[SST_MAX_INSTANCES];
};

/*
 * Each IOCTL request is processed under this lock. Also used to protect
 * registration functions and common data structures.
 */
static DEFINE_MUTEX(isst_tpmi_dev_lock);

/* Usage count to track, number of TPMI SST instances registered to this core. */
static int isst_core_usage_count;

/* Stores complete SST information for every package and power_domain */
static struct tpmi_sst_common_struct isst_common;

#define SST_MAX_AVX_LEVELS	3

#define SST_PP_OFFSET_0		8
#define SST_PP_OFFSET_1		16
#define SST_PP_OFFSET_SIZE	8

static int sst_add_perf_profiles(struct auxiliary_device *auxdev,
				 struct tpmi_per_power_domain_info *pd_info,
				 int levels)
{
	u64 perf_level_offsets;
	int i;

	pd_info->perf_levels = devm_kcalloc(&auxdev->dev, levels,
					    sizeof(struct perf_level),
					    GFP_KERNEL);
	if (!pd_info->perf_levels)
		return 0;

	pd_info->ratio_unit = pd_info->pp_header.ratio_unit;
	pd_info->avx_levels = SST_MAX_AVX_LEVELS;
	pd_info->pp_block_size = pd_info->pp_header.block_size;

	/* Read PP Offset 0: Get feature offset with PP level */
	*((u64 *)&pd_info->feature_offsets) = readq(pd_info->sst_base +
						    pd_info->sst_header.pp_offset +
						    SST_PP_OFFSET_0);
	dev_dbg(&auxdev->dev, "perf-level pp_offset:%x bf_offset:%x tf_offset:%x\n",
		pd_info->feature_offsets.pp_offset,
		pd_info->feature_offsets.bf_offset, pd_info->feature_offsets.tf_offset);

	perf_level_offsets = readq(pd_info->sst_base + pd_info->sst_header.pp_offset +
				   SST_PP_OFFSET_1);
	dev_dbg(&auxdev->dev, "perf-level-offsets :%llx\n", perf_level_offsets);

	for (i = 0; i < levels; ++i) {
		u64 offset;

		offset = perf_level_offsets & (0xffULL << (i * SST_PP_OFFSET_SIZE));
		offset >>= (i * 8);
		offset &= 0xff;
		offset *= 8; /* Convert to byte from QWORD offset */
		pd_info->perf_levels[i].mmio_offset = pd_info->sst_header.pp_offset + offset;
		dev_dbg(&auxdev->dev, "perf-level:%x offset:%llx\n", i, offset);
	}

	return 0;
}

static int sst_main(struct auxiliary_device *auxdev, struct tpmi_per_power_domain_info *pd_info)
{
	int i, mask, levels;

	*((u64 *)&pd_info->sst_header) = readq(pd_info->sst_base);
	pd_info->sst_header.cp_offset *= 8;
	pd_info->sst_header.pp_offset *= 8;
	dev_dbg(&auxdev->dev,
		"SST header: interface_ver:0x%x cap_mask:0x%x cp_off:0x%x pp_off:0x%x\n",
		pd_info->sst_header.interface_version,
		pd_info->sst_header.cap_mask,
		pd_info->sst_header.cp_offset,
		pd_info->sst_header.pp_offset);

	if (pd_info->sst_header.interface_version != ISST_HEADER_VERSION) {
		dev_err(&auxdev->dev, "SST: Unsupported version:%x\n",
		pd_info->sst_header.interface_version);
		return -ENODEV;
	}

	/* Read SST CP Header */
	*((u64 *)&pd_info->cp_header) = readq(pd_info->sst_base + pd_info->sst_header.cp_offset);
	dev_dbg(&auxdev->dev, "CP header: feature_id:0x%x rev:0x%x ratio_unit:0x%x\n",
		pd_info->cp_header.feature_id,
		pd_info->cp_header.feature_rev,
		pd_info->cp_header.ratio_unit
		);

	/* Read PP header */
	*((u64 *)&pd_info->pp_header) = readq(pd_info->sst_base + pd_info->sst_header.pp_offset);
	dev_dbg(&auxdev->dev,
		"PP hdr:id:0x%x rev:0x%x en_mask:0x%x lev_mask:0x%x dyn:0x%x unit:0x%x blk_sz:0x%x\n",
		pd_info->pp_header.feature_id,
		pd_info->pp_header.feature_rev,
		pd_info->pp_header.level_en_mask,
		pd_info->pp_header.allowed_level_mask,
		pd_info->pp_header.dynamic_switch,
		pd_info->pp_header.ratio_unit,
		pd_info->pp_header.block_size
		);

	/* Force level_en_mask level 0 */
	pd_info->pp_header.level_en_mask |= 0x01;

	mask = 0x01;
	levels = 0;
	for (i = 0; i < 8; ++i) {
		if (pd_info->pp_header.level_en_mask & mask)
			levels = i;
		mask <<= 1;
	}
	pd_info->max_level = levels;
	dev_dbg(&auxdev->dev, "max perf level %x\n", levels);
	sst_add_perf_profiles(auxdev, pd_info, levels + 1);

	return 0;
}

/*
 * Map a package and power_domain id to SST information structure unique for a power_domain.
 * The caller should call under isst_tpmi_dev_lock.
 */
static struct tpmi_per_power_domain_info *get_instance(int pkg_id, int power_domain_id)
{
	struct tpmi_per_power_domain_info *power_domain_info;
	struct tpmi_sst_struct *sst_inst;

	pr_debug("%s pkg:%d power_domain:%d\n", __func__, pkg_id, power_domain_id);

	if (pkg_id < 0 || power_domain_id < 0 || pkg_id > isst_common.max_index ||
	    pkg_id >= SST_MAX_INSTANCES)
		return NULL;

	sst_inst = isst_common.sst_inst[pkg_id];
	if (!sst_inst)
		return NULL;

	if (power_domain_id >= sst_inst->number_of_power_domains)
		return NULL;

	power_domain_info = &sst_inst->power_domain_info[power_domain_id];

	if (power_domain_info && !power_domain_info->sst_base)
		return NULL;

	return power_domain_info;
}

static inline int tpmi_start_mmio_rd_wr(struct tpmi_per_power_domain_info *pd_info)
{
	return pm_runtime_resume_and_get(&pd_info->auxdev->dev);
}

static inline void tpmi_end_mmio_rd_wr(struct tpmi_per_power_domain_info *pd_info)
{
	pm_runtime_mark_last_busy(&pd_info->auxdev->dev);
	pm_runtime_put_autosuspend(&pd_info->auxdev->dev);
}

#define _read_cp_info(name_str, name, offset, start, width, mult_factor)\
{\
	u64 val, mask;\
	\
	val = readq(power_domain_info->sst_base + power_domain_info->sst_header.cp_offset +\
			(offset));\
	mask = GENMASK_ULL((start + width - 1), start);\
	val &= mask; \
	val >>= start;\
	name = (val * mult_factor);\
	pr_debug("cp_info %s var:%s cp_offset:%x offset:%x start:%x mask:%llx mul_factor:%x res:%x\n",\
		 __func__, name_str, power_domain_info->sst_header.cp_offset, offset, start, mask, mult_factor, name);\
}

#define _write_cp_info(name_str, name, offset, start, width, div_factor)\
{\
	u64 val, mask;\
	\
	val = readq(power_domain_info->sst_base +\
		    power_domain_info->sst_header.cp_offset + (offset));\
	mask = GENMASK_ULL((start + width - 1), start);\
	val &= ~mask;\
	val |= (name / div_factor) << start;\
	writeq(val, power_domain_info->sst_base + power_domain_info->sst_header.cp_offset +\
		(offset));\
	pr_debug("wr_cp_info %s var:%s wr:%x cp_offset:%x offset:%x start:%x mask:%llx div_factor:%x res:%llx\n",\
		 __func__, name_str, name, power_domain_info->sst_header.cp_offset, offset, start, mask, div_factor, val);\
}

#define	SST_CP_CONTROL_OFFSET	8
#define	SST_CP_STATUS_OFFSET	16

#define SST_CP_ENABLE_START		0
#define SST_CP_ENABLE_WIDTH		1

#define SST_CP_PRIORITY_TYPE_START	1
#define SST_CP_PRIORITY_TYPE_WIDTH	1

static long isst_if_core_power_state(void __user *argp)
{
	struct tpmi_per_power_domain_info *power_domain_info;
	struct isst_core_power core_power;
	int ret;

	if (copy_from_user(&core_power, argp, sizeof(core_power)))
		return -EFAULT;

	power_domain_info = get_instance(core_power.socket_id, core_power.power_domain_id);
	if (!power_domain_info)
		return -EINVAL;

	ret = tpmi_start_mmio_rd_wr(power_domain_info);
	if (ret)
		return ret;

	ret = 0;
	if (core_power.get_set) {
		_write_cp_info("cp_enable", core_power.enable, SST_CP_CONTROL_OFFSET,
			       SST_CP_ENABLE_START, SST_CP_ENABLE_WIDTH, SST_MUL_FACTOR_NONE)
		_write_cp_info("cp_prio_type", core_power.priority_type, SST_CP_CONTROL_OFFSET,
			       SST_CP_PRIORITY_TYPE_START, SST_CP_PRIORITY_TYPE_WIDTH,
			       SST_MUL_FACTOR_NONE)
	} else {
		/* get */
		_read_cp_info("cp_enable", core_power.enable, SST_CP_STATUS_OFFSET,
			      SST_CP_ENABLE_START, SST_CP_ENABLE_WIDTH, SST_MUL_FACTOR_NONE)
		_read_cp_info("cp_prio_type", core_power.priority_type, SST_CP_STATUS_OFFSET,
			      SST_CP_PRIORITY_TYPE_START, SST_CP_PRIORITY_TYPE_WIDTH,
			      SST_MUL_FACTOR_NONE)
		core_power.supported = !!(power_domain_info->sst_header.cap_mask & BIT(0));
		if (copy_to_user(argp, &core_power, sizeof(core_power)))
			ret = -EFAULT;
	}

	tpmi_end_mmio_rd_wr(power_domain_info);

	return ret;
}

#define SST_CLOS_CONFIG_0_OFFSET	24

#define SST_CLOS_CONFIG_PRIO_START	4
#define SST_CLOS_CONFIG_PRIO_WIDTH	4

#define SST_CLOS_CONFIG_MIN_START	8
#define SST_CLOS_CONFIG_MIN_WIDTH	8

#define SST_CLOS_CONFIG_MAX_START	16
#define SST_CLOS_CONFIG_MAX_WIDTH	8

static long isst_if_clos_param(void __user *argp)
{
	struct tpmi_per_power_domain_info *power_domain_info;
	struct isst_clos_param clos_param;
	int ret;

	if (copy_from_user(&clos_param, argp, sizeof(clos_param)))
		return -EFAULT;

	power_domain_info = get_instance(clos_param.socket_id, clos_param.power_domain_id);
	if (!power_domain_info)
		return -EINVAL;

	ret = tpmi_start_mmio_rd_wr(power_domain_info);
	if (ret < 0)
		return ret;

	ret = 0;
	if (clos_param.get_set) {
		_write_cp_info("clos.min_freq", clos_param.min_freq_mhz,
			       (SST_CLOS_CONFIG_0_OFFSET + clos_param.clos * SST_REG_SIZE),
			       SST_CLOS_CONFIG_MIN_START, SST_CLOS_CONFIG_MIN_WIDTH,
			       SST_MUL_FACTOR_FREQ);
		_write_cp_info("clos.max_freq", clos_param.max_freq_mhz,
			       (SST_CLOS_CONFIG_0_OFFSET + clos_param.clos * SST_REG_SIZE),
			       SST_CLOS_CONFIG_MAX_START, SST_CLOS_CONFIG_MAX_WIDTH,
			       SST_MUL_FACTOR_FREQ);
		_write_cp_info("clos.prio", clos_param.prop_prio,
			       (SST_CLOS_CONFIG_0_OFFSET + clos_param.clos * SST_REG_SIZE),
			       SST_CLOS_CONFIG_PRIO_START, SST_CLOS_CONFIG_PRIO_WIDTH,
			       SST_MUL_FACTOR_NONE);
	} else {
		/* get */
		_read_cp_info("clos.min_freq", clos_param.min_freq_mhz,
				(SST_CLOS_CONFIG_0_OFFSET + clos_param.clos * SST_REG_SIZE),
				SST_CLOS_CONFIG_MIN_START, SST_CLOS_CONFIG_MIN_WIDTH,
				SST_MUL_FACTOR_FREQ)
		_read_cp_info("clos.max_freq", clos_param.max_freq_mhz,
				(SST_CLOS_CONFIG_0_OFFSET + clos_param.clos * SST_REG_SIZE),
				SST_CLOS_CONFIG_MAX_START, SST_CLOS_CONFIG_MAX_WIDTH,
				SST_MUL_FACTOR_FREQ)
		_read_cp_info("clos.prio", clos_param.prop_prio,
				(SST_CLOS_CONFIG_0_OFFSET + clos_param.clos * SST_REG_SIZE),
				SST_CLOS_CONFIG_PRIO_START, SST_CLOS_CONFIG_PRIO_WIDTH,
				SST_MUL_FACTOR_NONE)

		if (copy_to_user(argp, &clos_param, sizeof(clos_param)))
			ret = -EFAULT;
	}

	tpmi_end_mmio_rd_wr(power_domain_info);

	return ret;
}

#define SST_CLOS_ASSOC_0_OFFSET		56
#define SST_CLOS_ASSOC_CPUS_PER_REG	16
#define SST_CLOS_ASSOC_BITS_PER_CPU	4

static long isst_if_clos_assoc(void __user *argp)
{
	struct isst_if_clos_assoc_cmds assoc_cmds;
	unsigned char __user *ptr;
	int i;

	/* Each multi command has u16 command count as the first field */
	if (copy_from_user(&assoc_cmds, argp, sizeof(assoc_cmds)))
		return -EFAULT;

	if (!assoc_cmds.cmd_count)
		return -EINVAL;

	ptr = argp + offsetof(struct isst_if_clos_assoc_cmds, assoc_info);
	for (i = 0; i < assoc_cmds.cmd_count; ++i) {
		struct tpmi_per_power_domain_info *power_domain_info;
		struct isst_if_clos_assoc clos_assoc;
		int punit_id, punit_cpu_no, pkg_id;
		struct tpmi_sst_struct *sst_inst;
		int offset, shift, cpu;
		u64 val, mask, clos;
		int ret;

		if (copy_from_user(&clos_assoc, ptr, sizeof(clos_assoc)))
			return -EFAULT;

		cpu = clos_assoc.logical_cpu;
		clos = clos_assoc.clos;

		if (assoc_cmds.punit_cpu_map)
			punit_cpu_no = cpu;
		else
			punit_cpu_no = tpmi_get_punit_core_number(cpu);

		punit_id = clos_assoc.power_domain_id;
		pkg_id = clos_assoc.socket_id;

		sst_inst = isst_common.sst_inst[pkg_id];

		power_domain_info = &sst_inst->power_domain_info[punit_id];

		ret = tpmi_start_mmio_rd_wr(power_domain_info);
		if (ret < 0)
			return ret;

		offset = SST_CLOS_ASSOC_0_OFFSET +
				(punit_cpu_no / SST_CLOS_ASSOC_CPUS_PER_REG) * SST_REG_SIZE;
		shift = punit_cpu_no % SST_CLOS_ASSOC_CPUS_PER_REG;
		shift *= SST_CLOS_ASSOC_BITS_PER_CPU;

		val = readq(power_domain_info->sst_base +
				power_domain_info->sst_header.cp_offset + offset);
		if (assoc_cmds.get_set) {
			mask = GENMASK_ULL((shift + SST_CLOS_ASSOC_BITS_PER_CPU - 1), shift);
			val &= ~mask;
			val |= (clos << shift);
			intel_tpmi_writeq(power_domain_info->auxdev, val,
					  power_domain_info->sst_base +
					  power_domain_info->sst_header.cp_offset + offset);
		} else {
			val >>= shift;
			clos_assoc.clos = val & GENMASK(SST_CLOS_ASSOC_BITS_PER_CPU - 1, 0);
			if (copy_to_user(ptr, &clos_assoc, sizeof(clos_assoc))) {
				tpmi_end_mmio_rd_wr(power_domain_info);
				return -EFAULT;
			}
		}

		ptr += sizeof(clos_assoc);
		tpmi_end_mmio_rd_wr(power_domain_info);
	}

	return 0;
}

#define _read_pp_info(name_str, name, offset, start, width, mult_factor)\
{\
	u64 val, _mask;\
	\
	val = readq(power_domain_info->sst_base + power_domain_info->sst_header.pp_offset +\
		    (offset));\
	_mask = GENMASK_ULL((start + width - 1), start);\
	val &= _mask;\
	val >>= start;\
	name = (val * mult_factor);\
	pr_debug("pp_info %s var:%s pp_offset:%x offset:%x shift:%x mask:%llx mul_factor:%x res:0x%x\n",\
		__func__, name_str, power_domain_info->sst_header.pp_offset, offset, start, _mask, mult_factor, (u32)name);\
}

#define _write_pp_info(name_str, name, offset, start, width, div_factor)\
{\
	u64 val, _mask;\
	\
	val = readq(power_domain_info->sst_base + power_domain_info->sst_header.pp_offset +\
		    (offset));\
	_mask = GENMASK((start + width - 1), start);\
	val &= ~_mask;\
	val |= (name / div_factor) << start;\
	writeq(val, power_domain_info->sst_base + power_domain_info->sst_header.pp_offset +\
	      (offset));\
	pr_debug("wr_pp_info %s var:%s wr:%x pp_offset:%x offset:%x start:%x mask:%llx div_factor:%x res:%llx\n",\
		__func__, name_str, name, power_domain_info->sst_header.pp_offset, offset, start, _mask, div_factor, val);\
}

#define _read_bf_level_info(name_str, name, level, offset, start, width, mult_factor)\
{\
	u64 val, _mask;\
	\
	val = readq(power_domain_info->sst_base +\
		    power_domain_info->perf_levels[level].mmio_offset +\
		(power_domain_info->feature_offsets.bf_offset * 8) + (offset));\
	_mask = GENMASK_ULL((start + width - 1), start);\
	val &= _mask; \
	val >>= start;\
	name = (val * mult_factor);\
	pr_debug("bf_info %s var:%s pp_level:%x level_offset:%x bf_offset:%x offset:%x start:%d mask:%llx mul_factor:%x res:%x\n",\
		 __func__, name_str, level, power_domain_info->perf_levels[level].mmio_offset, power_domain_info->feature_offsets.bf_offset * 8, offset, start, _mask, mult_factor, (u32)name);\
}

#define _read_tf_level_info(name_str, name, level, offset, start, width, mult_factor)\
{\
	u64 val, _mask;\
	\
	val = readq(power_domain_info->sst_base +\
		    power_domain_info->perf_levels[level].mmio_offset +\
		(power_domain_info->feature_offsets.tf_offset * 8) + (offset));\
	_mask = GENMASK_ULL((start + width - 1), start);\
	val &= _mask; \
	val >>= start;\
	name = (val * mult_factor);\
	pr_debug("tf_info %s var:%s pp_level:%x level_offset:%x tf_offset:%x offset:%x start:%d mask:%llx mul_factor:%x res:%x\n",\
		 __func__, name_str, level, power_domain_info->perf_levels[level].mmio_offset, power_domain_info->feature_offsets.tf_offset * 8, offset, start, _mask, mult_factor, (u32)name);\
}

#define SST_PP_STATUS_OFFSET	32

#define SST_PP_LEVEL_START	0
#define SST_PP_LEVEL_WIDTH	3

#define SST_PP_LOCK_START	3
#define SST_PP_LOCK_WIDTH	1

#define SST_PP_FEATURE_STATE_START	8
#define SST_PP_FEATURE_STATE_WIDTH	8

#define SST_BF_FEATURE_SUPPORTED_START	12
#define SST_BF_FEATURE_SUPPORTED_WIDTH	1

#define SST_TF_FEATURE_SUPPORTED_START	12
#define SST_TF_FEATURE_SUPPORTED_WIDTH	1

static int isst_if_get_perf_level(void __user *argp)
{
	struct isst_perf_level_info perf_level;
	struct tpmi_per_power_domain_info *power_domain_info;
	int ret;

	if (copy_from_user(&perf_level, argp, sizeof(perf_level)))
		return -EFAULT;

	power_domain_info = get_instance(perf_level.socket_id, perf_level.power_domain_id);
	if (!power_domain_info)
		return -EINVAL;

	ret = tpmi_start_mmio_rd_wr(power_domain_info);
	if (ret < 0)
		return ret;

	ret = 0;
	perf_level.max_level = power_domain_info->max_level;
	perf_level.level_mask = power_domain_info->pp_header.allowed_level_mask;
	perf_level.feature_rev = power_domain_info->pp_header.feature_rev;
	_read_pp_info("current_level", perf_level.current_level, SST_PP_STATUS_OFFSET,
		      SST_PP_LEVEL_START, SST_PP_LEVEL_WIDTH, SST_MUL_FACTOR_NONE)
	_read_pp_info("locked", perf_level.locked, SST_PP_STATUS_OFFSET,
		      SST_PP_LOCK_START, SST_PP_LEVEL_WIDTH, SST_MUL_FACTOR_NONE)
	_read_pp_info("feature_state", perf_level.feature_state, SST_PP_STATUS_OFFSET,
		      SST_PP_FEATURE_STATE_START, SST_PP_FEATURE_STATE_WIDTH, SST_MUL_FACTOR_NONE)
	perf_level.enabled = !!(power_domain_info->sst_header.cap_mask & BIT(1));

	_read_bf_level_info("bf_support", perf_level.sst_bf_support, 0, 0,
			    SST_BF_FEATURE_SUPPORTED_START, SST_BF_FEATURE_SUPPORTED_WIDTH,
			    SST_MUL_FACTOR_NONE);
	_read_tf_level_info("tf_support", perf_level.sst_tf_support, 0, 0,
			    SST_TF_FEATURE_SUPPORTED_START, SST_TF_FEATURE_SUPPORTED_WIDTH,
			    SST_MUL_FACTOR_NONE);

	if (copy_to_user(argp, &perf_level, sizeof(perf_level)))
		ret = -EFAULT;

	tpmi_end_mmio_rd_wr(power_domain_info);

	return ret;
}

#define SST_PP_CONTROL_OFFSET		24
#define SST_PP_LEVEL_CHANGE_TIME_MS	5
#define SST_PP_LEVEL_CHANGE_RETRY_COUNT	10

static int isst_if_set_perf_level(void __user *argp)
{
	struct isst_perf_level_control perf_level;
	struct tpmi_per_power_domain_info *power_domain_info;
	int ret, level, retry = 0;

	if (copy_from_user(&perf_level, argp, sizeof(perf_level)))
		return -EFAULT;

	power_domain_info = get_instance(perf_level.socket_id, perf_level.power_domain_id);
	if (!power_domain_info)
		return -EINVAL;

	if (!(power_domain_info->pp_header.allowed_level_mask & BIT(perf_level.level)))
		return -EINVAL;

	ret = tpmi_start_mmio_rd_wr(power_domain_info);
	if (ret < 0)
		return ret;

	_read_pp_info("current_level", level, SST_PP_STATUS_OFFSET,
		      SST_PP_LEVEL_START, SST_PP_LEVEL_WIDTH, SST_MUL_FACTOR_NONE)

	/* If the requested new level is same as the current level, reject */
	if (perf_level.level == level)
		return -EINVAL;

	_write_pp_info("perf_level", perf_level.level, SST_PP_CONTROL_OFFSET,
		       SST_PP_LEVEL_START, SST_PP_LEVEL_WIDTH, SST_MUL_FACTOR_NONE)

	do {
		/* Give time to FW to process */
		msleep(SST_PP_LEVEL_CHANGE_TIME_MS);

		_read_pp_info("current_level", level, SST_PP_STATUS_OFFSET,
			      SST_PP_LEVEL_START, SST_PP_LEVEL_WIDTH, SST_MUL_FACTOR_NONE)

		/* Check if the new level is active */
		if (perf_level.level == level)
			break;

	} while (retry++ < SST_PP_LEVEL_CHANGE_RETRY_COUNT);

	if (perf_level.level != level)
		return -EFAULT;

	/* Reset the feature state on level change */
	_write_pp_info("perf_feature", 0, SST_PP_CONTROL_OFFSET,
		       SST_PP_FEATURE_STATE_START, SST_PP_FEATURE_STATE_WIDTH,
		       SST_MUL_FACTOR_NONE)

	/* Give time to FW to process */
	msleep(SST_PP_LEVEL_CHANGE_TIME_MS);

	tpmi_end_mmio_rd_wr(power_domain_info);

	return 0;
}

static int isst_if_set_perf_feature(void __user *argp)
{
	struct isst_perf_feature_control perf_feature;
	struct tpmi_per_power_domain_info *power_domain_info;
	int ret;

	if (copy_from_user(&perf_feature, argp, sizeof(perf_feature)))
		return -EFAULT;

	power_domain_info = get_instance(perf_feature.socket_id, perf_feature.power_domain_id);
	if (!power_domain_info)
		return -EINVAL;

	ret = tpmi_start_mmio_rd_wr(power_domain_info);
	if (ret)
		return ret;

	_write_pp_info("perf_feature", perf_feature.feature, SST_PP_CONTROL_OFFSET,
		       SST_PP_FEATURE_STATE_START, SST_PP_FEATURE_STATE_WIDTH,
		       SST_MUL_FACTOR_NONE)

	tpmi_end_mmio_rd_wr(power_domain_info);

	return 0;
}

#define _read_pp_level_info(name_str, name, level, offset, start, width, mult_factor)\
{\
	u64 val, _mask;\
	\
	val = readq(power_domain_info->sst_base +\
		    power_domain_info->perf_levels[level].mmio_offset +\
		(power_domain_info->feature_offsets.pp_offset * 8) + (offset));\
	_mask = GENMASK_ULL((start + width - 1), start);\
	val &= _mask; \
	val >>= start;\
	name = (val * mult_factor);\
	pr_debug("pp_level_info %s var:%s pp_level:%x level_offset:%x offset:%x start:%x width:%x mask:%llx mul_factor:%x res:%x\n",\
		 __func__, name_str, level, power_domain_info->perf_levels[level].mmio_offset, offset, start, width, _mask, mult_factor, (u32)name);\
}

#define SST_PP_INFO_0_OFFSET	0
#define SST_PP_INFO_1_OFFSET	8
#define SST_PP_INFO_2_OFFSET	16
#define SST_PP_INFO_3_OFFSET	24

/* SST_PP_INFO_4_OFFSET to SST_PP_INFO_9_OFFSET are trl levels */
#define SST_PP_INFO_4_OFFSET	32

#define SST_PP_INFO_10_OFFSET	80
#define SST_PP_INFO_11_OFFSET	88

#define SST_PP_P1_SSE_START	0
#define SST_PP_P1_SSE_WIDTH	8

#define SST_PP_P1_AVX2_START	8
#define SST_PP_P1_AVX2_WIDTH	8

#define SST_PP_P1_AVX512_START	16
#define SST_PP_P1_AVX512_WIDTH	8

#define SST_PP_P1_AMX_START	24
#define SST_PP_P1_AMX_WIDTH	8

#define SST_PP_TDP_START	32
#define SST_PP_TDP_WIDTH	15

#define SST_PP_T_PROCHOT_START	47
#define SST_PP_T_PROCHOT_WIDTH	8

#define SST_PP_MAX_MEMORY_FREQ_START	55
#define SST_PP_MAX_MEMORY_FREQ_WIDTH	5

#define SST_PP_COOLING_TYPE_START	60
#define SST_PP_COOLING_TYPE_WIDTH	3

#define SST_PP_TRL_0_RATIO_0_START	0
#define SST_PP_TRL_0_RATIO_0_WIDTH	8

#define SST_PP_TRL_CORES_BUCKET_0_START	0
#define SST_PP_TRL_CORES_BUCKET_0_WIDTH	8

#define SST_PP_CORE_RATIO_P0_START	0
#define SST_PP_CORE_RATIO_P0_WIDTH	8

#define SST_PP_CORE_RATIO_P1_START	8
#define SST_PP_CORE_RATIO_P1_WIDTH	8

#define SST_PP_CORE_RATIO_PN_START	16
#define SST_PP_CORE_RATIO_PN_WIDTH	8

#define SST_PP_CORE_RATIO_PM_START	24
#define SST_PP_CORE_RATIO_PM_WIDTH	8

#define SST_PP_CORE_RATIO_P0_FABRIC_START	32
#define SST_PP_CORE_RATIO_P0_FABRIC_WIDTH	8

#define SST_PP_CORE_RATIO_P1_FABRIC_START	40
#define SST_PP_CORE_RATIO_P1_FABRIC_WIDTH	8

#define SST_PP_CORE_RATIO_PM_FABRIC_START	48
#define SST_PP_CORE_RATIO_PM_FABRIC_WIDTH	8

static int isst_if_get_perf_level_info(void __user *argp)
{
	struct isst_perf_level_data_info perf_level;
	struct tpmi_per_power_domain_info *power_domain_info;
	int i, j, ret;

	if (copy_from_user(&perf_level, argp, sizeof(perf_level)))
		return -EFAULT;

	power_domain_info = get_instance(perf_level.socket_id, perf_level.power_domain_id);
	if (!power_domain_info)
		return -EINVAL;

	if (perf_level.level > power_domain_info->max_level)
		return -EINVAL;

	if (!(power_domain_info->pp_header.level_en_mask & BIT(perf_level.level)))
		return -EINVAL;

	ret = tpmi_start_mmio_rd_wr(power_domain_info);
	if (ret)
		return ret;

	_read_pp_level_info("tdp_ratio", perf_level.tdp_ratio, perf_level.level,
			    SST_PP_INFO_0_OFFSET, SST_PP_P1_SSE_START, SST_PP_P1_SSE_WIDTH,
			    SST_MUL_FACTOR_NONE)
	_read_pp_level_info("base_freq_mhz", perf_level.base_freq_mhz, perf_level.level,
			    SST_PP_INFO_0_OFFSET, SST_PP_P1_SSE_START, SST_PP_P1_SSE_WIDTH,
			    SST_MUL_FACTOR_FREQ)
	_read_pp_level_info("base_freq_avx2_mhz", perf_level.base_freq_avx2_mhz, perf_level.level,
			    SST_PP_INFO_0_OFFSET, SST_PP_P1_AVX2_START, SST_PP_P1_AVX2_WIDTH,
			    SST_MUL_FACTOR_FREQ)
	_read_pp_level_info("base_freq_avx512_mhz", perf_level.base_freq_avx512_mhz,
			    perf_level.level, SST_PP_INFO_0_OFFSET, SST_PP_P1_AVX512_START,
			    SST_PP_P1_AVX512_WIDTH, SST_MUL_FACTOR_FREQ)
	_read_pp_level_info("base_freq_amx_mhz", perf_level.base_freq_amx_mhz, perf_level.level,
			    SST_PP_INFO_0_OFFSET, SST_PP_P1_AMX_START, SST_PP_P1_AMX_WIDTH,
			    SST_MUL_FACTOR_FREQ)

	_read_pp_level_info("thermal_design_power_w", perf_level.thermal_design_power_w,
			    perf_level.level, SST_PP_INFO_1_OFFSET, SST_PP_TDP_START,
			    SST_PP_TDP_WIDTH, SST_MUL_FACTOR_NONE)
	perf_level.thermal_design_power_w /= 8; /* units are in 1/8th watt */
	_read_pp_level_info("tjunction_max_c", perf_level.tjunction_max_c, perf_level.level,
			    SST_PP_INFO_1_OFFSET, SST_PP_T_PROCHOT_START, SST_PP_T_PROCHOT_WIDTH,
			    SST_MUL_FACTOR_NONE)
	_read_pp_level_info("max_memory_freq_mhz", perf_level.max_memory_freq_mhz,
			    perf_level.level, SST_PP_INFO_1_OFFSET, SST_PP_MAX_MEMORY_FREQ_START,
			    SST_PP_MAX_MEMORY_FREQ_WIDTH, SST_MUL_FACTOR_FREQ)
	_read_pp_level_info("cooling_type", perf_level.cooling_type, perf_level.level,
			    SST_PP_INFO_1_OFFSET, SST_PP_COOLING_TYPE_START,
			    SST_PP_COOLING_TYPE_WIDTH, SST_MUL_FACTOR_NONE)

	for (i = 0; i < TRL_MAX_LEVELS; ++i) {
		for (j = 0; j < TRL_MAX_BUCKETS; ++j)
			_read_pp_level_info("trl*_bucket*_freq_mhz",
					    perf_level.trl_freq_mhz[i][j], perf_level.level,
					    SST_PP_INFO_4_OFFSET + (i * SST_PP_TRL_0_RATIO_0_WIDTH),
					    j * SST_PP_TRL_0_RATIO_0_WIDTH,
					    SST_PP_TRL_0_RATIO_0_WIDTH,
					    SST_MUL_FACTOR_FREQ);
	}

	for (i = 0; i < TRL_MAX_BUCKETS; ++i)
		_read_pp_level_info("bucket*_core_count", perf_level.bucket_core_counts[i],
				    perf_level.level, SST_PP_INFO_10_OFFSET,
				    SST_PP_TRL_CORES_BUCKET_0_WIDTH * i,
				    SST_PP_TRL_CORES_BUCKET_0_WIDTH, SST_MUL_FACTOR_NONE)

	perf_level.max_buckets = TRL_MAX_BUCKETS;
	perf_level.max_trl_levels = TRL_MAX_LEVELS;

	_read_pp_level_info("p0_freq_mhz", perf_level.p0_freq_mhz, perf_level.level,
			    SST_PP_INFO_11_OFFSET, SST_PP_CORE_RATIO_P0_START,
			    SST_PP_CORE_RATIO_P0_WIDTH, SST_MUL_FACTOR_FREQ)
	_read_pp_level_info("p1_freq_mhz", perf_level.p1_freq_mhz, perf_level.level,
			    SST_PP_INFO_11_OFFSET, SST_PP_CORE_RATIO_P1_START,
			    SST_PP_CORE_RATIO_P1_WIDTH, SST_MUL_FACTOR_FREQ)
	_read_pp_level_info("pn_freq_mhz", perf_level.pn_freq_mhz, perf_level.level,
			    SST_PP_INFO_11_OFFSET, SST_PP_CORE_RATIO_PN_START,
			    SST_PP_CORE_RATIO_PN_WIDTH, SST_MUL_FACTOR_FREQ)
	_read_pp_level_info("pm_freq_mhz", perf_level.pm_freq_mhz, perf_level.level,
			    SST_PP_INFO_11_OFFSET, SST_PP_CORE_RATIO_PM_START,
			    SST_PP_CORE_RATIO_PM_WIDTH, SST_MUL_FACTOR_FREQ)
	_read_pp_level_info("p0_fabric_freq_mhz", perf_level.p0_fabric_freq_mhz,
			    perf_level.level, SST_PP_INFO_11_OFFSET,
			    SST_PP_CORE_RATIO_P0_FABRIC_START,
			    SST_PP_CORE_RATIO_P0_FABRIC_WIDTH, SST_MUL_FACTOR_FREQ)
	_read_pp_level_info("p1_fabric_freq_mhz", perf_level.p1_fabric_freq_mhz,
			    perf_level.level, SST_PP_INFO_11_OFFSET,
			    SST_PP_CORE_RATIO_P1_FABRIC_START,
			    SST_PP_CORE_RATIO_P1_FABRIC_WIDTH, SST_MUL_FACTOR_FREQ)
	_read_pp_level_info("pm_fabric_freq_mhz", perf_level.pm_fabric_freq_mhz,
			    perf_level.level, SST_PP_INFO_11_OFFSET,
			    SST_PP_CORE_RATIO_PM_FABRIC_START,
			    SST_PP_CORE_RATIO_PM_FABRIC_WIDTH, SST_MUL_FACTOR_FREQ)

	if (copy_to_user(argp, &perf_level, sizeof(perf_level)))
		ret = -EFAULT;
	else
		ret = 0;

	tpmi_end_mmio_rd_wr(power_domain_info);

	return ret;
}

static int isst_print_cpu_map(char *buf, int len, u64 mask, int pkg, int power_domain)
{
	cpumask_var_t cpumask;
	int i, n;

	if (!alloc_cpumask_var(&cpumask, GFP_KERNEL))
		return 0;

	for (i = 0; i < 64; ++i) {
		if (mask & BIT_ULL(i)) {
			int cpu;

			cpu = tpmi_get_linux_cpu_number(pkg, power_domain, i);
			if (cpu >= 0) {
				int sibling;

				cpumask_set_cpu(cpu, cpumask);
				for_each_cpu(sibling, topology_sibling_cpumask(cpu)) {
					cpumask_set_cpu(sibling, cpumask);
				}
			}
		}
	}

	n = cpumap_print_bitmask_to_buf(buf, cpumask, 0, len);

	free_cpumask_var(cpumask);

	return n;
}

#define SST_PP_FUSED_CORE_COUNT_START	0
#define SST_PP_FUSED_CORE_COUNT_WIDTH	8

#define SST_PP_RSLVD_CORE_COUNT_START	8
#define SST_PP_RSLVD_CORE_COUNT_WIDTH	8

#define SST_PP_RSLVD_CORE_MASK_START	0
#define SST_PP_RSLVD_CORE_MASK_WIDTH	64

static int isst_if_get_perf_level_mask(void __user *argp)
{
	static struct isst_perf_level_cpu_mask cpumask;
	struct tpmi_per_power_domain_info *power_domain_info;
	u64 mask;
	int ret;

	if (copy_from_user(&cpumask, argp, sizeof(cpumask)))
		return -EFAULT;

	power_domain_info = get_instance(cpumask.socket_id, cpumask.power_domain_id);
	if (!power_domain_info)
		return -EINVAL;

	ret = tpmi_start_mmio_rd_wr(power_domain_info);
	if (ret)
		return ret;

	_read_pp_level_info("mask", mask, cpumask.level, SST_PP_INFO_2_OFFSET,
			    SST_PP_RSLVD_CORE_MASK_START, SST_PP_RSLVD_CORE_MASK_WIDTH,
			    SST_MUL_FACTOR_NONE)

	cpumask.mask = mask;

	if (!cpumask.punit_cpu_map) {
		if (!cpumask.cpu_buffer_size)
			return -EINVAL;

		cpumask.cpu_buffer_size = isst_print_cpu_map(cpumask.cpu_buffer,
							     cpumask.cpu_buffer_size,
							     mask,
							     cpumask.socket_id,
							     cpumask.power_domain_id);
	}

	if (copy_to_user(argp, &cpumask, sizeof(cpumask)))
		ret = -EFAULT;
	else
		ret = 0;

	tpmi_end_mmio_rd_wr(power_domain_info);

	return ret;
}

#define SST_BF_INFO_0_OFFSET	0
#define SST_BF_INFO_1_OFFSET	8

#define SST_BF_P1_HIGH_START	13
#define SST_BF_P1_HIGH_WIDTH	8

#define SST_BF_P1_LOW_START	21
#define SST_BF_P1_LOW_WIDTH	8

#define SST_BF_T_PROHOT_START	38
#define SST_BF_T_PROHOT_WIDTH	8

#define SST_BF_TDP_START	46
#define SST_BF_TDP_WIDTH	15

static int isst_if_get_base_freq_info(void __user *argp)
{
	static struct isst_base_freq_info base_freq;
	struct tpmi_per_power_domain_info *power_domain_info;
	int ret;

	if (copy_from_user(&base_freq, argp, sizeof(base_freq)))
		return -EFAULT;

	power_domain_info = get_instance(base_freq.socket_id, base_freq.power_domain_id);
	if (!power_domain_info)
		return -EINVAL;

	ret = tpmi_start_mmio_rd_wr(power_domain_info);
	if (ret)
		return ret;

	_read_bf_level_info("p1_high", base_freq.high_base_freq_mhz, base_freq.level,
			    SST_BF_INFO_0_OFFSET, SST_BF_P1_HIGH_START, SST_BF_P1_HIGH_WIDTH,
			    SST_MUL_FACTOR_FREQ)
	_read_bf_level_info("p1_low", base_freq.low_base_freq_mhz, base_freq.level,
			    SST_BF_INFO_0_OFFSET, SST_BF_P1_LOW_START, SST_BF_P1_LOW_WIDTH,
			    SST_MUL_FACTOR_FREQ)
	_read_bf_level_info("BF-TJ", base_freq.tjunction_max_c, base_freq.level,
			    SST_BF_INFO_0_OFFSET, SST_BF_T_PROHOT_START, SST_BF_T_PROHOT_WIDTH,
			    SST_MUL_FACTOR_NONE)
	_read_bf_level_info("BF-tdp", base_freq.thermal_design_power_w, base_freq.level,
			    SST_BF_INFO_0_OFFSET, SST_BF_TDP_START, SST_BF_TDP_WIDTH,
			    SST_MUL_FACTOR_NONE)
	base_freq.thermal_design_power_w /= 8; /*unit = 1/8th watt*/

	if (copy_to_user(argp, &base_freq, sizeof(base_freq)))
		ret = -EFAULT;
	else
		ret = 0;

	tpmi_end_mmio_rd_wr(power_domain_info);

	return ret;
}

#define P1_HI_CORE_MASK_START	0
#define P1_HI_CORE_MASK_WIDTH	64

static int isst_if_get_base_freq_mask(void __user *argp)
{
	static struct isst_perf_level_cpu_mask cpumask;
	struct tpmi_per_power_domain_info *power_domain_info;
	u64 mask;
	int ret;

	if (copy_from_user(&cpumask, argp, sizeof(cpumask)))
		return -EFAULT;

	power_domain_info = get_instance(cpumask.socket_id, cpumask.power_domain_id);
	if (!power_domain_info)
		return -EINVAL;

	ret = tpmi_start_mmio_rd_wr(power_domain_info);
	if (ret)
		return ret;

	_read_bf_level_info("BF-cpumask", mask, cpumask.level, SST_BF_INFO_1_OFFSET,
			    P1_HI_CORE_MASK_START, P1_HI_CORE_MASK_WIDTH,
			    SST_MUL_FACTOR_NONE)

	cpumask.mask = mask;

	if (!cpumask.punit_cpu_map) {
		if (!cpumask.cpu_buffer_size)
			return -EINVAL;

		cpumask.cpu_buffer_size = isst_print_cpu_map(cpumask.cpu_buffer,
							     cpumask.cpu_buffer_size,
							     mask,
							     cpumask.socket_id,
							     cpumask.power_domain_id);
	}

	if (copy_to_user(argp, &cpumask, sizeof(cpumask)))
		ret = -EFAULT;
	else
		ret = 0;


	tpmi_end_mmio_rd_wr(power_domain_info);

	return ret;
}

static int isst_if_get_tpmi_instance_count(void __user *argp)
{
	struct isst_tpmi_instance_count tpmi_inst;
	struct tpmi_sst_struct *sst_inst;
	int i;

	if (copy_from_user(&tpmi_inst, argp, sizeof(tpmi_inst)))
		return -EFAULT;

	if (tpmi_inst.socket_id >= SST_MAX_INSTANCES)
		return -EINVAL;

	tpmi_inst.count = isst_common.sst_inst[tpmi_inst.socket_id]->number_of_power_domains;

	sst_inst = isst_common.sst_inst[tpmi_inst.socket_id];
	tpmi_inst.valid_mask = 0;
	for (i = 0; i < sst_inst->number_of_power_domains; ++i) {
		struct tpmi_per_power_domain_info *pd_info;

		pd_info = &sst_inst->power_domain_info[i];
		if (pd_info->sst_base)
			tpmi_inst.valid_mask |= BIT(i);
	}

	if (copy_to_user(argp, &tpmi_inst, sizeof(tpmi_inst)))
		return -EFAULT;

	return 0;
}

#define SST_TF_INFO_0_OFFSET	0
#define SST_TF_INFO_1_OFFSET	8
#define SST_TF_INFO_2_OFFSET	16

#define SST_TF_MAX_LP_CLIP_RATIOS	TRL_MAX_LEVELS

#define SST_TF_LP_CLIP_RATIO_0_START	16
#define SST_TF_LP_CLIP_RATIO_0_WIDTH	8

#define SST_TF_RATIO_0_START	0
#define SST_TF_RATIO_0_WIDTH	8

#define SST_TF_NUM_CORE_0_START 0
#define SST_TF_NUM_CORE_0_WIDTH 8

static int isst_if_get_turbo_freq_info(void __user *argp)
{
	static struct isst_turbo_freq_info turbo_freq;
	struct tpmi_per_power_domain_info *power_domain_info;
	int i, j, ret;

	if (copy_from_user(&turbo_freq, argp, sizeof(turbo_freq)))
		return -EFAULT;

	power_domain_info = get_instance(turbo_freq.socket_id, turbo_freq.power_domain_id);
	if (!power_domain_info)
		return -EINVAL;

	ret = tpmi_start_mmio_rd_wr(power_domain_info);
	if (ret)
		return ret;

	turbo_freq.max_buckets = TRL_MAX_BUCKETS;
	turbo_freq.max_trl_levels = TRL_MAX_LEVELS;
	turbo_freq.max_clip_freqs = SST_TF_MAX_LP_CLIP_RATIOS;

	for (i = 0; i < turbo_freq.max_clip_freqs; ++i)
		_read_tf_level_info("lp_clip*", turbo_freq.lp_clip_freq_mhz[i],
				    turbo_freq.level, SST_TF_INFO_0_OFFSET,
				    SST_TF_LP_CLIP_RATIO_0_START +
				    (i * SST_TF_LP_CLIP_RATIO_0_WIDTH),
				    SST_TF_LP_CLIP_RATIO_0_WIDTH, SST_MUL_FACTOR_FREQ)

	for (i = 0; i < TRL_MAX_LEVELS; ++i) {
		for (j = 0; j < TRL_MAX_BUCKETS; ++j)
			_read_tf_level_info("cydn*_bucket_*_trl",
					    turbo_freq.trl_freq_mhz[i][j], turbo_freq.level,
					    SST_TF_INFO_2_OFFSET + (i * SST_TF_RATIO_0_WIDTH),
					    j * SST_TF_RATIO_0_WIDTH, SST_TF_RATIO_0_WIDTH,
					    SST_MUL_FACTOR_FREQ)
	}

	for (i = 0; i < TRL_MAX_BUCKETS; ++i)
		_read_tf_level_info("bucket_*_core_count", turbo_freq.bucket_core_counts[i],
				    turbo_freq.level, SST_TF_INFO_1_OFFSET,
				    SST_TF_NUM_CORE_0_WIDTH * i, SST_TF_NUM_CORE_0_WIDTH,
				    SST_MUL_FACTOR_NONE)

	if (copy_to_user(argp, &turbo_freq, sizeof(turbo_freq)))
		ret = -EFAULT;
	else
		ret = 0;

	tpmi_end_mmio_rd_wr(power_domain_info);

	return ret;
}

static long isst_if_def_ioctl(struct file *file, unsigned int cmd,
			      unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	long ret = -ENOTTY;

	mutex_lock(&isst_tpmi_dev_lock);
	switch (cmd) {
	case ISST_IF_COUNT_TPMI_INSTANCES:
		ret = isst_if_get_tpmi_instance_count(argp);
		break;
	case ISST_IF_CORE_POWER_STATE:
		ret = isst_if_core_power_state(argp);
		break;
	case ISST_IF_CLOS_PARAM:
		ret = isst_if_clos_param(argp);
		break;
	case ISST_IF_CLOS_ASSOC:
		ret = isst_if_clos_assoc(argp);
		break;
	case ISST_IF_PERF_LEVELS:
		ret = isst_if_get_perf_level(argp);
		break;
	case ISST_IF_PERF_SET_LEVEL:
		ret = isst_if_set_perf_level(argp);
		break;
	case ISST_IF_PERF_SET_FEATURE:
		ret = isst_if_set_perf_feature(argp);
		break;
	case ISST_IF_GET_PERF_LEVEL_INFO:
		ret = isst_if_get_perf_level_info(argp);
		break;
	case ISST_IF_GET_PERF_LEVEL_CPU_MASK:
		ret = isst_if_get_perf_level_mask(argp);
		break;
	case ISST_IF_GET_BASE_FREQ_INFO:
		ret = isst_if_get_base_freq_info(argp);
		break;
	case ISST_IF_GET_BASE_FREQ_CPU_MASK:
		ret = isst_if_get_base_freq_mask(argp);
		break;
	case ISST_IF_GET_TURBO_FREQ_INFO:
		ret = isst_if_get_turbo_freq_info(argp);
		break;
	default:
		break;
	}
	mutex_unlock(&isst_tpmi_dev_lock);

	return ret;
}

static struct tpmi_per_power_domain_info *isst_if_mbox_power_domain_inst(int logical_cpu)
{
	int pkg_id, power_domain_id;

	pkg_id = topology_physical_package_id(logical_cpu);
	power_domain_id = tpmi_get_power_domain_id(logical_cpu);

	return get_instance(pkg_id, power_domain_id);
}

#define CONFIG_TDP_GET_LEVELS_INFO	0x7F00
#define CONFIG_TDP_GET_TDP_CONTROL	0x7F01
#define CONFIG_TDP_SET_TDP_CONTROL	0x7F02
#define CONFIG_TDP_GET_TDP_INFO		0x7F03
#define CONFIG_TDP_SET_LEVEL		0x7F08

#define CLOS_PM_QOS_CONFIG		0xD002

#define READ_PM_CONFIG			0x9403
#define WRITE_PM_CONFIG			0x9503

#define MBOX_TDP_LEVEL_ENABLE_BIT	31
#define MBOX_TDP_LEVEL_LOCK_BIT		24
#define MBOX_CURRENT_CONFIG_TDP_LEVEL_BIT	16
#define MBOX_CONFIG_TDP_LEVELS_BIT	8

#define MBOX_TF_SUPPORT_BIT		0
#define MBOX_BF_SUPPORT_BIT		1
#define MBOX_TF_ENABLE_BIT		16
#define MBOX_BF_ENABLE_BIT		17

#define MBOX_TF_ENABLE_BIT		16
#define MBOX_BF_ENABLE_BIT		17

#define MBOX_TDP_RATIO_START		16
#define MBOX_PKG_TDP_WIDTH		15

#define SST_CP_STATE_BIT		16
#define SST_CP_CAP_BIT			0

#define CLOS_ENABLE_BIT			0
#define CLOS_PRIO_BIT			1

static int isst_if_mbox_ctdp_get_levels_info(struct tpmi_per_power_domain_info *power_domain_info,
					     struct isst_if_mbox_cmd *mbox_cmd)
{
	u32 resp;

	mbox_cmd->resp_data = 0;

	mbox_cmd->resp_data = !!(power_domain_info->sst_header.cap_mask & BIT(1));
	mbox_cmd->resp_data <<= MBOX_TDP_LEVEL_LOCK_BIT;

	_read_pp_info("locked", resp, SST_PP_STATUS_OFFSET, SST_PP_LOCK_START,
		      SST_PP_LEVEL_WIDTH, SST_MUL_FACTOR_NONE)
	if (resp)
		mbox_cmd->resp_data |= BIT(MBOX_TDP_LEVEL_LOCK_BIT);

	_read_pp_info("current_level", resp, SST_PP_STATUS_OFFSET, SST_PP_LEVEL_START,
		      SST_PP_LEVEL_WIDTH, SST_MUL_FACTOR_NONE)
	mbox_cmd->resp_data |= ((resp & 0xff) << MBOX_CURRENT_CONFIG_TDP_LEVEL_BIT);
	mbox_cmd->resp_data |= ((power_domain_info->max_level & 0xff) <<
				MBOX_CONFIG_TDP_LEVELS_BIT);
	mbox_cmd->resp_data |= (power_domain_info->pp_header.feature_rev & 0xff);
	pr_debug("mbox_resp:%x\n", mbox_cmd->resp_data);

	return 0;
}

static int isst_if_mbox_ctdp_get_tdp_control(struct tpmi_per_power_domain_info *power_domain_info,
					     struct isst_if_mbox_cmd *mbox_cmd)
{
	u32 resp;

	mbox_cmd->resp_data = 0;

	_read_bf_level_info("bf_support", resp, 0, 0, SST_BF_FEATURE_SUPPORTED_START,
			    SST_BF_FEATURE_SUPPORTED_WIDTH, SST_MUL_FACTOR_NONE);
	if (resp)
		mbox_cmd->resp_data |= BIT(MBOX_BF_SUPPORT_BIT);

	_read_tf_level_info("tf_support", resp, 0, 0, SST_TF_FEATURE_SUPPORTED_START,
			    SST_TF_FEATURE_SUPPORTED_WIDTH, SST_MUL_FACTOR_NONE);
	if (resp)
		mbox_cmd->resp_data |= BIT(MBOX_TF_SUPPORT_BIT);

	_read_pp_info("feature_state", resp, SST_PP_STATUS_OFFSET,
		      SST_PP_FEATURE_STATE_START, SST_PP_FEATURE_STATE_WIDTH,
		      SST_MUL_FACTOR_NONE)
	if (resp & BIT(0))
		mbox_cmd->resp_data |= BIT(MBOX_BF_ENABLE_BIT);

	if (resp & BIT(1))
		mbox_cmd->resp_data |= BIT(MBOX_TF_ENABLE_BIT);

	pr_debug("mbox_resp:%x\n", mbox_cmd->resp_data);

	return 0;
}

static int isst_if_mbox_ctdp_set_tdp_level(struct tpmi_per_power_domain_info *power_domain_info,
					   struct isst_if_mbox_cmd *mbox_cmd)
{
	mbox_cmd->resp_data = 0;

	if (mbox_cmd->req_data >= power_domain_info->max_level)
		return -EINVAL;

	_write_pp_info("perf_level", mbox_cmd->req_data, SST_PP_CONTROL_OFFSET,
		       SST_PP_LEVEL_START, SST_PP_LEVEL_WIDTH, SST_MUL_FACTOR_NONE)

	return 0;
}

static int isst_if_mbox_ctdp_set_tdp_control(struct tpmi_per_power_domain_info *power_domain_info,
					     struct isst_if_mbox_cmd *mbox_cmd)
{
	int req = 0;

	mbox_cmd->resp_data = 0;

	if (mbox_cmd->req_data >= power_domain_info->max_level)
		return -EINVAL;

	if (mbox_cmd->req_data & BIT(MBOX_BF_ENABLE_BIT))
		req = BIT(0);

	if (mbox_cmd->req_data & BIT(MBOX_TF_ENABLE_BIT))
		req |= BIT(1);

	_write_pp_info("perf_feature", req, SST_PP_CONTROL_OFFSET, SST_PP_FEATURE_STATE_START,
		       SST_PP_FEATURE_STATE_WIDTH, SST_MUL_FACTOR_NONE)

	return 0;
}

static int isst_if_mbox_ctdp_get_info(struct tpmi_per_power_domain_info *power_domain_info,
					    struct isst_if_mbox_cmd *mbox_cmd)
{
	u32 resp;

	mbox_cmd->resp_data = 0;

	if (mbox_cmd->req_data >= power_domain_info->max_level)
		return -EINVAL;

	_read_pp_level_info("tdp_ratio", resp, mbox_cmd->req_data, SST_PP_INFO_0_OFFSET,
			    SST_PP_P1_SSE_START, SST_PP_P1_SSE_WIDTH, SST_MUL_FACTOR_NONE)
	mbox_cmd->resp_data = resp << MBOX_TDP_RATIO_START;
	_read_pp_level_info("thermal_design_power_w", resp, mbox_cmd->req_data,
			    SST_PP_INFO_1_OFFSET, SST_PP_TDP_START, SST_PP_TDP_WIDTH,
			    SST_MUL_FACTOR_NONE)
	resp /= 8; /* units are in 1/8th watt */
	mbox_cmd->resp_data |= resp & GENMASK(MBOX_PKG_TDP_WIDTH, 0);

	return 0;
}

static int isst_if_mbox_set_pm_config(struct tpmi_per_power_domain_info *power_domain_info,
				      struct isst_if_mbox_cmd *mbox_cmd)
{
	u32 req = 0;

	mbox_cmd->resp_data = 0;

	if (mbox_cmd->req_data)
		req = 1;

	_write_cp_info("cp_enable", req, SST_CP_CONTROL_OFFSET, SST_CP_ENABLE_START,
		       SST_CP_ENABLE_WIDTH, SST_MUL_FACTOR_NONE)

	return 0;
}

static int isst_if_mbox_get_pm_config(struct tpmi_per_power_domain_info *power_domain_info,
				      struct isst_if_mbox_cmd *mbox_cmd)
{
	u32 resp = BIT(SST_CP_CAP_BIT); /* This is default capability now */

	mbox_cmd->resp_data = 1; /* Always supported */

	_read_cp_info("cp_enable", resp, SST_CP_STATUS_OFFSET, SST_CP_ENABLE_START,
		      SST_CP_ENABLE_WIDTH, SST_MUL_FACTOR_NONE)
	if (resp)
		mbox_cmd->resp_data |= BIT(SST_CP_STATE_BIT);

	return 0;
}

static int isst_if_mbox_get_qos_config(struct tpmi_per_power_domain_info *power_domain_info,
				       struct isst_if_mbox_cmd *mbox_cmd)
{
	u32 resp;

	mbox_cmd->resp_data = BIT(CLOS_ENABLE_BIT);

	_read_cp_info("cp_prio_type", resp, SST_CP_STATUS_OFFSET, SST_CP_PRIORITY_TYPE_START,
		      SST_CP_PRIORITY_TYPE_WIDTH, SST_MUL_FACTOR_NONE)
	if (resp)
		mbox_cmd->resp_data |= BIT(CLOS_PRIO_BIT);

	return 0;
}

static int isst_if_mbox_set_qos_config(struct tpmi_per_power_domain_info *power_domain_info,
				       struct isst_if_mbox_cmd *mbox_cmd)
{
	u32 req = 0;

	if (mbox_cmd->req_data & BIT(CLOS_PRIO_BIT))
		req = 1;

	_write_cp_info("cp_prio_type", req, SST_CP_CONTROL_OFFSET, SST_CP_PRIORITY_TYPE_START,
		       SST_CP_PRIORITY_TYPE_WIDTH, SST_MUL_FACTOR_NONE)

	return 0;
}

static long isst_if_mbox_proc_cmd(u8 *cmd_ptr, int *write_only, int resume)
{
	struct tpmi_per_power_domain_info *power_domain_info;
	struct isst_if_mbox_cmd *mbox_cmd;
	int cmd;
	long ret = 0;

	mbox_cmd = (struct isst_if_mbox_cmd *)cmd_ptr;

	if (isst_if_mbox_cmd_invalid(mbox_cmd))
		return -EINVAL;

	pr_debug("cpu:%x mbox_cmd->command:%x mbox_cmd-sub_command:%x param:%x req_data:%x\n",
		mbox_cmd->logical_cpu,
		mbox_cmd->command,
		mbox_cmd->sub_command,
		mbox_cmd->parameter,
		mbox_cmd->req_data);

	cmd = (mbox_cmd->command << 8) | mbox_cmd->sub_command;

	power_domain_info = isst_if_mbox_power_domain_inst(mbox_cmd->logical_cpu);
	if (!power_domain_info)
		return -EINVAL;

	ret = tpmi_start_mmio_rd_wr(power_domain_info);
	if (ret)
		return ret;

	switch (cmd) {
	case CONFIG_TDP_GET_LEVELS_INFO:
		ret = isst_if_mbox_ctdp_get_levels_info(power_domain_info, mbox_cmd);
		*write_only = 0;
		break;
	case CONFIG_TDP_GET_TDP_CONTROL:
		ret = isst_if_mbox_ctdp_get_tdp_control(power_domain_info, mbox_cmd);
		*write_only = 0;
		break;
	case CONFIG_TDP_SET_TDP_CONTROL:
		ret = isst_if_mbox_ctdp_set_tdp_control(power_domain_info, mbox_cmd);
		break;
	case CONFIG_TDP_GET_TDP_INFO:
		ret = isst_if_mbox_ctdp_get_info(power_domain_info, mbox_cmd);
		*write_only = 0;
		break;
	case CONFIG_TDP_SET_LEVEL:
		ret = isst_if_mbox_ctdp_set_tdp_level(power_domain_info, mbox_cmd);
		break;
	case READ_PM_CONFIG:
		ret = isst_if_mbox_get_pm_config(power_domain_info, mbox_cmd);
		*write_only = 0;
		break;
	case WRITE_PM_CONFIG:
		ret = isst_if_mbox_set_pm_config(power_domain_info, mbox_cmd);
		break;
	case CLOS_PM_QOS_CONFIG:
		if (mbox_cmd->parameter) {
			ret = isst_if_mbox_set_qos_config(power_domain_info, mbox_cmd);
		} else {
			ret = isst_if_mbox_get_qos_config(power_domain_info, mbox_cmd);
			*write_only = 0;
		}
		break;
	default:
		pr_debug("Not implemented\n");
		ret = -EINVAL;
		break;
	}

	tpmi_end_mmio_rd_wr(power_domain_info);

	return ret;
}

#define PM_CLOS_0_REG			0x08
#define PM_CLOS_1_REG			0x0C
#define PM_CLOS_2_REG			0x10
#define PM_CLOS_3_REG			0x14
#define PM_CLOS_ASSOC_REG_START		0x20
#define PM_CLOS_ASSOC_WIDTH_PER_CPU	0x04
#define PM_CLOS_ASSOC_OFFSET_CLOS	16
#define PM_CLOS_PRIO_OFFSET		4
#define PM_CLOS_PRIO_MASK		0x0F
#define PM_CLOS_MIN_OFFSET		8
#define PM_CLOS_MIN_MASK		0xFF
#define PM_CLOS_MAX_OFFSET		16
#define PM_CLOS_MAX_MASK		0xFF

static void isst_if_mmio_pm_clos(struct tpmi_per_power_domain_info *power_domain_info,
				 struct isst_if_io_reg *io_reg)
{
	int min, max, prio;
	int clos;

	clos = (io_reg->reg - PM_CLOS_0_REG) / 4;

	if (io_reg->read_write) {
		prio = (io_reg->value >> PM_CLOS_PRIO_OFFSET) & PM_CLOS_PRIO_MASK;
		min = (io_reg->value >> PM_CLOS_MIN_OFFSET) & PM_CLOS_MIN_MASK;
		max = (io_reg->value >> PM_CLOS_MAX_OFFSET) & PM_CLOS_MAX_MASK;

		_write_cp_info("clos.min_freq", min,
			       (SST_CLOS_CONFIG_0_OFFSET + clos * SST_REG_SIZE),
			       SST_CLOS_CONFIG_MIN_START, SST_CLOS_CONFIG_MIN_WIDTH,
			       SST_MUL_FACTOR_NONE);
		_write_cp_info("clos.max_freq", max,
			       (SST_CLOS_CONFIG_0_OFFSET + clos * SST_REG_SIZE),
			       SST_CLOS_CONFIG_MAX_START, SST_CLOS_CONFIG_MAX_WIDTH,
			       SST_MUL_FACTOR_NONE);
		_write_cp_info("clos.prio", prio,
			       (SST_CLOS_CONFIG_0_OFFSET + clos * SST_REG_SIZE),
			       SST_CLOS_CONFIG_PRIO_START, SST_CLOS_CONFIG_PRIO_WIDTH,
			       SST_MUL_FACTOR_NONE);
	} else {

		_read_cp_info("clos.min_freq", min,
			      (SST_CLOS_CONFIG_0_OFFSET + clos * SST_REG_SIZE),
			      SST_CLOS_CONFIG_MIN_START, SST_CLOS_CONFIG_MIN_WIDTH,
			      SST_MUL_FACTOR_NONE)
		_read_cp_info("clos.max_freq", max,
			      (SST_CLOS_CONFIG_0_OFFSET + clos * SST_REG_SIZE),
			      SST_CLOS_CONFIG_MAX_START, SST_CLOS_CONFIG_MAX_WIDTH,
			      SST_MUL_FACTOR_NONE)
		_read_cp_info("clos.prio", prio,
			      (SST_CLOS_CONFIG_0_OFFSET + clos * SST_REG_SIZE),
			      SST_CLOS_CONFIG_PRIO_START, SST_CLOS_CONFIG_PRIO_WIDTH,
			      SST_MUL_FACTOR_NONE)
		pr_debug("min:%x max:%x prio:%x\n", min, max, prio);
		io_reg->value = (max << 16 | min << 8 | prio << 4);
		pr_debug("%x\n", io_reg->value);
	}
}

static void isst_if_mmio_pm_clos_assoc(struct tpmi_per_power_domain_info *power_domain_info,
				       struct isst_if_io_reg *io_reg)
{
	int offset, shift, punit_cpu;
	u64 val, mask, clos;

	punit_cpu = (io_reg->reg - PM_CLOS_ASSOC_REG_START) / PM_CLOS_ASSOC_WIDTH_PER_CPU;

	offset = SST_CLOS_ASSOC_0_OFFSET + (punit_cpu / SST_CLOS_ASSOC_CPUS_PER_REG) * SST_REG_SIZE;
	shift = punit_cpu % SST_CLOS_ASSOC_CPUS_PER_REG;
	shift *= SST_CLOS_ASSOC_BITS_PER_CPU;

	val = readq(power_domain_info->sst_base + power_domain_info->sst_header.cp_offset + offset);
	if (io_reg->read_write) {
		mask = GENMASK_ULL((shift + SST_CLOS_ASSOC_BITS_PER_CPU - 1), shift);
		val &= ~mask;
		clos = (io_reg->value >> PM_CLOS_ASSOC_OFFSET_CLOS);
		val |= (clos << shift);
		intel_tpmi_writeq(power_domain_info->auxdev, val, power_domain_info->sst_base +
				  power_domain_info->sst_header.cp_offset + offset);
	} else {
		val >>= shift;
		clos = val & GENMASK(SST_CLOS_ASSOC_BITS_PER_CPU - 1, 0);
		io_reg->value = clos << PM_CLOS_ASSOC_OFFSET_CLOS;
	}
}

static long isst_if_mmio_rd_wr(u8 *cmd_ptr, int *write_only, int resume)
{
	struct tpmi_per_power_domain_info *power_domain_info;
	struct isst_if_io_reg *io_reg;
	int ret;

	io_reg = (struct isst_if_io_reg *)cmd_ptr;

	if (io_reg->reg % 4)
		return -EINVAL;

	power_domain_info = isst_if_mbox_power_domain_inst(io_reg->logical_cpu);
	if (!power_domain_info)
		return -EINVAL;

	ret = tpmi_start_mmio_rd_wr(power_domain_info);
	if (ret)
		return ret;

	pr_debug("io_reg:%x read_write:%x\n", io_reg->reg, io_reg->read_write);

	if (io_reg->reg >= PM_CLOS_0_REG && io_reg->reg <= PM_CLOS_3_REG) {
		isst_if_mmio_pm_clos(power_domain_info, io_reg);
		*write_only = io_reg->read_write;
	} else if (io_reg->reg >= PM_CLOS_ASSOC_REG_START) {
		isst_if_mmio_pm_clos_assoc(power_domain_info, io_reg);
		*write_only = io_reg->read_write;
	}

	tpmi_end_mmio_rd_wr(power_domain_info);

	return 0;
}

#define TPMI_SST_AUTO_SUSPEND_DELAY_MS	2000

int tpmi_sst_dev_add(struct auxiliary_device *auxdev)
{
	struct intel_tpmi_plat_info *plat_info;
	struct tpmi_sst_struct *tpmi_sst;
	int i, ret, pkg = 0, inst = 0;
	int num_resources;

	plat_info = tpmi_get_platform_data(auxdev);
	if (!plat_info) {
		dev_info(&auxdev->dev, "No platform info\n");
		return -EINVAL;
	}

	pkg = plat_info->package_id;
	if (pkg >= SST_MAX_INSTANCES) {
		dev_info(&auxdev->dev, "Invalid package id :%x\n", pkg);
		return -EINVAL;
	}

	if (isst_common.sst_inst[pkg])
		return -EEXIST;

	num_resources = tpmi_get_resource_count(auxdev);
	dev_dbg(&auxdev->dev, "Number of resources:%x\n", num_resources);

	if (!num_resources)
		return -EINVAL;

	tpmi_sst = devm_kzalloc(&auxdev->dev, sizeof(*tpmi_sst), GFP_KERNEL);
	if (!tpmi_sst)
		return -ENOMEM;

	tpmi_sst->power_domain_info = devm_kcalloc(&auxdev->dev, num_resources,
						   sizeof(*tpmi_sst->power_domain_info),
						   GFP_KERNEL);
	if (!tpmi_sst->power_domain_info)
		return -ENOMEM;

	tpmi_sst->number_of_power_domains = num_resources;

	for (i = 0; i < num_resources; ++i) {
		struct resource *res;

		res = tpmi_get_resource_at_index(auxdev, i);
		if (!res) {
			tpmi_sst->power_domain_info[i].sst_base = NULL;
			continue;
		}

		tpmi_sst->power_domain_info[i].package_id = pkg;
		tpmi_sst->power_domain_info[i].power_domain_id = i;
		tpmi_sst->power_domain_info[i].auxdev = auxdev;
		tpmi_sst->power_domain_info[i].sst_base = devm_ioremap_resource(&auxdev->dev, res);
		if (IS_ERR(tpmi_sst->power_domain_info[i].sst_base))
			return PTR_ERR(tpmi_sst->power_domain_info[i].sst_base);

		ret = sst_main(auxdev, &tpmi_sst->power_domain_info[i]);
		if (ret) {
			dev_dbg(&auxdev->dev, "Invalid resource id at :%x\n", i);
			devm_iounmap(&auxdev->dev, tpmi_sst->power_domain_info[i].sst_base);
			tpmi_sst->power_domain_info[i].sst_base =  NULL;
			continue;
		}

		++inst;
	}

	if (!inst)
		return -ENODEV;

	tpmi_sst->package_id = pkg;
	auxiliary_set_drvdata(auxdev, tpmi_sst);

	mutex_lock(&isst_tpmi_dev_lock);
	if (isst_common.max_index < pkg)
		isst_common.max_index = pkg;
	isst_common.sst_inst[pkg] = tpmi_sst;
	mutex_unlock(&isst_tpmi_dev_lock);

	pm_runtime_set_active(&auxdev->dev);
	pm_runtime_set_autosuspend_delay(&auxdev->dev, TPMI_SST_AUTO_SUSPEND_DELAY_MS);
	pm_runtime_use_autosuspend(&auxdev->dev);
	pm_runtime_enable(&auxdev->dev);
	pm_runtime_mark_last_busy(&auxdev->dev);

	return 0;
}
EXPORT_SYMBOL_NS_GPL(tpmi_sst_dev_add, INTEL_TPMI_SST);

void tpmi_sst_dev_remove(struct auxiliary_device *auxdev)
{
	struct tpmi_sst_struct *tpmi_sst = auxiliary_get_drvdata(auxdev);

	mutex_lock(&isst_tpmi_dev_lock);
	isst_common.sst_inst[tpmi_sst->package_id] = NULL;
	mutex_unlock(&isst_tpmi_dev_lock);
	pm_runtime_disable(&auxdev->dev);
}
EXPORT_SYMBOL_NS_GPL(tpmi_sst_dev_remove, INTEL_TPMI_SST);

void tpmi_sst_dev_suspend(struct auxiliary_device *auxdev)
{
	struct tpmi_sst_struct *tpmi_sst = auxiliary_get_drvdata(auxdev);
	struct tpmi_per_power_domain_info *power_domain_info = tpmi_sst->power_domain_info;
	void __iomem *cp_base;

	cp_base = power_domain_info->sst_base + power_domain_info->sst_header.cp_offset;
	power_domain_info->saved_sst_cp_control = readq(cp_base + SST_CP_CONTROL_OFFSET);

	memcpy_fromio(power_domain_info->saved_clos_configs, cp_base + SST_CLOS_CONFIG_0_OFFSET,
		      sizeof(power_domain_info->saved_clos_configs));

	memcpy_fromio(power_domain_info->saved_clos_assocs, cp_base + SST_CLOS_ASSOC_0_OFFSET,
		      sizeof(power_domain_info->saved_clos_assocs));

	power_domain_info->saved_pp_control = readq(power_domain_info->sst_base +
						    power_domain_info->sst_header.pp_offset +
						    SST_PP_CONTROL_OFFSET);
}
EXPORT_SYMBOL_NS_GPL(tpmi_sst_dev_suspend, INTEL_TPMI_SST);

void tpmi_sst_dev_resume(struct auxiliary_device *auxdev)
{
	struct tpmi_sst_struct *tpmi_sst = auxiliary_get_drvdata(auxdev);
	struct tpmi_per_power_domain_info *power_domain_info = tpmi_sst->power_domain_info;
	void __iomem *cp_base;

	cp_base = power_domain_info->sst_base + power_domain_info->sst_header.cp_offset;
	intel_tpmi_writeq(power_domain_info->auxdev, power_domain_info->saved_sst_cp_control,
			 cp_base + SST_CP_CONTROL_OFFSET);

	memcpy_toio(cp_base + SST_CLOS_CONFIG_0_OFFSET, power_domain_info->saved_clos_configs,
		    sizeof(power_domain_info->saved_clos_configs));

	memcpy_toio(cp_base + SST_CLOS_ASSOC_0_OFFSET, power_domain_info->saved_clos_assocs,
		    sizeof(power_domain_info->saved_clos_assocs));

	intel_tpmi_writeq(power_domain_info->auxdev, power_domain_info->saved_pp_control,
			  power_domain_info->sst_base +
			  power_domain_info->sst_header.pp_offset + SST_PP_CONTROL_OFFSET);
}
EXPORT_SYMBOL_NS_GPL(tpmi_sst_dev_resume, INTEL_TPMI_SST);

#define ISST_TPMI_API_VERSION	0x02

int tpmi_sst_init(void)
{
	struct isst_if_cmd_cb cb;
	int ret = 0;

	mutex_lock(&isst_tpmi_dev_lock);

	if (isst_core_usage_count) {
		++isst_core_usage_count;
		goto init_done;
	}

	memset(&cb, 0, sizeof(cb));
	cb.cmd_size = sizeof(struct isst_if_io_reg);
	cb.offset = offsetof(struct isst_if_io_regs, io_reg);
	cb.cmd_callback = NULL;
	cb.api_version = ISST_TPMI_API_VERSION;
	cb.def_ioctl = isst_if_def_ioctl;
	cb.owner = THIS_MODULE;
	ret = isst_if_cdev_register(ISST_IF_DEV_TPMI, &cb);
	if (ret)
		goto init_done;

	memset(&cb, 0, sizeof(cb));
	cb.cmd_size = sizeof(struct isst_if_mbox_cmd);
	cb.offset = offsetof(struct isst_if_mbox_cmds, mbox_cmd);
	cb.cmd_callback = isst_if_mbox_proc_cmd;
	cb.owner = THIS_MODULE;
	ret = isst_if_cdev_register(ISST_IF_DEV_MBOX, &cb);
	if (ret)
		goto err_mbox;

	memset(&cb, 0, sizeof(cb));
	cb.cmd_size = sizeof(struct isst_if_io_reg);
	cb.offset = offsetof(struct isst_if_io_regs, io_reg);
	cb.cmd_callback = isst_if_mmio_rd_wr;
	cb.owner = THIS_MODULE;
	ret = isst_if_cdev_register(ISST_IF_DEV_MMIO, &cb);
	if (!ret)
		goto init_done;

	isst_if_cdev_unregister(ISST_IF_DEV_MBOX);
err_mbox:
	isst_if_cdev_unregister(ISST_IF_DEV_TPMI);
init_done:
	mutex_unlock(&isst_tpmi_dev_lock);
	return ret;
}
EXPORT_SYMBOL_NS_GPL(tpmi_sst_init, INTEL_TPMI_SST);

void tpmi_sst_exit(void)
{
	mutex_lock(&isst_tpmi_dev_lock);
	if (isst_core_usage_count)
		--isst_core_usage_count;

	if (!isst_core_usage_count) {
		isst_if_cdev_unregister(ISST_IF_DEV_MMIO);
		isst_if_cdev_unregister(ISST_IF_DEV_MBOX);
		isst_if_cdev_unregister(ISST_IF_DEV_TPMI);
	}
	mutex_unlock(&isst_tpmi_dev_lock);
}
EXPORT_SYMBOL_NS_GPL(tpmi_sst_exit, INTEL_TPMI_SST);

MODULE_IMPORT_NS(INTEL_TPMI);
MODULE_IMPORT_NS(INTEL_TPMI_POWER_DOMAIN);

MODULE_LICENSE("GPL");
