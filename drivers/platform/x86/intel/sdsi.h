/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SDSI_H_
#define __SDSI_H_

#include <linux/auxiliary_bus.h>
#include <linux/spdm.h>

struct sdsi_priv {
	struct mutex			mb_lock;	/* Mailbox access lock */
	struct device			*dev;
	struct intel_vsec_device	*ivdev;
	struct spdm_state		*spdm_state;
	struct list_head		node;
	void __iomem			*control_addr;
	void __iomem			*mbox_addr;
	void __iomem			*regs_addr;
	const char			*name;
	int				id;
	int				control_size;
	int				maibox_size;
	int				registers_size;
	u32				guid;
	u32				features;
};

int for_each_sdsi_device(int (*cb)(struct sdsi_priv *, void *),
			 void *data);
struct sdsi_priv *sdsi_dev_get_by_id(int id);
#endif
