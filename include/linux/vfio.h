/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * VFIO API definition
 *
 * Copyright (C) 2012 Red Hat, Inc.  All rights reserved.
 *     Author: Alex Williamson <alex.williamson@redhat.com>
 */
#ifndef VFIO_H
#define VFIO_H


#include <linux/iommu.h>
#include <linux/mm.h>
#include <linux/workqueue.h>
#include <linux/poll.h>
#include <linux/pci-tdisp.h>
#include <linux/irqbypass.h>
#include <uapi/linux/vfio.h>
#include <linux/cdev.h>

struct kvm;

/*
 * VFIO devices can be placed in a set, this allows all devices to share this
 * structure and the VFIO core will provide a lock that is held around
 * open_device()/close_device() for all devices in the set.
 */
struct vfio_device_set {
	void *set_id;
	struct mutex lock;
	struct list_head device_list;
	unsigned int device_count;
};

struct vfio_ims_entry {
	struct eventfd_ctx *trigger;
	struct irq_bypass_producer producer;
	char *name;
	bool ims;
	int ims_id;
};

struct vfio_ims {
	struct vfio_ims_entry *ims_entries;
	int num;
	int ims_num;
	int irq_type;
	bool ims_en;
};

struct vfio_device {
	struct device *dev;
	const struct vfio_device_ops *ops;
	struct vfio_group *group;
	struct vfio_device_set *dev_set;
	struct list_head dev_set_list;
	unsigned int migration_flags;
	/* Driver must reference the kvm during open_device or never touch it */
	struct kvm *kvm;

	/* Members below here are private, not for driver use */
	struct device device;
	struct cdev cdev;
	struct rcu_head rcu;
	refcount_t refcount; /* user count */
	unsigned int open_count;
	struct completion comp;
	struct list_head group_next;
	struct vfio_ims ims;
	struct eventfd_ctx *req_trigger;

	bool trusted;
	struct pci_tdisp_dev *tdev;
};

static inline struct vfio_device *ims_to_vdev(struct vfio_ims *ims)
{
	return container_of(ims, struct vfio_device, ims);
}

/**
 * struct vfio_device_ops - VFIO bus driver device callbacks
 *
 * @open_device: Called when the first file descriptor is opened for this device
 * @close_device: Opposite of open_device
 * @release: Reclaim private fields in device state structure
 * @read: Perform read(2) on device file descriptor
 * @write: Perform write(2) on device file descriptor
 * @ioctl: Perform ioctl(2) on device file descriptor, supporting VFIO_DEVICE_*
 *         operations documented below
 * @mmap: Perform mmap(2) on a region of the device file descriptor
 * @request: Request for the bus driver to release the device
 * @match: Optional device name match callback (return: 0 for no-match, >0 for
 *         match, -errno for abort (ex. match with insufficient or incorrect
 *         additional args)
 * @device_feature: Optional, fill in the VFIO_DEVICE_FEATURE ioctl
 * @migration_set_state: Optional callback to change the migration state for
 *         devices that support migration. It's mandatory for
 *         VFIO_DEVICE_FEATURE_MIGRATION migration support.
 *         The returned FD is used for data transfer according to the FSM
 *         definition. The driver is responsible to ensure that FD reaches end
 *         of stream or error whenever the migration FSM leaves a data transfer
 *         state or before close_device() returns.
 * @migration_get_state: Optional callback to get the migration state for
 *         devices that support migration. It's mandatory for
 *         VFIO_DEVICE_FEATURE_MIGRATION migration support.
 */
struct vfio_device_ops {
	char	*name;
	int	(*bind_iommufd)(struct vfio_device *vdev,
				struct vfio_device_bind_iommufd *bind);
	void	(*unbind_iommufd)(struct vfio_device *vdev);
	int	(*attach_ioas)(struct vfio_device *vdev,
			       struct vfio_device_attach_ioas *attach);
	int	(*attach_hwpt)(struct vfio_device *vdev,
			       struct vfio_device_attach_hwpt *attach);
	void	(*detach_hwpt)(struct vfio_device *vdev,
			       struct vfio_device_detach_hwpt *detach);
	int	(*open_device)(struct vfio_device *vdev);
	void	(*close_device)(struct vfio_device *vdev);
	void	(*release)(struct vfio_device *vdev);
	ssize_t	(*read)(struct vfio_device *vdev, char __user *buf,
			size_t count, loff_t *ppos);
	ssize_t	(*write)(struct vfio_device *vdev, const char __user *buf,
			 size_t count, loff_t *size);
	long	(*ioctl)(struct vfio_device *vdev, unsigned int cmd,
			 unsigned long arg);
	int	(*mmap)(struct vfio_device *vdev, struct vm_area_struct *vma);
	void	(*request)(struct vfio_device *vdev, unsigned int count);
	int	(*match)(struct vfio_device *vdev, char *buf);
	int	(*device_feature)(struct vfio_device *device, u32 flags,
				  void __user *arg, size_t argsz);
	struct file *(*migration_set_state)(
		struct vfio_device *device,
		enum vfio_device_mig_state new_state);
	int (*migration_get_state)(struct vfio_device *device,
				   enum vfio_device_mig_state *curr_state);
};

/**
 * vfio_check_feature - Validate user input for the VFIO_DEVICE_FEATURE ioctl
 * @flags: Arg from the device_feature op
 * @argsz: Arg from the device_feature op
 * @supported_ops: Combination of VFIO_DEVICE_FEATURE_GET and SET the driver
 *                 supports
 * @minsz: Minimum data size the driver accepts
 *
 * For use in a driver's device_feature op. Checks that the inputs to the
 * VFIO_DEVICE_FEATURE ioctl are correct for the driver's feature. Returns 1 if
 * the driver should execute the get or set, otherwise the relevant
 * value should be returned.
 */
static inline int vfio_check_feature(u32 flags, size_t argsz, u32 supported_ops,
				    size_t minsz)
{
	if ((flags & (VFIO_DEVICE_FEATURE_GET | VFIO_DEVICE_FEATURE_SET)) &
	    ~supported_ops)
		return -EINVAL;
	if (flags & VFIO_DEVICE_FEATURE_PROBE)
		return 0;
	/* Without PROBE one of GET or SET must be requested */
	if (!(flags & (VFIO_DEVICE_FEATURE_GET | VFIO_DEVICE_FEATURE_SET)))
		return -EINVAL;
	if (argsz < minsz)
		return -EINVAL;
	return 1;
}

struct vfio_device *_vfio_alloc_device(size_t size, struct device *dev,
				       const struct vfio_device_ops *ops);
#define vfio_alloc_device(dev_struct, member, __dev, __ops)			\
	container_of(_vfio_alloc_device(sizeof(struct dev_struct) +		\
					BUILD_BUG_ON_ZERO(offsetof(		\
						struct dev_struct, member)),	\
					__dev, __ops),				\
		     struct dev_struct, member)

void vfio_put_device(struct vfio_device *device);
void vfio_init_group_dev(struct vfio_device *device, struct device *dev,
			 const struct vfio_device_ops *ops);
void vfio_uninit_group_dev(struct vfio_device *device);
int vfio_register_group_dev(struct vfio_device *device);
int vfio_register_emulated_iommu_dev(struct vfio_device *device);
void vfio_unregister_group_dev(struct vfio_device *device);
bool vfio_device_try_get(struct vfio_device *device);

int vfio_assign_device_set(struct vfio_device *device, void *set_id);

int vfio_mig_get_next_state(struct vfio_device *device,
			    enum vfio_device_mig_state cur_fsm,
			    enum vfio_device_mig_state new_fsm,
			    enum vfio_device_mig_state *next_fsm);

/*
 * External user API
 */
struct iommu_group *vfio_file_iommu_group(struct file *file);
bool vfio_file_enforced_coherent(struct file *file);
void vfio_file_set_kvm(struct file *file, struct kvm *kvm);
bool vfio_file_has_dev(struct file *file, struct vfio_device *device);

#define VFIO_PIN_PAGES_MAX_ENTRIES	(PAGE_SIZE/sizeof(unsigned long))

int vfio_pin_pages(struct vfio_device *device, unsigned long *user_pfn,
		   int npage, int prot, unsigned long *phys_pfn);
int vfio_unpin_pages(struct vfio_device *device, unsigned long *user_pfn,
		     int npage);
int vfio_dma_rw(struct vfio_device *device, dma_addr_t user_iova,
		void *data, size_t len, bool write);

/* each type has independent events */
enum vfio_notify_type {
	VFIO_IOMMU_NOTIFY = 0,
};

/* events for VFIO_IOMMU_NOTIFY */
#define VFIO_IOMMU_NOTIFY_DMA_UNMAP	BIT(0)

int vfio_register_notifier(struct vfio_device *device,
			   enum vfio_notify_type type,
			   unsigned long *required_events,
			   struct notifier_block *nb);
int vfio_unregister_notifier(struct vfio_device *device,
			     enum vfio_notify_type type,
			     struct notifier_block *nb);


/*
 * Sub-module helpers
 */
struct vfio_info_cap {
	struct vfio_info_cap_header *buf;
	size_t size;
};
struct vfio_info_cap_header *vfio_info_cap_add(struct vfio_info_cap *caps,
					       size_t size, u16 id,
					       u16 version);
void vfio_info_cap_shift(struct vfio_info_cap *caps, size_t offset);

int vfio_info_add_capability(struct vfio_info_cap *caps,
			     struct vfio_info_cap_header *cap, size_t size);

int vfio_set_irqs_validate_and_prepare(struct vfio_irq_set *hdr,
				       int num_irqs, int max_irq_type,
				       size_t *data_size);

struct pci_dev;
#if IS_ENABLED(CONFIG_VFIO_SPAPR_EEH)
void vfio_spapr_pci_eeh_open(struct pci_dev *pdev);
void vfio_spapr_pci_eeh_release(struct pci_dev *pdev);
long vfio_spapr_iommu_eeh_ioctl(struct iommu_group *group, unsigned int cmd,
				unsigned long arg);
#else
static inline void vfio_spapr_pci_eeh_open(struct pci_dev *pdev)
{
}

static inline void vfio_spapr_pci_eeh_release(struct pci_dev *pdev)
{
}

static inline long vfio_spapr_iommu_eeh_ioctl(struct iommu_group *group,
					      unsigned int cmd,
					      unsigned long arg)
{
	return -ENOTTY;
}
#endif /* CONFIG_VFIO_SPAPR_EEH */

/*
 * IRQfd - generic
 */
struct virqfd {
	void			*opaque;
	struct eventfd_ctx	*eventfd;
	int			(*handler)(void *, void *);
	void			(*thread)(void *, void *);
	void			*data;
	struct work_struct	inject;
	wait_queue_entry_t		wait;
	poll_table		pt;
	struct work_struct	shutdown;
	struct virqfd		**pvirqfd;
};

int vfio_virqfd_enable(void *opaque, int (*handler)(void *, void *),
		       void (*thread)(void *, void *), void *data,
		       struct virqfd **pvirqfd, int fd);
void vfio_virqfd_disable(struct virqfd **pvirqfd);

extern void vfio_device_set_pasid(struct vfio_device *device, u32 pasid);
extern u32 vfio_device_get_pasid(struct vfio_device *device);
extern void vfio_device_set_msi_domain(struct vfio_device *device, struct irq_domain *domain);
extern int vfio_device_msi_hwirq(struct vfio_device *device, int index);

/* common lib functions */
extern int vfio_set_ctx_trigger_single(struct eventfd_ctx **ctx,
				       unsigned int count, u32 flags,
				       void *data);
extern int vfio_set_req_trigger(struct vfio_device *vdev, unsigned int index,
				unsigned int start, unsigned int count, u32 flags,
				void *data);
extern void vfio_device_request(struct vfio_device *vdev, unsigned int count);

/*
 * IMS - generic
 */
#if IS_ENABLED(CONFIG_VFIO_IMS)
int vfio_set_ims_trigger(struct vfio_device *vdev, unsigned int index,
			 unsigned int start, unsigned int count, u32 flags,
			 void *data);
void vfio_ims_send_signal(struct vfio_device *vdev, int vector);
int vfio_ims_init(struct vfio_device *vdev, int num, bool *ims_map);
void vfio_ims_free(struct vfio_device *vdev);
#else
static inline int vfio_set_ims_trigger(struct vfio_device *vdev, unsigned int index,
				       unsigned int start, unsigned int count, u32 flags,
				       void *data)
{
	return -EOPNOTSUPP;
}

static inline void vfio_ims_send_signal(struct vfio_device *vdev, int vector) {}

static inline int vfio_ims_init(struct vfio_device *vdev, int num, bool *ims_map)
{
	return -EOPNOTSUPP;
}

static inline void vfio_ims_free(struct vfio_device *vdev) {}
#endif /* CONFIG_VFIO_MDEV_IMS */

#endif /* VFIO_H */
