// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * zswap.c - zswap driver file
 *
 * zswap is a backend for frontswap that takes pages that are in the process
 * of being swapped out and attempts to compress and store them in a
 * RAM-based memory pool.  This can result in a significant I/O reduction on
 * the swap device and, in the case where decompressing from RAM is faster
 * than reading from the swap device, can also improve workload performance.
 *
 * Copyright (C) 2012  Seth Jennings <sjenning@linux.vnet.ibm.com>
*/

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/cpu.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/frontswap.h>
#include <linux/rbtree.h>
#include <linux/swap.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/mempool.h>
#include <linux/zpool.h>
#include <crypto/acompress.h>

#include <linux/mm_types.h>
#include <linux/page-flags.h>
#include <linux/swapops.h>
#include <linux/writeback.h>
#include <linux/pagemap.h>
#include <linux/workqueue.h>

#include "swap.h"

#define CREATE_TRACE_POINTS
#include <trace/events/zswap.h>

/*********************************
* statistics
**********************************/
/* Total bytes used by the compressed storage */
u64 zswap_pool_total_size;
/* The number of compressed pages currently stored in zswap */
atomic_t zswap_stored_pages = ATOMIC_INIT(0);
/* The number of same-value filled pages currently stored in zswap */
static atomic_t zswap_same_filled_pages = ATOMIC_INIT(0);

static atomic_t zswap_primary_used = ATOMIC_INIT(0);
static atomic_t zswap_secondary_used = ATOMIC_INIT(0);

/*
 * The statistics below are not protected from concurrent access for
 * performance reasons so they may not be a 100% accurate.  However,
 * they do provide useful information on roughly how many times a
 * certain event is occurring.
*/

/* Pool limit was hit (see zswap_max_pool_percent) */
static u64 zswap_pool_limit_hit;
/* Pages written back when pool limit was reached */
static u64 zswap_written_back_pages;
/* Store failed due to a reclaim failure after pool limit was reached */
static u64 zswap_reject_reclaim_fail;
/* Compressed page was too big for the allocator to (optimally) store */
static u64 zswap_reject_compress_poor;
/* Store failed because underlying allocator could not get memory */
static u64 zswap_reject_alloc_fail;
/* Store failed because the entry metadata could not be allocated (rare) */
static u64 zswap_reject_kmemcache_fail;
/* Duplicate store was encountered (rare) */
static u64 zswap_duplicate_entry;

/* Shrinker work queue */
static struct workqueue_struct *shrink_wq;
/* Pool limit was hit, we need to calm down */
static bool zswap_pool_reached_full;

/*********************************
* tunables
**********************************/

#define ZSWAP_PARAM_UNSET ""

/* Enable/disable zswap */
static bool zswap_enabled = IS_ENABLED(CONFIG_ZSWAP_DEFAULT_ON);
static int zswap_enabled_param_set(const char *,
				   const struct kernel_param *);
static const struct kernel_param_ops zswap_enabled_param_ops = {
	.set =		zswap_enabled_param_set,
	.get =		param_get_bool,
};
module_param_cb(enabled, &zswap_enabled_param_ops, &zswap_enabled, 0644);

/* Crypto compressor to use */
static char *zswap_compressor = CONFIG_ZSWAP_COMPRESSOR_DEFAULT;
static int zswap_compressor_param_set(const char *,
				      const struct kernel_param *);
static const struct kernel_param_ops zswap_compressor_param_ops = {
	.set =		zswap_compressor_param_set,
	.get =		param_get_charp,
	.free =		param_free_charp,
};
module_param_cb(compressor, &zswap_compressor_param_ops,
		&zswap_compressor, 0644);

/* Compressed storage zpool to use */
static char *zswap_zpool_type = CONFIG_ZSWAP_ZPOOL_DEFAULT;
static int zswap_zpool_param_set(const char *, const struct kernel_param *);
static const struct kernel_param_ops zswap_zpool_param_ops = {
	.set =		zswap_zpool_param_set,
	.get =		param_get_charp,
	.free =		param_free_charp,
};
module_param_cb(zpool, &zswap_zpool_param_ops, &zswap_zpool_type, 0644);

/* The maximum percentage of memory that the compressed pool can occupy */
static unsigned int zswap_max_pool_percent = 20;
module_param_named(max_pool_percent, zswap_max_pool_percent, uint, 0644);

/* The threshold for accepting new pages after the max_pool_percent was hit */
static unsigned int zswap_accept_thr_percent = 90; /* of max pool size */
module_param_named(accept_threshold_percent, zswap_accept_thr_percent,
		   uint, 0644);

/*
 * Enable/disable handling same-value filled pages (enabled by default).
 * If disabled every page is considered non-same-value filled.
 */
static bool zswap_same_filled_pages_enabled = true;
module_param_named(same_filled_pages_enabled, zswap_same_filled_pages_enabled,
		   bool, 0644);

/* Enable/disable handling non-same-value filled pages (enabled by default) */
static bool zswap_non_same_filled_pages_enabled = true;
module_param_named(non_same_filled_pages_enabled, zswap_non_same_filled_pages_enabled,
		   bool, 0644);

static unsigned int zswap_secondary_threshold = 0;
module_param_named(secondary_threshold, zswap_secondary_threshold, uint, 0644);

#define MAX_BY_N 4
#define MAX_BY_N_THRESHOLD 4096

struct by_n {
	struct scatterlist input, output;
	struct acomp_req *req;
};

static int zswap_by_n_chunk_threshold_set(const char *val,
					  const struct kernel_param *kp)
{
	unsigned int n;
	int ret;

	ret = kstrtouint(val, 10, &n);
	if (ret != 0 || n > MAX_BY_N_THRESHOLD)
		return -EINVAL;

	return param_set_uint(val, kp);
}

static const struct kernel_param_ops by_n_chunk_threshold_ops = {
	.set = zswap_by_n_chunk_threshold_set,
	.get = param_get_uint,
};

/* The chunk_threshold for splitting a page into 2 compresses */
static unsigned int zswap_by_n_chunk_threshold = PAGE_SIZE; /* bytes */
module_param_cb(by_n_chunk_threshold, &by_n_chunk_threshold_ops, &zswap_by_n_chunk_threshold, 0644);

static int zswap_by_n_threshold_set(const char *val,
				    const struct kernel_param *kp)
{
	unsigned int n;
	int ret;

	ret = kstrtouint(val, 10, &n);
	if (ret != 0 || n > MAX_BY_N_THRESHOLD)
		return -EINVAL;

	return param_set_uint(val, kp);
}

static const struct kernel_param_ops by_n_threshold_ops = {
	.set = zswap_by_n_threshold_set,
	.get = param_get_uint,
};

/* The threshold for splitting a page into n compresses */
static unsigned int zswap_by_n_threshold; /* bytes */
module_param_cb(by_n_threshold, &by_n_threshold_ops, &zswap_by_n_threshold, 0644);

static unsigned int zswap_by_n; /* bytes */

static int zswap_by_n_set(const char *val,
			  const struct kernel_param *kp)
{
	unsigned int n;
	int ret;

	ret = kstrtouint(val, 10, &n);
	if (ret != 0 || n > MAX_BY_N)
		return -EINVAL;

	ret = param_set_uint(val, kp);
	if (ret)
		return ret;

	if (zswap_by_n == 1) /* 0 or 1 mean by1 = by_n disabled */
		zswap_by_n = 0;

	return ret;
}

static const struct kernel_param_ops by_n_ops = {
	.set = zswap_by_n_set,
	.get = param_get_uint,
};

/* Split pages into n compresses */
module_param_cb(by_n, &by_n_ops, &zswap_by_n, 0644);

/*********************************
* data structures
**********************************/

struct crypto_acomp_ctx {
	struct crypto_acomp *acomp;
	struct acomp_req *req;
	struct acomp_req *by_n_req[MAX_BY_N];
	struct crypto_wait wait;
	u8 *dstmem;
	struct mutex *mutex;
};

struct zswap_pool {
	struct zpool *zpool;
	struct crypto_acomp_ctx __percpu *acomp_ctx;
	struct crypto_acomp_ctx __percpu *secondary_acomp_ctx;
	struct kref kref;
	struct list_head list;
	struct work_struct release_work;
	struct work_struct shrink_work;
	struct hlist_node node;
	char tfm_name[CRYPTO_MAX_ALG_NAME];
};

/*
 * struct zswap_entry
 *
 * This structure contains the metadata for tracking a single compressed
 * page within zswap.
 *
 * rbnode - links the entry into red-black tree for the appropriate swap type
 * offset - the swap offset for the entry.  Index into the red-black tree.
 * refcount - the number of outstanding reference to the entry. This is needed
 *            to protect against premature freeing of the entry by code
 *            concurrent calls to load, invalidate, and writeback.  The lock
 *            for the zswap_tree structure that contains the entry must
 *            be held while changing the refcount.  Since the lock must
 *            be held, there is no reason to also make refcount atomic.
 * length - the length in bytes of the compressed page data.  Needed during
 *          decompression. For a same value filled page length is 0.
 * pool - the zswap_pool the entry's data is in
 * handle - zpool allocation handle that stores the compressed page data
 * value - value of the same-value filled pages which have same content
 */
struct zswap_entry {
	struct rb_node rbnode;
	pgoff_t offset;
	int refcount;
	unsigned int length;
	unsigned int by_n_length[MAX_BY_N];
	int by_n_length_order[MAX_BY_N];

	struct zswap_pool *pool;
	bool use_secondary; /* use `pool`'s secondary_acomp_ctx */
	union {
		unsigned long handle;
		unsigned long value;
	};
	struct obj_cgroup *objcg;
};

struct zswap_header {
	swp_entry_t swpentry;
};

/*
 * The tree lock in the zswap_tree struct protects a few things:
 * - the rbtree
 * - the refcount field of each entry in the tree
 */
struct zswap_tree {
	struct rb_root rbroot;
	spinlock_t lock;
};

static struct zswap_tree *zswap_trees[MAX_SWAPFILES];

/* RCU-protected iteration */
static LIST_HEAD(zswap_pools);
/* protects zswap_pools list modification */
static DEFINE_SPINLOCK(zswap_pools_lock);
/* pool counter to provide unique names to zpool */
static atomic_t zswap_pools_count = ATOMIC_INIT(0);

/* used by param callback function */
static bool zswap_init_started;

/* fatal error during init */
static bool zswap_init_failed;

/* init completed, but couldn't create the initial pool */
static bool zswap_has_pool;

/*********************************
* helpers and fwd declarations
**********************************/

#define zswap_pool_debug(msg, p)				\
	pr_debug("%s pool %s/%s\n", msg, (p)->tfm_name,		\
		 zpool_get_type((p)->zpool))

static int zswap_writeback_entry(struct zpool *pool, unsigned long handle);
static int zswap_pool_get(struct zswap_pool *pool);
static void zswap_pool_put(struct zswap_pool *pool);

static const struct zpool_ops zswap_zpool_ops = {
	.evict = zswap_writeback_entry
};

static bool zswap_is_full(void)
{
	return totalram_pages() * zswap_max_pool_percent / 100 <
			DIV_ROUND_UP(zswap_pool_total_size, PAGE_SIZE);
}

static bool zswap_can_accept(void)
{
	return totalram_pages() * zswap_accept_thr_percent / 100 *
				zswap_max_pool_percent / 100 >
			DIV_ROUND_UP(zswap_pool_total_size, PAGE_SIZE);
}

static void zswap_update_total_size(void)
{
	struct zswap_pool *pool;
	u64 total = 0;

	rcu_read_lock();

	list_for_each_entry_rcu(pool, &zswap_pools, list)
		total += zpool_get_total_size(pool->zpool);

	rcu_read_unlock();

	zswap_pool_total_size = total;
}

/*********************************
* zswap entry functions
**********************************/
static struct kmem_cache *zswap_entry_cache;

static int __init zswap_entry_cache_create(void)
{
	zswap_entry_cache = KMEM_CACHE(zswap_entry, 0);
	return zswap_entry_cache == NULL;
}

static void __init zswap_entry_cache_destroy(void)
{
	kmem_cache_destroy(zswap_entry_cache);
}

static struct zswap_entry *zswap_entry_cache_alloc(gfp_t gfp)
{
	struct zswap_entry *entry;
	entry = kmem_cache_alloc(zswap_entry_cache, gfp);
	if (!entry)
		return NULL;
	entry->refcount = 1;
	RB_CLEAR_NODE(&entry->rbnode);
	return entry;
}

static void zswap_entry_cache_free(struct zswap_entry *entry)
{
	kmem_cache_free(zswap_entry_cache, entry);
}

/**
 * by_n_corder_swap - swap values of @o1 and @o2 if @l1 < @l2
 * @l1: length1
 * @l2; length2
 * @o1: order index 1
 * @o2: order index 2
 */
#define by_n_corder_swap(l1, l2,o1,o2) \
	do { if ((l1) < (l2)) {typeof(o1) __tmp = (o1); (o1) = (o2); (o2) = __tmp;} } while (0)

static void __zswap_sort_by_n_order(struct zswap_entry *entry)
{
	switch (zswap_by_n) {
		case 2: /* by2*/
			by_n_corder_swap(entry->by_n_length[entry->by_n_length_order[0]],entry->by_n_length[entry->by_n_length_order[1]],entry->by_n_length_order[0],entry->by_n_length_order[1]);
			break;
		case 3: /* by3*/
			by_n_corder_swap(entry->by_n_length[entry->by_n_length_order[0]],entry->by_n_length[entry->by_n_length_order[2]],entry->by_n_length_order[0],entry->by_n_length_order[2]);
			by_n_corder_swap(entry->by_n_length[entry->by_n_length_order[0]],entry->by_n_length[entry->by_n_length_order[1]],entry->by_n_length_order[0],entry->by_n_length_order[1]);
			by_n_corder_swap(entry->by_n_length[entry->by_n_length_order[1]],entry->by_n_length[entry->by_n_length_order[2]],entry->by_n_length_order[1],entry->by_n_length_order[2]);
			break;
		case 4: /* by4*/
			by_n_corder_swap(entry->by_n_length[entry->by_n_length_order[0]],entry->by_n_length[entry->by_n_length_order[2]],entry->by_n_length_order[0],entry->by_n_length_order[2]);
			by_n_corder_swap(entry->by_n_length[entry->by_n_length_order[1]],entry->by_n_length[entry->by_n_length_order[3]],entry->by_n_length_order[1],entry->by_n_length_order[3]);
			by_n_corder_swap(entry->by_n_length[entry->by_n_length_order[0]],entry->by_n_length[entry->by_n_length_order[1]],entry->by_n_length_order[0],entry->by_n_length_order[1]);
			by_n_corder_swap(entry->by_n_length[entry->by_n_length_order[2]],entry->by_n_length[entry->by_n_length_order[3]],entry->by_n_length_order[2],entry->by_n_length_order[3]);
			by_n_corder_swap(entry->by_n_length[entry->by_n_length_order[1]],entry->by_n_length[entry->by_n_length_order[2]],entry->by_n_length_order[1],entry->by_n_length_order[2]);
    }
}

/*********************************
* rbtree functions
**********************************/
static struct zswap_entry *zswap_rb_search(struct rb_root *root, pgoff_t offset)
{
	struct rb_node *node = root->rb_node;
	struct zswap_entry *entry;

	while (node) {
		entry = rb_entry(node, struct zswap_entry, rbnode);
		if (entry->offset > offset)
			node = node->rb_left;
		else if (entry->offset < offset)
			node = node->rb_right;
		else
			return entry;
	}
	return NULL;
}

/*
 * In the case that a entry with the same offset is found, a pointer to
 * the existing entry is stored in dupentry and the function returns -EEXIST
 */
static int zswap_rb_insert(struct rb_root *root, struct zswap_entry *entry,
			struct zswap_entry **dupentry)
{
	struct rb_node **link = &root->rb_node, *parent = NULL;
	struct zswap_entry *myentry;

	while (*link) {
		parent = *link;
		myentry = rb_entry(parent, struct zswap_entry, rbnode);
		if (myentry->offset > entry->offset)
			link = &(*link)->rb_left;
		else if (myentry->offset < entry->offset)
			link = &(*link)->rb_right;
		else {
			*dupentry = myentry;
			return -EEXIST;
		}
	}
	rb_link_node(&entry->rbnode, parent, link);
	rb_insert_color(&entry->rbnode, root);
	return 0;
}

static void zswap_rb_erase(struct rb_root *root, struct zswap_entry *entry)
{
	if (!RB_EMPTY_NODE(&entry->rbnode)) {
		rb_erase(&entry->rbnode, root);
		RB_CLEAR_NODE(&entry->rbnode);
	}
}

/*
 * Carries out the common pattern of freeing and entry's zpool allocation,
 * freeing the entry itself, and decrementing the number of stored pages.
 */
static void zswap_free_entry(struct zswap_entry *entry)
{
	if (entry->objcg) {
		obj_cgroup_uncharge_zswap(entry->objcg, entry->length);
		obj_cgroup_put(entry->objcg);
	}
	if (!entry->length)
		atomic_dec(&zswap_same_filled_pages);
	else {
		zpool_free(entry->pool->zpool, entry->handle);
		zswap_pool_put(entry->pool);
	}
	zswap_entry_cache_free(entry);
	atomic_dec(&zswap_stored_pages);
	zswap_update_total_size();
}

/* caller must hold the tree lock */
static void zswap_entry_get(struct zswap_entry *entry)
{
	entry->refcount++;
}

/* caller must hold the tree lock
* remove from the tree and free it, if nobody reference the entry
*/
static void zswap_entry_put(struct zswap_tree *tree,
			struct zswap_entry *entry)
{
	int refcount = --entry->refcount;

	BUG_ON(refcount < 0);
	if (refcount == 0) {
		zswap_rb_erase(&tree->rbroot, entry);
		zswap_free_entry(entry);
	}
}

/* caller must hold the tree lock */
static struct zswap_entry *zswap_entry_find_get(struct rb_root *root,
				pgoff_t offset)
{
	struct zswap_entry *entry;

	entry = zswap_rb_search(root, offset);
	if (entry)
		zswap_entry_get(entry);

	return entry;
}

/*********************************
* per-cpu code
**********************************/
static DEFINE_PER_CPU(u8 *, zswap_dstmem);
/*
 * If users dynamically change the zpool type and compressor at runtime, i.e.
 * zswap is running, zswap can have more than one zpool on one cpu, but they
 * are sharing dtsmem. So we need this mutex to be per-cpu.
 */
static DEFINE_PER_CPU(struct mutex *, zswap_mutex);

static int zswap_dstmem_prepare(unsigned int cpu)
{
	struct mutex *mutex;
	u8 *dst;

	dst = kmalloc_node(PAGE_SIZE * 2, GFP_KERNEL, cpu_to_node(cpu));
	if (!dst)
		return -ENOMEM;

	mutex = kmalloc_node(sizeof(*mutex), GFP_KERNEL, cpu_to_node(cpu));
	if (!mutex) {
		kfree(dst);
		return -ENOMEM;
	}

	mutex_init(mutex);
	per_cpu(zswap_dstmem, cpu) = dst;
	per_cpu(zswap_mutex, cpu) = mutex;
	return 0;
}

static int zswap_dstmem_dead(unsigned int cpu)
{
	struct mutex *mutex;
	u8 *dst;

	mutex = per_cpu(zswap_mutex, cpu);
	kfree(mutex);
	per_cpu(zswap_mutex, cpu) = NULL;

	dst = per_cpu(zswap_dstmem, cpu);
	kfree(dst);
	per_cpu(zswap_dstmem, cpu) = NULL;

	return 0;
}

static int zswap_cpu_comp_prepare(unsigned int cpu, struct hlist_node *node)
{
	struct zswap_pool *pool = hlist_entry(node, struct zswap_pool, node);
	struct crypto_acomp_ctx *acomp_ctx = per_cpu_ptr(pool->acomp_ctx, cpu);
	struct crypto_acomp_ctx *secondary_acomp_ctx = per_cpu_ptr(pool->secondary_acomp_ctx, cpu);
	struct crypto_acomp *acomp;
	struct acomp_req *req;
	int i, j;
	const char *secondary_tfm_name = "lzo-rle";

	acomp = crypto_alloc_acomp_node(pool->tfm_name, 0, 0, cpu_to_node(cpu));
	if (IS_ERR(acomp)) {
		pr_err("could not alloc crypto acomp %s : %ld\n",
				pool->tfm_name, PTR_ERR(acomp));
		return PTR_ERR(acomp);
	}
	acomp_ctx->acomp = acomp;

	req = acomp_request_alloc(acomp_ctx->acomp);
	if (!req) {
		pr_err("could not alloc crypto acomp_request %s\n",
		       pool->tfm_name);
		crypto_free_acomp(acomp_ctx->acomp);
		return -ENOMEM;
	}
	acomp_ctx->req = req;

	for (i = 0; i < MAX_BY_N; i++) {
		struct acomp_req *by_n_req;

		by_n_req = acomp_request_alloc(acomp_ctx->acomp);
		if (!by_n_req) {
			pr_err("could not alloc crypto acomp_request req[%d] %s\n",
			       i, pool->tfm_name);
			for (j = 0; j < i; j++)
				acomp_request_free(acomp_ctx->by_n_req[j]);
			acomp_request_free(acomp_ctx->req);
			crypto_free_acomp(acomp_ctx->acomp);
			return -ENOMEM;
		}
		acomp_ctx->by_n_req[i] = by_n_req;
	}

	crypto_init_wait(&acomp_ctx->wait);
	/*
	 * if the backend of acomp is async zip, crypto_req_done() will wakeup
	 * crypto_wait_req(); if the backend of acomp is scomp, the callback
	 * won't be called, crypto_wait_req() will return without blocking.
	 */
	acomp_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				   crypto_req_done, &acomp_ctx->wait);

	acomp_ctx->mutex = per_cpu(zswap_mutex, cpu);
	acomp_ctx->dstmem = per_cpu(zswap_dstmem, cpu);

	/* Set up secondary crypto_acomp_ctx: */
	acomp = crypto_alloc_acomp_node(secondary_tfm_name, 0, 0, cpu_to_node(cpu));
	if (IS_ERR(acomp)) {
		pr_err("could not alloc secondary crypto acomp %s : %ld\n",
				secondary_tfm_name, PTR_ERR(acomp));
		return PTR_ERR(acomp);
	}
	secondary_acomp_ctx->acomp = acomp;

	req = acomp_request_alloc(secondary_acomp_ctx->acomp);
	if (!req) {
		pr_err("could not alloc secondary crypto acomp_request %s\n",
		       secondary_tfm_name);
		acomp_request_free(acomp_ctx->req);
		crypto_free_acomp(acomp_ctx->acomp);
		crypto_free_acomp(secondary_acomp_ctx->acomp);
		return -ENOMEM;
	}
	secondary_acomp_ctx->req = req;

	crypto_init_wait(&secondary_acomp_ctx->wait);
	acomp_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				   crypto_req_done, &secondary_acomp_ctx->wait);

	secondary_acomp_ctx->mutex = per_cpu(zswap_mutex, cpu);
	secondary_acomp_ctx->dstmem = per_cpu(zswap_dstmem, cpu);
	/* *** */

	return 0;
}

static int zswap_cpu_comp_dead(unsigned int cpu, struct hlist_node *node)
{
	struct zswap_pool *pool = hlist_entry(node, struct zswap_pool, node);
	struct crypto_acomp_ctx *acomp_ctx = per_cpu_ptr(pool->acomp_ctx, cpu);
	int i;

	if (!IS_ERR_OR_NULL(acomp_ctx)) {
		if (!IS_ERR_OR_NULL(acomp_ctx->req))
			acomp_request_free(acomp_ctx->req);
		for (i = 0; i < MAX_BY_N; i++) {
			if (!IS_ERR_OR_NULL(acomp_ctx->by_n_req[i]))
				acomp_request_free(acomp_ctx->by_n_req[i]);
		}
		if (!IS_ERR_OR_NULL(acomp_ctx->acomp))
			crypto_free_acomp(acomp_ctx->acomp);
	}

	acomp_ctx = per_cpu_ptr(pool->secondary_acomp_ctx, cpu);
	if (!IS_ERR_OR_NULL(acomp_ctx)) {
		if (!IS_ERR_OR_NULL(acomp_ctx->req))
			acomp_request_free(acomp_ctx->req);
		if (!IS_ERR_OR_NULL(acomp_ctx->acomp))
			crypto_free_acomp(acomp_ctx->acomp);
	}

	return 0;
}

/*********************************
* pool functions
**********************************/

static struct zswap_pool *__zswap_pool_current(void)
{
	struct zswap_pool *pool;

	pool = list_first_or_null_rcu(&zswap_pools, typeof(*pool), list);
	WARN_ONCE(!pool && zswap_has_pool,
		  "%s: no page storage pool!\n", __func__);

	return pool;
}

static struct zswap_pool *zswap_pool_current(void)
{
	assert_spin_locked(&zswap_pools_lock);

	return __zswap_pool_current();
}

static struct zswap_pool *zswap_pool_current_get(void)
{
	struct zswap_pool *pool;

	rcu_read_lock();

	pool = __zswap_pool_current();
	if (!zswap_pool_get(pool))
		pool = NULL;

	rcu_read_unlock();

	return pool;
}

static struct zswap_pool *zswap_pool_last_get(void)
{
	struct zswap_pool *pool, *last = NULL;

	rcu_read_lock();

	list_for_each_entry_rcu(pool, &zswap_pools, list)
		last = pool;
	WARN_ONCE(!last && zswap_has_pool,
		  "%s: no page storage pool!\n", __func__);
	if (!zswap_pool_get(last))
		last = NULL;

	rcu_read_unlock();

	return last;
}

/* type and compressor must be null-terminated */
static struct zswap_pool *zswap_pool_find_get(char *type, char *compressor)
{
	struct zswap_pool *pool;

	assert_spin_locked(&zswap_pools_lock);

	list_for_each_entry_rcu(pool, &zswap_pools, list) {
		if (strcmp(pool->tfm_name, compressor))
			continue;
		if (strcmp(zpool_get_type(pool->zpool), type))
			continue;
		/* if we can't get it, it's about to be destroyed */
		if (!zswap_pool_get(pool))
			continue;
		return pool;
	}

	return NULL;
}

static void shrink_worker(struct work_struct *w)
{
	struct zswap_pool *pool = container_of(w, typeof(*pool),
						shrink_work);

	if (zpool_shrink(pool->zpool, 1, NULL))
		zswap_reject_reclaim_fail++;
	zswap_pool_put(pool);
}

static struct zswap_pool *zswap_pool_create(char *type, char *compressor)
{
	struct zswap_pool *pool;
	char name[38]; /* 'zswap' + 32 char (max) num + \0 */
	gfp_t gfp = __GFP_NORETRY | __GFP_NOWARN | __GFP_KSWAPD_RECLAIM;
	int ret;

	if (!zswap_has_pool) {
		/* if either are unset, pool initialization failed, and we
		 * need both params to be set correctly before trying to
		 * create a pool.
		 */
		if (!strcmp(type, ZSWAP_PARAM_UNSET))
			return NULL;
		if (!strcmp(compressor, ZSWAP_PARAM_UNSET))
			return NULL;
	}

	pool = kzalloc(sizeof(*pool), GFP_KERNEL);
	if (!pool)
		return NULL;

	/* unique name for each pool specifically required by zsmalloc */
	snprintf(name, 38, "zswap%x", atomic_inc_return(&zswap_pools_count));

	pool->zpool = zpool_create_pool(type, name, gfp, &zswap_zpool_ops);
	if (!pool->zpool) {
		pr_err("%s zpool not available\n", type);
		goto error;
	}
	pr_debug("using %s zpool\n", zpool_get_type(pool->zpool));

	strscpy(pool->tfm_name, compressor, sizeof(pool->tfm_name));

	pool->acomp_ctx = alloc_percpu(*pool->acomp_ctx);
	if (!pool->acomp_ctx) {
		pr_err("percpu alloc failed\n");
		goto error;
	}

	pool->secondary_acomp_ctx = alloc_percpu(*pool->secondary_acomp_ctx);
	if (!pool->secondary_acomp_ctx) {
		pr_err("percpu alloc failed\n");
		goto error;
	}

	ret = cpuhp_state_add_instance(CPUHP_MM_ZSWP_POOL_PREPARE,
				       &pool->node);
	if (ret)
		goto error;
	pr_debug("using %s compressor\n", pool->tfm_name);

	/* being the current pool takes 1 ref; this func expects the
	 * caller to always add the new pool as the current pool
	 */
	kref_init(&pool->kref);
	INIT_LIST_HEAD(&pool->list);
	INIT_WORK(&pool->shrink_work, shrink_worker);

	zswap_pool_debug("created", pool);

	return pool;

error:
	if (pool->acomp_ctx)
		free_percpu(pool->acomp_ctx);
	if (pool->secondary_acomp_ctx)
		free_percpu(pool->secondary_acomp_ctx);
	if (pool->zpool)
		zpool_destroy_pool(pool->zpool);
	kfree(pool);
	return NULL;
}

static __init struct zswap_pool *__zswap_pool_create_fallback(void)
{
	bool has_comp, has_zpool;

	has_comp = crypto_has_acomp(zswap_compressor, 0, 0);
	if (!has_comp && strcmp(zswap_compressor,
				CONFIG_ZSWAP_COMPRESSOR_DEFAULT)) {
		pr_err("compressor %s not available, using default %s\n",
		       zswap_compressor, CONFIG_ZSWAP_COMPRESSOR_DEFAULT);
		param_free_charp(&zswap_compressor);
		zswap_compressor = CONFIG_ZSWAP_COMPRESSOR_DEFAULT;
		has_comp = crypto_has_acomp(zswap_compressor, 0, 0);
	}
	if (!has_comp) {
		pr_err("default compressor %s not available\n",
		       zswap_compressor);
		param_free_charp(&zswap_compressor);
		zswap_compressor = ZSWAP_PARAM_UNSET;
	}

	has_zpool = zpool_has_pool(zswap_zpool_type);
	if (!has_zpool && strcmp(zswap_zpool_type,
				 CONFIG_ZSWAP_ZPOOL_DEFAULT)) {
		pr_err("zpool %s not available, using default %s\n",
		       zswap_zpool_type, CONFIG_ZSWAP_ZPOOL_DEFAULT);
		param_free_charp(&zswap_zpool_type);
		zswap_zpool_type = CONFIG_ZSWAP_ZPOOL_DEFAULT;
		has_zpool = zpool_has_pool(zswap_zpool_type);
	}
	if (!has_zpool) {
		pr_err("default zpool %s not available\n",
		       zswap_zpool_type);
		param_free_charp(&zswap_zpool_type);
		zswap_zpool_type = ZSWAP_PARAM_UNSET;
	}

	if (!has_comp || !has_zpool)
		return NULL;

	return zswap_pool_create(zswap_zpool_type, zswap_compressor);
}

static void zswap_pool_destroy(struct zswap_pool *pool)
{
	zswap_pool_debug("destroying", pool);

	cpuhp_state_remove_instance(CPUHP_MM_ZSWP_POOL_PREPARE, &pool->node);
	free_percpu(pool->acomp_ctx);
	free_percpu(pool->secondary_acomp_ctx);
	zpool_destroy_pool(pool->zpool);
	kfree(pool);
}

static int __must_check zswap_pool_get(struct zswap_pool *pool)
{
	if (!pool)
		return 0;

	return kref_get_unless_zero(&pool->kref);
}

static void __zswap_pool_release(struct work_struct *work)
{
	struct zswap_pool *pool = container_of(work, typeof(*pool),
						release_work);

	synchronize_rcu();

	/* nobody should have been able to get a kref... */
	WARN_ON(kref_get_unless_zero(&pool->kref));

	/* pool is now off zswap_pools list and has no references. */
	zswap_pool_destroy(pool);
}

static void __zswap_pool_empty(struct kref *kref)
{
	struct zswap_pool *pool;

	pool = container_of(kref, typeof(*pool), kref);

	spin_lock(&zswap_pools_lock);

	WARN_ON(pool == zswap_pool_current());

	list_del_rcu(&pool->list);

	INIT_WORK(&pool->release_work, __zswap_pool_release);
	schedule_work(&pool->release_work);

	spin_unlock(&zswap_pools_lock);
}

static void zswap_pool_put(struct zswap_pool *pool)
{
	kref_put(&pool->kref, __zswap_pool_empty);
}

/*********************************
* param callbacks
**********************************/

/* val must be a null-terminated string */
static int __zswap_param_set(const char *val, const struct kernel_param *kp,
			     char *type, char *compressor)
{
	struct zswap_pool *pool, *put_pool = NULL;
	char *s = strstrip((char *)val);
	int ret;

	if (zswap_init_failed) {
		pr_err("can't set param, initialization failed\n");
		return -ENODEV;
	}

	/* no change required */
	if (!strcmp(s, *(char **)kp->arg) && zswap_has_pool)
		return 0;

	/* if this is load-time (pre-init) param setting,
	 * don't create a pool; that's done during init.
	 */
	if (!zswap_init_started)
		return param_set_charp(s, kp);

	if (!type) {
		if (!zpool_has_pool(s)) {
			pr_err("zpool %s not available\n", s);
			return -ENOENT;
		}
		type = s;
	} else if (!compressor) {
		if (!crypto_has_acomp(s, 0, 0)) {
			pr_err("compressor %s not available\n", s);
			return -ENOENT;
		}
		compressor = s;
	} else {
		WARN_ON(1);
		return -EINVAL;
	}

	spin_lock(&zswap_pools_lock);

	pool = zswap_pool_find_get(type, compressor);
	if (pool) {
		zswap_pool_debug("using existing", pool);
		WARN_ON(pool == zswap_pool_current());
		list_del_rcu(&pool->list);
	}

	spin_unlock(&zswap_pools_lock);

	if (!pool)
		pool = zswap_pool_create(type, compressor);

	if (pool)
		ret = param_set_charp(s, kp);
	else
		ret = -EINVAL;

	spin_lock(&zswap_pools_lock);

	if (!ret) {
		put_pool = zswap_pool_current();
		list_add_rcu(&pool->list, &zswap_pools);
		zswap_has_pool = true;
	} else if (pool) {
		/* add the possibly pre-existing pool to the end of the pools
		 * list; if it's new (and empty) then it'll be removed and
		 * destroyed by the put after we drop the lock
		 */
		list_add_tail_rcu(&pool->list, &zswap_pools);
		put_pool = pool;
	}

	spin_unlock(&zswap_pools_lock);

	if (!zswap_has_pool && !pool) {
		/* if initial pool creation failed, and this pool creation also
		 * failed, maybe both compressor and zpool params were bad.
		 * Allow changing this param, so pool creation will succeed
		 * when the other param is changed. We already verified this
		 * param is ok in the zpool_has_pool() or crypto_has_acomp()
		 * checks above.
		 */
		ret = param_set_charp(s, kp);
	}

	/* drop the ref from either the old current pool,
	 * or the new pool we failed to add
	 */
	if (put_pool)
		zswap_pool_put(put_pool);

	return ret;
}

static int zswap_compressor_param_set(const char *val,
				      const struct kernel_param *kp)
{
	return __zswap_param_set(val, kp, zswap_zpool_type, NULL);
}

static int zswap_zpool_param_set(const char *val,
				 const struct kernel_param *kp)
{
	return __zswap_param_set(val, kp, NULL, zswap_compressor);
}

static int zswap_enabled_param_set(const char *val,
				   const struct kernel_param *kp)
{
	if (zswap_init_failed) {
		pr_err("can't enable, initialization failed\n");
		return -ENODEV;
	}
	if (!zswap_has_pool && zswap_init_started) {
		pr_err("can't enable, no pool configured\n");
		return -ENODEV;
	}

	return param_set_bool(val, kp);
}

/*********************************
* writeback code
**********************************/
/* return enum for zswap_get_swap_cache_page */
enum zswap_get_swap_ret {
	ZSWAP_SWAPCACHE_NEW,
	ZSWAP_SWAPCACHE_EXIST,
	ZSWAP_SWAPCACHE_FAIL,
};

/*
 * zswap_get_swap_cache_page
 *
 * This is an adaption of read_swap_cache_async()
 *
 * This function tries to find a page with the given swap entry
 * in the swapper_space address space (the swap cache).  If the page
 * is found, it is returned in retpage.  Otherwise, a page is allocated,
 * added to the swap cache, and returned in retpage.
 *
 * If success, the swap cache page is returned in retpage
 * Returns ZSWAP_SWAPCACHE_EXIST if page was already in the swap cache
 * Returns ZSWAP_SWAPCACHE_NEW if the new page needs to be populated,
 *     the new page is added to swapcache and locked
 * Returns ZSWAP_SWAPCACHE_FAIL on error
 */
static int zswap_get_swap_cache_page(swp_entry_t entry,
				struct page **retpage)
{
	bool page_was_allocated;

	*retpage = __read_swap_cache_async(entry, GFP_KERNEL,
			NULL, 0, &page_was_allocated);
	if (page_was_allocated)
		return ZSWAP_SWAPCACHE_NEW;
	if (!*retpage)
		return ZSWAP_SWAPCACHE_FAIL;
	return ZSWAP_SWAPCACHE_EXIST;
}

static int do_by_n(struct by_n by_n[], int by_n_length_order[], unsigned int dlen[], bool decompress, u8* src, struct page *page)
{
	u8 req = 0xff >> (8 - zswap_by_n);
	int i, ret = 0;
	unsigned int dst_size = PAGE_SIZE/zswap_by_n;
	bool odd = zswap_by_n & 1;
	char *dst;
	unsigned int offset = 0;

	for (i = 0; i < zswap_by_n; i++) {
		if (decompress) {
			int index = by_n_length_order[i];
			if( by_n[index].req->slen  >= zswap_by_n_chunk_threshold) {
				req &= 0xff - (1 << index);
				dlen[index] = by_n[index].req->slen;
				ret = 0;
			}
		}
	}

	/* fire off all async compresses one after the other, wait below */
	for (i = 0; i < zswap_by_n; i++) {
		if (decompress ) {
			int index = by_n_length_order[i];
			if (req & (1 << index) ) {
				ret = crypto_acomp_decompress(by_n[index].req);
			}else
				ret = -EINPROGRESS;
		} else
			ret = crypto_acomp_compress(by_n[i].req);
		if (ret != -EINPROGRESS)
			goto err;
	}

	if(decompress == true) {
	    bool page_mapped = false;
		for (i = 0; i < zswap_by_n; i++) {
			if( by_n[i].req->slen  >= zswap_by_n_chunk_threshold ) {
				unsigned long by_n_dlen = (odd && (i == zswap_by_n - 1)) ? dst_size + 1 : dst_size;
				char *local_src = src;
				if (!page_mapped) {
					dst = kmap_atomic(page);
					page_mapped = true;
				}
				memcpy(dst + (i * dst_size), local_src + offset, by_n[i].req->slen);
				dlen[i] = by_n_dlen;
				ret = 0;
			}
			offset += by_n[i].req->slen;
		}

	    if (page_mapped)
		    kunmap_atomic(dst);
	}

	/* wait for all async compresses to finish */
	do {
		for (i = 0; i < zswap_by_n; i++) {
			int index = decompress ? by_n_length_order[i] : i;
			if (req & (1 << index) ) {
				ret = crypto_acomp_poll(by_n[index].req);

				if (ret && ret != -EAGAIN)
					goto err;
				if (ret == 0)
					req &= 0xff - (1 << index);
				dlen[index] = by_n[index].req->dlen;
			}
		}
		cpu_relax();
	} while (req);
err:
	return ret;
}

static int by_n_compress(struct crypto_acomp_ctx *acomp_ctx,
			 struct page *page, u8 *dst[],
			 unsigned int dlen[])
{
	unsigned int src_size, dst_size;
	bool odd = zswap_by_n & 1;
	struct by_n by_n[MAX_BY_N];
	int i;
	char *src;
	bool page_mapped = false;
	int ret;

	/* Each by_n gets (1/n)*2 pages e.g. by_2 gets (1/2)*2 = 1
	   page by_3 gets (1/3)*2 = 2/3 page, by_ gets (1/4)*2 = 1/2
	   page.  Since the source is a single page, that leaves
	   plenty of room for each compression even if the compressed
	   size is greater than the uncompressed size. */

	/* total src size is 1 page, divide this between nths */
	src_size = PAGE_SIZE / zswap_by_n;
	/* total dest size is 2 pages, divide this between nths */
	dst_size = 2 * src_size;

	for (i = 0; i < zswap_by_n; i++) {
		/* offset each nth by dst_size*/
		dst[i] = acomp_ctx->dstmem + (i * dst_size);
		sg_init_table(&by_n[i].input, 1);
		/* the input size is 1 page divided into nths, length/offset */
		sg_set_page(&by_n[i].input, page,
			    // if n is odd and it's last nth, claim last byte
			    (odd && (i == zswap_by_n - 1)) ? src_size + 1 : src_size, i * src_size);
		/* the output size is dst_size */
		sg_init_one(&by_n[i].output, dst[i], dst_size);
	}

	/* allocate and set up the requests */
	for (i = 0; i < zswap_by_n; i++) {
		by_n[i].req = acomp_ctx->by_n_req[i];

		acomp_request_set_params(by_n[i].req, &by_n[i].input,
					 &by_n[i].output, (odd && (i == zswap_by_n - 1)) ? src_size + 1 : src_size,
					 dst_size);
	}

	ret = do_by_n(by_n, NULL, dlen, false, NULL, NULL);

	if (ret)
		goto out;

	for (i = 0; i < zswap_by_n; i++) {
		if(dlen[i] >= zswap_by_n_chunk_threshold) {
			unsigned long by_n_dlen = (odd && (i == zswap_by_n - 1)) ? src_size + 1 : src_size;
			if (!page_mapped) {
				src = kmap_atomic(page);
				page_mapped = true;
			}
			memcpy(dst[i], src + (i * src_size), by_n_dlen);
			dlen[i] = by_n_dlen;
		}
	}
	if (page_mapped)
		kunmap_atomic(src);

out:
	return ret;
}

static unsigned int by_n_length(struct zswap_entry *entry)
{
	unsigned int length = 0;
	int i;

	for (i = 0; i < zswap_by_n; i++)
		length += entry->by_n_length[i];

	return length;
}

static int by_n_decompress(struct crypto_acomp_ctx *acomp_ctx,
			   struct page *page, u8 *src,
			   struct zswap_entry *entry,
			   unsigned int dlen[])
{
	struct by_n by_n[MAX_BY_N];
	unsigned int dst_size, offset = 0;
	int i;
	bool odd = zswap_by_n & 1;

	/* total dst size is 1 page, divide this between nths */
	dst_size = PAGE_SIZE / zswap_by_n;

	for (i = 0; i < zswap_by_n; i++) {
		sg_init_one(&by_n[i].input, src + offset, entry->by_n_length[i]);
		offset += entry->by_n_length[i];
		sg_init_table(&by_n[i].output, 1);
		/* the out size is 1 page divided into nths, length/offset */
		sg_set_page(&by_n[i].output, page, dst_size, i * dst_size);
	}

	/* allocate and set up the requests */
	for (i = 0; i < zswap_by_n; i++) {
		by_n[i].req = acomp_ctx->by_n_req[i];

		acomp_request_set_params(by_n[i].req, &by_n[i].input,
					 &by_n[i].output, entry->by_n_length[i], (odd && (i == zswap_by_n - 1)) ? dst_size + 1 : dst_size);
	}

	return do_by_n(by_n, entry->by_n_length_order, dlen, true, src, page);
}

/*
 * Attempts to free an entry by adding a page to the swap cache,
 * decompressing the entry data into the page, and issuing a
 * bio write to write the page back to the swap device.
 *
 * This can be thought of as a "resumed writeback" of the page
 * to the swap device.  We are basically resuming the same swap
 * writeback path that was intercepted with the frontswap_store()
 * in the first place.  After the page has been decompressed into
 * the swap cache, the compressed version stored by zswap can be
 * freed.
 */
static int zswap_writeback_entry(struct zpool *pool, unsigned long handle)
{
	struct zswap_header *zhdr;
	swp_entry_t swpentry;
	struct zswap_tree *tree;
	pgoff_t offset;
	struct zswap_entry *entry;
	struct page *page;
	struct scatterlist input, output;
	struct crypto_acomp_ctx *acomp_ctx;
	u64 start_time_ns;

	u8 *src, *tmp = NULL;
	unsigned int dlen;
	int ret;
	struct writeback_control wbc = {
		.sync_mode = WB_SYNC_NONE,
	};

	if (!zpool_can_sleep_mapped(pool)) {
		tmp = kmalloc(PAGE_SIZE, GFP_KERNEL);
		if (!tmp)
			return -ENOMEM;
	}

	/* extract swpentry from data */
	zhdr = zpool_map_handle(pool, handle, ZPOOL_MM_RO);
	swpentry = zhdr->swpentry; /* here */
	tree = zswap_trees[swp_type(swpentry)];
	offset = swp_offset(swpentry);
	zpool_unmap_handle(pool, handle);

	/* find and ref zswap entry */
	spin_lock(&tree->lock);
	entry = zswap_entry_find_get(&tree->rbroot, offset);
	if (!entry) {
		/* entry was invalidated */
		spin_unlock(&tree->lock);
		kfree(tmp);
		return 0;
	}
	spin_unlock(&tree->lock);
	BUG_ON(offset != entry->offset);

	/* try to allocate swap cache page */
	switch (zswap_get_swap_cache_page(swpentry, &page)) {
	case ZSWAP_SWAPCACHE_FAIL: /* no memory or invalidate happened */
		ret = -ENOMEM;
		goto fail;

	case ZSWAP_SWAPCACHE_EXIST:
		/* page is already in the swap cache, ignore for now */
		put_page(page);
		ret = -EEXIST;
		goto fail;

	case ZSWAP_SWAPCACHE_NEW: /* page is locked */
		/* decompress */
		if (entry->use_secondary)
			acomp_ctx = raw_cpu_ptr(entry->pool->secondary_acomp_ctx);
		else
			acomp_ctx = raw_cpu_ptr(entry->pool->acomp_ctx);

		dlen = PAGE_SIZE;

		zhdr = zpool_map_handle(pool, handle, ZPOOL_MM_RO);
		src = (u8 *)zhdr + sizeof(struct zswap_header);
		if (!zpool_can_sleep_mapped(pool)) {
			memcpy(tmp, src, entry->length);
			src = tmp;
			zpool_unmap_handle(pool, handle);
		}

		mutex_lock(acomp_ctx->mutex);
		if (zswap_by_n && entry->by_n_length[0])
			/* page was compressed using by_n */
			goto by_n;
		sg_init_one(&input, src, entry->length);
		sg_init_table(&output, 1);
		sg_set_page(&output, page, PAGE_SIZE, 0);
		acomp_request_set_params(acomp_ctx->req, &input, &output, entry->length, dlen);

		if (acomp_ctx->acomp->poll) {
			/* normal page or by_n enabled but page wasn't split */

			start_time_ns = ktime_get_ns();
			ret = crypto_acomp_decompress(acomp_ctx->req);
			if (ret == -EINPROGRESS) {
				do {
					ret = crypto_acomp_poll(acomp_ctx->req);
					if (ret && ret != -EAGAIN)
						break;
					cpu_relax();
				} while (ret);
			}
			trace_zswap_writeback_lat_async(acomp_ctx->req, ktime_get_ns() - start_time_ns, raw_smp_processor_id(), ret);
		} else {
			start_time_ns = ktime_get_ns();
			ret = crypto_wait_req(crypto_acomp_decompress(acomp_ctx->req), &acomp_ctx->wait);
			trace_zswap_writeback_lat_sync(acomp_ctx->req, ktime_get_ns() - start_time_ns, raw_smp_processor_id(), ret);
		}
by_n:
		if (zswap_by_n && entry->by_n_length[0]) {
			unsigned int by_n_dlen[MAX_BY_N];
			int i;

			start_time_ns = ktime_get_ns();
			ret = by_n_decompress(acomp_ctx, page, src, entry, by_n_dlen);
			trace_zswap_writeback_lat_by_n(acomp_ctx->req, zswap_by_n, ktime_get_ns() - start_time_ns, raw_smp_processor_id(), ret);			
			dlen = 0;
			for (i = 0; i < zswap_by_n; i++)
				dlen += by_n_dlen[i];
		} else
			dlen = acomp_ctx->req->dlen;
		mutex_unlock(acomp_ctx->mutex);

		if (!zpool_can_sleep_mapped(pool))
			kfree(tmp);
		else
			zpool_unmap_handle(pool, handle);

		BUG_ON(ret);
		BUG_ON(dlen != PAGE_SIZE);

		/* page is up to date */
		SetPageUptodate(page);
	}

	/* move it to the tail of the inactive list after end_writeback */
	SetPageReclaim(page);

	/* start writeback */
	__swap_writepage(page, &wbc);
	put_page(page);
	zswap_written_back_pages++;

	spin_lock(&tree->lock);
	/* drop local reference */
	zswap_entry_put(tree, entry);

	/*
	* There are two possible situations for entry here:
	* (1) refcount is 1(normal case),  entry is valid and on the tree
	* (2) refcount is 0, entry is freed and not on the tree
	*     because invalidate happened during writeback
	*  search the tree and free the entry if find entry
	*/
	if (entry == zswap_rb_search(&tree->rbroot, offset))
		zswap_entry_put(tree, entry);
	spin_unlock(&tree->lock);

	return ret;

fail:
	if (!zpool_can_sleep_mapped(pool))
		kfree(tmp);

	/*
	* if we get here due to ZSWAP_SWAPCACHE_EXIST
	* a load may be happening concurrently.
	* it is safe and okay to not free the entry.
	* if we free the entry in the following put
	* it is also okay to return !0
	*/
	spin_lock(&tree->lock);
	zswap_entry_put(tree, entry);
	spin_unlock(&tree->lock);

	return ret;
}

static int zswap_is_page_same_filled(void *ptr, unsigned long *value)
{
	unsigned int pos;
	unsigned long *page;

	page = (unsigned long *)ptr;
	for (pos = 1; pos < PAGE_SIZE / sizeof(*page); pos++) {
		if (page[pos] != page[0])
			return 0;
	}
	*value = page[0];
	return 1;
}

static void zswap_fill_page(void *ptr, unsigned long value)
{
	unsigned long *page;

	page = (unsigned long *)ptr;
	memset_l(page, value, PAGE_SIZE / sizeof(unsigned long));
}

/*********************************
* frontswap hooks
**********************************/
/* attempts to compress and store an single page */
static int zswap_frontswap_store(unsigned type, pgoff_t offset,
				struct page *page)
{
	struct zswap_tree *tree = zswap_trees[type];
	struct zswap_entry *entry, *dupentry;
	struct scatterlist input, output;
	struct crypto_acomp_ctx *acomp_ctx = NULL;
	struct obj_cgroup *objcg = NULL;
	struct zswap_pool *pool;
	int ret;
	unsigned int hlen, dlen = PAGE_SIZE;
	unsigned long handle, value;
	char *buf;
	u8 *src, *dst;
	u8 *by_n_dst[MAX_BY_N];
	unsigned int by_n_dlen[MAX_BY_N];
	struct zswap_header zhdr = { .swpentry = swp_entry(type, offset) };
	u64 start_time_ns;
	u64 end_time_ns;
	gfp_t gfp;
	bool is_by_n = false; /* will be set true if page will be stored by_n */

	/* THP isn't supported */
	if (PageTransHuge(page)) {
		ret = -EINVAL;
		goto reject;
	}

	if (!zswap_enabled || !tree) {
		ret = -ENODEV;
		goto reject;
	}

	objcg = get_obj_cgroup_from_page(page);
	if (objcg && !obj_cgroup_may_zswap(objcg))
		goto shrink;

	/* reclaim space if needed */
	if (zswap_is_full()) {
		zswap_pool_limit_hit++;
		zswap_pool_reached_full = true;
		goto shrink;
	}

	if (zswap_pool_reached_full) {
	       if (!zswap_can_accept()) {
			ret = -ENOMEM;
			goto reject;
		} else
			zswap_pool_reached_full = false;
	}

	/* allocate entry */
	entry = zswap_entry_cache_alloc(GFP_KERNEL);
	if (!entry) {
		zswap_reject_kmemcache_fail++;
		ret = -ENOMEM;
		goto reject;
	}

	if (zswap_same_filled_pages_enabled) {
		src = kmap_atomic(page);
		if (zswap_is_page_same_filled(src, &value)) {
			kunmap_atomic(src);
			entry->offset = offset;
			entry->length = 0;
			entry->value = value;
			atomic_inc(&zswap_same_filled_pages);
			goto insert_entry;
		}
		kunmap_atomic(src);
	}

	if (!zswap_non_same_filled_pages_enabled) {
		ret = -EINVAL;
		goto freepage;
	}

	/* if entry is successfully added, it keeps the reference */
	entry->pool = zswap_pool_current_get();
	if (!entry->pool) {
		ret = -EINVAL;
		goto freepage;
	}

	/* compress */

	acomp_ctx = raw_cpu_ptr(entry->pool->acomp_ctx);
	entry->use_secondary = false;

	if (zswap_secondary_threshold) {
		/*
		 * Start with the secondary compressor so that the threshold is
		 * made against its result (rather than against the result of
		 * the primary compressor).
		 */
		acomp_ctx = raw_cpu_ptr(entry->pool->secondary_acomp_ctx);
		entry->use_secondary = true;
	}
recompress:
	mutex_lock(acomp_ctx->mutex);

	/* If by_n is disabled, use normal compress/decompress
	   pathways.  That means either 1) sync mode (internal driver
	   polling before returning, or 2) driver irq wakes up sleeping
	   caller).

	   If by_n is enabled, that means using async mode with the
	   crypto layer poll() interface (called from zswap).  If by_n
	   threshold is 0, all pages use by_n splitting.  If by_n
	   threshold is 4096, pages are never split.  If the threshold
	   is anything in between, some pages will be split and others
	   not.  In order to do the latter, the page needs to first be
	   compressed and the dlen checked against the threshold.

	   The threshold = 0 and 4096 cases are never checked but
	   still use the crypto poll() interface.  The poll()
	   interface is always used when by_n is enabled on the
	   assumption that polling is the fastest and otherwise by_n
	   wouldn't be being used.

	   This provides an easy way to test the async no-irq
	   interface against the interrupt interface - just set
	   threshold to 4096 to never split and compare against the
	   async irq version (e.g. set iaa crypto driver to use async
	   irq vs async noirq with 4096 zswap by_n threshold.
	 */
	if (zswap_by_n && (zswap_by_n_threshold == 0) && !entry->use_secondary)
		/* always hit threshold, no need to check */
		goto by_n;

	dst = acomp_ctx->dstmem;
	sg_init_table(&input, 1);
	sg_set_page(&input, page, PAGE_SIZE, 0);

	/* zswap_dstmem is of size (PAGE_SIZE * 2). Reflect same in sg_list */
	sg_init_one(&output, dst, PAGE_SIZE * 2);
	acomp_request_set_params(acomp_ctx->req, &input, &output, PAGE_SIZE, dlen);
	/*
	 * it maybe looks a little bit silly that we send an asynchronous request,
	 * then wait for its completion synchronously. This makes the process look
	 * synchronous in fact.
	 * Theoretically, acomp supports users send multiple acomp requests in one
	 * acomp instance, then get those requests done simultaneously. but in this
	 * case, frontswap actually does store and load page by page, there is no
	 * existing method to send the second page before the first page is done
	 * in one thread doing frontswap.
	 * but in different threads running on different cpu, we have different
	 * acomp instance, so multiple threads can do (de)compression in parallel.
	 */
	if (acomp_ctx->acomp->poll) {
		start_time_ns = ktime_get_ns();

		ret = crypto_acomp_compress(acomp_ctx->req);
		if (ret == -EINPROGRESS) {
			do {
				ret = crypto_acomp_poll(acomp_ctx->req);
				if (ret && ret != -EAGAIN)
					break;
				cpu_relax();
			} while (ret);
		}
		end_time_ns = ktime_get_ns();
	} else {
		start_time_ns = ktime_get_ns();
		ret = crypto_wait_req(crypto_acomp_compress(acomp_ctx->req), &acomp_ctx->wait);
		end_time_ns = ktime_get_ns();
	}

	if (ret) {
		ret = -EINVAL;
		goto put_dstmem;
	}

	dlen = acomp_ctx->req->dlen;
by_n:
	if (zswap_by_n && dlen > zswap_by_n_threshold && !entry->use_secondary) {
		start_time_ns = ktime_get_ns();
		ret = by_n_compress(acomp_ctx, page, by_n_dst, by_n_dlen);
		end_time_ns = ktime_get_ns();
		if (ret)
			goto put_dstmem;
		is_by_n = true;
	}

	if (ret) {
		ret = -EINVAL;
		goto put_dstmem;
	}

	if (entry->use_secondary && dlen >= zswap_secondary_threshold) {
		mutex_unlock(acomp_ctx->mutex);
		acomp_ctx = raw_cpu_ptr(entry->pool->acomp_ctx);
		entry->use_secondary = false;
		is_by_n = false;
		goto recompress;
	}

	/* store */
	hlen = zpool_evictable(entry->pool->zpool) ? sizeof(zhdr) : 0;
	gfp = __GFP_NORETRY | __GFP_NOWARN | __GFP_KSWAPD_RECLAIM;
	if (zpool_malloc_support_movable(entry->pool->zpool))
		gfp |= __GFP_HIGHMEM | __GFP_MOVABLE;
	if (is_by_n) {
		int i;

		dlen = 0;
		for (i = 0; i < zswap_by_n; i++)
			dlen += by_n_dlen[i];
	}
	ret = zpool_malloc(entry->pool->zpool, hlen + dlen, gfp, &handle);
	if (ret == -ENOSPC) {
		zswap_reject_compress_poor++;
		goto put_dstmem;
	}
	if (ret) {
		zswap_reject_alloc_fail++;
		goto put_dstmem;
	}
	buf = zpool_map_handle(entry->pool->zpool, handle, ZPOOL_MM_WO);
	memcpy(buf, &zhdr, hlen);
	if (is_by_n) {
		unsigned int offset = 0;
		int i;

		for (i = 0; i < zswap_by_n; i++) {
			memcpy(buf + hlen + offset, by_n_dst[i], by_n_dlen[i]);
			offset += by_n_dlen[i];
		}
	} else
		memcpy(buf + hlen, dst, dlen);

	zpool_unmap_handle(entry->pool->zpool, handle);
	mutex_unlock(acomp_ctx->mutex);

	/* populate entry */
	entry->offset = offset;
	entry->handle = handle;
	if (is_by_n) {
		unsigned int length = 0;
		int i;
		for (i = 0; i < zswap_by_n; i++) {
			entry->by_n_length[i] = by_n_dlen[i];
			length += by_n_dlen[i];
			entry->by_n_length_order[i] = i;
		}
		entry->length = length;
		__zswap_sort_by_n_order(entry);
	} else {
		entry->length = dlen;
		/*
		 * This is necessary to indicate that the page has *not* been
		 * stored by_n:
		 */
		entry->by_n_length[0] = 0;
	}

	if (is_by_n) {
		trace_zswap_store_lat_by_n(acomp_ctx->req, zswap_by_n,
					   end_time_ns - start_time_ns,
					   raw_smp_processor_id(),
					   by_n_dlen[0], by_n_dlen[1],
					   by_n_dlen[2], by_n_dlen[3], ret);
	} else if (acomp_ctx->acomp->poll) {
		trace_zswap_store_lat_async(acomp_ctx->req,
					    end_time_ns - start_time_ns,
					    raw_smp_processor_id(),
					    acomp_ctx->req->dlen, ret);
	} else {
		trace_zswap_store_lat_sync(acomp_ctx->req,
					   end_time_ns - start_time_ns,
					   raw_smp_processor_id(),
					   acomp_ctx->req->dlen, ret);
	}

	if (entry->use_secondary)
		atomic_inc(&zswap_secondary_used);
	else
		atomic_inc(&zswap_primary_used);

insert_entry:
	entry->objcg = objcg;
	if (objcg) {
		obj_cgroup_charge_zswap(objcg, entry->length);
		/* Account before objcg ref is moved to tree */
		count_objcg_event(objcg, ZSWPOUT);
	}

	/* map */
	spin_lock(&tree->lock);
	do {
		ret = zswap_rb_insert(&tree->rbroot, entry, &dupentry);
		if (ret == -EEXIST) {
			zswap_duplicate_entry++;
			/* remove from rbtree */
			zswap_rb_erase(&tree->rbroot, dupentry);
			zswap_entry_put(tree, dupentry);
		}
	} while (ret == -EEXIST);
	spin_unlock(&tree->lock);

	/* update stats */
	atomic_inc(&zswap_stored_pages);
	zswap_update_total_size();
	count_vm_event(ZSWPOUT);

	return 0;

put_dstmem:
	mutex_unlock(acomp_ctx->mutex);
	zswap_pool_put(entry->pool);
freepage:
	zswap_entry_cache_free(entry);
reject:
	trace_zswap_store_reject(acomp_ctx ? acomp_ctx->req : NULL,
				 raw_smp_processor_id(), ret);
	if (objcg)
		obj_cgroup_put(objcg);
	return ret;

shrink:
	pool = zswap_pool_last_get();
	if (pool)
		queue_work(shrink_wq, &pool->shrink_work);
	ret = -ENOMEM;
	goto reject;
}

/*
 * returns 0 if the page was successfully decompressed
 * return -1 on entry not found or error
*/
static int zswap_frontswap_load(unsigned type, pgoff_t offset,
				struct page *page)
{
	struct zswap_tree *tree = zswap_trees[type];
	struct zswap_entry *entry;
	struct scatterlist input, output;
	struct crypto_acomp_ctx *acomp_ctx;
	u8 *src, *dst, *tmp;
	unsigned int dlen;
	u64 start_time_ns;
	int ret;
	int i;
	bool is_by_n = false; /* will be set to true of page was stored by_n */

	/* find */
	spin_lock(&tree->lock);
	entry = zswap_entry_find_get(&tree->rbroot, offset);
	if (!entry) {
		/* entry was written back */
		spin_unlock(&tree->lock);
		return -1;
	}
	spin_unlock(&tree->lock);

	if (!entry->length) {
		dst = kmap_atomic(page);
		zswap_fill_page(dst, entry->value);
		kunmap_atomic(dst);
		ret = 0;
		goto stats;
	}

	is_by_n = entry->by_n_length[0] != 0;

	if (!zpool_can_sleep_mapped(entry->pool->zpool)) {
		unsigned length = entry->length;

		if (is_by_n)
			length = by_n_length(entry);

		tmp = kmalloc(length, GFP_KERNEL);
		if (!tmp) {
			ret = -ENOMEM;
			goto freeentry;
		}
	}

	/* decompress */
	dlen = PAGE_SIZE;
	src = zpool_map_handle(entry->pool->zpool, entry->handle, ZPOOL_MM_RO);
	if (zpool_evictable(entry->pool->zpool))
		src += sizeof(struct zswap_header);

	if (!zpool_can_sleep_mapped(entry->pool->zpool)) {
		unsigned length = entry->length;

		if (is_by_n)
			length = by_n_length(entry);

		memcpy(tmp, src, length);
		src = tmp;
		zpool_unmap_handle(entry->pool->zpool, entry->handle);
	}

	if (entry->use_secondary)
		acomp_ctx = raw_cpu_ptr(entry->pool->secondary_acomp_ctx);
	else
		acomp_ctx = raw_cpu_ptr(entry->pool->acomp_ctx);
	mutex_lock(acomp_ctx->mutex);

	if (is_by_n)
		/* page was compressed using by_n */
		goto by_n;

	sg_init_one(&input, src, entry->length);
	sg_init_table(&output, 1);
	sg_set_page(&output, page, PAGE_SIZE, 0);
	acomp_request_set_params(acomp_ctx->req, &input, &output, entry->length, dlen);
	if (acomp_ctx->acomp->poll) {
		/* normal page or by_n enabled but page wasn't split */
		start_time_ns = ktime_get_ns();
		ret = crypto_acomp_decompress(acomp_ctx->req);
		if (ret == -EINPROGRESS) {
			do {
				ret = crypto_acomp_poll(acomp_ctx->req);
				if (ret && ret != -EAGAIN)
					break;
				cpu_relax();
			} while (ret);
		}
		trace_zswap_load_lat_async(acomp_ctx->req,
					   ktime_get_ns() - start_time_ns,
					   raw_smp_processor_id(),
					   entry->length, ret);
	} else {
		start_time_ns = ktime_get_ns();
		ret = crypto_wait_req(crypto_acomp_decompress(acomp_ctx->req), &acomp_ctx->wait);
		trace_zswap_load_lat_sync(acomp_ctx->req,
					  ktime_get_ns() - start_time_ns,
					  raw_smp_processor_id(), entry->length,
					  ret);
	}
	dlen = acomp_ctx->req->dlen;
by_n:
	if (is_by_n) {
		unsigned int by_n_dlen[MAX_BY_N];

		start_time_ns = ktime_get_ns();
		ret = by_n_decompress(acomp_ctx, page, src, entry, by_n_dlen);
		trace_zswap_load_lat_by_n(acomp_ctx->req, zswap_by_n,
					  ktime_get_ns() - start_time_ns,
					  raw_smp_processor_id(),
					  entry->by_n_length[0],
					  entry->by_n_length[1],
					  entry->by_n_length[2],
					  entry->by_n_length[3],
					  ret);
		dlen = 0;
		for (i = 0; i < zswap_by_n; i++)
			dlen += by_n_dlen[i];
	}

	BUG_ON(dlen != PAGE_SIZE);
	mutex_unlock(acomp_ctx->mutex);

	if (zpool_can_sleep_mapped(entry->pool->zpool))
		zpool_unmap_handle(entry->pool->zpool, entry->handle);
	else
		kfree(tmp);

	BUG_ON(ret);
stats:
	count_vm_event(ZSWPIN);
	if (entry->objcg)
		count_objcg_event(entry->objcg, ZSWPIN);
freeentry:
	spin_lock(&tree->lock);
	zswap_entry_put(tree, entry);
	spin_unlock(&tree->lock);

	return ret;
}

/* frees an entry in zswap */
static void zswap_frontswap_invalidate_page(unsigned type, pgoff_t offset)
{
	struct zswap_tree *tree = zswap_trees[type];
	struct zswap_entry *entry;

	/* find */
	spin_lock(&tree->lock);
	entry = zswap_rb_search(&tree->rbroot, offset);
	if (!entry) {
		/* entry was written back */
		spin_unlock(&tree->lock);
		return;
	}

	/* remove from rbtree */
	zswap_rb_erase(&tree->rbroot, entry);

	/* drop the initial reference from entry creation */
	zswap_entry_put(tree, entry);

	spin_unlock(&tree->lock);
}

/* frees all zswap entries for the given swap type */
static void zswap_frontswap_invalidate_area(unsigned type)
{
	struct zswap_tree *tree = zswap_trees[type];
	struct zswap_entry *entry, *n;

	if (!tree)
		return;

	/* walk the tree and free everything */
	spin_lock(&tree->lock);
	rbtree_postorder_for_each_entry_safe(entry, n, &tree->rbroot, rbnode)
		zswap_free_entry(entry);
	tree->rbroot = RB_ROOT;
	spin_unlock(&tree->lock);
	kfree(tree);
	zswap_trees[type] = NULL;
}

static void zswap_frontswap_init(unsigned type)
{
	struct zswap_tree *tree;

	tree = kzalloc(sizeof(*tree), GFP_KERNEL);
	if (!tree) {
		pr_err("alloc failed, zswap disabled for swap type %d\n", type);
		return;
	}

	tree->rbroot = RB_ROOT;
	spin_lock_init(&tree->lock);
	zswap_trees[type] = tree;
}

static const struct frontswap_ops zswap_frontswap_ops = {
	.store = zswap_frontswap_store,
	.load = zswap_frontswap_load,
	.invalidate_page = zswap_frontswap_invalidate_page,
	.invalidate_area = zswap_frontswap_invalidate_area,
	.init = zswap_frontswap_init
};

/*********************************
* debugfs functions
**********************************/
#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>

static struct dentry *zswap_debugfs_root;

static int __init zswap_debugfs_init(void)
{
	if (!debugfs_initialized())
		return -ENODEV;

	zswap_debugfs_root = debugfs_create_dir("zswap", NULL);

	debugfs_create_u64("pool_limit_hit", 0444,
			   zswap_debugfs_root, &zswap_pool_limit_hit);
	debugfs_create_u64("reject_reclaim_fail", 0444,
			   zswap_debugfs_root, &zswap_reject_reclaim_fail);
	debugfs_create_u64("reject_alloc_fail", 0444,
			   zswap_debugfs_root, &zswap_reject_alloc_fail);
	debugfs_create_u64("reject_kmemcache_fail", 0444,
			   zswap_debugfs_root, &zswap_reject_kmemcache_fail);
	debugfs_create_u64("reject_compress_poor", 0444,
			   zswap_debugfs_root, &zswap_reject_compress_poor);
	debugfs_create_u64("written_back_pages", 0444,
			   zswap_debugfs_root, &zswap_written_back_pages);
	debugfs_create_u64("duplicate_entry", 0444,
			   zswap_debugfs_root, &zswap_duplicate_entry);
	debugfs_create_u64("pool_total_size", 0444,
			   zswap_debugfs_root, &zswap_pool_total_size);
	debugfs_create_atomic_t("stored_pages", 0444,
				zswap_debugfs_root, &zswap_stored_pages);
	debugfs_create_atomic_t("same_filled_pages", 0444,
				zswap_debugfs_root, &zswap_same_filled_pages);

	debugfs_create_atomic_t("primary_used", 0444, zswap_debugfs_root,
				&zswap_primary_used);
	debugfs_create_atomic_t("secondary_used", 0444, zswap_debugfs_root,
				&zswap_secondary_used);

	return 0;
}
#else
static int __init zswap_debugfs_init(void)
{
	return 0;
}
#endif

/*********************************
* module init and exit
**********************************/
static int __init init_zswap(void)
{
	struct zswap_pool *pool;
	int ret;

	zswap_init_started = true;

	if (zswap_entry_cache_create()) {
		pr_err("entry cache creation failed\n");
		goto cache_fail;
	}

	ret = cpuhp_setup_state(CPUHP_MM_ZSWP_MEM_PREPARE, "mm/zswap:prepare",
				zswap_dstmem_prepare, zswap_dstmem_dead);
	if (ret) {
		pr_err("dstmem alloc failed\n");
		goto dstmem_fail;
	}

	ret = cpuhp_setup_state_multi(CPUHP_MM_ZSWP_POOL_PREPARE,
				      "mm/zswap_pool:prepare",
				      zswap_cpu_comp_prepare,
				      zswap_cpu_comp_dead);
	if (ret)
		goto hp_fail;

	pool = __zswap_pool_create_fallback();
	if (pool) {
		pr_info("loaded using pool %s/%s\n", pool->tfm_name,
			zpool_get_type(pool->zpool));
		list_add(&pool->list, &zswap_pools);
		zswap_has_pool = true;
	} else {
		pr_err("pool creation failed\n");
		zswap_enabled = false;
	}

	shrink_wq = create_workqueue("zswap-shrink");
	if (!shrink_wq)
		goto fallback_fail;

	ret = frontswap_register_ops(&zswap_frontswap_ops);
	if (ret)
		goto destroy_wq;
	if (zswap_debugfs_init())
		pr_warn("debugfs initialization failed\n");
	return 0;

destroy_wq:
	destroy_workqueue(shrink_wq);
fallback_fail:
	if (pool)
		zswap_pool_destroy(pool);
hp_fail:
	cpuhp_remove_state(CPUHP_MM_ZSWP_MEM_PREPARE);
dstmem_fail:
	zswap_entry_cache_destroy();
cache_fail:
	/* if built-in, we aren't unloaded on failure; don't allow use */
	zswap_init_failed = true;
	zswap_enabled = false;
	return -ENOMEM;
}
/* must be late so crypto has time to come up */
late_initcall(init_zswap);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Seth Jennings <sjennings@variantweb.net>");
MODULE_DESCRIPTION("Compressed cache for swap pages");
