/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM zswap

#if !defined(_TRACE_ZSWAP_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_ZSWAP_H

#include <linux/tracepoint.h>

TRACE_EVENT(zswap_store_lat_sync,
	    TP_PROTO(struct acomp_req *req, u64 lat, unsigned int cpu, unsigned int dlen, int ret),
	    TP_ARGS(req, lat, cpu, dlen, ret),
	    TP_STRUCT__entry(
		    __field(struct acomp_req *,	req)
		    __field(u64, lat)
		    __field(unsigned int, cpu)
		    __field(unsigned int, dlen)
		    __field(int, ret)
		    ),
	    TP_fast_assign(
		    __entry->req = req;
		    __entry->lat = lat;
		    __entry->cpu = cpu;
		    __entry->dlen = dlen;
		    __entry->ret = ret;
		    ),
	    TP_printk("req=%p lat=%llu cpu=%u dlen=%u ret=%d",
		      __entry->req, __entry->lat, __entry->cpu, __entry->dlen, __entry->ret)
	   );

TRACE_EVENT(zswap_load_lat_sync,
	    TP_PROTO(struct acomp_req *req, u64 lat, unsigned int cpu,
		     unsigned int length, int ret),
	    TP_ARGS(req, lat, cpu, length, ret),
	    TP_STRUCT__entry(
		    __field(struct acomp_req *,	req)
		    __field(u64, lat)
		    __field(unsigned int, cpu)
		    __field(unsigned int, length)
		    __field(int, ret)
		    ),
	    TP_fast_assign(
		    __entry->req = req;
		    __entry->lat = lat;
		    __entry->cpu = cpu;
		    __entry->length = length;
		    __entry->ret = ret;
		    ),
	    TP_printk("req=%p lat=%llu cpu=%u length=%u ret=%d",
		      __entry->req, __entry->lat, __entry->cpu, __entry->length,
		      __entry->ret)
	   );

TRACE_EVENT(zswap_store_lat_async,
	    TP_PROTO(struct acomp_req *req, u64 lat, unsigned int cpu, unsigned int dlen, int ret),
	    TP_ARGS(req, lat, cpu, dlen, ret),
	    TP_STRUCT__entry(
		    __field(struct acomp_req *,	req)
		    __field(u64, lat)
		    __field(unsigned int, cpu)
		    __field(unsigned int, dlen)
		    __field(int, ret)
		    ),
	    TP_fast_assign(
		    __entry->req = req;
		    __entry->lat = lat;
		    __entry->cpu = cpu;
		    __entry->dlen = dlen;
		    __entry->ret = ret;
		    ),
	    TP_printk("req=%p lat=%llu cpu=%u dlen=%u ret=%d",
		      __entry->req, __entry->lat, __entry->cpu, __entry->dlen, __entry->ret)
	   );

TRACE_EVENT(zswap_load_lat_async,
	    TP_PROTO(struct acomp_req *req, u64 lat, unsigned int cpu,
		     unsigned int length, int ret),
	    TP_ARGS(req, lat, cpu, length, ret),
	    TP_STRUCT__entry(
		    __field(struct acomp_req *,	req)
		    __field(u64, lat)
		    __field(unsigned int, cpu)
		    __field(unsigned int, length)
		    __field(int, ret)
		    ),
	    TP_fast_assign(
		    __entry->req = req;
		    __entry->lat = lat;
		    __entry->cpu = cpu;
		    __entry->length = length;
		    __entry->ret = ret;
		    ),
	    TP_printk("req=%p lat=%llu cpu=%u length=%u ret=%d",
		      __entry->req, __entry->lat, __entry->cpu, __entry->length,
		      __entry->ret)
	   );

TRACE_EVENT(zswap_store_lat_by_n,
	    TP_PROTO(struct acomp_req *req, unsigned int by_n, u64 lat, unsigned int cpu, unsigned int dlen1, unsigned int dlen2, unsigned int dlen3, unsigned int dlen4, int ret),
	    TP_ARGS(req, by_n, lat, cpu, dlen1, dlen2, dlen3, dlen4, ret),
	    TP_STRUCT__entry(
		    __field(struct acomp_req *,	req)
		    __field(unsigned int, by_n)
		    __field(u64, lat)
		    __field(unsigned int, cpu)
		    __field(unsigned int, dlen1)
		    __field(unsigned int, dlen2)
		    __field(unsigned int, dlen3)
		    __field(unsigned int, dlen4)
		    __field(int, ret)
		    ),
	    TP_fast_assign(
		    __entry->req = req;
		    __entry->by_n = by_n;
		    __entry->lat = lat;
		    __entry->cpu = cpu;
		    __entry->dlen1 = dlen1;
		    __entry->dlen2 = dlen2;
		    __entry->dlen3 = dlen3;
		    __entry->dlen4 = dlen4;
		    __entry->ret = ret;
		    ),
	    TP_printk("req=%p by_n=%u lat=%llu cpu=%u dlen1=%u dlen2=%u dlen3=%u dlen4=%u ret=%d",
		      __entry->req, __entry->by_n, __entry->lat, __entry->cpu, __entry->dlen1, __entry->dlen2, __entry->dlen3, __entry->dlen4, ret)
	   );

TRACE_EVENT(zswap_load_lat_by_n,
	    TP_PROTO(struct acomp_req *req, unsigned int by_n, u64 lat,
		     unsigned int cpu, unsigned int length1,
		     unsigned int length2, unsigned int length3,
		     unsigned int length4, int ret),
	    TP_ARGS(req, by_n, lat, cpu, length1, length2, length3, length4,
		    ret),
	    TP_STRUCT__entry(
		    __field(struct acomp_req *,	req)
		    __field(unsigned int, by_n)
		    __field(u64, lat)
		    __field(unsigned int, cpu)
		    __field(unsigned int, length1)
		    __field(unsigned int, length2)
		    __field(unsigned int, length3)
		    __field(unsigned int, length4)
		    __field(int, ret)
		    ),
	    TP_fast_assign(
		    __entry->req = req;
		    __entry->by_n = by_n;
		    __entry->lat = lat;
		    __entry->cpu = cpu;
		    __entry->length1 = length1;
		    __entry->length2 = length2;
		    __entry->length3 = length3;
		    __entry->length4 = length4;
		    __entry->ret = ret;
		    ),
	    TP_printk("req=%p by_n=%u lat=%llu cpu=%u length1=%u length2=%u "
		      "length3=%u length4=%u ret=%d",
		      __entry->req, __entry->by_n, __entry->lat, __entry->cpu,
		      __entry->length1, __entry->length2, __entry->length3,
		      __entry->length4, __entry->ret)
	   );

TRACE_EVENT(zswap_store_reject,
	    TP_PROTO(struct acomp_req *req, unsigned int cpu, int ret),
	    TP_ARGS(req, cpu, ret),
	    TP_STRUCT__entry(
		    __field(struct acomp_req *,	req)
		    __field(unsigned int, cpu)
		    __field(int, ret)
		    ),
	    TP_fast_assign(
		    __entry->req = req;
		    __entry->cpu = cpu;
		    __entry->ret = ret;
		    ),
	    TP_printk("req=%p cpu=%u ret=%d",
		      __entry->req, __entry->cpu, __entry->ret)
	   );

TRACE_EVENT(zswap_writeback_lat_sync,
	    TP_PROTO(struct acomp_req *req, u64 lat, unsigned int cpu, int ret),
	    TP_ARGS(req, lat, cpu, ret),
	    TP_STRUCT__entry(
		    __field(struct acomp_req *,	req)
		    __field(u64, lat)
		    __field(unsigned int, cpu)
		    __field(int, ret)
		    ),
	    TP_fast_assign(
		    __entry->req = req;
		    __entry->lat = lat;
		    __entry->cpu = cpu;
		    __entry->ret = ret;
		    ),
	    TP_printk("req=%p lat=%llu cpu=%u ret %d",
		      __entry->req, __entry->lat, __entry->cpu, __entry->ret)
	   );

TRACE_EVENT(zswap_writeback_lat_async,
	    TP_PROTO(struct acomp_req *req, u64 lat, unsigned int cpu, unsigned int ret),
	    TP_ARGS(req, lat, cpu, ret),
	    TP_STRUCT__entry(
		    __field(struct acomp_req *,	req)
		    __field(u64, lat)
		    __field(unsigned int, cpu)
		    __field(int, ret)
		    ),
	    TP_fast_assign(
		    __entry->req = req;
		    __entry->lat = lat;
		    __entry->cpu = cpu;
		    __entry->ret = ret;
		    ),
	    TP_printk("req=%p lat=%llu cpu=%u ret=%d",
		      __entry->req, __entry->lat, __entry->cpu, __entry->ret)
	   );

TRACE_EVENT(zswap_writeback_lat_by_n,
	    TP_PROTO(struct acomp_req *req, unsigned int by_n, u64 lat, unsigned int cpu, int ret),
	    TP_ARGS(req, by_n, lat, cpu, ret),
	    TP_STRUCT__entry(
		    __field(struct acomp_req *,	req)
		    __field(unsigned int, by_n)
		    __field(u64, lat)
		    __field(unsigned int, cpu)
		    __field(int, ret)
		    ),
	    TP_fast_assign(
		    __entry->req = req;
		    __entry->by_n = by_n;
		    __entry->lat = lat;
		    __entry->cpu = cpu;
		    __entry->ret = ret;
		    ),
	    TP_printk("req=%p by_n=%u lat=%llu cpu=%u ret=%d",
		      __entry->req, __entry->by_n, __entry->lat, __entry->cpu, __entry->ret)
	   );

#endif /* _TRACE_ZSWAP_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
