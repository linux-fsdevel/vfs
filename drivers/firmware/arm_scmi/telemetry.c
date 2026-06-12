// SPDX-License-Identifier: GPL-2.0
/*
 * System Control and Management Interface (SCMI) Telemetry Protocol
 *
 * Copyright (C) 2026 ARM Ltd.
 */

#include <linux/atomic.h>
#include <linux/bitfield.h>
#include <linux/device.h>
#include <linux/compiler_types.h>
#include <linux/completion.h>
#include <linux/err.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/limits.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/sprintf.h>
#include <linux/string.h>
#include <linux/xarray.h>

#include "protocols.h"
#include "notify.h"

#include <trace/events/scmi.h>

/* Updated only after ALL the mandatory features for that version are merged */
#define SCMI_PROTOCOL_SUPPORTED_VERSION		0x10000

#define SCMI_TLM_TDCF_MAX_RETRIES	5

enum scmi_telemetry_protocol_cmd {
	TELEMETRY_LIST_SHMTI = 0x3,
	TELEMETRY_DE_DESCRIPTION = 0x4,
	TELEMETRY_LIST_UPDATE_INTERVALS = 0x5,
	TELEMETRY_DE_CONFIGURE = 0x6,
	TELEMETRY_DE_ENABLED_LIST = 0x7,
	TELEMETRY_CONFIG_SET = 0x8,
	TELEMETRY_READING_COMPLETE = TELEMETRY_CONFIG_SET,
	TELEMETRY_CONFIG_GET = 0x9,
	TELEMETRY_RESET = 0xA,
};

struct scmi_msg_resp_telemetry_protocol_attributes {
	__le32 de_num;
	__le32 groups_num;
	__le32 de_implementation_rev_dword[SCMI_TLM_DE_IMPL_MAX_DWORDS];
	__le32 attributes;
#define SUPPORTS_SINGLE_READ(x)		((x) & BIT(31))
#define SUPPORTS_CONTINUOS_UPDATE(x)	((x) & BIT(30))
#define SUPPORTS_PER_GROUP_CONFIG(x)	((x) & BIT(18))
#define SUPPORTS_RESET(x)		((x) & BIT(17))
#define SUPPORTS_FC(x)			((x) & BIT(16))
	__le32 default_blk_ts_rate;
};

struct scmi_telemetry_update_notify_payld {
	__le32 agent_id;
	__le32 status;
	__le32 num_dwords;
	__le32 array[] __counted_by(num_dwords);
};

struct scmi_shmti_desc {
	__le32 id;
	__le32 addr_low;
	__le32 addr_high;
	__le32 length;
	__le32 flags;
};

struct scmi_msg_resp_telemetry_shmti_list {
	__le32 num_shmti;
	struct scmi_shmti_desc desc[] __counted_by(num_shmti);
};

struct de_desc_fc {
	__le32 addr_low;
	__le32 addr_high;
	__le32 size;
};

struct scmi_de_desc {
	__le32 id;
	__le32 grp_id;
	__le32 data_sz;
	__le32 attr_1;
#define	IS_NAME_SUPPORTED(d)	((d)->attr_1 & BIT(31))
#define	IS_FC_SUPPORTED(d)	((d)->attr_1 & BIT(30))
#define	GET_DE_TYPE(d)		(le32_get_bits((d)->attr_1, GENMASK(29, 22)))
#define	IS_PERSISTENT(d)	((d)->attr_1 & BIT(21))
#define GET_DE_UNIT_EXP(d)						\
	({								\
		__u32 __signed_exp =					\
			le32_get_bits((d)->attr_1, GENMASK(20, 13));	\
									\
		sign_extend32(__signed_exp, 7);				\
	})
#define	GET_DE_UNIT(d)		(le32_get_bits((d)->attr_1, GENMASK(12, 5)))
#define	TSTAMP_SUPPORT(d)	(le32_get_bits((d)->attr_1, GENMASK(1, 0)))
	__le32 attr_2;
#define	GET_DE_INSTA_ID(d)	(le32_get_bits((d)->attr_2, GENMASK(31, 24)))
#define	GET_COMPO_INSTA_ID(d)	(le32_get_bits((d)->attr_2, GENMASK(23, 8)))
#define	GET_COMPO_TYPE(d)	(le32_get_bits((d)->attr_2, GENMASK(7, 0)))
	__le32 reserved;
};

struct scmi_msg_resp_telemetry_de_description {
	__le32 num_desc;
	struct scmi_de_desc desc[] __counted_by(num_desc);
};

struct scmi_msg_telemetry_update_intervals {
	__le32 index;
	__le32 group_identifier;
#define	ALL_DES_NO_GROUP	0x0
#define SPECIFIC_GROUP_DES	0x1
#define ALL_DES_ANY_GROUP	0x2
	__le32 flags;
};

struct scmi_msg_resp_telemetry_update_intervals {
	__le32 flags;
#define INTERVALS_DISCRETE(x)	(!((x) & BIT(12)))
	__le32 intervals[];
};

struct scmi_msg_telemetry_de_enabled_list {
	__le32 index;
	__le32 flags;
};

struct scmi_enabled_de_desc {
	__le32 id;
	__le32 mode;
};

struct scmi_msg_resp_telemetry_de_enabled_list {
	__le32 flags;
	struct scmi_enabled_de_desc entry[];
};

struct scmi_msg_telemetry_de_configure {
	__le32 id;
	__le32 flags;
#define DE_ENABLE_NO_TSTAMP	BIT(0)
#define DE_ENABLE_WTH_TSTAMP	BIT(1)
#define DE_DISABLE_ALL		BIT(2)
#define GROUP_SELECTOR		BIT(3)
#define EVENT_DE		0
#define EVENT_GROUP		1
#define DE_DISABLE_ONE		0x0
};

struct scmi_msg_resp_telemetry_de_configure {
	__le32 shmti_id;
#define IS_SHMTI_ID_VALID(x)	((x) != 0xFFFFFFFF)
	__le32 shmti_de_offset;
	__le32 blk_ts_offset;
};

struct scmi_msg_telemetry_config_set {
	__le32 grp_id;
	__le32 control;
#define TELEMETRY_ENABLE		(BIT(0))

#define TELEMETRY_MODE_SET(x)		(FIELD_PREP(GENMASK(4, 1), (x)))
#define	TLM_ONDEMAND			(0)
#define	TLM_NOTIFS			(1)
#define	TLM_SINGLE			(2)
#define TELEMETRY_MODE_ONDEMAND		TELEMETRY_MODE_SET(TLM_ONDEMAND)
#define TELEMETRY_MODE_NOTIFS		TELEMETRY_MODE_SET(TLM_NOTIFS)
#define TELEMETRY_MODE_SINGLE		TELEMETRY_MODE_SET(TLM_SINGLE)

#define TLM_ORPHANS			(0)
#define TLM_GROUP			(1)
#define TLM_ALL				(2)
#define TELEMETRY_SET_SELECTOR(x)	(FIELD_PREP(GENMASK(8, 5), (x)))
#define	TELEMETRY_SET_SELECTOR_ORPHANS	TELEMETRY_SET_SELECTOR(TLM_ORPHANS)
#define	TELEMETRY_SET_SELECTOR_GROUP	TELEMETRY_SET_SELECTOR(TLM_GROUP)
#define	TELEMETRY_SET_SELECTOR_ALL	TELEMETRY_SET_SELECTOR(TLM_ALL)
	__le32 sampling_rate;
};

struct scmi_msg_resp_telemetry_reading_complete {
	__le32 num_dwords;
	__le32 dwords[] __counted_by(num_dwords);
};

struct scmi_msg_telemetry_config_get {
	__le32 grp_id;
	__le32 flags;
#define TELEMETRY_GET_SELECTOR(x)	(FIELD_PREP(GENMASK(3, 0), (x)))
#define	TELEMETRY_GET_SELECTOR_ORPHANS	TELEMETRY_GET_SELECTOR(TLM_ORPHANS)
#define	TELEMETRY_GET_SELECTOR_GROUP	TELEMETRY_GET_SELECTOR(TLM_GROUP)
#define	TELEMETRY_GET_SELECTOR_ALL	TELEMETRY_GET_SELECTOR(TLM_ALL)
};

struct scmi_msg_resp_telemetry_config_get {
	__le32 control;
#define TELEMETRY_MODE_GET		(FIELD_GET(GENMASK(4, 1)))
	__le32 sampling_rate;
};

/* TDCF */

#define _I(__a)		(ioread32((void __iomem *)(__a)))

#define TO_CPU_64(h, l)	((((u64)(h)) << 32) | (l))

/*
 * Define the behaviour of a SHMTI scan defining what information will
 * be gathered and which Telemetry items can be updated.
 */
enum scan_mode {
	SCAN_LOOKUP,	/* Update only value/tstamp */
	SCAN_UPDATE,	/* Update also location offset */
	SCAN_DISCOVERY  /* Update xa_des: allows for new DEs to be discovered */
};

struct fc_line {
	u32 data_low;
	u32 data_high;
};

struct fc_tsline {
	u32 data_low;
	u32 data_high;
	u32 ts_low;
	u32 ts_high;
};

struct line {
	u32 data_low;
	u32 data_high;
};

struct blk_tsline {
	u32 ts_low;
	u32 ts_high;
};

struct tsline {
	u32 data_low;
	u32 data_high;
	u32 ts_low;
	u32 ts_high;
};

struct uuid_line {
	u32 dwords[SCMI_TLM_DE_IMPL_MAX_DWORDS];
};

#define LINE_DATA_GET(f)					\
({								\
	typeof(f) _f = (f);					\
								\
	(TO_CPU_64(_I(&_f->data_high), _I(&_f->data_low)));	\
})

#define LINE_TSTAMP_GET(f)					\
({								\
	typeof(f) _f = (f);					\
								\
	(TO_CPU_64(_I(&_f->ts_high), _I(&_f->ts_low)));	\
})

#define BLK_TS_STAMP(f)		LINE_TSTAMP_GET(f)
#define BLK_TS_RATE(p)		PAYLD_ID(p)

enum tdcf_line_types {
	TDCF_DATA_LINE,
	TDCF_BLK_TS_LINE,
	TDCF_UUID_LINE,
};

struct payload {
	u32 meta;
#define LINE_TYPE(x)		(le32_get_bits(_I(&((x)->meta)), GENMASK(7, 4)))
#define IS_DATA_LINE(x)		(LINE_TYPE(x) == TDCF_DATA_LINE)
#define IS_BLK_TS_LINE(x)	(LINE_TYPE(x) == TDCF_BLK_TS_LINE)
#define IS_UUID_LINE(x)		(LINE_TYPE(x) == TDCF_UUID_LINE)
#define USE_BLK_TS(x)		(_I(&((x)->meta)) & BIT(3))
#define HAS_LINE_EXT(x)		(_I(&((x)->meta)) & BIT(2))
#define LINE_TS_VALID(x)	(_I(&((x)->meta)) & BIT(1))
#define	DATA_INVALID(x)		(_I(&((x)->meta)) & BIT(0))
#define	BLK_TS_INVALID(p)					\
({								\
	typeof(p) _p = (p);					\
	bool invalid;						\
								\
	invalid  = LINE_TS_VALID(_p) || HAS_LINE_EXT(_p) ||	\
			USE_BLK_TS(_p) || DATA_INVALID(_p);	\
	invalid;						\
})

#define	UUID_INVALID(p)						\
({								\
	typeof(p) _p = (p);					\
	bool invalid;						\
								\
	invalid = LINE_TS_VALID(_p) || USE_BLK_TS(_p) ||	\
			DATA_INVALID(_p) || !HAS_LINE_EXT(_p);	\
	invalid;						\
})
	u32 id;
	union {
		struct line l;
		struct tsline tsl;
		struct blk_tsline blk_tsl;
		struct uuid_line uuid_l;
	};
};

#define PAYLD_ID(x)	(_I(&(((struct payload *)(x))->id)))

#define LINE_DATA_PAYLD_WORDS						       \
	((sizeof(u32) + sizeof(u32) + sizeof(struct line)) / sizeof(u32))
#define EXT_LINE_DATA_PAYLD_WORDS					       \
	((sizeof(u32) + sizeof(u32) + sizeof(struct tsline)) / sizeof(u32))

#define LINE_LENGTH_WORDS(x)				\
	(HAS_LINE_EXT((x)) ? EXT_LINE_DATA_PAYLD_WORDS : LINE_DATA_PAYLD_WORDS)

#define LINE_LENGTH_QWORDS(x)		((LINE_LENGTH_WORDS(x)) / 2)

struct prlg {
	u32 sign_start;
#define SIGNATURE_START	0x5442474E	/* TBGN */
	u32 match_start;
	u32 num_qwords;
	u32 hdr_meta_1;
#define TDCF_REVISION_GET(x)	(le32_get_bits((x)->hdr_meta_1, GENMASK(7, 0)))
};

struct eplg {
	u32 match_end;
	u32 sign_end;
#define SIGNATURE_END	0x54454E44	/* TEND */
};

#define TDCF_EPLG_SZ	(sizeof(struct eplg))

struct tdcf {
	struct prlg prlg;
	unsigned char payld[];
};

#define QWORDS(_t)	(_I(&(_t)->prlg.num_qwords))

#define SHMTI_MIN_SIZE	(sizeof(struct tdcf) + TDCF_EPLG_SZ)

#define TDCF_START_SIGNATURE(x)	(_I(&((x)->prlg.sign_start)))
#define TDCF_START_SEQ_GET(x)	(_I(&((x)->prlg.match_start)))
#define IS_BAD_START_SEQ(s)	((s) & 0x1)

#define TDCF_END_SEQ_GET(e)	(_I(&((e)->match_end)))
#define TDCF_END_SIGNATURE(e)	(_I(&((e)->sign_end)))
#define	TDCF_BAD_END_SEQ	GENMASK(31, 0)

struct telemetry_shmti {
	int id;
	u32 flags;
	void __iomem *base;
	u32 len;
	u32 last_magic;
};

#define SHMTI_EPLG(s)						\
	({							\
		struct telemetry_shmti *_s = (s);		\
		struct eplg *_eplg;				\
								\
		_eplg = _s->base + _s->len - TDCF_EPLG_SZ;	\
		(_eplg);					\
	})

struct telemetry_line {
	refcount_t users;
	u32 last_magic;
	struct payload __iomem *payld;
	struct xarray *xa_lines;
	/* Protect line accesses  */
	struct mutex mtx;
};

struct telemetry_block_ts {
	u64 last_ts;
	u32 last_rate;
	struct telemetry_line line;
};

#define to_blkts(l)	container_of(l, struct telemetry_block_ts, line)

struct telemetry_uuid {
	u32 de_impl_version[SCMI_TLM_DE_IMPL_MAX_DWORDS];
	struct telemetry_line line;
};

#define to_uuid(l)	container_of(l, struct telemetry_uuid, line)

enum timestamps {
	TSTAMP_NONE,
	TSTAMP_LINE,
	TSTAMP_BLK
};

struct telemetry_de {
	enum timestamps ts_type;
	u32 ts_rate;
	bool enumerated;
	bool cached_msg;
	void __iomem *base;
	struct eplg __iomem *eplg;
	u32 offset;
	/* NOTE THAT DE data_sz is registered in scmi_telemetry_de */
	u32 fc_size;
	/* Protect last_val/ts/magic accesses  */
	struct mutex mtx;
	u64 last_val;
	u64 last_ts;
	u32 last_magic;
	struct list_head item;
	struct telemetry_block_ts *bts;
	struct telemetry_uuid *uuid;
	struct scmi_telemetry_de de;
};

#define to_tde(d)	container_of(d, struct telemetry_de, de)

#define TDE_HAS_TSTAMP(_t)						\
	({								\
		bool ts;						\
		struct telemetry_de *t = _t;				\
									\
		ts = t->de.tstamp_support && t->de.tstamp_enabled;	\
	})

#define DE_ENABLED_WITH_TSTAMP	2

enum de_state {
	ENA_STATE,
	ENA_TSTAMP,
	ENA_MAX
};

struct telemetry_info {
	bool streaming_mode;
	unsigned int num_shmti;
	unsigned int num_des_tstamp;
	atomic_t des_enabled[ENA_MAX];
	unsigned int default_blk_ts_rate;
	const struct scmi_protocol_handle *ph;
	struct telemetry_shmti *shmti;
	struct telemetry_de *tdes;
	struct scmi_telemetry_group *grps;
	struct xarray xa_des;
	struct xarray xa_lines;
	/* Mutex to protect access to @free_des */
	struct mutex free_mtx;
	struct list_head free_des;
	struct list_head fcs_des;
	struct scmi_telemetry_info info;
	atomic_t rinfo_initializing;
	struct completion rinfo_initdone;
	struct scmi_telemetry_res_info __private *rinfo;
	struct scmi_telemetry_res_info *(*res_get)(struct telemetry_info *ti);
};

static struct scmi_telemetry_res_info *
__scmi_telemetry_resources_get(struct telemetry_info *ti);

static int scmi_telemetry_shmti_scan(struct telemetry_info *ti,
				     unsigned int shmti_id, enum scan_mode mode);

static inline void
scmi_telemetry_de_state_update(struct telemetry_info *ti, enum de_state state,
			       bool *current_state, bool next_state)
{
	if (!current_state || *current_state != next_state)
		atomic_add(next_state ? 1 : -1, &ti->des_enabled[state]);

	if (current_state)
		*current_state = next_state;

	dev_dbg(ti->ph->dev, "Telemetry des_enabled[%s]:%u\n",
		state == ENA_STATE ? "STATE" : "TSTAMP",
		atomic_read(&ti->des_enabled[state]));
}

static struct telemetry_de *
scmi_telemetry_free_tde_get(struct telemetry_info *ti)
{
	struct telemetry_de *tde;

	guard(mutex)(&ti->free_mtx);

	tde = list_first_entry_or_null(&ti->free_des, struct telemetry_de, item);
	if (!tde)
		return tde;

	list_del(&tde->item);

	return tde;
}

static void scmi_telemetry_free_tde_put(struct telemetry_info *ti,
					struct telemetry_de *tde)
{
	guard(mutex)(&ti->free_mtx);

	list_add_tail(&tde->item, &ti->free_des);
}

static struct telemetry_de *scmi_telemetry_tde_lookup(struct telemetry_info *ti,
						      unsigned int de_id)
{
	struct scmi_telemetry_de *de;

	de = xa_load(&ti->xa_des, de_id);
	if (!de)
		return NULL;

	return to_tde(de);
}

static struct telemetry_de *scmi_telemetry_tde_get(struct telemetry_info *ti,
						   unsigned int de_id)
{
	static struct telemetry_de *tde;

	/* Pick a new tde */
	tde = scmi_telemetry_free_tde_get(ti);
	if (!tde) {
		dev_err(ti->ph->dev, "Cannot allocate DE for ID:0x%08X\n", de_id);
		return ERR_PTR(-ENOSPC);
	}

	return tde;
}

static int scmi_telemetry_tde_register(struct telemetry_info *ti,
				       struct telemetry_de *tde)
{
	struct scmi_telemetry_res_info *rinfo = ACCESS_PRIVATE(ti, rinfo);
	int ret;

	if (rinfo->num_des >= ti->info.base.num_des) {
		ret = -ENOSPC;
		goto err;
	}

	/* Store DE pointer by de_id ... */
	ret = xa_insert(&ti->xa_des, tde->de.info->id, &tde->de, GFP_KERNEL);
	if (ret)
		goto err;

	/* ... and in the general array */
	rinfo->des[rinfo->num_des++] = &tde->de;

	return 0;

err:
	dev_err(ti->ph->dev, "Cannot register DE for ID:0x%08X\n",
		tde->de.info->id);

	return ret;
}

static bool
scmi_telemetry_tde_cache_unchanged(struct telemetry_de *tde, u32 magic)
{
	guard(mutex)(&tde->mtx);

	return tde->last_magic == magic;
}

static void
scmi_telemetry_tde_cache_update(struct telemetry_de *tde, u64 val,
				u64 *tstamp, u32 *magic)
{
	guard(mutex)(&tde->mtx);

	tde->last_magic = magic ? *magic : TDCF_BAD_END_SEQ;
	tde->last_val = val;
	tde->last_ts = tstamp && TDE_HAS_TSTAMP(tde) ? *tstamp : 0;
	if (tstamp)
		*tstamp = tde->last_ts;
}

struct scmi_tlm_de_priv {
	struct telemetry_info *ti;
	void *next;
};

static int
scmi_telemetry_protocol_attributes_get(struct telemetry_info *ti)
{
	struct scmi_msg_resp_telemetry_protocol_attributes *resp;
	const struct scmi_protocol_handle *ph = ti->ph;
	struct scmi_xfer *t;
	int ret;

	ret = ph->xops->xfer_get_init(ph, PROTOCOL_ATTRIBUTES, 0,
				      sizeof(*resp), &t);
	if (ret)
		return ret;

	resp = t->rx.buf;
	ret = ph->xops->do_xfer(ph, t);
	if (!ret) {
		__le32 attr = resp->attributes;

		ti->info.base.num_des = le32_to_cpu(resp->de_num);
		ti->info.base.num_groups = le32_to_cpu(resp->groups_num);
		for (int i = 0; i < SCMI_TLM_DE_IMPL_MAX_DWORDS; i++)
			ti->info.base.de_impl_version[i] =
				le32_to_cpu(resp->de_implementation_rev_dword[i]);
		ti->info.single_read_support = SUPPORTS_SINGLE_READ(attr);
		ti->info.continuos_update_support = SUPPORTS_CONTINUOS_UPDATE(attr);
		ti->info.per_group_config_support = SUPPORTS_PER_GROUP_CONFIG(attr);
		ti->info.reset_support = SUPPORTS_RESET(attr);
		ti->info.fc_support = SUPPORTS_FC(attr);
		ti->num_shmti = le32_get_bits(attr, GENMASK(15, 0));
		ti->default_blk_ts_rate = le32_to_cpu(resp->default_blk_ts_rate);
	}

	ph->xops->xfer_put(ph, t);

	return ret;
}

static void iter_tlm_prepare_message(void *message,
				     unsigned int desc_index, const void *priv)
{
	put_unaligned_le32(desc_index, message);
}

static int iter_de_descr_update_state(struct scmi_iterator_state *st,
				      const void *response, void *priv)
{
	const struct scmi_msg_resp_telemetry_de_description *r = response;
	struct scmi_tlm_de_priv *p = priv;

	st->num_returned = le32_get_bits(r->num_desc, GENMASK(15, 0));
	st->num_remaining = le32_get_bits(r->num_desc, GENMASK(31, 16));

	if (st->rx_len < (sizeof(*r) + sizeof(r->desc[0]) * st->num_returned))
		return -EINVAL;

	/* Initialized to first descriptor */
	p->next = (void *)r->desc;

	return 0;
}

static int scmi_telemetry_de_descriptor_parse(struct telemetry_info *ti,
					      struct telemetry_de *tde,
					      void **next)
{
	struct scmi_telemetry_res_info *rinfo = ACCESS_PRIVATE(ti, rinfo);
	const struct scmi_de_desc *desc = *next;
	unsigned int grp_id;

	tde->de.info->id = le32_to_cpu(desc->id);
	grp_id = le32_to_cpu(desc->grp_id);
	if (grp_id != SCMI_TLM_GRP_INVALID) {
		/* Group descriptors are empty but allocated at this point */
		if (grp_id >= ti->info.base.num_groups)
			return -EINVAL;

		/* Link to parent group */
		tde->de.info->grp_id = grp_id;
		tde->de.grp = &rinfo->grps[grp_id];
	}

	tde->de.info->data_sz = le32_to_cpu(desc->data_sz);
	tde->de.info->type = GET_DE_TYPE(desc);
	tde->de.info->unit = GET_DE_UNIT(desc);
	tde->de.info->unit_exp = GET_DE_UNIT_EXP(desc);
	tde->de.info->instance_id = GET_DE_INSTA_ID(desc);
	tde->de.info->compo_instance_id = GET_COMPO_INSTA_ID(desc);
	tde->de.info->compo_type = GET_COMPO_TYPE(desc);
	tde->de.info->persistent = IS_PERSISTENT(desc);
	tde->ts_type = TSTAMP_SUPPORT(desc);
	tde->de.tstamp_support = !!tde->ts_type;
	/* Count timestamped DEs */
	ti->num_des_tstamp += !!tde->de.tstamp_support;
	tde->de.fc_support = IS_FC_SUPPORTED(desc);
	tde->de.name_support = IS_NAME_SUPPORTED(desc);
	/* Update DE_DESCRIPTOR size for the next iteration */
	*next += sizeof(*desc);

	if (tde->ts_type == TSTAMP_LINE) {
		u32 *line_ts_rate = *next;

		tde->de.info->ts_rate = *line_ts_rate;

		/* Variably sized depending on TS support */
		*next += sizeof(*line_ts_rate);
	} else if (tde->ts_type == TSTAMP_BLK) {
		/* Setup default BLK TS value at first */
		tde->de.info->ts_rate = ti->default_blk_ts_rate;
	}

	if (tde->de.fc_support) {
		u32 size;
		u64 phys_addr;
		void __iomem *addr;
		struct de_desc_fc *dfc;

		dfc = *next;
		phys_addr = le32_to_cpu(dfc->addr_low);
		phys_addr |= (u64)le32_to_cpu(dfc->addr_high) << 32;

		size = le32_to_cpu(dfc->size);
		addr = devm_ioremap(ti->ph->dev, phys_addr, size);
		if (!addr)
			return -EADDRNOTAVAIL;

		tde->base = addr;
		tde->offset = 0;
		tde->fc_size = size;

		/* Add to FastChannels list */
		list_add(&tde->item, &ti->fcs_des);

		/* Variably sized depending on FC support */
		*next += sizeof(*dfc);
	}

	if (tde->de.name_support) {
		const char *de_name = *next;

		strscpy(tde->de.info->name, de_name, SCMI_SHORT_NAME_MAX_SIZE);
		/* Variably sized depending on name support */
		*next += SCMI_SHORT_NAME_MAX_SIZE;
	}

	return 0;
}

static int iter_de_descr_process_response(const struct scmi_protocol_handle *ph,
					  const void *response,
					  struct scmi_iterator_state *st,
					  void *priv)
{
	struct scmi_tlm_de_priv *p = priv;
	struct telemetry_info *ti = p->ti;
	const struct scmi_de_desc *desc = p->next;
	struct telemetry_de *tde;
	bool discovered = false;
	unsigned int de_id;
	int ret;

	de_id = le32_to_cpu(desc->id);
	/* Check if this DE has already been discovered by other means... */
	tde = scmi_telemetry_tde_lookup(ti, de_id);
	if (!tde) {
		/* Create a new one */
		tde = scmi_telemetry_tde_get(ti, de_id);
		if (IS_ERR(tde))
			return PTR_ERR(tde);

		discovered = true;
	} else if (tde->enumerated) {
		/* Cannot be a duplicate of a DE already created by enumeration */
		dev_err(ph->dev,
			"Discovered INVALID DE with DUPLICATED ID:0x%08X\n",
			de_id);
		return -EINVAL;
	}

	ret = scmi_telemetry_de_descriptor_parse(ti, tde, &p->next);
	if (ret)
		goto err;

	if (discovered) {
		/* Register if it was not already ... */
		ret = scmi_telemetry_tde_register(ti, tde);
		if (ret)
			goto err;

		tde->enumerated = true;
	}

	/* Account for this DE in group num_de counter */
	if (tde->de.grp)
		tde->de.grp->info->num_des++;

	return 0;

err:
	/* DE not enumerated at this point were created in this call */
	if (!tde->enumerated)
		scmi_telemetry_free_tde_put(ti, tde);

	return ret;
}

static int
scmi_telemetry_de_groups_init(struct device *dev, struct telemetry_info *ti)
{
	struct scmi_telemetry_res_info *rinfo = ACCESS_PRIVATE(ti, rinfo);

	/* Allocate all groups DEs IDs arrays at first ... */
	for (int i = 0; i < ti->info.base.num_groups; i++) {
		struct scmi_telemetry_group *grp = &rinfo->grps[i];
		size_t des_str_sz;

		unsigned int *des __free(kfree) = kcalloc(grp->info->num_des,
							  sizeof(unsigned int),
							  GFP_KERNEL);
		if (!des)
			return -ENOMEM;

		/*
		 * Max size 32bit ID string in Hex: 0xCAFECAFE
		 *  - 10 digits + ' '/'\n' = 11 bytes per  number
		 *  - terminating NUL character
		 */
		des_str_sz = grp->info->num_des * 11 + 1;
		char *des_str __free(kfree) = kzalloc(des_str_sz, GFP_KERNEL);
		if (!des_str)
			return -ENOMEM;

		grp->des = no_free_ptr(des);
		grp->des_str = no_free_ptr(des_str);
		/* Reset group DE counter */
		grp->info->num_des = 0;
	}

	/* Scan DEs and populate DE IDs arrays for all groups */
	for (int i = 0; i < rinfo->num_des; i++) {
		struct scmi_telemetry_group *grp = rinfo->des[i]->grp;

		if (!grp)
			continue;

		/*
		 * Note that, at this point, num_des is guaranteed to be
		 * sane (in-bounds) by construction.
		 */
		grp->des[grp->info->num_des++] = i;
	}

	/* Build composing DES string */
	for (int i = 0; i < ti->info.base.num_groups; i++) {
		struct scmi_telemetry_group *grp = &rinfo->grps[i];
		size_t bufsize = grp->info->num_des * 11 + 1;
		char *buf = grp->des_str;

		for (int j = 0; j < grp->info->num_des; j++) {
			char term = j != (grp->info->num_des - 1) ? ' ' : '\0';
			int len;

			len = scnprintf(buf, bufsize, "0x%08X%c",
					rinfo->des[grp->des[j]]->info->id, term);

			buf += len;
			bufsize -= len;
		}
	}

	rinfo->num_groups = ti->info.base.num_groups;

	return 0;
}

static int scmi_telemetry_de_descriptors_get(struct telemetry_info *ti)
{
	const struct scmi_protocol_handle *ph = ti->ph;

	struct scmi_iterator_ops ops = {
		.prepare_message = iter_tlm_prepare_message,
		.update_state = iter_de_descr_update_state,
		.process_response = iter_de_descr_process_response,
	};
	struct scmi_tlm_de_priv tpriv = {
		.ti = ti,
		.next = NULL,
	};
	void *iter;
	int ret;

	if (!ti->info.base.num_des)
		return 0;

	iter = ph->hops->iter_response_init(ph, &ops, ti->info.base.num_des,
					    TELEMETRY_DE_DESCRIPTION,
					    sizeof(u32), &tpriv);
	if (IS_ERR(iter))
		return PTR_ERR(iter);

	ret = ph->hops->iter_response_run(iter);
	if (ret)
		return ret;

	return scmi_telemetry_de_groups_init(ph->dev, ti);
}

struct scmi_tlm_ivl_priv {
	struct device *dev;
	struct scmi_tlm_intervals **intrvs;
	unsigned int grp_id;
	unsigned int flags;
};

static void iter_intervals_prepare_message(void *message,
					   unsigned int desc_index,
					   const void *priv)
{
	struct scmi_msg_telemetry_update_intervals *msg = message;
	const struct scmi_tlm_ivl_priv *p = priv;

	msg->index = cpu_to_le32(desc_index);
	msg->group_identifier = cpu_to_le32(p->grp_id);
	msg->flags = FIELD_PREP(GENMASK(3, 0), p->flags);
}

static int iter_intervals_update_state(struct scmi_iterator_state *st,
				       const void *response, void *priv)
{
	const struct scmi_msg_resp_telemetry_update_intervals *r = response;

	st->num_returned = le32_get_bits(r->flags, GENMASK(11, 0));
	st->num_remaining = le32_get_bits(r->flags, GENMASK(31, 16));

	if (st->rx_len < (sizeof(*r) + sizeof(r->intervals[0]) * st->num_returned))
		return -EINVAL;

	/*
	 * total intervals is not declared previously anywhere so we
	 * assume it's returned+remaining on first call.
	 */
	if (!st->max_resources) {
		struct scmi_tlm_ivl_priv *p = priv;
		struct scmi_tlm_intervals *intrvs;
		bool discrete;
		int inum;

		discrete = INTERVALS_DISCRETE(r->flags);
		/* Check consistency on first call */
		if (!discrete && (st->num_returned != 3 || st->num_remaining != 0))
			return -EINVAL;

		inum = st->num_returned + st->num_remaining;
		intrvs = kzalloc(sizeof(*intrvs) + inum * sizeof(__u32), GFP_KERNEL);
		if (!intrvs)
			return -ENOMEM;

		intrvs->num_intervals = inum;
		intrvs->discrete = discrete;
		st->max_resources = intrvs->num_intervals;

		*p->intrvs = intrvs;
	}

	return 0;
}

static int
iter_intervals_process_response(const struct scmi_protocol_handle *ph,
				const void *response,
				struct scmi_iterator_state *st, void *priv)
{
	const struct scmi_msg_resp_telemetry_update_intervals *r = response;
	struct scmi_tlm_ivl_priv *p = priv;
	struct scmi_tlm_intervals *intrvs = *p->intrvs;
	unsigned int idx = st->loop_idx;

	intrvs->update_intervals[st->desc_index + idx] = r->intervals[idx];

	return 0;
}

static int
scmi_tlm_enumerate_update_intervals(struct telemetry_info *ti,
				    struct scmi_tlm_intervals **intervals,
				    int grp_id, unsigned int flags)
{
	struct scmi_iterator_ops ops = {
		.prepare_message = iter_intervals_prepare_message,
		.update_state = iter_intervals_update_state,
		.process_response = iter_intervals_process_response,
	};
	const struct scmi_protocol_handle *ph = ti->ph;
	struct scmi_tlm_ivl_priv ipriv = {
		.dev = ph->dev,
		.grp_id = grp_id,
		.intrvs = intervals,
		.flags = flags,
	};
	void *iter;

	iter = ph->hops->iter_response_init(ph, &ops, 0,
		TELEMETRY_LIST_UPDATE_INTERVALS,
		sizeof(struct scmi_msg_telemetry_update_intervals),
		&ipriv);
	if (IS_ERR(iter))
		return PTR_ERR(iter);

	return ph->hops->iter_response_run(iter);
}

static int
scmi_telemetry_enumerate_groups_intervals(struct telemetry_info *ti)
{
	struct scmi_telemetry_res_info *rinfo = ACCESS_PRIVATE(ti, rinfo);

	if (!ti->info.per_group_config_support)
		return 0;

	for (int id = 0; id < rinfo->num_groups; id++) {
		int ret;

		ret = scmi_tlm_enumerate_update_intervals(ti,
							  &rinfo->grps[id].intervals,
							  id, SPECIFIC_GROUP_DES);
		if (ret)
			return ret;

		rinfo->grps_store[id].num_intervals =
			rinfo->grps[id].intervals->num_intervals;
	}

	return 0;
}

static void scmi_telemetry_intervals_free(void *interval)
{
	kfree(interval);
}

static int
scmi_telemetry_enumerate_common_intervals(struct telemetry_info *ti)
{
	unsigned int flags;
	int ret;

	flags = !ti->info.per_group_config_support ?
		ALL_DES_ANY_GROUP : ALL_DES_NO_GROUP;

	ret = scmi_tlm_enumerate_update_intervals(ti, &ti->info.intervals,
						  SCMI_TLM_GRP_INVALID, flags);
	if (ret)
		return ret;

	/* A copy for UAPI access... */
	ti->info.base.num_intervals = ti->info.intervals->num_intervals;

	/* Delegate freeing of allocated intervals to unbind time */
	return devm_add_action_or_reset(ti->ph->dev,
					scmi_telemetry_intervals_free,
					ti->info.intervals);
}

static int iter_shmti_update_state(struct scmi_iterator_state *st,
				   const void *response, void *priv)
{
	const struct scmi_msg_resp_telemetry_shmti_list *r = response;

	st->num_returned = le32_get_bits(r->num_shmti, GENMASK(15, 0));
	st->num_remaining = le32_get_bits(r->num_shmti, GENMASK(31, 16));

	if (st->rx_len < (sizeof(*r) + sizeof(r->desc[0]) * st->num_returned))
		return -EINVAL;

	return 0;
}

static inline int
scmi_telemetry_shmti_validate(struct device *dev, struct telemetry_shmti *shmti)
{
	struct tdcf __iomem *tdcf = shmti->base;
	u32 sign_start, sign_end;

	sign_start = TDCF_START_SIGNATURE(tdcf);
	sign_end = TDCF_END_SIGNATURE(SHMTI_EPLG(shmti));

	if (sign_start != SIGNATURE_START || sign_end != SIGNATURE_END) {
		dev_err(dev,
			"BAD signature for SHMTI ID:%u @phys:%pK - START:0x%04X END:0x%04X\n",
			shmti->id, shmti->base, sign_start, sign_end);
		return -EINVAL;
	}

	return 0;
}

static int iter_shmti_process_response(const struct scmi_protocol_handle *ph,
				       const void *response,
				       struct scmi_iterator_state *st,
				       void *priv)
{
	const struct scmi_msg_resp_telemetry_shmti_list *r = response;
	struct telemetry_info *ti = priv;
	struct telemetry_shmti *shmti;
	const struct scmi_shmti_desc *desc;
	void __iomem *addr;
	u64 phys_addr;
	u32 len;

	desc = &r->desc[st->loop_idx];
	shmti = &ti->shmti[st->desc_index + st->loop_idx];

	shmti->id = le32_to_cpu(desc->id);
	shmti->flags = le32_to_cpu(desc->flags);
	phys_addr = le32_to_cpu(desc->addr_low);
	phys_addr |= (u64)le32_to_cpu(desc->addr_high) << 32;

	len = le32_to_cpu(desc->length);
	if (len < SHMTI_MIN_SIZE) {
		dev_err(ph->dev, "Invalid length for SHMTI ID:%u len:%u\n",
			shmti->id, len);
		return -EINVAL;
	}

	addr = devm_ioremap(ph->dev, phys_addr, len);
	if (!addr)
		return -EADDRNOTAVAIL;

	shmti->base = addr;
	shmti->len = len;

	return scmi_telemetry_shmti_validate(ph->dev, shmti);
}

static int scmi_telemetry_shmti_list(const struct scmi_protocol_handle *ph,
				     struct telemetry_info *ti)
{
	struct scmi_iterator_ops ops = {
		.prepare_message = iter_tlm_prepare_message,
		.update_state = iter_shmti_update_state,
		.process_response = iter_shmti_process_response,
	};
	void *iter;

	iter = ph->hops->iter_response_init(ph, &ops, ti->info.base.num_des,
					    TELEMETRY_LIST_SHMTI,
					    sizeof(u32), ti);
	if (IS_ERR(iter))
		return PTR_ERR(iter);

	return ph->hops->iter_response_run(iter);
}

static int scmi_telemetry_enumerate_shmti(struct telemetry_info *ti)
{
	const struct scmi_protocol_handle *ph = ti->ph;
	int ret;

	if (!ti->num_shmti)
		return 0;

	ti->shmti = devm_kcalloc(ph->dev, ti->num_shmti, sizeof(*ti->shmti),
				 GFP_KERNEL);
	if (!ti->shmti)
		return -ENOMEM;

	ret = scmi_telemetry_shmti_list(ph, ti);
	if (ret) {
		dev_err(ph->dev, "Cannot get SHMTI list descriptors");
		return ret;
	}

	return 0;
}

static const struct scmi_telemetry_info *
scmi_telemetry_info_get(const struct scmi_protocol_handle *ph)
{
	struct telemetry_info *ti = ph->get_priv(ph);

	return &ti->info;
}

static const struct scmi_telemetry_de *
scmi_telemetry_de_lookup(const struct scmi_protocol_handle *ph, u32 id)
{
	struct telemetry_info *ti = ph->get_priv(ph);

	ti->res_get(ti);
	return xa_load(&ti->xa_des, id);
}

static const struct scmi_telemetry_res_info *
scmi_telemetry_resources_get(const struct scmi_protocol_handle *ph)
{
	struct telemetry_info *ti = ph->get_priv(ph);

	return ti->res_get(ti);
}

static u64
scmi_telemetry_blkts_read(u32 magic, struct telemetry_block_ts *bts)
{
	if (WARN_ON(!bts || !refcount_read(&bts->line.users)))
		return 0;

	guard(mutex)(&bts->line.mtx);

	if (bts->line.last_magic == magic)
		return bts->last_ts;

	/* Note that the bts->last_rate can change ONLY on creation */
	bts->last_ts = BLK_TS_STAMP(&bts->line.payld->blk_tsl);
	bts->line.last_magic = magic;

	return bts->last_ts;
}

static void scmi_telemetry_blkts_update(struct telemetry_info *ti, u32 magic,
					struct telemetry_block_ts *bts)
{
	guard(mutex)(&bts->line.mtx);

	if (bts->line.last_magic != magic) {
		bts->last_ts = BLK_TS_STAMP(&bts->line.payld->blk_tsl);
		bts->last_rate = BLK_TS_RATE(bts->line.payld);
		/* BLK_TS clock rate value can change ONLY here on creation */
		if (!bts->last_rate)
			bts->last_rate = ti->default_blk_ts_rate;
		bts->line.last_magic = magic;
	}
}

static void scmi_telemetry_line_put(struct telemetry_line *line, void *blob)
{
	if (refcount_dec_and_test(&line->users)) {
		scoped_guard(mutex, &line->mtx)
			xa_erase(line->xa_lines, (unsigned long)line->payld);
		kfree(blob);
	}
}

static void scmi_telemetry_blkts_unlink(struct telemetry_de *tde)
{
	scmi_telemetry_line_put(&tde->bts->line, tde->bts);
	tde->bts = NULL;
}

static void scmi_telemetry_uuid_unlink(struct telemetry_de *tde)
{
	scmi_telemetry_line_put(&tde->uuid->line, tde->uuid);
	tde->uuid = NULL;
}

static void scmi_telemetry_de_unlink(struct scmi_telemetry_de *de)
{
	struct telemetry_de *tde = to_tde(de);

	/* Unlink all related lines triggering their deallocation */
	if (tde->bts)
		scmi_telemetry_blkts_unlink(tde);
	if (tde->uuid)
		scmi_telemetry_uuid_unlink(tde);
}

static struct telemetry_line *
scmi_telemetry_line_get(struct xarray *xa_lines, struct payload *payld)
{
	struct telemetry_line *line;

	line = xa_load(xa_lines, (unsigned long)payld);
	if (!line)
		return NULL;

	refcount_inc(&line->users);

	return line;
}

static int
scmi_telemetry_line_init(struct telemetry_line *line, struct xarray *xa_lines,
			 struct payload __iomem *payld)
{
	refcount_set(&line->users, 1);
	line->payld = payld;
	line->xa_lines = xa_lines;
	mutex_init(&line->mtx);

	return xa_insert(xa_lines, (unsigned long)payld, line, GFP_KERNEL);
}

static struct telemetry_block_ts *
scmi_telemetry_blkts_create(struct device *dev, struct xarray *xa_lines,
			    struct payload *payld)
{
	struct telemetry_block_ts *bts;
	int ret;

	bts = kzalloc_obj(*bts);
	if (!bts)
		return NULL;

	ret = scmi_telemetry_line_init(&bts->line, xa_lines, payld);
	if (ret) {
		kfree(bts);
		return NULL;
	}

	trace_scmi_tlm_collect(0, (u64)payld, 0, "SHMTI_NEW_BLKTS");

	return bts;
}

static struct telemetry_block_ts *
scmi_telemetry_blkts_get_or_create(struct device *dev, struct xarray *xa_lines,
				   struct payload *payld)
{
	struct telemetry_line *line;

	line = scmi_telemetry_line_get(xa_lines, payld);
	if (line)
		return to_blkts(line);

	return scmi_telemetry_blkts_create(dev, xa_lines, payld);
}

static struct telemetry_uuid *
scmi_telemetry_uuid_create(struct device *dev, struct xarray *xa_lines,
			   struct payload *payld)
{
	struct telemetry_uuid *uuid;
	int ret;

	uuid = kzalloc_obj(*uuid);
	if (!uuid)
		return NULL;

	for (int i = 0; i < SCMI_TLM_DE_IMPL_MAX_DWORDS; i++)
		uuid->de_impl_version[i] = le32_to_cpu(payld->uuid_l.dwords[i]);

	ret = scmi_telemetry_line_init(&uuid->line, xa_lines, payld);
	if (ret) {
		kfree(uuid);
		return NULL;
	}

	trace_scmi_tlm_collect(0, (u64)payld, 0, "SHMTI_NEW_UUID");

	return uuid;
}

static struct telemetry_uuid *
scmi_telemetry_uuid_get_or_create(struct device *dev, struct xarray *xa_lines,
				  struct payload *payld)
{
	struct telemetry_line *line;

	line = scmi_telemetry_line_get(xa_lines, payld);
	if (line)
		return to_uuid(line);

	return scmi_telemetry_uuid_create(dev, xa_lines, payld);
}

static void scmi_telemetry_tdcf_uuid_parse(struct telemetry_info *ti,
					   struct payload __iomem *payld,
					   struct telemetry_shmti *shmti,
					   void **active_uuid)
{
	struct telemetry_uuid *uuid;

	if (UUID_INVALID(payld)) {
		trace_scmi_tlm_access(0, "UUID_INVALID", 0, 0);
		return;
	}

	/* A UUID descriptor MUST be returned: it is found or it is created */
	uuid = scmi_telemetry_uuid_get_or_create(ti->ph->dev, &ti->xa_lines,
						 payld);
	if (WARN_ON(!uuid))
		return;

	*active_uuid = uuid;
}

static struct payload *
scmi_telemetry_nearest_line_by_type(struct telemetry_shmti *shmti,
				    void *last, enum tdcf_line_types ltype)
{
	struct tdcf __iomem *tdcf = shmti->base;
	void *next, *found = NULL;

	/* Scan from start of TDCF payloads up to last_payld */
	next = tdcf->payld;
	while (next < last) {
		if (LINE_TYPE((struct payload *)next) == ltype)
			found = next;

		next += LINE_LENGTH_WORDS((struct payload *)next);
	}

	return found;
}

static struct telemetry_block_ts *
scmi_telemetry_blkts_bind(struct device *dev, struct telemetry_shmti *shmti,
			  struct payload *payld, struct xarray *xa_lines,
			  struct payload *bts_payld)
{
	/* Trigger a manual search when no BLK_TS payload offset was provided */
	if (!bts_payld) {
		/* Find the BLK_TS immediately preceding this DE payld */
		bts_payld = scmi_telemetry_nearest_line_by_type(shmti, payld,
								TDCF_BLK_TS_LINE);
		if (!bts_payld)
			return NULL;
	}

	return scmi_telemetry_blkts_get_or_create(dev, xa_lines, bts_payld);
}

/**
 * scmi_telemetry_tdcf_blkts_parse  - A BLK_TS line parser
 *
 * @ti: A reference to the telemetry_info descriptor
 * @payld: TDCF payld line to process
 * @shmti: SHMTI descriptor inside which the scan is happening
 * @active_bts: Input/output reference to keep track of the last blk_ts found
 *
 * Process a valid TDCF BLK_TS line and, after having looked up or created a
 * blk_ts descriptor, update the related data and return it as the currently
 * active blk_ts, given that it is effectively the last found during this
 * scan.
 */
static void scmi_telemetry_tdcf_blkts_parse(struct telemetry_info *ti,
					    struct payload __iomem *payld,
					    struct telemetry_shmti *shmti,
					    void **active_bts)
{
	struct telemetry_block_ts *bts;

	/* Check for spec compliance */
	if (BLK_TS_INVALID(payld)) {
		trace_scmi_tlm_access(0, "BLK_TS_INVALID", 0, 0);
		return;
	}

	/* A BLK_TS descriptor MUST be returned: it is found or it is created */
	bts = scmi_telemetry_blkts_get_or_create(ti->ph->dev,
						 &ti->xa_lines, payld);
	if (WARN_ON(!bts))
		return;

	/* Update the descriptor with the lastest TS */
	scmi_telemetry_blkts_update(ti, shmti->last_magic, bts);
	*active_bts = bts;
}

static inline struct telemetry_de *
scmi_telemetry_tde_allocate(struct telemetry_info *ti, u32 de_id,
			    struct payload __iomem *payld)
{
	struct telemetry_de *tde;

	tde = scmi_telemetry_tde_get(ti, de_id);
	if (IS_ERR(tde))
		return NULL;

	tde->de.info->id = de_id;
	tde->de.enabled = true;
	tde->de.tstamp_enabled = LINE_TS_VALID(payld) || USE_BLK_TS(payld);

	if (scmi_telemetry_tde_register(ti, tde)) {
		scmi_telemetry_free_tde_put(ti, tde);
		return NULL;
	}

	scmi_telemetry_de_state_update(ti, ENA_STATE, NULL, true);
	if (tde->de.tstamp_enabled)
		scmi_telemetry_de_state_update(ti, ENA_TSTAMP, NULL, true);

	return tde;
}

static inline void
scmi_telemetry_line_data_parse(struct telemetry_de *tde, u64 *val, u64 *tstamp,
			       struct payload __iomem *payld, u32 magic)
{
	/* Data is always valid since we are NOT handling BLK TS lines here */
	*val = LINE_DATA_GET(&payld->l);
	if (tstamp) {
		if (USE_BLK_TS(payld)) {
			/* Read out the actual BLK_TS */
			*tstamp = scmi_telemetry_blkts_read(magic, tde->bts);
		} else if (LINE_TS_VALID(payld)) {
			/*
			 * Note that LINE_TS_VALID implies HAS_LINE_EXT and that
			 * the per DE line_ts_rate is advertised in the DE
			 * descriptor.
			 */
			*tstamp = LINE_TSTAMP_GET(&payld->tsl);
		} else {
			*tstamp = 0;
		}
	}

	trace_scmi_tlm_collect(tstamp ? *tstamp : 0, tde->de.info->id,
			       *val, "SHMTI_DE_READ");

	scmi_telemetry_tde_cache_update(tde, *val, tstamp, &magic);
}

static inline void scmi_telemetry_bts_link(struct telemetry_de *tde,
					   struct telemetry_block_ts *bts)
{
	refcount_inc(&bts->line.users);
	tde->bts = bts;
	/* Update TS clock rate if provided by the BLK_TS */
	if (tde->bts->last_rate)
		tde->de.info->ts_rate = tde->bts->last_rate;
}

static inline void scmi_telemetry_uuid_link(struct telemetry_de *tde,
					    struct telemetry_uuid *uuid)
{
	refcount_inc(&uuid->line.users);
	tde->uuid = uuid;
}

/**
 * scmi_telemetry_tdcf_data_parse  - TDCF DataLine parsing
 * @ti: A reference to the telemetry info descriptor
 * @payld: Line payload to parse
 * @shmti: A reference to the containing SHMTI area
 * @mode: A flag to determine the behaviour of the scan
 * @active_bts: A pointer to keep track and report any found BLK timestamp line
 * @active_uuid: A pointer to keep track and report any found UUID line
 *
 * This routine takes care to:
 *  - verify line consistency in relation to the used flags and the current
 *    context: e.g. is there an active preceding BLK_TS line if the DataLine
 *    sports a USE_BLKTS flag ?
 *  - verify the related Data Event ID exists OR create a brand new DE
 *    (depending on the @mode of operation)
 *  - links any active BLK_TS or UUID line to the current DE
 *  - read and save value/tstamp for the DE ONLY if anything has changed (by
 *    tracking the last TDCF magic) and update related magic: this allows to
 *    minimize future needs of single-DE reads
 *
 *    Modes of operation.
 *
 *    The scan behaviour depends on the chosen @mode:
 *    - SCAN_LOOKUP: the basic scan which aims to update value associated to
 *		     existing DEs. Any discovered DataLine that could NOT be
 *		     matched to an existing, previously discovered, DE is
 *		     discarded. This is the normal scan behaviour.
 *    - SCAN_UPDATE: a more advanced scan which provides all the SCAN_LOOKUP
 *		     features plus takes care to update the DEs location
 *		     coordinates inside the SHMTI: note that the related DEs are
 *		     still supposed to have been previously discovered when
 *		     this scan runs. This is used to update location
 *		     coordinates for DEs contained in a Group when such group
 *		     is enabled.
 *    - SCAN_DISCOVERY: the most advanced scan available which provides all
 *			the SCAN_LOOKUP features plus discovery capabilities:
 *			any DataLine referring to a previously unknown DE leads
 *			to the allocation of a new DE descriptor.
 *			This mode is used on the first scan at init time, ONLY
 *			if Telemetry was found to be already enabled at boot on
 *			the platform side: this helps to maximize gathered
 *			information when dealing with out of spec firmwares.
 *			Any usage of this discovery mode other than in a boot-on
 *			enabled scenario is discouraged since it can easily
 *			lead to spurious DE discoveries.
 */
static void scmi_telemetry_tdcf_data_parse(struct telemetry_info *ti,
					   struct payload __iomem *payld,
					   struct telemetry_shmti *shmti,
					   enum scan_mode mode,
					   void *active_bts, void *active_uuid)
{
	bool use_blk_ts = USE_BLK_TS(payld);
	struct telemetry_de *tde;
	u64 val, tstamp = 0;
	u32 de_id;

	de_id = PAYLD_ID(payld);
	/* Discard malformed lines...a preceding BLK_TS must exist */
	if (use_blk_ts && !active_bts) {
		trace_scmi_tlm_access(de_id, "BAD_USE_BLK_TS", 0, 0);
		return;
	}

	/* Is this DE ID known ? */
	tde = scmi_telemetry_tde_lookup(ti, de_id);
	if (!tde) {
		if (mode != SCAN_DISCOVERY) {
			trace_scmi_tlm_access(de_id, "DE_INVALID", 0, 0);
			return;
		}

		/* In SCAN_DISCOVERY mode we allocate new DEs for unknown IDs */
		tde = scmi_telemetry_tde_allocate(ti, de_id, payld);
		if (!tde)
			return;
	}

	/* Update DE location refs if requested: normally done only on enable */
	if (mode >= SCAN_UPDATE) {
		tde->base = shmti->base;
		tde->eplg = SHMTI_EPLG(shmti);
		tde->offset = (void *)payld - (void *)shmti->base;

		dev_dbg(ti->ph->dev,
			"TDCF-updated DE_ID:0x%08X - shmti:%pK  offset:%u\n",
			tde->de.info->id, tde->base, tde->offset);
	}

	/* Has any value/tstamp really changed ?*/
	if (scmi_telemetry_tde_cache_unchanged(tde, shmti->last_magic))
		return;

	/* Link the related BTS when needed, it's unlinked on disable */
	if (use_blk_ts && !tde->bts)
		scmi_telemetry_bts_link(tde, active_bts);

	/* Link the active UUID when existent, it's unlinked on disable */
	if (active_uuid)
		scmi_telemetry_uuid_link(tde, active_uuid);

	/* Parse data words */
	scmi_telemetry_line_data_parse(tde, &val, &tstamp, payld,
				       shmti->last_magic);

}

static int scmi_telemetry_tdcf_line_parse(struct telemetry_info *ti,
					  struct payload __iomem *payld,
					  struct telemetry_shmti *shmti,
					  enum scan_mode mode,
					  void **active_bts, void **active_uuid)
{
	int used_qwords;

	used_qwords = LINE_LENGTH_QWORDS(payld);
	/* Invalid lines are not an error, could simply be disabled DEs */
	if (DATA_INVALID(payld)) {
		trace_scmi_tlm_access(PAYLD_ID(payld), "TDCF_INVALID", 0, 0);
		return used_qwords;
	}

	switch (LINE_TYPE(payld)) {
	case TDCF_DATA_LINE:
		scmi_telemetry_tdcf_data_parse(ti, payld, shmti, mode,
					       *active_bts, *active_uuid);
		break;
	case TDCF_BLK_TS_LINE:
		scmi_telemetry_tdcf_blkts_parse(ti, payld, shmti, active_bts);
		break;
	case TDCF_UUID_LINE:
		scmi_telemetry_tdcf_uuid_parse(ti, payld, shmti, active_uuid);
		break;
	default:
		trace_scmi_tlm_access(PAYLD_ID(payld), "TDCF_UNKNOWN", 0, 0);
		break;
	}

	return used_qwords;
}

/**
 * scmi_telemetry_shmti_scan  - Full SHMTI scan
 * @ti: A reference to the telemetry info descriptor
 * @shmti_id: ID of the SHMTI area that has to be scanned
 * @mode: A flag to determine the behaviour of the scan
 *
 * Return: 0 on Success
 */
static int scmi_telemetry_shmti_scan(struct telemetry_info *ti,
				     unsigned int shmti_id, enum scan_mode mode)
{
	struct telemetry_shmti *shmti = &ti->shmti[shmti_id];
	struct tdcf __iomem *tdcf = shmti->base;
	int retries = SCMI_TLM_TDCF_MAX_RETRIES;
	u32 startm = 0, endm = TDCF_BAD_END_SEQ;

	if (!tdcf)
		return -ENODEV;

	do {
		void *active_bts = NULL, *active_uuid = NULL;
		unsigned int qwords;
		void __iomem *next;

		/* A bit of exponential backoff between retries */
		fsleep((SCMI_TLM_TDCF_MAX_RETRIES - retries) * 1000);

		/*
		 * Note that during a full SHMTI scan the magic seq numbers are
		 * checked only at the start and at the end of the scan, NOT
		 * between each parsed line and this has these consequences:
		 *  - TDCF magic numbers accesses are reduced to 2 reads
		 *  - the set of values obtained from a full scan belong all
		 *    to the same platform update (same magic number)
		 *  - a SHMTI full scan is an all or nothing operation: when
		 *    a potentially corrupted read is detected along the way
		 *    (MSEQ_MISMATCH) another full scan is triggered.
		 */
		startm = TDCF_START_SEQ_GET(tdcf);
		if (IS_BAD_START_SEQ(startm)) {
			trace_scmi_tlm_access(0, "MSEQ_BADSTART", startm, 0);
			continue;
		}

		/* On a BAD_SEQ this will be updated on the next attempt */
		shmti->last_magic = startm;

		qwords = QWORDS(tdcf);
		next = tdcf->payld;
		while (qwords) {
			int used_qwords;

			used_qwords = scmi_telemetry_tdcf_line_parse(ti, next,
								     shmti, mode,
								     &active_bts,
								     &active_uuid);
			if (qwords < used_qwords) {
				trace_scmi_tlm_access(PAYLD_ID(next),
						      "BAD_QWORDS", startm, 0);
				return -EINVAL;
			}

			next += used_qwords * 8;
			qwords -= used_qwords;
		}

		endm = TDCF_END_SEQ_GET(SHMTI_EPLG(shmti));
		if (startm != endm)
			trace_scmi_tlm_access(0, "MSEQ_MISMATCH", startm, endm);
	} while (startm != endm && --retries);

	if (startm != endm) {
		trace_scmi_tlm_access(0, "TDCF_SCAN_FAIL", startm, endm);
		return -EPROTO;
	}

	return 0;
}

static int scmi_telemetry_group_state_update(struct telemetry_info *ti,
					     struct scmi_telemetry_group *grp,
					     bool *enable, bool *tstamp)
{
	struct scmi_telemetry_res_info *rinfo;

	rinfo = ti->res_get(ti);
	for (int i = 0; i < grp->info->num_des; i++) {
		struct scmi_telemetry_de *de = rinfo->des[grp->des[i]];

		if (enable)
			scmi_telemetry_de_state_update(ti, ENA_STATE,
						       &de->enabled, *enable);

		if (tstamp && de->tstamp_support)
			scmi_telemetry_de_state_update(ti, ENA_TSTAMP,
						       &de->tstamp_enabled, *tstamp);
	}

	return 0;
}

static int
scmi_telemetry_state_set_resp_process(struct telemetry_info *ti,
				      struct scmi_telemetry_de *de,
				      void *r, bool is_group)
{
	struct scmi_msg_resp_telemetry_de_configure *resp = r;
	u32 sid = le32_to_cpu(resp->shmti_id);

	/* Update DE SHMTI and offset, if applicable */
	if (IS_SHMTI_ID_VALID(sid)) {
		if (sid >= ti->num_shmti)
			return -EPROTO;

		/*
		 * Update SHMTI/offset while skipping non-SHMTI-DEs like
		 * FCs and notif-only.
		 */
		if (!is_group) {
			struct telemetry_de *tde;
			struct payload *payld;
			u32 de_offs;

			de_offs = le32_to_cpu(resp->shmti_de_offset);
			if (de_offs >= ti->shmti[sid].len - de->info->data_sz)
				return -EPROTO;

			tde = to_tde(de);
			tde->base = ti->shmti[sid].base;
			tde->offset = de_offs;
			/* A handy reference to the Epilogue updated */
			tde->eplg = SHMTI_EPLG(&ti->shmti[sid]);

			payld = tde->base + tde->offset;
			if (USE_BLK_TS(payld) && !tde->bts) {
				struct payload *bts_payld;
				u32 bts_offs;

				bts_offs = le32_to_cpu(resp->blk_ts_offset);
				bts_payld = (bts_offs) ? tde->base + bts_offs : NULL;
				tde->bts = scmi_telemetry_blkts_bind(ti->ph->dev,
								     &ti->shmti[sid],
								     payld,
								     &ti->xa_lines,
								     bts_payld);
				if (WARN_ON(!tde->bts))
					return -EPROTO;
			}
		} else {
			int ret;

			/*
			 * A full SHMTI scan is needed when enabling a
			 * group or its timestamps in order to retrieve
			 * offsets: note that when group-timestamp is
			 * enabled for composing DEs a re-scan is needed
			 * since some DEs could have been relocated due
			 * to lack of space in the TDCF.
			 */
			ret = scmi_telemetry_shmti_scan(ti, sid, SCAN_UPDATE);
			if (ret)
				dev_warn(ti->ph->dev,
					 "Failed group-scan of SHMTI ID:%d - ret:%d\n",
					 sid, ret);
		}
	} else if (!is_group) {
		/* Unlink the related BLK_TS/UUID lines on disable */
		scmi_telemetry_de_unlink(de);
	}

	return 0;
}

static int __scmi_telemetry_state_set(const struct scmi_protocol_handle *ph,
				      bool is_group, bool *enable,
				      bool *enabled_state, bool *tstamp,
				      bool *tstamp_enabled_state, void *obj)
{
	struct scmi_msg_resp_telemetry_de_configure *resp;
	struct scmi_msg_telemetry_de_configure *msg;
	struct telemetry_info *ti = ph->get_priv(ph);
	struct scmi_telemetry_de *de = !is_group ? obj : NULL;
	struct scmi_telemetry_group *grp = is_group ? obj : NULL;
	unsigned int obj_id = !is_group ? de->info->id : grp->info->id;
	struct scmi_xfer *t;
	int ret;

	if (!enabled_state || !tstamp_enabled_state)
		return -EINVAL;

	/* Is anything to do at all on this DE ? */
	if (!is_group && (!enable || *enable == *enabled_state) &&
	    (!tstamp || *tstamp == *tstamp_enabled_state))
		return 0;

	/*
	 * DE is currently disabled AND no enable state change was requested,
	 * while timestamp is being changed: update only local state...no need
	 * to send a message.
	 */
	if (!is_group && !enable && !*enabled_state) {
		if (de->tstamp_support)
			scmi_telemetry_de_state_update(ti, ENA_TSTAMP,
						       tstamp_enabled_state,
						       *tstamp);

		return 0;
	}

	ret = ph->xops->xfer_get_init(ph, TELEMETRY_DE_CONFIGURE,
				      sizeof(*msg), sizeof(*resp), &t);
	if (ret)
		return ret;

	msg = t->tx.buf;
	/* Note that BOTH DE and GROUPS have a first ID field.. */
	msg->id = cpu_to_le32(obj_id);
	/* Default to disable mode for one DE */
	msg->flags = DE_DISABLE_ONE;
	msg->flags |= FIELD_PREP(GENMASK(3, 3),
				 is_group ? EVENT_GROUP : EVENT_DE);

	if ((!enable && *enabled_state) || (enable && *enable)) {
		/* Already enabled but tstamp_enabled state changed */
		if (tstamp) {
			/* Here, tstamp cannot be NULL too */
			msg->flags |= *tstamp ? DE_ENABLE_WTH_TSTAMP :
				DE_ENABLE_NO_TSTAMP;
		} else {
			msg->flags |= *tstamp_enabled_state ?
				DE_ENABLE_WTH_TSTAMP : DE_ENABLE_NO_TSTAMP;
		}
	}

	resp = t->rx.buf;
	ret = ph->xops->do_xfer(ph, t);
	if (!ret) {
		ret = scmi_telemetry_state_set_resp_process(ti, obj, resp, is_group);
		if (!ret) {
			/* Update cached state on success */
			if (enable) {
				if (!is_group)
					scmi_telemetry_de_state_update(ti, ENA_STATE,
								       enabled_state,
								       *enable);
				else
					*enabled_state = *enable;
			}
			if (tstamp) {
				if (!is_group) {
					if (de->tstamp_support)
						scmi_telemetry_de_state_update(ti, ENA_TSTAMP,
									       tstamp_enabled_state,
									       *tstamp);
				} else {
					*tstamp_enabled_state = *tstamp;
				}
			}

			if (is_group)
				scmi_telemetry_group_state_update(ti, grp, enable,
								  tstamp);
		}
	}

	ph->xops->xfer_put(ph, t);

	return ret;
}

static int scmi_telemetry_state_get(const struct scmi_protocol_handle *ph,
				    u32 *id, bool *enabled, bool *tstamp_enabled)
{
	struct telemetry_info *ti = ph->get_priv(ph);
	struct scmi_telemetry_de *de;

	if (!enabled || !tstamp_enabled)
		return -EINVAL;

	if (!id) {
		/* Returning the all_des_* state */
		*enabled =
			(atomic_read(&ti->des_enabled[ENA_STATE]) == ti->info.base.num_des);
		*tstamp_enabled =
			(atomic_read(&ti->des_enabled[ENA_TSTAMP]) == ti->num_des_tstamp);

		return 0;
	}

	de = xa_load(&ti->xa_des, *id);
	if (!de)
		return -ENODEV;

	*enabled = de->enabled;
	*tstamp_enabled = de->tstamp_enabled;

	return 0;
}

static int scmi_telemetry_state_set(const struct scmi_protocol_handle *ph,
				    bool is_group, u32 id, bool *enable,
				    bool *tstamp)
{
	struct telemetry_info *ti = ph->get_priv(ph);
	bool *enabled_state, *tstamp_enabled_state;
	struct scmi_telemetry_res_info *rinfo;
	void *obj;

	rinfo = ti->res_get(ti);
	if (!is_group) {
		struct scmi_telemetry_de *de;

		de = xa_load(&ti->xa_des, id);
		if (!de)
			return -ENODEV;

		enabled_state = &de->enabled;
		tstamp_enabled_state = &de->tstamp_enabled;
		obj = de;
	} else {
		struct scmi_telemetry_group *grp;

		if (id >= ti->info.base.num_groups)
			return -EINVAL;

		grp = &rinfo->grps[id];

		enabled_state = &grp->enabled;
		tstamp_enabled_state = &grp->tstamp_enabled;
		obj = grp;
	}

	return __scmi_telemetry_state_set(ph, is_group, enable, enabled_state,
					  tstamp, tstamp_enabled_state, obj);
}

static int scmi_telemetry_all_disable(const struct scmi_protocol_handle *ph,
				      bool is_group)
{
	struct telemetry_info *ti = ph->get_priv(ph);
	struct scmi_msg_telemetry_de_configure *msg;
	struct scmi_telemetry_res_info *rinfo;
	struct scmi_xfer *t;
	int ret;

	rinfo = ti->res_get(ti);
	ret = ph->xops->xfer_get_init(ph, TELEMETRY_DE_CONFIGURE,
				      sizeof(*msg), 0, &t);
	if (ret)
		return ret;

	msg = t->tx.buf;
	msg->flags = DE_DISABLE_ALL;
	if (is_group)
		msg->flags |= GROUP_SELECTOR;
	ret = ph->xops->do_xfer(ph, t);
	if (!ret) {
		for (int i = 0; i < ti->info.base.num_des; i++)
			scmi_telemetry_de_state_update(ti, ENA_STATE,
						       &rinfo->des[i]->enabled,
						       false);

		if (is_group) {
			for (int i = 0; i < ti->info.base.num_groups; i++)
				rinfo->grps[i].enabled = false;
		}
	}

	ph->xops->xfer_put(ph, t);

	return ret;
}

static int
scmi_telemetry_collection_configure(const struct scmi_protocol_handle *ph,
				    unsigned int res_id, bool grp_ignore,
				    bool *enable,
				    unsigned int *update_interval_ms,
				    enum scmi_telemetry_collection *mode)
{
	enum scmi_telemetry_collection *current_mode, next_mode;
	struct telemetry_info *ti = ph->get_priv(ph);
	struct scmi_msg_telemetry_config_set *msg;
	unsigned int *active_update_interval;
	struct scmi_xfer *t;
	bool tlm_enable;
	u32 interval;
	int ret;

	if (mode && *mode == SCMI_TLM_NOTIFICATION &&
	    !ti->info.continuos_update_support)
		return -EINVAL;

	if (res_id != SCMI_TLM_GRP_INVALID && res_id >= ti->info.base.num_groups)
		return -EINVAL;

	if (res_id == SCMI_TLM_GRP_INVALID || grp_ignore) {
		active_update_interval = &ti->info.active_update_interval;
		current_mode = &ti->info.current_mode;
	} else {
		struct scmi_telemetry_res_info *rinfo;

		rinfo = ti->res_get(ti);
		active_update_interval =
			&rinfo->grps[res_id].active_update_interval;
		current_mode = &rinfo->grps[res_id].current_mode;
	}

	if (!enable && !update_interval_ms && (!mode || *mode == *current_mode))
		return 0;

	ret = ph->xops->xfer_get_init(ph, TELEMETRY_CONFIG_SET,
				      sizeof(*msg), 0, &t);
	if (ret)
		return ret;

	if (!update_interval_ms)
		interval = cpu_to_le32(*active_update_interval);
	else
		interval = *update_interval_ms;

	tlm_enable = enable ? *enable : ti->info.enabled;
	next_mode = mode ? *mode : *current_mode;

	msg = t->tx.buf;
	msg->grp_id = res_id;
	msg->control = tlm_enable ? TELEMETRY_ENABLE : 0;
	msg->control |= grp_ignore ? TELEMETRY_SET_SELECTOR_ALL :
		TELEMETRY_SET_SELECTOR_GROUP;
	msg->control |= TELEMETRY_MODE_SET(next_mode);
	msg->sampling_rate = interval;
	ret = ph->xops->do_xfer(ph, t);
	if (!ret) {
		ti->info.enabled = tlm_enable;
		*current_mode = next_mode;
		ti->info.notif_enabled = *current_mode == SCMI_TLM_NOTIFICATION;
		if (update_interval_ms)
			*active_update_interval = interval;
	}

	ph->xops->xfer_put(ph, t);

	return ret;
}

static const struct scmi_telemetry_proto_ops tlm_proto_ops = {
	.info_get = scmi_telemetry_info_get,
	.de_lookup = scmi_telemetry_de_lookup,
	.res_get = scmi_telemetry_resources_get,
	.state_get = scmi_telemetry_state_get,
	.state_set = scmi_telemetry_state_set,
	.all_disable = scmi_telemetry_all_disable,
	.collection_configure = scmi_telemetry_collection_configure,
};

/**
 * scmi_telemetry_resources_alloc  - Resources allocation
 * @ti: A reference to the telemetry info descriptor for this instance
 *
 * This allocates and initializes dedicated resources for the maximum possible
 * number of needed telemetry resources, based on information gathered from
 * the initial enumeration: these allocations represent an upper bound on
 * the number of discoverable telemetry resources and they will be later
 * populated during late deferred further discovery phases.
 *
 * Return: 0 on Success, errno otherwise
 */
static int scmi_telemetry_resources_alloc(struct telemetry_info *ti)
{
	/* Array to hold pointers to discovered DEs */
	struct scmi_telemetry_de **des __free(kfree) =
		kcalloc(ti->info.base.num_des, sizeof(*des), GFP_KERNEL);
	if (!des)
		return -ENOMEM;

	/* The allocated DE descriptors */
	struct telemetry_de *tdes __free(kfree) =
		kcalloc(ti->info.base.num_des, sizeof(*tdes), GFP_KERNEL);
	if (!tdes)
		return -ENOMEM;

	/* Allocate a set of contiguous DE info descriptors. */
	struct scmi_tlm_de_info *dei_store __free(kfree) =
		kcalloc(ti->info.base.num_des, sizeof(*dei_store), GFP_KERNEL);
	if (!dei_store)
		return -ENOMEM;

	/* Array to hold descriptors of discovered GROUPs */
	struct scmi_telemetry_group *grps __free(kfree) =
		kcalloc(ti->info.base.num_groups, sizeof(*grps), GFP_KERNEL);
	if (!grps)
		return -ENOMEM;

	/* Allocate a set of contiguous Group info descriptors. */
	struct scmi_tlm_grp_info *grps_store __free(kfree) =
		kcalloc(ti->info.base.num_groups, sizeof(*grps_store), GFP_KERNEL);
	if (!grps_store)
		return -ENOMEM;

	struct scmi_telemetry_res_info *rinfo __free(kfree) =
		kzalloc(sizeof(*rinfo), GFP_KERNEL);
	if (!rinfo)
		return -ENOMEM;

	mutex_init(&ti->free_mtx);
	INIT_LIST_HEAD(&ti->free_des);
	for (int i = 0; i < ti->info.base.num_des; i++) {
		mutex_init(&tdes[i].mtx);
		/* Bind contiguous DE info structures */
		tdes[i].de.info = &dei_store[i];
		list_add_tail(&tdes[i].item, &ti->free_des);
	}

	for (int i = 0; i < ti->info.base.num_groups; i++) {
		grps_store[i].id = i;
		/* Bind contiguous Group info struct */
		grps[i].info = &grps_store[i];
	}

	INIT_LIST_HEAD(&ti->fcs_des);

	ti->tdes = no_free_ptr(tdes);

	rinfo->des = no_free_ptr(des);
	rinfo->dei_store = no_free_ptr(dei_store);
	rinfo->grps = no_free_ptr(grps);
	rinfo->grps_store = no_free_ptr(grps_store);

	ACCESS_PRIVATE(ti, rinfo) = no_free_ptr(rinfo);

	return 0;
}

static void scmi_telemetry_resources_free(void *arg)
{
	struct telemetry_info *ti = arg;
	struct scmi_telemetry_res_info *rinfo = ACCESS_PRIVATE(ti, rinfo);

	/*
	 * Unlinking all the BLK_TS/UUID lines related to a DE triggers also
	 * the deallocation of such lines when the embedded refcount hits zero.
	 */
	for (int i = 0; i < rinfo->num_des; i++)
		scmi_telemetry_de_unlink(rinfo->des[i]);

	kfree(ti->tdes);
	kfree(rinfo->des);
	kfree(rinfo->dei_store);
	kfree(rinfo->grps);
	kfree(rinfo->grps_store);

	kfree(rinfo);

	ACCESS_PRIVATE(ti, rinfo) = NULL;
}

static struct scmi_telemetry_res_info *
__scmi_telemetry_resources_get(struct telemetry_info *ti)
{
	return ACCESS_PRIVATE(ti, rinfo);
}

/**
 * scmi_telemetry_resources_enumerate  - Enumeration helper
 * @ti: A reference to the telemetry info descriptor for this instance
 *
 * This helper is configured to be called once on the first enumeration
 * attempt, when triggered by invoking ti->res_get() from somewhere else.
 * Once run it substitues itself in ti->res_get() with the simple accessor
 * __scmi_telemetry_resources_get, which returns a descriptor to the resources
 * that were possibly discovered.
 *
 * Note that, while it attempts to fully enumerate Data Events and Groups, it
 * does NOT fail when such enumerations fail, instead it simply gives up with
 * the end result that only a partially populated, but consistent, resources
 * descriptor will be returned; in such a case the incomplete descriptor will
 * be marked as NOT fully_enumerated: this design enables the kernel to deal
 * with badly implemented out-of-spec firmware support while keep on providing
 * a minimal sane, albeit possibly incomplete, set of telemetry respources.
 *
 * Return: A reference to a fully or partially populated resources descriptor
 */
static struct scmi_telemetry_res_info *
scmi_telemetry_resources_enumerate(struct telemetry_info *ti)
{
	struct scmi_telemetry_res_info *rinfo = ACCESS_PRIVATE(ti, rinfo);
	struct device *dev = ti->ph->dev;
	int ret;

	/*
	 * Ensure this init function can be called only once and
	 * handles properly concurrent calls.
	 */
	if (atomic_cmpxchg(&ti->rinfo_initializing, 0, 1)) {
		if (!completion_done(&ti->rinfo_initdone))
			wait_for_completion(&ti->rinfo_initdone);
		goto out;
	}

	ret = scmi_telemetry_de_descriptors_get(ti);
	if (ret) {
		dev_err(dev, FW_BUG "Cannot fully enumerate DEs resources. Degraded system.\n");
		goto done;
	}

	ret = scmi_telemetry_enumerate_groups_intervals(ti);
	if (ret) {
		dev_err(dev, FW_BUG "Cannot fully enumerate group intervals. Degraded system.\n");
		goto done;
	}

	/* If we got here, the enumeration was fully successful */
	rinfo->fully_enumerated = true;
done:
	/* Disable initialization permanently */
	smp_store_mb(ti->res_get, __scmi_telemetry_resources_get);
	complete_all(&ti->rinfo_initdone);

out:
	return rinfo;
}

/**
 * scmi_telemetry_instance_init  - Instance initializer
 * @ti: A reference to the telemetry info descriptor for this instance
 *
 * Note that this allocates and initialize all the resources possibly needed
 * and then setups the @scmi_telemetry_resources_enumerate helper as the
 * default method for the first call to ti->res_get(): this mechanism enables
 * the possibility of optionally implementing deferred enumeration policies
 * which optionally delay the discovery phase and related SCMI message exchanges
 * to a later point in time.
 *
 * Return: 0 on Success, errno otherwise
 */
static int scmi_telemetry_instance_init(struct telemetry_info *ti)
{
	int ret;

	/* Allocate and Initialize on first call... */
	ret = scmi_telemetry_resources_alloc(ti);
	if (ret)
		return ret;

	ret = devm_add_action_or_reset(ti->ph->dev,
				       scmi_telemetry_resources_free, ti);
	if (ret)
		return ret;

	xa_init(&ti->xa_des);
	xa_init(&ti->xa_lines);
	atomic_set(&ti->des_enabled[ENA_STATE], 0);
	atomic_set(&ti->des_enabled[ENA_TSTAMP], 0);
	/* Setup resources lazy initialization */
	atomic_set(&ti->rinfo_initializing, 0);
	init_completion(&ti->rinfo_initdone);
	/* Ensure the new res_get() operation is visible after this point */
	smp_store_mb(ti->res_get, scmi_telemetry_resources_enumerate);

	return 0;
}

static int scmi_telemetry_protocol_init(const struct scmi_protocol_handle *ph)
{
	struct device *dev = ph->dev;
	struct telemetry_info *ti;
	int ret;

	dev_dbg(dev, "Telemetry Version %d.%d\n",
		PROTOCOL_REV_MAJOR(ph->version), PROTOCOL_REV_MINOR(ph->version));

	ti = devm_kzalloc(dev, sizeof(*ti), GFP_KERNEL);
	if (!ti)
		return -ENOMEM;

	ti->ph = ph;

	ret = scmi_telemetry_protocol_attributes_get(ti);
	if (ret) {
		dev_err(dev, FW_BUG "Cannot retrieve protocol attributes. Abort.\n");
		return ret;
	}

	ret = scmi_telemetry_instance_init(ti);
	if (ret) {
		dev_err(dev, "Cannot initialize instance. Abort.\n");
		return ret;
	}

	ret = scmi_telemetry_enumerate_common_intervals(ti);
	if (ret) {
		dev_err(dev, FW_BUG "Cannot enumerate update intervals. Abort.\n");
		return ret;
	}

	ret = scmi_telemetry_enumerate_shmti(ti);
	if (ret) {
		dev_err(dev, FW_BUG "Cannot enumerate SHMTIs. Abort.\n");
		return ret;
	}

	ti->info.base.version = ph->version;

	return ph->set_priv(ph, ti);
}

static const struct scmi_protocol scmi_telemetry = {
	.id = SCMI_PROTOCOL_TELEMETRY,
	.owner = THIS_MODULE,
	.instance_init = &scmi_telemetry_protocol_init,
	.ops = &tlm_proto_ops,
	.supported_version = SCMI_PROTOCOL_SUPPORTED_VERSION,
};

DEFINE_SCMI_PROTOCOL_REGISTER_UNREGISTER(telemetry, scmi_telemetry)
