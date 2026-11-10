// SPDX-License-Identifier: GPL-2.0
/*
 * KGuard Kernel Module - per-source state, blocklist and allowlist
 *
 * Source table
 *   An rhashtable keyed by (address, network namespace). Lookups run under
 *   RCU from the packet path; each entry's counters are protected by its own
 *   spinlock, so different sources never contend. Entries are created on the
 *   first connection attempt, up to max_sources; beyond that, new sources
 *   are counted but not tracked. A delayed work item frees idle entries
 *   every second (sooner when the table is nearly full) with kfree_rcu().
 *
 *   Per source:
 *     - a 1024-bit bitmap of destination ports tried in the current window
 *       (distinct-port count for scan detection). A port's bit is a keyed
 *       hash of it (siphash, key drawn at load time): a plain "port % 1024"
 *       let a scanner pick ports 1024 apart, which all share one bit, and
 *       never be counted. Random collisions undercount by about n^2/2048
 *       ports after n distinct ones, under 0.2 at the default threshold.
 *     - a token bucket for TCP SYNs (rate limiting)
 *
 * Blocklist
 *   An rhashtable of addresses with optional expiry. Checked first in the
 *   guard hook. Local addresses can never be blocked.
 *
 * Allowlist
 *   A small array of CIDR prefixes, replaced copy-on-write under a mutex and
 *   read under RCU. Allowlisted sources skip the guard entirely.
 */

#include "kguard.h"
#include "kguard_compat.h"

#include <linux/inet.h>
#include <linux/jiffies.h>
#include <linux/random.h>
#include <linux/rhashtable.h>
#include <linux/siphash.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <net/addrconf.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/route.h>

#define KGUARD_PORT_BITS	1024

/* Maps ports to bitmap bits; secret so that collisions cannot be chosen */
static siphash_key_t kguard_port_key __read_mostly;
#define KGUARD_ALLOW_MAX	256
#define KGUARD_BLOCK_MAX	65536
#define KGUARD_GC_PERIOD	HZ
/* Do not repeat an alert for the same source and kind within this time */
#define KGUARD_ALERT_COOLDOWN_NS	(10ULL * NSEC_PER_SEC)
/* Token buckets count thousandths of a token */
#define KGUARD_TOKEN		1000ULL

struct kguard_src_key {
	struct kguard_addr addr;
	u32 netns;
};

struct kguard_src {
	struct rhash_head node;
	struct kguard_src_key key;
	struct rcu_head rcu;
	bool protected;		/* local address: never drop or block */
	spinlock_t lock;	/* protects everything below */
	u64 last_seen_ns;
	u64 window_start_ns;
	u32 ports;		/* distinct ports in the window */
	u32 attempts;		/* attempts in the window */
	u64 tokens;		/* thousandths of a token */
	u64 tokens_ns;		/* last refill */
	u64 scan_alert_ns;
	u64 rate_alert_ns;
	DECLARE_BITMAP(port_bits, KGUARD_PORT_BITS);
};

struct kguard_block {
	struct rhash_head node;
	struct kguard_addr addr;
	struct rcu_head rcu;
	u64 expires_ns;		/* monotonic; 0 = never */
	u8 reason;
};

struct kguard_prefix {
	struct kguard_addr addr;
	u8 prefix_len;
};

struct kguard_allowlist {
	struct rcu_head rcu;
	unsigned int count;
	struct kguard_prefix entries[];
};

static const struct rhashtable_params kguard_src_params = {
	.key_len		= sizeof(struct kguard_src_key),
	.key_offset		= offsetof(struct kguard_src, key),
	.head_offset		= offsetof(struct kguard_src, node),
	.automatic_shrinking	= true,
};

static const struct rhashtable_params kguard_block_params = {
	.key_len		= sizeof(struct kguard_addr),
	.key_offset		= offsetof(struct kguard_block, addr),
	.head_offset		= offsetof(struct kguard_block, node),
	.automatic_shrinking	= true,
};

static struct rhashtable kguard_src_ht;
static struct rhashtable kguard_block_ht;
static struct kmem_cache *kguard_src_cache;
static atomic_t kguard_src_count = ATOMIC_INIT(0);
static atomic_t kguard_block_nr = ATOMIC_INIT(0);
static atomic64_t kguard_src_full = ATOMIC64_INIT(0);
static unsigned int kguard_max_sources;
static u64 kguard_idle_ns;

static struct kguard_allowlist __rcu *kguard_allowlist;
static DEFINE_MUTEX(kguard_allow_lock);

static struct delayed_work kguard_gc_work;

/* ---- addresses ---- */

int kguard_addr_len(const struct kguard_addr *a)
{
	return a->family == AF_INET6 ? 16 : 4;
}

int kguard_addr_from_nla(struct kguard_addr *a, const void *data, int len)
{
	memset(a, 0, sizeof(*a));
	if (len == 4)
		a->family = AF_INET;
	else if (len == 16)
		a->family = AF_INET6;
	else
		return -EINVAL;
	memcpy(a->bytes, data, len);
	return 0;
}

bool kguard_addr_is_local(struct net *net, const struct kguard_addr *a)
{
	if (a->family == AF_INET) {
		__be32 addr;

		memcpy(&addr, a->bytes, sizeof(addr));
		return ipv4_is_loopback(addr) || ipv4_is_zeronet(addr) ||
		       inet_addr_type(net, addr) == RTN_LOCAL;
	}
#if IS_ENABLED(CONFIG_IPV6)
	{
		struct in6_addr addr;

		memcpy(&addr, a->bytes, sizeof(addr));
		return ipv6_addr_loopback(&addr) || ipv6_addr_any(&addr) ||
		       ipv6_chk_addr(net, &addr, NULL, 0);
	}
#else
	return false;
#endif
}

static bool kguard_prefix_match(const struct kguard_prefix *p,
				const struct kguard_addr *a)
{
	unsigned int bytes, bits;

	if (p->addr.family != a->family)
		return false;
	bytes = p->prefix_len / 8;
	bits = p->prefix_len % 8;
	if (memcmp(p->addr.bytes, a->bytes, bytes))
		return false;
	if (bits) {
		u8 mask = 0xff << (8 - bits);

		return !((p->addr.bytes[bytes] ^ a->bytes[bytes]) & mask);
	}
	return true;
}

/* Clear the host bits after the prefix */
static void kguard_prefix_mask(struct kguard_addr *a, u8 prefix_len)
{
	unsigned int i;

	for (i = 0; i < 16; i++) {
		unsigned int start = i * 8;

		if (prefix_len <= start)
			a->bytes[i] = 0;
		else if (prefix_len < start + 8)
			a->bytes[i] &= 0xff << (8 - (prefix_len - start));
	}
}

/* ---- source table ---- */

u64 kguard_track_count(void)
{
	return atomic_read(&kguard_src_count);
}

u64 kguard_track_full(void)
{
	return atomic64_read(&kguard_src_full);
}

static struct kguard_src *kguard_src_lookup_or_create(struct net *net,
						      const struct kguard_src_key *key,
						      u64 now)
{
	struct kguard_src *src, *old;

	src = rhashtable_lookup(&kguard_src_ht, key, kguard_src_params);
	if (src)
		return src;

	if (atomic_inc_return(&kguard_src_count) > kguard_max_sources) {
		atomic_dec(&kguard_src_count);
		atomic64_inc(&kguard_src_full);
		return NULL;
	}

	src = kmem_cache_zalloc(kguard_src_cache, GFP_ATOMIC);
	if (!src) {
		atomic_dec(&kguard_src_count);
		return NULL;
	}
	src->key = *key;
	spin_lock_init(&src->lock);
	src->protected = kguard_addr_is_local(net, &key->addr);
	src->window_start_ns = now;
	src->tokens_ns = now;
	src->tokens = (u64)READ_ONCE(kguard_cfg.syn_burst) * KGUARD_TOKEN;

	old = rhashtable_lookup_get_insert_fast(&kguard_src_ht, &src->node,
						kguard_src_params);
	if (old) {
		/* Lost a race with another CPU, or the insert failed */
		kmem_cache_free(kguard_src_cache, src);
		atomic_dec(&kguard_src_count);
		return IS_ERR(old) ? NULL : old;
	}
	return src;
}

/*
 * Account one connection attempt (TCP SYN without ACK, or UDP) from src.
 * Called from the guard hook under RCU. Returns -ENOSPC when the source
 * could not be tracked.
 */
int kguard_track_attempt(struct net *net, const struct kguard_addr *addr,
			 u16 dport, bool syn, struct kguard_attempt_result *res)
{
	u64 now = ktime_get_ns();
	u64 window_ns = (u64)READ_ONCE(kguard_cfg.scan_window_ms) * NSEC_PER_MSEC;
	u32 threshold = READ_ONCE(kguard_cfg.scan_threshold);
	u32 rate = READ_ONCE(kguard_cfg.syn_rate);
	u64 burst = (u64)READ_ONCE(kguard_cfg.syn_burst) * KGUARD_TOKEN;
	struct kguard_src_key key;
	struct kguard_src *src;

	memset(&key, 0, sizeof(key));
	key.addr = *addr;
	key.netns = net->ns.inum;

	memset(res, 0, sizeof(*res));
	src = kguard_src_lookup_or_create(net, &key, now);
	if (!src)
		return -ENOSPC;

	spin_lock_bh(&src->lock);
	src->last_seen_ns = now;

	if (now - src->window_start_ns > window_ns) {
		bitmap_zero(src->port_bits, KGUARD_PORT_BITS);
		src->ports = 0;
		src->attempts = 0;
		src->window_start_ns = now;
	}
	if (!__test_and_set_bit(siphash_1u32(dport, &kguard_port_key) % KGUARD_PORT_BITS,
				src->port_bits))
		src->ports++;
	src->attempts++;

	if (syn) {
		/* Cap the idle time so the multiplication cannot overflow */
		u64 elapsed = min_t(u64, now - src->tokens_ns, 100 * NSEC_PER_SEC);
		u64 refill = div_u64(elapsed * rate, NSEC_PER_MSEC);

		src->tokens = min(src->tokens + refill, burst);
		src->tokens_ns = now;
		if (src->tokens >= KGUARD_TOKEN)
			src->tokens -= KGUARD_TOKEN;
		else
			res->over_rate = true;
	}

	if (src->ports >= threshold &&
	    (!src->scan_alert_ns || now - src->scan_alert_ns > KGUARD_ALERT_COOLDOWN_NS)) {
		res->scan = true;
		src->scan_alert_ns = now;
	}
	if (res->over_rate &&
	    (!src->rate_alert_ns || now - src->rate_alert_ns > KGUARD_ALERT_COOLDOWN_NS)) {
		res->rate_alert = true;
		src->rate_alert_ns = now;
	}
	res->ports = src->ports;
	res->attempts = src->attempts;
	res->protected = src->protected;
	spin_unlock_bh(&src->lock);
	return 0;
}

/* ---- blocklist ---- */

u64 kguard_block_count(void)
{
	return atomic_read(&kguard_block_nr);
}

static bool kguard_block_expired(const struct kguard_block *b, u64 now)
{
	u64 expires = READ_ONCE(b->expires_ns);

	return expires && now >= expires;
}

bool kguard_block_check(const struct kguard_addr *a)
{
	struct kguard_block *b;
	bool blocked;

	rcu_read_lock();
	b = rhashtable_lookup(&kguard_block_ht, a, kguard_block_params);
	blocked = b && !kguard_block_expired(b, ktime_get_ns());
	rcu_read_unlock();
	return blocked;
}

int kguard_block_add(struct net *net, const struct kguard_addr *a,
		     u32 timeout_s, u8 reason, gfp_t gfp)
{
	u64 expires = timeout_s ? ktime_get_ns() + (u64)timeout_s * NSEC_PER_SEC : 0;
	struct kguard_block *b, *old;

	/* Never lock out this machine or a trusted address */
	if (kguard_addr_is_local(net, a) || kguard_allow_match(a))
		return -EADDRNOTAVAIL;

	rcu_read_lock();
	b = rhashtable_lookup(&kguard_block_ht, a, kguard_block_params);
	if (b) {
		WRITE_ONCE(b->expires_ns, expires);
		WRITE_ONCE(b->reason, reason);
		rcu_read_unlock();
		return 0;
	}
	rcu_read_unlock();

	if (atomic_inc_return(&kguard_block_nr) > KGUARD_BLOCK_MAX) {
		atomic_dec(&kguard_block_nr);
		return -ENOSPC;
	}
	b = kzalloc(sizeof(*b), gfp);
	if (!b) {
		atomic_dec(&kguard_block_nr);
		return -ENOMEM;
	}
	b->addr = *a;
	b->expires_ns = expires;
	b->reason = reason;

	old = rhashtable_lookup_get_insert_fast(&kguard_block_ht, &b->node,
						kguard_block_params);
	if (old) {
		kfree(b);
		atomic_dec(&kguard_block_nr);
		if (IS_ERR(old))
			return PTR_ERR(old);
		WRITE_ONCE(old->expires_ns, expires);
		WRITE_ONCE(old->reason, reason);
	}
	return 0;
}

static void kguard_block_remove(struct kguard_block *b)
{
	if (!rhashtable_remove_fast(&kguard_block_ht, &b->node, kguard_block_params)) {
		atomic_dec(&kguard_block_nr);
		kfree_rcu(b, rcu);
	}
}

int kguard_block_del(const struct kguard_addr *a)
{
	struct kguard_block *b;
	int ret = -ENOENT;

	rcu_read_lock();
	b = rhashtable_lookup(&kguard_block_ht, a, kguard_block_params);
	if (b) {
		kguard_block_remove(b);
		ret = 0;
	}
	rcu_read_unlock();
	return ret;
}

/*
 * Call fn for each live block, skipping the first skip entries. Stops early
 * when fn returns non-zero. Returns how many entries were passed to fn.
 */
int kguard_block_walk(int (*fn)(void *ctx, const struct kguard_addr *a,
				u64 expires_ms, u8 reason),
		      void *ctx, unsigned long skip)
{
	struct rhashtable_iter iter;
	struct kguard_block *b;
	u64 now = ktime_get_ns();
	unsigned long seen = 0;
	int done = 0;

	rhashtable_walk_enter(&kguard_block_ht, &iter);
	rhashtable_walk_start(&iter);
	while ((b = rhashtable_walk_next(&iter)) != NULL) {
		u64 expires, left_ms;

		if (IS_ERR(b)) {
			if (PTR_ERR(b) == -EAGAIN)
				continue;
			break;
		}
		if (kguard_block_expired(b, now) || seen++ < skip)
			continue;
		expires = READ_ONCE(b->expires_ns);
		left_ms = expires ? div_u64(expires - now, NSEC_PER_MSEC) + 1 : 0;
		if (fn(ctx, &b->addr, left_ms, READ_ONCE(b->reason)))
			break;
		done++;
	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);
	return done;
}

/* ---- allowlist ---- */

bool kguard_allow_match(const struct kguard_addr *a)
{
	const struct kguard_allowlist *list;
	bool match = false;
	unsigned int i;

	rcu_read_lock();
	list = rcu_dereference(kguard_allowlist);
	for (i = 0; list && i < list->count && !match; i++)
		match = kguard_prefix_match(&list->entries[i], a);
	rcu_read_unlock();
	return match;
}

/* Replace the allowlist with a copy that adds or removes one prefix */
static int kguard_allow_update(const struct kguard_addr *a, u8 prefix_len, bool add)
{
	struct kguard_allowlist *old, *new;
	struct kguard_prefix p;
	unsigned int i, n = 0, count;
	bool found = false;

	if (prefix_len > kguard_addr_len(a) * 8)
		return -EINVAL;
	p.addr = *a;
	p.prefix_len = prefix_len;
	kguard_prefix_mask(&p.addr, prefix_len);

	mutex_lock(&kguard_allow_lock);
	old = rcu_dereference_protected(kguard_allowlist, lockdep_is_held(&kguard_allow_lock));
	count = old ? old->count : 0;
	for (i = 0; i < count; i++)
		if (old->entries[i].prefix_len == prefix_len &&
		    !memcmp(&old->entries[i].addr, &p.addr, sizeof(p.addr)))
			found = true;

	if (add == found) {
		mutex_unlock(&kguard_allow_lock);
		return add ? 0 : -ENOENT;
	}
	if (add && count >= KGUARD_ALLOW_MAX) {
		mutex_unlock(&kguard_allow_lock);
		return -ENOSPC;
	}

	new = kzalloc(struct_size(new, entries, count + 1), GFP_KERNEL);
	if (!new) {
		mutex_unlock(&kguard_allow_lock);
		return -ENOMEM;
	}
	for (i = 0; i < count; i++) {
		const struct kguard_prefix *e = &old->entries[i];

		if (!add && e->prefix_len == prefix_len &&
		    !memcmp(&e->addr, &p.addr, sizeof(p.addr)))
			continue;
		new->entries[n++] = *e;
	}
	if (add)
		new->entries[n++] = p;
	new->count = n;

	rcu_assign_pointer(kguard_allowlist, new);
	mutex_unlock(&kguard_allow_lock);
	if (old)
		kfree_rcu(old, rcu);
	return 0;
}

int kguard_allow_add(const struct kguard_addr *a, u8 prefix_len)
{
	return kguard_allow_update(a, prefix_len, true);
}

int kguard_allow_del(const struct kguard_addr *a, u8 prefix_len)
{
	return kguard_allow_update(a, prefix_len, false);
}

int kguard_allow_walk(int (*fn)(void *ctx, const struct kguard_addr *a, u8 prefix_len),
		      void *ctx)
{
	const struct kguard_allowlist *list;
	unsigned int i;
	int done = 0;

	rcu_read_lock();
	list = rcu_dereference(kguard_allowlist);
	for (i = 0; list && i < list->count; i++, done++)
		if (fn(ctx, &list->entries[i].addr, list->entries[i].prefix_len))
			break;
	rcu_read_unlock();
	return done;
}

/* Parse "10.0.0.0/8,192.168.1.5,2001:db8::/32" (the allow= parameter) */
static int kguard_allow_parse(const char *list)
{
	char *copy, *cur, *item;
	int ret = 0;

	if (!list || !*list)
		return 0;
	copy = kstrdup(list, GFP_KERNEL);
	if (!copy)
		return -ENOMEM;

	cur = copy;
	while ((item = strsep(&cur, ",")) != NULL) {
		struct kguard_addr a = {};
		char *slash = strchr(item, '/');
		unsigned int plen;

		if (!*item)
			continue;
		if (slash)
			*slash = '\0';
		if (in4_pton(item, -1, a.bytes, -1, NULL)) {
			a.family = AF_INET;
			plen = 32;
		} else if (in6_pton(item, -1, a.bytes, -1, NULL)) {
			a.family = AF_INET6;
			plen = 128;
		} else {
			kguard_err("allow: cannot parse address '%s'", item);
			ret = -EINVAL;
			break;
		}
		if (slash && kstrtouint(slash + 1, 10, &plen)) {
			kguard_err("allow: bad prefix length for '%s'", item);
			ret = -EINVAL;
			break;
		}
		ret = kguard_allow_add(&a, plen);
		if (ret)
			break;
	}
	kfree(copy);
	return ret;
}

/* ---- garbage collection ---- */

/*
 * Sources come from a module-owned slab cache: free them with call_rcu() so
 * rcu_barrier() at unload waits for every pending free (it does not wait
 * for kfree_rcu() batches on all kernels).
 */
static void kguard_src_free_rcu(struct rcu_head *head)
{
	kmem_cache_free(kguard_src_cache, container_of(head, struct kguard_src, rcu));
}

static void kguard_gc(struct work_struct *work)
{
	u64 now = ktime_get_ns();
	u64 idle_ns = kguard_idle_ns;
	struct rhashtable_iter iter;
	struct kguard_block *b;
	struct kguard_src *src;

	/* Nearly full: free sources idle for more than a few seconds */
	if (atomic_read(&kguard_src_count) > kguard_max_sources / 10 * 9)
		idle_ns = min_t(u64, idle_ns, 5 * NSEC_PER_SEC);

	rhashtable_walk_enter(&kguard_src_ht, &iter);
	rhashtable_walk_start(&iter);
	while ((src = rhashtable_walk_next(&iter)) != NULL) {
		if (IS_ERR(src))
			continue;
		if (now - READ_ONCE(src->last_seen_ns) > idle_ns &&
		    !rhashtable_remove_fast(&kguard_src_ht, &src->node, kguard_src_params)) {
			atomic_dec(&kguard_src_count);
			call_rcu(&src->rcu, kguard_src_free_rcu);
		}
	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);

	rhashtable_walk_enter(&kguard_block_ht, &iter);
	rhashtable_walk_start(&iter);
	while ((b = rhashtable_walk_next(&iter)) != NULL) {
		if (!IS_ERR(b) && kguard_block_expired(b, now))
			kguard_block_remove(b);
	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);

	queue_delayed_work(system_unbound_wq, &kguard_gc_work, KGUARD_GC_PERIOD);
}

/* ---- init / cleanup ---- */

int kguard_track_init(unsigned int max_sources, unsigned int idle_timeout,
		      const char *allow)
{
	int ret;

	kguard_max_sources = max(max_sources, 16U);
	kguard_idle_ns = (u64)max(idle_timeout, 1U) * NSEC_PER_SEC;

	get_random_bytes(&kguard_port_key, sizeof(kguard_port_key));

	/*
	 * Unmerged, so its size shows in /proc/slabinfo and any leak is
	 * reported when the cache is destroyed at unload.
	 */
	kguard_src_cache = KMEM_CACHE(kguard_src, SLAB_NO_MERGE);
	if (!kguard_src_cache)
		return -ENOMEM;
	ret = rhashtable_init(&kguard_src_ht, &kguard_src_params);
	if (ret)
		goto err_cache;
	ret = rhashtable_init(&kguard_block_ht, &kguard_block_params);
	if (ret)
		goto err_src;
	ret = kguard_allow_parse(allow);
	if (ret)
		goto err_block;

	INIT_DELAYED_WORK(&kguard_gc_work, kguard_gc);
	/*
	 * Unbound: after a random-source flood the walk covers up to
	 * max_sources entries, too long to hold up a per-CPU worker
	 */
	queue_delayed_work(system_unbound_wq, &kguard_gc_work, KGUARD_GC_PERIOD);
	return 0;

err_block:
	kfree(rcu_dereference_protected(kguard_allowlist, true));
	RCU_INIT_POINTER(kguard_allowlist, NULL);
	rhashtable_destroy(&kguard_block_ht);
err_src:
	rhashtable_destroy(&kguard_src_ht);
err_cache:
	kmem_cache_destroy(kguard_src_cache);
	return ret;
}

static void kguard_free_src(void *ptr, void *arg)
{
	kmem_cache_free(kguard_src_cache, ptr);
}

static void kguard_free_block(void *ptr, void *arg)
{
	kfree(ptr);
}

/* Called after the hooks are gone, so nothing else touches the tables */
void kguard_track_cleanup(void)
{
	cancel_delayed_work_sync(&kguard_gc_work);
	rhashtable_free_and_destroy(&kguard_src_ht, kguard_free_src, NULL);
	rhashtable_free_and_destroy(&kguard_block_ht, kguard_free_block, NULL);
	kfree(rcu_dereference_protected(kguard_allowlist, true));
	RCU_INIT_POINTER(kguard_allowlist, NULL);
	/* Wait for call_rcu() frees of sources before destroying their cache */
	rcu_barrier();
	kmem_cache_destroy(kguard_src_cache);
}
