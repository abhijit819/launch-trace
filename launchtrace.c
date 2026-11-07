// SPDX-License-Identifier: GPL-2.0
/*
 * LaunchTrace - Linux 4.4 application-startup read recorder.
 *
 * Scope: best-effort attribution of file-backed READ BIOs submitted in the
 * original application's task context. This module does not preload data.
 *
 * Important: the two kernel hooks in launchtrace-hooks.patch are required.
 * The exec hook is intentionally before exec success in this first version;
 * failed-exec rollback is a known limitation. The task-exit hook must be
 * called only when the thread group is actually dead (see patch notes).
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/mempool.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/hash.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/timekeeping.h>
#include <linux/sched.h>
#include <linux/pagemap.h>
#include <linux/blkdev.h>
#include <linux/major.h>
#include <linux/jiffies.h>
#include <linux/kref.h>
#include <linux/mutex.h>
#include <linux/capability.h>
#include <linux/compat.h>
#include <linux/errno.h>
#include <linux/ktime.h>
#include <linux/limits.h>
#include <linux/launchtrace.h>

#define LT_HASH_BITS             10
#define LT_IDLE_NS               (2ULL * NSEC_PER_SEC)
#define LT_MAX_AGE_NS            (120ULL * NSEC_PER_SEC)
#define LT_RETENTION_NS          (600ULL * NSEC_PER_SEC)
#define LT_RETRY_NS              (30ULL * NSEC_PER_SEC)
#define LT_SCAN_MS               250
#define LT_DEFAULT_MAX_APPS      50U
#define LT_DEFAULT_MAX_RECORDS   100000U
#define LT_GLOBAL_MAX_RECORDS    200000U
#define LT_MEMPOOL_MIN           256
#define LT_PATH_MAX              4096

/* Completion reasons are part of the serialized ABI. */
enum lt_complete_reason {
        LT_REASON_IDLE = 1,
        LT_REASON_MAX_AGE = 2,
        LT_REASON_PROCESS_EXIT = 3,
        LT_REASON_STOP = 4,
        LT_REASON_RECORD_LIMIT = 5,
        LT_REASON_ALLOC_LIMIT = 6,
};

enum lt_pattern_state {
        LT_PATTERN_ACTIVE = 1,
        LT_PATTERN_COMPLETED,
        LT_PATTERN_IN_FLIGHT,
        LT_PATTERN_ACKED,
        LT_PATTERN_EXPIRED,
};

struct lt_record {
        struct list_head sector_link;
        struct hlist_node hash_link;
        u64 inode;
        u64 page_index;
        u64 start_sector;
        u32 nr_sectors; /* Approximate until partial-bvec accounting is added. */
};

struct lt_device {
        struct list_head link;
        dev_t dev;
        struct list_head records; /* ascending start_sector */
        DECLARE_HASHTABLE(record_hash, LT_HASH_BITS);
        u32 record_count;
};

struct lt_pattern {
        struct list_head lifecycle_link;
        struct list_head devices;
        struct kref refs;
        spinlock_t lock; /* records, state, timestamps, counters */
        u64 id;
        u64 created_ns;
        u64 last_activity_ns;
        u64 completed_ns;
        u64 inflight_since_ns;
        pid_t tgid;
        char *path;
        u32 record_count;
        u32 device_count;
        u32 reason;
        enum lt_pattern_state state; /* changed under lt_global_lock + lock */
        bool read_active; /* protected by lt_global_lock */
};

struct lt_session {
        struct hlist_node hash_link;
        pid_t tgid;
        struct lt_pattern *pattern; /* lifecycle list owns pattern reference */
};

static DEFINE_HASHTABLE(lt_sessions, LT_HASH_BITS);
static LIST_HEAD(lt_active_patterns);
static LIST_HEAD(lt_completed_patterns);
static LIST_HEAD(lt_inflight_patterns);

/*
 * Locking contract:
 *   lt_global_lock protects session hash, all three lifecycle lists,
 *   recording_enabled, retained_sessions, max_apps, pattern state/list moves,
 *   and read_active.
 *   Pattern lock protects its device/record structures and timestamps/counts.
 *   Lock order, when nesting is unavoidable: lt_global_lock -> pattern lock.
 *   BIO lookup takes a temporary kref under lt_global_lock, drops it, then
 *   takes only pattern lock. No user copy or sleep occurs under a spinlock.
 */
static DEFINE_SPINLOCK(lt_global_lock);
static DEFINE_MUTEX(lt_read_mutex);
static DECLARE_WAIT_QUEUE_HEAD(lt_read_wait);
static atomic_t lt_completed_count = ATOMIC_INIT(0);
static struct delayed_work lt_scan_work;
static struct kmem_cache *lt_record_cache;
static mempool_t *lt_record_pool;
static atomic_t lt_global_records = ATOMIC_INIT(0);
static atomic64_t lt_next_pattern_id = ATOMIC64_INIT(0);
static bool lt_recording_enabled;
static bool lt_config_locked; /* max_apps becomes immutable on first START */
static u32 lt_max_apps = LT_DEFAULT_MAX_APPS;
static u32 lt_retained_sessions;
static u32 lt_max_records_per_pattern = LT_DEFAULT_MAX_RECORDS;

static void lt_pattern_release(struct kref *ref)
{
        struct lt_pattern *p = container_of(ref, struct lt_pattern, refs);
        struct lt_device *d, *dn;

        list_for_each_entry_safe(d, dn, &p->devices, link) {
                struct lt_record *r, *rn;
                list_for_each_entry_safe(r, rn, &d->records, sector_link) {
                        list_del(&r->sector_link);
                        hash_del(&r->hash_link);
                        mempool_free(r, lt_record_pool);
                        atomic_dec(&lt_global_records);
                }
                list_del(&d->link);
                kfree(d);
        }
        kfree(p->path);
        kfree(p);
}

static inline void lt_pattern_get(struct lt_pattern *p)
{
        kref_get(&p->refs);
}

static inline void lt_pattern_put(struct lt_pattern *p)
{
        kref_put(&p->refs, lt_pattern_release);
}

static struct lt_session *lt_find_session_locked(pid_t tgid)
{
        struct lt_session *s;
        hash_for_each_possible(lt_sessions, s, hash_link, (unsigned long)tgid) {
                if (s->tgid == tgid)
                        return s;
        }
        return NULL;
}

static struct lt_device *lt_find_device_locked(struct lt_pattern *p, dev_t dev)
{
        struct lt_device *d;
        list_for_each_entry(d, &p->devices, link) {
                if (d->dev == dev)
                        return d;
        }
        return NULL;
}

static struct lt_device *lt_create_device_locked(struct lt_pattern *p,
                                                  dev_t dev)
{
        struct lt_device *d;

        d = kzalloc(sizeof(*d), GFP_ATOMIC);
        if (!d)
                return NULL;
        d->dev = dev;
        INIT_LIST_HEAD(&d->link);
        INIT_LIST_HEAD(&d->records);
        hash_init(d->record_hash);
        list_add_tail(&d->link, &p->devices);
        p->device_count++;
        return d;
}

static u32 lt_record_hash_key(u64 inode, u64 index)
{
        return hash_64(inode ^ (index * 0x9e3779b97f4a7c15ULL), LT_HASH_BITS);
}

static bool lt_record_exists_locked(struct lt_device *d, u64 inode, u64 index)
{
        struct lt_record *r;
        u32 key = lt_record_hash_key(inode, index);

        hash_for_each_possible(d->record_hash, r, hash_link, key) {
                if (r->inode == inode && r->page_index == index)
                        return true;
        }
        return false;
}

static void lt_insert_record_locked(struct lt_device *d, struct lt_record *r)
{
        struct lt_record *pos;
        u32 key = lt_record_hash_key(r->inode, r->page_index);

        list_for_each_entry_reverse(pos, &d->records, sector_link) {
                if (pos->start_sector <= r->start_sector) {
                        list_add(&r->sector_link, &pos->sector_link);
                        goto add_hash;
                }
        }
        list_add(&r->sector_link, &d->records);
add_hash:
        hash_add(d->record_hash, &r->hash_link, key);
        d->record_count++;
}

static void lt_remove_session_locked(struct lt_pattern *p)
{
        struct lt_session *s = lt_find_session_locked(p->tgid);

        if (s && s->pattern == p) {
                hash_del(&s->hash_link);
                kfree(s);
        }
}

/* Caller holds lt_global_lock. Transfers the lifecycle-list reference. */
static bool lt_complete_locked(struct lt_pattern *p, u32 reason, u64 now)
{
        unsigned long flags;

        spin_lock_irqsave(&p->lock, flags);
        if (p->state != LT_PATTERN_ACTIVE) {
                spin_unlock_irqrestore(&p->lock, flags);
                return false;
        }
        p->state = LT_PATTERN_COMPLETED;
        p->reason = reason;
        p->completed_ns = now;
        spin_unlock_irqrestore(&p->lock, flags);

        list_move_tail(&p->lifecycle_link, &lt_completed_patterns);
        lt_remove_session_locked(p); /* no later BIO can find this session */
        atomic_inc(&lt_completed_count);
        return true;
}

static struct lt_pattern *lt_new_pattern(pid_t tgid, const char *path)
{
        struct lt_pattern *p;

        p = kzalloc(sizeof(*p), GFP_KERNEL);
        if (!p)
                return NULL;
        p->path = kstrndup(path ? path : "<unknown>", LT_PATH_MAX - 1,
                           GFP_KERNEL);
        if (!p->path) {
                kfree(p);
                return NULL;
        }
        INIT_LIST_HEAD(&p->lifecycle_link);
        INIT_LIST_HEAD(&p->devices);
        kref_init(&p->refs); /* one reference owned by lifecycle list */
        spin_lock_init(&p->lock);
        p->id = atomic64_inc_return(&lt_next_pattern_id);
        p->created_ns = ktime_get_ns();
        p->last_activity_ns = p->created_ns;
        p->tgid = tgid;
        p->state = LT_PATTERN_ACTIVE;
        return p;
}

/* Called from exec path in process context. */
static void lt_exec_start(const char *filename)
{
        struct lt_session *s;
        struct lt_pattern *p, *oldp = NULL;
        unsigned long flags;
        bool completed_old = false;
        pid_t tgid = task_tgid_nr(current);

        p = lt_new_pattern(tgid, filename);
        if (!p)
                return;
        s = kzalloc(sizeof(*s), GFP_KERNEL);
        if (!s) {
                lt_pattern_put(p);
                return;
        }
        s->tgid = tgid;
        s->pattern = p;

        spin_lock_irqsave(&lt_global_lock, flags);
        if (!lt_recording_enabled) {
                spin_unlock_irqrestore(&lt_global_lock, flags);
                kfree(s);
                lt_pattern_put(p);
                return;
        }
        /* Re-exec in the same TGID closes the previous startup capture. */
        {
                struct lt_session *old = lt_find_session_locked(tgid);
                if (old) {
                        oldp = old->pattern;
                        completed_old = lt_complete_locked(oldp,
                                           LT_REASON_PROCESS_EXIT,
                                           ktime_get_ns());
                }
        }
        if (lt_retained_sessions >= lt_max_apps) {
                spin_unlock_irqrestore(&lt_global_lock, flags);
                kfree(s);
                lt_pattern_put(p);
                wake_up_interruptible(&lt_read_wait);
                return;
        }
        hash_add(lt_sessions, &s->hash_link, (unsigned long)tgid);
        list_add_tail(&p->lifecycle_link, &lt_active_patterns);
        lt_retained_sessions++;
        spin_unlock_irqrestore(&lt_global_lock, flags);
        if (completed_old)
                wake_up_interruptible(&lt_read_wait);
}

/* Called only when the thread group is actually dead, not per-thread exit. */
static void lt_task_exit(pid_t tgid)
{
        struct lt_session *s;
        struct lt_pattern *p;
        unsigned long flags;

        spin_lock_irqsave(&lt_global_lock, flags);
        s = lt_find_session_locked(tgid);
        if (s) {
                p = s->pattern;
                lt_complete_locked(p, LT_REASON_PROCESS_EXIT, ktime_get_ns());
        }
        spin_unlock_irqrestore(&lt_global_lock, flags);
        if (s)
                wake_up_interruptible(&lt_read_wait);
}

/* Called from submit_bio(). Never sleeps. */
static void lt_bio_submit(struct bio *bio)
{
        struct lt_session *s;
        struct lt_pattern *p = NULL;
        struct bvec_iter iter;
        struct bio_vec bv;
        unsigned long flags;
        dev_t dev;
        bool cap_hit = false;
        u32 cap_reason = LT_REASON_RECORD_LIMIT;

        if (!bio || bio_data_dir(bio) != READ || !bio->bi_bdev)
                return;

        spin_lock_irqsave(&lt_global_lock, flags);
        if (!lt_recording_enabled) {
                spin_unlock_irqrestore(&lt_global_lock, flags);
                return;
        }
        s = lt_find_session_locked(task_tgid_nr(current));
        if (s && s->pattern->state == LT_PATTERN_ACTIVE) {
                p = s->pattern;
                lt_pattern_get(p);
        }
        spin_unlock_irqrestore(&lt_global_lock, flags);
        if (!p)
                return;

        dev = bio->bi_bdev->bd_dev;
        bio_for_each_segment(bv, bio, iter) {
                struct address_space *mapping;
                struct inode *inode;
                struct lt_device *d;
                struct lt_record *r;
                unsigned long pflags;
                u64 now;

                if (!bv.bv_page)
                        continue;
                mapping = page_mapping(bv.bv_page);
                if (!mapping || !mapping->host)
                        continue; /* intentionally file-backed page-cache only */
                inode = mapping->host;

                r = mempool_alloc(lt_record_pool, GFP_ATOMIC);
                if (!r) {
                        cap_hit = true;
                        cap_reason = LT_REASON_ALLOC_LIMIT;
                        break;
                }
                memset(r, 0, sizeof(*r));
                INIT_LIST_HEAD(&r->sector_link);
                INIT_HLIST_NODE(&r->hash_link);
                r->inode = inode->i_ino;
                r->page_index = bv.bv_page->index;
                /* Approximation: partial-page vector normalization deferred. */
                r->start_sector = (u64)(iter.bi_sector - (bv.bv_offset >> 9));
                r->nr_sectors = PAGE_SIZE >> 9;

                spin_lock_irqsave(&p->lock, pflags);
                if (p->state != LT_PATTERN_ACTIVE) {
                        spin_unlock_irqrestore(&p->lock, pflags);
                        mempool_free(r, lt_record_pool);
                        break;
                }
                d = lt_find_device_locked(p, dev);
                if (!d)
                        d = lt_create_device_locked(p, dev);
                if (!d) {
                        spin_unlock_irqrestore(&p->lock, pflags);
                        mempool_free(r, lt_record_pool);
                        continue;
                }
                if (lt_record_exists_locked(d, r->inode, r->page_index)) {
                        spin_unlock_irqrestore(&p->lock, pflags);
                        mempool_free(r, lt_record_pool);
                        continue;
                }
                if (p->record_count >= READ_ONCE(lt_max_records_per_pattern)) {
                        cap_hit = true;
                        cap_reason = LT_REASON_RECORD_LIMIT;
                        spin_unlock_irqrestore(&p->lock, pflags);
                        mempool_free(r, lt_record_pool);
                        break;
                }
                if (atomic_inc_return(&lt_global_records) >
                    LT_GLOBAL_MAX_RECORDS) {
                        atomic_dec(&lt_global_records);
                        cap_hit = true;
                        cap_reason = LT_REASON_ALLOC_LIMIT;
                        spin_unlock_irqrestore(&p->lock, pflags);
                        mempool_free(r, lt_record_pool);
                        break;
                }
                lt_insert_record_locked(d, r);
                p->record_count++;
                now = ktime_get_ns();
                p->last_activity_ns = now;
                spin_unlock_irqrestore(&p->lock, pflags);
        }

        if (cap_hit) {
                spin_lock_irqsave(&lt_global_lock, flags);
                if (p->state == LT_PATTERN_ACTIVE) {
                        unsigned long pflags;
                        spin_lock_irqsave(&p->lock, pflags);
                        p->state = LT_PATTERN_COMPLETED;
                        p->reason = cap_reason;
                        p->completed_ns = ktime_get_ns();
                        spin_unlock_irqrestore(&p->lock, pflags);
                        list_move_tail(&p->lifecycle_link,
                                       &lt_completed_patterns);
                        lt_remove_session_locked(p);
                        atomic_inc(&lt_completed_count);
                }
                spin_unlock_irqrestore(&lt_global_lock, flags);
                wake_up_interruptible(&lt_read_wait);
        }
        lt_pattern_put(p);
}

static void lt_scan_workfn(struct work_struct *work)
{
        struct lt_pattern *p, *n;
        LIST_HEAD(to_free);
        unsigned long flags;
        u64 now = ktime_get_ns();

        spin_lock_irqsave(&lt_global_lock, flags);
        list_for_each_entry_safe(p, n, &lt_active_patterns, lifecycle_link) {
                unsigned long pflags;
                u64 idle, age;
                u32 reason = 0;

                /* Recheck and transition under the same pattern lock. */
                spin_lock_irqsave(&p->lock, pflags);
                if (p->state == LT_PATTERN_ACTIVE) {
                        idle = now - p->last_activity_ns;
                        age = now - p->created_ns;
                        if (age >= LT_MAX_AGE_NS)
                                reason = LT_REASON_MAX_AGE;
                        else if (idle >= LT_IDLE_NS)
                                reason = LT_REASON_IDLE;
                        if (reason) {
                                p->state = LT_PATTERN_COMPLETED;
                                p->reason = reason;
                                p->completed_ns = now;
                        }
                }
                spin_unlock_irqrestore(&p->lock, pflags);
                if (reason) {
                        list_move_tail(&p->lifecycle_link,
                                       &lt_completed_patterns);
                        lt_remove_session_locked(p);
                        atomic_inc(&lt_completed_count);
                }
        }

        list_for_each_entry_safe(p, n, &lt_completed_patterns,
                                 lifecycle_link) {
                if (now - p->completed_ns >= LT_RETENTION_NS) {
                        list_del_init(&p->lifecycle_link);
                        p->state = LT_PATTERN_EXPIRED;
                        list_add_tail(&p->lifecycle_link, &to_free);
                        if (atomic_read(&lt_completed_count) > 0)
                                atomic_dec(&lt_completed_count);
                        if (lt_retained_sessions)
                                lt_retained_sessions--;
                }
        }
        list_for_each_entry_safe(p, n, &lt_inflight_patterns,
                                 lifecycle_link) {
                if (now - p->completed_ns >= LT_RETENTION_NS &&
                    !p->read_active) {
                        list_del_init(&p->lifecycle_link);
                        p->state = LT_PATTERN_EXPIRED;
                        list_add_tail(&p->lifecycle_link, &to_free);
                        if (lt_retained_sessions)
                                lt_retained_sessions--;
                } else if (!p->read_active &&
                           now - p->inflight_since_ns >= LT_RETRY_NS) {
                        p->state = LT_PATTERN_COMPLETED;
                        list_move_tail(&p->lifecycle_link,
                                       &lt_completed_patterns);
                        atomic_inc(&lt_completed_count);
                }
        }
        spin_unlock_irqrestore(&lt_global_lock, flags);

        list_for_each_entry_safe(p, n, &to_free, lifecycle_link) {
                list_del_init(&p->lifecycle_link);
                lt_pattern_put(p); /* drop lifecycle ownership */
        }
        wake_up_interruptible(&lt_read_wait);
        schedule_delayed_work(&lt_scan_work, msecs_to_jiffies(LT_SCAN_MS));
}

static int lt_serialize_pattern(struct lt_pattern *p, u8 **out,
                                size_t *out_len)
{
        struct lt_wire_header wh;
        struct lt_device *d;
        struct lt_record *r;
        size_t need = sizeof(wh), path_len = strlen(p->path);
        u8 *buf, *cur;
        u32 device_count = 0;

        list_for_each_entry(d, &p->devices, link) {
                if (need > SIZE_MAX - sizeof(struct lt_wire_device) -
                           (size_t)d->record_count * sizeof(struct lt_wire_record))
                        return -EOVERFLOW;
                need += sizeof(struct lt_wire_device) +
                        (size_t)d->record_count * sizeof(struct lt_wire_record);
                device_count++;
        }
        if (need > SIZE_MAX - path_len)
                return -EOVERFLOW;
        need += path_len;
        buf = kmalloc(need, GFP_KERNEL);
        if (!buf)
                return -ENOMEM;

        memset(&wh, 0, sizeof(wh));
        wh.magic = cpu_to_le32(LT_WIRE_MAGIC);
        wh.version = cpu_to_le32(LT_WIRE_VERSION);
        wh.header_bytes = cpu_to_le32(sizeof(wh));
        wh.pattern_id = cpu_to_le64(p->id);
        wh.created_ns = cpu_to_le64(p->created_ns);
        wh.completed_ns = cpu_to_le64(p->completed_ns);
        wh.tgid = cpu_to_le32((u32)p->tgid);
        wh.reason = cpu_to_le32(p->reason);
        wh.path_len = cpu_to_le32((u32)path_len);
        wh.device_count = cpu_to_le32(device_count);
        wh.record_count = cpu_to_le32(p->record_count);
        memcpy(buf, &wh, sizeof(wh));
        cur = buf + sizeof(wh);
        memcpy(cur, p->path, path_len);
        cur += path_len;

        list_for_each_entry(d, &p->devices, link) {
                struct lt_wire_device wd;
                memset(&wd, 0, sizeof(wd));
                wd.major = cpu_to_le32(MAJOR(d->dev));
                wd.minor = cpu_to_le32(MINOR(d->dev));
                wd.record_count = cpu_to_le32(d->record_count);
                memcpy(cur, &wd, sizeof(wd));
                cur += sizeof(wd);
                list_for_each_entry(r, &d->records, sector_link) {
                        struct lt_wire_record wr;
                        wr.inode = cpu_to_le64(r->inode);
                        wr.page_index = cpu_to_le64(r->page_index);
                        wr.start_sector = cpu_to_le64(r->start_sector);
                        wr.nr_sectors = cpu_to_le32(r->nr_sectors);
                        wr.reserved = 0;
                        memcpy(cur, &wr, sizeof(wr));
                        cur += sizeof(wr);
                }
        }
        *out = buf;
        *out_len = need;
        return 0;
}

static ssize_t lt_read(struct file *file, char __user *ubuf,
                       size_t len, loff_t *ppos)
{
        struct lt_pattern *p;
        unsigned long flags;
        u8 *buf = NULL;
        size_t need = 0;
        int ret;

        if (mutex_lock_interruptible(&lt_read_mutex))
                return -ERESTARTSYS;
        /* poll()+O_NONBLOCK users must never sleep after a readiness race. */
        if ((file->f_flags & O_NONBLOCK) &&
            atomic_read(&lt_completed_count) == 0) {
                mutex_unlock(&lt_read_mutex);
                return -EAGAIN;
        }
        ret = wait_event_interruptible(lt_read_wait,
                         atomic_read(&lt_completed_count) > 0 ||
                         !READ_ONCE(lt_recording_enabled));
        if (ret) {
                mutex_unlock(&lt_read_mutex);
                return ret;
        }

        spin_lock_irqsave(&lt_global_lock, flags);
        if (list_empty(&lt_completed_patterns)) {
                bool stopped = !lt_recording_enabled;
                spin_unlock_irqrestore(&lt_global_lock, flags);
                mutex_unlock(&lt_read_mutex);
                return stopped ? 0 : -EAGAIN;
        }
        p = list_first_entry(&lt_completed_patterns, struct lt_pattern,
                             lifecycle_link);
        list_move_tail(&p->lifecycle_link, &lt_inflight_patterns);
        p->state = LT_PATTERN_IN_FLIGHT;
        p->inflight_since_ns = ktime_get_ns();
        p->read_active = true;
        lt_pattern_get(p); /* protects serialization/copy against ACK/expiry */
        atomic_dec(&lt_completed_count);
        spin_unlock_irqrestore(&lt_global_lock, flags);

        ret = lt_serialize_pattern(p, &buf, &need);
        if (ret)
                goto restore;
        if (len < need) {
                ret = -EMSGSIZE;
                goto restore;
        }
        if (copy_to_user(ubuf, buf, need)) {
                ret = -EFAULT;
                goto restore;
        }
        kfree(buf);

        spin_lock_irqsave(&lt_global_lock, flags);
        p->read_active = false;
        spin_unlock_irqrestore(&lt_global_lock, flags);
        lt_pattern_put(p);
        mutex_unlock(&lt_read_mutex);
        return need;

restore:
        kfree(buf);
        spin_lock_irqsave(&lt_global_lock, flags);
        p->read_active = false;
        if (p->state == LT_PATTERN_IN_FLIGHT) {
                p->state = LT_PATTERN_COMPLETED;
                list_move_tail(&p->lifecycle_link, &lt_completed_patterns);
                atomic_inc(&lt_completed_count);
        }
        spin_unlock_irqrestore(&lt_global_lock, flags);
        lt_pattern_put(p);
        mutex_unlock(&lt_read_mutex);
        return ret;
}

static long lt_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
        unsigned long flags;
        u32 value;
        u64 id;
        struct lt_pattern *p, *n, *found = NULL;
        bool wake = false;

        switch (cmd) {
        case LT_IOCTL_SET_MAX_APPS:
                if (!capable(CAP_SYS_ADMIN))
                        return -EPERM;
                if (copy_from_user(&value, (void __user *)arg, sizeof(value)))
                        return -EFAULT;
                if (!value || value > 4096)
                        return -EINVAL;
                spin_lock_irqsave(&lt_global_lock, flags);
                if (lt_config_locked || lt_recording_enabled || lt_retained_sessions) {
                        spin_unlock_irqrestore(&lt_global_lock, flags);
                        return -EBUSY;
                }
                lt_max_apps = value;
                spin_unlock_irqrestore(&lt_global_lock, flags);
                return 0;

        case LT_IOCTL_START:
                if (!capable(CAP_SYS_ADMIN))
                        return -EPERM;
                spin_lock_irqsave(&lt_global_lock, flags);
                if (lt_recording_enabled) {
                        spin_unlock_irqrestore(&lt_global_lock, flags);
                        return -EALREADY;
                }
                lt_recording_enabled = true;
                lt_config_locked = true;
                spin_unlock_irqrestore(&lt_global_lock, flags);
                return 0;

        case LT_IOCTL_STOP:
                if (!capable(CAP_SYS_ADMIN))
                        return -EPERM;
                spin_lock_irqsave(&lt_global_lock, flags);
                if (!lt_recording_enabled) {
                        spin_unlock_irqrestore(&lt_global_lock, flags);
                        return 0;
                }
                lt_recording_enabled = false;
                list_for_each_entry_safe(p, n, &lt_active_patterns,
                                         lifecycle_link)
                        lt_complete_locked(p, LT_REASON_STOP, ktime_get_ns());
                wake = true;
                spin_unlock_irqrestore(&lt_global_lock, flags);
                if (wake)
                        wake_up_interruptible(&lt_read_wait);
                return 0;

        case LT_IOCTL_ACK:
                if (copy_from_user(&id, (void __user *)arg, sizeof(id)))
                        return -EFAULT;
                id = le64_to_cpu((__force __le64)id);
                spin_lock_irqsave(&lt_global_lock, flags);
                list_for_each_entry_safe(p, n, &lt_inflight_patterns,
                                         lifecycle_link) {
                        if (p->id == id && p->state == LT_PATTERN_IN_FLIGHT &&
                            !p->read_active) {
                                list_del_init(&p->lifecycle_link);
                                p->state = LT_PATTERN_ACKED;
                                if (lt_retained_sessions)
                                        lt_retained_sessions--;
                                found = p;
                                break;
                        }
                }
                spin_unlock_irqrestore(&lt_global_lock, flags);
                if (!found)
                        return -ENOENT;
                lt_pattern_put(found); /* lifecycle ownership */
                return 0;
        default:
                return -ENOTTY;
        }
}

static unsigned int lt_poll(struct file *file, poll_table *wait)
{
        unsigned int mask = 0;
        poll_wait(file, &lt_read_wait, wait);
        if (atomic_read(&lt_completed_count) > 0)
                mask |= POLLIN | POLLRDNORM;
        return mask;
}

static const struct file_operations lt_fops = {
        .owner = THIS_MODULE,
        .read = lt_read,
        .unlocked_ioctl = lt_ioctl,
#ifdef CONFIG_COMPAT
        .compat_ioctl = lt_ioctl,
#endif
        .poll = lt_poll,
        .llseek = no_llseek,
};

static struct miscdevice lt_misc = {
        .minor = MISC_DYNAMIC_MINOR,
        .name = "launchtrace",
        .fops = &lt_fops,
        .mode = 0600,
};

static const struct launchtrace_ops lt_ops = {
        .owner = THIS_MODULE,
        .exec_start = lt_exec_start,
        .bio_submit = lt_bio_submit,
        .task_exit = lt_task_exit,
};

static int __init launchtrace_init(void)
{
        int ret;

        lt_record_cache = kmem_cache_create("launchtrace_record",
                                sizeof(struct lt_record), 0,
                                SLAB_HWCACHE_ALIGN, NULL);
        if (!lt_record_cache)
                return -ENOMEM;
        lt_record_pool = mempool_create_slab_pool(LT_MEMPOOL_MIN,
                                                  lt_record_cache);
        if (!lt_record_pool) {
                kmem_cache_destroy(lt_record_cache);
                return -ENOMEM;
        }
        INIT_DELAYED_WORK(&lt_scan_work, lt_scan_workfn);
        ret = misc_register(&lt_misc);
        if (ret) {
                mempool_destroy(lt_record_pool);
                kmem_cache_destroy(lt_record_cache);
                return ret;
        }
        ret = launchtrace_register_ops(&lt_ops);
        if (ret) {
                misc_deregister(&lt_misc);
                mempool_destroy(lt_record_pool);
                kmem_cache_destroy(lt_record_cache);
                return ret;
        }
        schedule_delayed_work(&lt_scan_work, msecs_to_jiffies(LT_SCAN_MS));
        pr_info("LaunchTrace: loaded; device /dev/launchtrace (disabled)\n");
        return 0;
}

static void __exit launchtrace_exit(void)
{
        struct lt_pattern *p, *n;
        struct lt_session *s;
        struct hlist_node *tmp;
        unsigned long flags;
        int bucket;
        LIST_HEAD(to_free);

        launchtrace_unregister_ops(&lt_ops);
        misc_deregister(&lt_misc);
        cancel_delayed_work_sync(&lt_scan_work);
        spin_lock_irqsave(&lt_global_lock, flags);
        hash_for_each_safe(lt_sessions, bucket, tmp, s, hash_link) {
                hash_del(&s->hash_link);
                kfree(s);
        }
        list_for_each_entry_safe(p, n, &lt_active_patterns, lifecycle_link) {
                list_move_tail(&p->lifecycle_link, &to_free);
                p->state = LT_PATTERN_EXPIRED;
        }
        list_for_each_entry_safe(p, n, &lt_completed_patterns, lifecycle_link) {
                list_move_tail(&p->lifecycle_link, &to_free);
                p->state = LT_PATTERN_EXPIRED;
        }
        list_for_each_entry_safe(p, n, &lt_inflight_patterns, lifecycle_link) {
                list_move_tail(&p->lifecycle_link, &to_free);
                p->state = LT_PATTERN_EXPIRED;
        }
        spin_unlock_irqrestore(&lt_global_lock, flags);

        list_for_each_entry_safe(p, n, &to_free, lifecycle_link) {
                list_del_init(&p->lifecycle_link);
                lt_pattern_put(p);
        }
        mempool_destroy(lt_record_pool);
        kmem_cache_destroy(lt_record_cache);
        pr_info("LaunchTrace: unloaded\n");
}

module_init(launchtrace_init);
module_exit(launchtrace_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("LaunchTrace contributors");
MODULE_DESCRIPTION("Application startup block-read recorder for Linux 4.4");
