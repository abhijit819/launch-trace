/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_LAUNCHTRACE_H
#define _LINUX_LAUNCHTRACE_H

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/bio.h>
#include <linux/ioctl.h>
#include <linux/module.h>

/*
 * Kernel-side callback registration API. The wrappers are built into the
 * kernel; the recorder itself may be a loadable module.
 */
struct launchtrace_ops {
        struct module *owner;
        void (*exec_start)(const char *filename);
        void (*bio_submit)(struct bio *bio);
        void (*task_exit)(pid_t tgid);
};

int launchtrace_register_ops(const struct launchtrace_ops *ops);
void launchtrace_unregister_ops(const struct launchtrace_ops *ops);
void launchtrace_exec_start(const char *filename);
void launchtrace_bio_submit(struct bio *bio);
void launchtrace_task_exit(pid_t tgid);

#define LT_IOCTL_MAGIC          'L'
#define LT_IOCTL_SET_MAX_APPS   _IOW(LT_IOCTL_MAGIC, 1, __u32)
#define LT_IOCTL_START          _IO(LT_IOCTL_MAGIC, 2)
#define LT_IOCTL_STOP           _IO(LT_IOCTL_MAGIC, 3)
#define LT_IOCTL_ACK            _IOW(LT_IOCTL_MAGIC, 4, __u64)

#define LT_WIRE_MAGIC           0x4352544cU /* "LTRC" */
#define LT_WIRE_VERSION         1U

/* All multi-byte wire fields are little-endian. */
struct lt_wire_header {
        __le32 magic;
        __le32 version;
        __le32 header_bytes;
        __le32 reserved0;
        __le64 pattern_id;
        __le64 created_ns;
        __le64 completed_ns;
        __le32 tgid;
        __le32 reason;
        __le32 path_len;
        __le32 device_count;
        __le32 record_count;
        __le32 reserved1;
};
struct lt_wire_device {
        __le32 major;
        __le32 minor;
        __le32 record_count;
        __le32 reserved;
};
struct lt_wire_record {
        __le64 inode;
        __le64 page_index;
        __le64 start_sector;
        __le32 nr_sectors;
        __le32 reserved;
};

#endif /* _LINUX_LAUNCHTRACE_H */
