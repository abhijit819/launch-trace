// SPDX-License-Identifier: GPL-2.0
/* Built-in dispatch layer for the optional LaunchTrace recorder module. */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/errno.h>
#include <linux/launchtrace.h>

static DEFINE_SPINLOCK(launchtrace_ops_lock);
static const struct launchtrace_ops *launchtrace_ops;

int launchtrace_register_ops(const struct launchtrace_ops *ops)
{
        unsigned long flags;
        int ret = 0;

        if (!ops || !ops->owner || !ops->exec_start ||
            !ops->bio_submit || !ops->task_exit)
                return -EINVAL;
        spin_lock_irqsave(&launchtrace_ops_lock, flags);
        if (launchtrace_ops)
                ret = -EBUSY;
        else
                launchtrace_ops = ops;
        spin_unlock_irqrestore(&launchtrace_ops_lock, flags);
        return ret;
}
EXPORT_SYMBOL_GPL(launchtrace_register_ops);

void launchtrace_unregister_ops(const struct launchtrace_ops *ops)
{
        unsigned long flags;
        spin_lock_irqsave(&launchtrace_ops_lock, flags);
        if (launchtrace_ops == ops)
                launchtrace_ops = NULL;
        spin_unlock_irqrestore(&launchtrace_ops_lock, flags);
}
EXPORT_SYMBOL_GPL(launchtrace_unregister_ops);

static const struct launchtrace_ops *launchtrace_get_ops(void)
{
        const struct launchtrace_ops *ops;
        unsigned long flags;

        spin_lock_irqsave(&launchtrace_ops_lock, flags);
        ops = launchtrace_ops;
        if (ops && !try_module_get(ops->owner))
                ops = NULL;
        spin_unlock_irqrestore(&launchtrace_ops_lock, flags);
        return ops;
}

void launchtrace_exec_start(const char *filename)
{
        const struct launchtrace_ops *ops = launchtrace_get_ops();
        if (ops) {
                ops->exec_start(filename);
                module_put(ops->owner);
        }
}

void launchtrace_bio_submit(struct bio *bio)
{
        const struct launchtrace_ops *ops = launchtrace_get_ops();
        if (ops) {
                ops->bio_submit(bio);
                module_put(ops->owner);
        }
}

void launchtrace_task_exit(pid_t tgid)
{
        const struct launchtrace_ops *ops = launchtrace_get_ops();
        if (ops) {
                ops->task_exit(tgid);
                module_put(ops->owner);
        }
}
