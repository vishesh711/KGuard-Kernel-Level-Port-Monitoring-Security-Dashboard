/*
 * KGuard Kernel Module - Proc Filesystem Interface
 * 
 * This file implements the /proc/kguard interface that allows user-space
 * applications to read network events captured by the kernel module.
 */

#include "kguard.h"

/* Maximum number of events to read in one operation */
#define MAX_EVENTS_PER_READ 100

/*
 * Convert IP address from network byte order to string
 */
static void ip_to_string(u32 ip, char *buffer, size_t size)
{
    snprintf(buffer, size, "%u.%u.%u.%u",
             (ip >> 24) & 0xFF,
             (ip >> 16) & 0xFF,
             (ip >> 8) & 0xFF,
             ip & 0xFF);
}

/*
 * Proc file show function
 * Called when user-space reads from /proc/kguard
 */
static int kguard_proc_show(struct seq_file *m, void *v)
{
    struct kguard_event events[MAX_EVENTS_PER_READ];
    int count, i;
    char src_ip_str[16], dst_ip_str[16];

    /* Get events from buffer */
    count = kguard_buffer_get_events(events, MAX_EVENTS_PER_READ);
    if (count < 0) {
        seq_printf(m, "{\"error\": \"Failed to read events: %d\"}\n", count);
        return 0;
    }

    if (count == 0) {
        seq_printf(m, "{\"events\": []}\n");
        return 0;
    }

    /* Output events in JSON format */
    seq_printf(m, "{\"events\": [\n");

    for (i = 0; i < count; i++) {
        /* Convert IP addresses to strings */
        ip_to_string(events[i].src_ip, src_ip_str, sizeof(src_ip_str));
        ip_to_string(events[i].dst_ip, dst_ip_str, sizeof(dst_ip_str));

        /* Output event in JSON format */
        seq_printf(m, "  {\n");
        seq_printf(m, "    \"timestamp\": %llu,\n", events[i].timestamp);
        seq_printf(m, "    \"src_ip\": \"%s\",\n", src_ip_str);
        seq_printf(m, "    \"dst_ip\": \"%s\",\n", dst_ip_str);
        seq_printf(m, "    \"src_port\": %u,\n", events[i].src_port);
        seq_printf(m, "    \"dst_port\": %u,\n", events[i].dst_port);
        seq_printf(m, "    \"protocol\": \"%s\",\n", 
                   kguard_protocol_name(events[i].protocol));
        seq_printf(m, "    \"flags\": %u\n", events[i].flags);
        seq_printf(m, "  }%s\n", (i < count - 1) ? "," : "");
    }

    seq_printf(m, "]}\n");

    kguard_debug("Served %d events via proc interface", count);
    return 0;
}

/*
 * Proc file open function
 */
static int kguard_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, kguard_proc_show, NULL);
}

/*
 * Proc file operations structure
 */
static const struct proc_ops kguard_proc_ops = {
    .proc_open = kguard_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/*
 * Initialize proc filesystem interface
 * Creates /proc/kguard entry
 */
int kguard_proc_init(void)
{
    /* Create proc entry */
    kguard_proc_entry = proc_create(KGUARD_PROC_NAME, 0444, NULL, 
                                    &kguard_proc_ops);
    if (!kguard_proc_entry) {
        kguard_err("Failed to create proc entry");
        return -ENOMEM;
    }

    kguard_debug("Proc entry created: /proc/%s", KGUARD_PROC_NAME);
    return 0;
}

/*
 * Cleanup proc filesystem interface
 * Removes /proc/kguard entry
 */
void kguard_proc_cleanup(void)
{
    if (kguard_proc_entry) {
        proc_remove(kguard_proc_entry);
        kguard_proc_entry = NULL;
        kguard_debug("Proc entry removed");
    }
}