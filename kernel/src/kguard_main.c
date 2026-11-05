// SPDX-License-Identifier: GPL-2.0
/*
 * KGuard Kernel Module - Main Module File
 *
 * This file contains the main module initialization and cleanup functions.
 * It serves as the entry point for the KGuard network monitoring kernel module.
 */

#include "kguard.h"

/* Module metadata */
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(KGUARD_MODULE_DESC);
MODULE_AUTHOR(KGUARD_MODULE_AUTHOR);
MODULE_VERSION(KGUARD_MODULE_VERSION);

/* Global variables */
struct kguard_buffer *event_buffer;
struct proc_dir_entry *kguard_proc_entry;

/*
 * Module initialization function
 * Called when the module is loaded with insmod
 */
static int __init kguard_init(void)
{
	int ret = 0;

	kguard_info("Initializing KGuard kernel module v%s", KGUARD_MODULE_VERSION);

	/* Initialize the event buffer */
	ret = kguard_buffer_init();
	if (ret) {
		kguard_err("Failed to initialize event buffer: %d", ret);
		goto error_buffer;
	}
	kguard_info("Event buffer initialized successfully");

	/* Initialize proc filesystem interface */
	ret = kguard_proc_init();
	if (ret) {
		kguard_err("Failed to initialize proc interface: %d", ret);
		goto error_proc;
	}
	kguard_info("Proc interface initialized successfully");

	/* Initialize Netfilter hooks */
	ret = kguard_netfilter_init();
	if (ret) {
		kguard_err("Failed to initialize Netfilter hooks: %d", ret);
		goto error_netfilter;
	}
	kguard_info("Netfilter hooks initialized successfully");

	kguard_info("KGuard module loaded successfully");
	return 0;

error_netfilter:
	kguard_proc_cleanup();
error_proc:
	kguard_buffer_cleanup();
error_buffer:
	return ret;
}

/*
 * Module cleanup function
 * Called when the module is unloaded with rmmod
 */
static void __exit kguard_exit(void)
{
	kguard_info("Unloading KGuard kernel module");

	/* Cleanup Netfilter hooks */
	kguard_netfilter_cleanup();
	kguard_info("Netfilter hooks cleaned up");

	/* Cleanup proc filesystem interface */
	kguard_proc_cleanup();
	kguard_info("Proc interface cleaned up");

	/* Cleanup event buffer */
	kguard_buffer_cleanup();
	kguard_info("Event buffer cleaned up");

	kguard_info("KGuard module unloaded successfully");
}

/* Register module init and exit functions */
module_init(kguard_init);
module_exit(kguard_exit);
