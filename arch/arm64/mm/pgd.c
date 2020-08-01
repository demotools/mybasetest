// SPDX-License-Identifier: GPL-2.0-only
/*
 * PGD allocation/freeing
 *
 * Copyright (C) 2012 ARM Ltd.
 * Author: Catalin Marinas <catalin.marinas@arm.com>
 */

#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/slab.h>

#include <asm/pgalloc.h>
#include <asm/page.h>
#include <asm/tlbflush.h>

static struct kmem_cache *pgd_cache __ro_after_init;
#ifdef CONFIG_PGTABLE_REPLICATION
pgd_t *pgd_alloc(struct mm_struct *mm)
{
	gfp_t gfp = GFP_PGTABLE_USER;
	if (PGD_SIZE == PAGE_SIZE)
	{
		pgd_t * pgd = (pgd_t *)__get_free_page(gfp);
		mm->pgd = pgd;
		/* this will replicate the pgd */
		pgtable_repl_pgd_alloc(mm);
		return pgd;
	}
	else
		return kmem_cache_alloc(pgd_cache, gfp);
}

void pgd_free(struct mm_struct *mm, pgd_t *pgd)
{
	if (PGD_SIZE == PAGE_SIZE)
	{
		pgtable_repl_pgd_free(mm, pgd);
		free_page((unsigned long)pgd);
	}
	else
		kmem_cache_free(pgd_cache, pgd);
}
#else
pgd_t *pgd_alloc(struct mm_struct *mm)
{
	gfp_t gfp = GFP_PGTABLE_USER;

	if (PGD_SIZE == PAGE_SIZE)
		return (pgd_t *)__get_free_page(gfp);
	else
		return kmem_cache_alloc(pgd_cache, gfp);
}

void pgd_free(struct mm_struct *mm, pgd_t *pgd)
{
	if (PGD_SIZE == PAGE_SIZE)
		free_page((unsigned long)pgd);
	else
		kmem_cache_free(pgd_cache, pgd);
}
#endif
void __init pgtable_cache_init(void)
{
	if (PGD_SIZE == PAGE_SIZE)
		return;

#ifdef CONFIG_ARM64_PA_BITS_52
	/*
	 * With 52-bit physical addresses, the architecture requires the
	 * top-level table to be aligned to at least 64 bytes.
	 */
	BUILD_BUG_ON(PGD_SIZE < 64);
#endif

	/*
	 * Naturally aligned pgds required by the architecture.
	 */
	pgd_cache = kmem_cache_create("pgd_cache", PGD_SIZE, PGD_SIZE,
				      SLAB_PANIC, NULL);
}

//==========================================================================================
/*
 * ==================================================================
 * Page Table replication extension using paravirt ops
 * ==================================================================
 */

#ifdef CONFIG_PGTABLE_REPLICATION
void pgtable_cache_free(int node, struct page *p);
struct page *pgtable_cache_alloc(int node);

///> pgtable_repl_initialized tracks whether the system is ready for handling page table replication
// static bool pgtable_repl_initialized = false;
bool pgtable_repl_initialized = false;

///> tracks whether page table replication is activated for new processes by default
// static bool pgtable_repl_activated = false;
bool pgtable_repl_activated = false;

///> where to allocate the page tables from
int pgtable_fixed_node = -1;
nodemask_t pgtable_fixed_nodemask = NODE_MASK_NONE;


#define MAX_SUPPORTED_NODE 8

///> page table cache
static struct page *pgtable_cache[MAX_SUPPORTED_NODE] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };

///> page table cache sizes
static size_t pgtable_cache_size[MAX_SUPPORTED_NODE] = { 0 };

//#include <linux/spinlock_types.h>

///> lock for the page table cache
static DEFINE_SPINLOCK(pgtable_cache_lock);

/*
 * ==================================================================
 * Debug Macros
 * ==================================================================
 */

// #define DEBUG_PGTABLE_REPLICATION
#ifdef DEBUG_PGTABLE_REPLICATION
// #include <linux/mmzone.h>
#define check_page(p) \
	if (unlikely(!(p))) { printk("PTREPL:%s:%u - page was NULL!\n", __FUNCTION__, __LINE__); }

#define check_offset(offset) if (offset >= 4096 || (offset % 8)) { \
	printk("PTREPL: %s:%d - offset=%lu, %lu\n", __FUNCTION__, __LINE__, offset, offset % 8); }

#define check_page_node(p, n) do {\
	if (!virt_addr_valid((void *)p)) {/*printk("PTREP: PAGE IS NOT VALID!\n");*/} \
	if (p == NULL) {printk("PTREPL: PAGE WAS NULL!\n");} \
	if (pfn_to_nid(page_to_pfn(p)) != (n)) { \
		printk("PTREPL: %s:%u page table nid mismatch! pfn: %zu, nid %u expected: %u\n", \
		__FUNCTION__, __LINE__, page_to_pfn(p), pfn_to_nid(page_to_pfn(p)), (int)(n)); \
		dump_stack();\
	}} while(0);

#else
#define check_page(p)
#define check_offset(offset)
#define check_page_node(p, n)
#endif

/*
 * ===============================================================================
 * Helper functions
 * ===============================================================================
 */
struct page *page_of_ptable_entry(void *pgtableep)
{
	/* the pointer to a page table entry is a kernel virtual address.
	   we need to get the page of this pointer.
	   kva -> pa -> pfn -> struct page, virt_to_page should do this for us
	 */
	return virt_to_page((long)pgtableep);
}

/*
 * ===============================================================================
 * Allocation and Freeing of Page Tables
 * ===============================================================================
 */
int pgtable_repl_pgd_alloc(struct mm_struct *mm)
{
	int i;
	struct page *pgd, *pgd2;

	for (i = 0; i < sizeof(mm->repl_pgd) / sizeof(mm->repl_pgd[0]); i++) {
		/* set the first replicatin entry */
		mm->repl_pgd[i] = mm->pgd;
	}

	/* don't do replication for init */
	if (unlikely(mm == &init_mm)) {
		printk("PTREPL: Not activating mm because it was init.\n");
		mm->repl_pgd_enabled = false;
		return 0;
	}

	if (unlikely(!pgtable_repl_initialized)) {
		pgtable_repl_initialized = (nr_node_ids != MAX_NUMNODES);
		if (pgtable_repl_initialized) {
			if (pgtable_fixed_node == -1) {
				pgtable_repl_activated = false;
			}
			printk("PTREPL: set state to %s.\n", (pgtable_repl_activated ? "activated" : "deactivated"));
		}
	}

	if (!pgtable_repl_initialized) {
		mm->repl_pgd_enabled = false;
		return 0;
	}

	if (pgtable_repl_activated) {
		mm->repl_pgd_enabled = true;
	}

	if (mm->repl_pgd_enabled == false ) {
		return 0;
	}

	printk("PTREPL: enable replication for the pgd of process\n");

	// replication is enabled for this domain
	mm->repl_pgd_enabled = true;

	/* get the page of the previously allocated pgd */
	pgd = page_of_ptable_entry(mm->pgd);

	pgd2 = pgd;
	for (i = 0; i < nr_node_ids; i++) {

		/* allocte a new page, and place it in the replica list */
		pgd2->replica = pgtable_cache_alloc(i);
		if (pgd2->replica == NULL) {
			goto cleanup;
		}

		check_page_node(pgd2->replica, i);

		/* set the replica pgd poiter */
		mm->repl_pgd[i] = (pgd_t *) page_to_virt(pgd2->replica);

		pgd2 = pgd2->replica;
	}

	/* finish the loop: last -> first replica */
	pgd2->replica = pgd;

	/* let's verify */
	#if 1
	pgd2 = pgd->replica;
	for (i = 0; i < nr_node_ids; i++) {
		check_page_node(pgd2, i);
		pgd2 = pgd2->replica;
	}
	if (pgd2 != pgd) {
		panic("%s:%d: PTREPL: NOT THE ASAME????\n", __FUNCTION__, __LINE__);
	}
	#endif

	return 0;
	cleanup:

	panic("%s:%d: PTREPL: FAILED!!!!\n", __FUNCTION__, __LINE__);

	return -1;
}

void pgtable_repl_pgd_free(struct mm_struct *mm, pgd_t *pgd)
{
	int i;
	struct page *pgd_page, *p;

	if (unlikely(mm == &init_mm)) {
		return;
	}

	pgd_page = page_of_ptable_entry(mm->pgd);
	if (pgd_page->replica == NULL) {
		if (mm->repl_pgd[0] != mm->pgd) {
			printk("pgtable_repl_pgd_free mm->repl_pgd[i] != mm->pgd. should have been the same\n");
		}
		return;
	}

	pgd_page = pgd_page->replica;

	/* XXX: check if there are infact replicas */
	for (i = 0; i < nr_node_ids; i++) {
		p = pgd_page;
		pgd_page = pgd_page->replica;

		if (p != page_of_ptable_entry(mm->repl_pgd[i])) {
			panic("mm->repl_pgd[i] != mm->pgd. should have been the same\n");
		};
		// p = page_of_ptable_entry(mm->repl_pgd[i]);
		check_page_node(p, i);

		/* free the pgd */
		pgtable_cache_free(i, p);

		/* we set the replica pointer to the first one */
		mm->repl_pgd[i] = pgd;
	}
	pgd_page = page_of_ptable_entry(mm->pgd);
	pgd_page->replica = NULL;
}
#endif