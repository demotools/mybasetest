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
#include <asm/mmu_context.h>

static struct kmem_cache *pgd_cache __ro_after_init;
#ifdef CONFIG_PGTABLE_REPLICATION
pgd_t *pgd_alloc(struct mm_struct *mm)
{
	gfp_t gfp = GFP_PGTABLE_USER;
	if (PGD_SIZE == PAGE_SIZE)
	{
		#ifdef CONFIG_Migration_test //迁移测试
		pgd_t * pgd = (pgd_t *)pgtable_page_alloc_2(gfp,0);
		#else
		//正常测试
		pgd_t * pgd = (pgd_t *)__get_free_page(gfp);
		#endif

		mm->pgd = pgd;
		// printk("[mitosis-origin] pgd_alloc for mm=%lx and mm->pgd =%lx.\n",(long)mm,(long)mm->pgd);
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
		// printk("[mitosis-origin] pgd_free for mm=%lx and pgd =%lx and mm->pgd=%lx.\n",(long)mm,(long)pgd,(long)mm->pgd);
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
static bool pgtable_repl_initialized = false;
// bool pgtable_repl_initialized = false;

///> tracks whether page table replication is activated for new processes by default
//这个是控制以后创建的其他进程的页表复制功能开启的
static bool pgtable_repl_activated = false;
// bool pgtable_repl_activated = false;

//手动激活控制
static bool pgtable_repl_custom_activated = false;

///> where to allocate the page tables from
int pgtable_fixed_node = -1;
nodemask_t pgtable_fixed_nodemask = NODE_MASK_NONE;

static bool migration_test = false;


#define MAX_SUPPORTED_NODE 8

///> page table cache
static struct page *pgtable_cache[MAX_SUPPORTED_NODE] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };

///> page table cache sizes
static size_t pgtable_cache_size[MAX_SUPPORTED_NODE] = { 0 };

//#include <linux/spinlock_types.h>

///> lock for the page table cache
static DEFINE_SPINLOCK(pgtable_cache_lock);



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
		if (!pgtable_repl_custom_activated) {
		return 0;
		}
		pgtable_repl_initialized = (nr_node_ids != MAX_NUMNODES);
		if (pgtable_repl_initialized) {
			if (pgtable_fixed_node == -1) {
				pgtable_repl_activated = false;
			}
			printk("[mitosis] pgd_alloc: pid = %d\n",current->pid);
			printk("[mitosis] pgd_alloc for mm=%lx and mm->pgd =%lx.\n",(long)mm,(long)mm->pgd);
			printk("PTREPL: set state to %s.\n", (pgtable_repl_activated ? "activated" : "deactivated"));
		}
	}
	
	if (!pgtable_repl_initialized) {
		mm->repl_pgd_enabled = false;
		return 0;
	}
	// printk("[mitosis] pgd_alloc start: pid = %d\n",current->pid);
	if (pgtable_repl_activated) {
		mm->repl_pgd_enabled = true;
	}

	if (mm->repl_pgd_enabled == false ) {
		return 0;
	}
	printk("[mitosis]------PTREPL: alloc pgd start------\n");
	printk("[mitosis] nr_node_ids=%d.\n",nr_node_ids);
	printk("[mitosis] pgd_alloc origin mm->pgd =%lx.\n",(long)mm->pgd);
	// replication is enabled for this domain
	mm->repl_pgd_enabled = true;

	// pfn_to_nid(virt_to_pfn(mm->pgd))
	/* get the page of the previously allocated pgd */
	pgd = page_of_ptable_entry(mm->pgd);
	pgd->replica_node_id = -1;
	pgd2 = pgd;
	for (i = 0; i < nr_node_ids; i++) {

		/* allocte a new page, and place it in the replica list */
		pgd2->replica = pgtable_cache_alloc(i);
		pgd2->replica->replica_node_id = i;
		if (pgd2->replica == NULL) {
			goto cleanup;
		}

		check_page_node(pgd2->replica, i);

		/* set the replica pgd poiter */
		mm->repl_pgd[i] = (pgd_t *) page_to_virt(pgd2->replica);
		printk("[mitosis] pgd_alloc mm->repl_pgd[%d]=%lx.\n",i,(long)mm->repl_pgd[i]);
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
	printk("------PTREPL: alloc pgd success------\n");
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

	// if (unlikely(!pgtable_repl_initialized)) {
	// 	return;
	// }
	// printk("[mitosis] pgd_free start: pid = %d\n",current->pid);
	pgd_page = page_of_ptable_entry(mm->pgd);
	if (pgd_page->replica == NULL) {
		if (mm->repl_pgd[0] != mm->pgd) {
			printk("pgtable_repl_pgd_free mm->repl_pgd[i] != mm->pgd. should have been the same\n");
		}
		return;
	}
	printk("[mitosis] PTREPL: free pgd start \n");
	printk("[mitosis] pgtable_repl_pgd_free freed pgd=%lx and mm->pgd=%lx.\n",(long)pgd,(long)mm->pgd);
	pgd_page = pgd_page->replica;
	// BUG_ON(1);
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
	printk("[mitosis]------PTREPL: free pgd done------\n");
}

static inline void __pgtable_repl_alloc_one(struct mm_struct *mm, unsigned long pfn)
{
	int i;
	struct page *p, *p2;
	if (unlikely(!pgtable_repl_initialized)) {
		return;
	}
	/* obtain the page for the pfn */
	p = pfn_to_page(pfn);
	if (p == NULL) {
		return;
	}
	p->replica_node_id = -1;
	if (!mm->repl_pgd_enabled) {
		p->replica = NULL;
		return;
	}

	if (p->replica) {
		printk("PTREP: Called alloc on an already allocated replica... verifying!\n");
		p2 = p->replica;
		for (i = 0; i < nr_node_ids; i++) {
			check_page_node(p2, i);
			p2 = p2->replica;
		}
		if (p2 != p) {
			printk("%s:%d: PTREPL: NOT THE ASAME????\n", __FUNCTION__, __LINE__);
		}
		return;
	}
	// printk("%s:%u pud alloc =%lx , node = %i\n", __FUNCTION__, __LINE__, (long)page_to_virt(p),pfn_to_nid(pfn));
	
	p2 = p;
	for (i = 0; i < nr_node_ids; i++) {
		/* allocte a new page, and place it in the replica list */
		p2->replica  = pgtable_cache_alloc(i);
		p2->replica->replica_node_id = i;
		if (p2->replica == NULL) {
			goto cleanup;
		}
		
		// printk("[mitosis] __pgtable_repl_alloc_one origin pagep=%lx and new pagep = %lx\n",(long) page_to_virt(p),(long)page_to_virt(p2->replica));
		check_page_node(p2->replica, i);

		// if (ctor) {
		// 	if(!ctor(p2->replica)) {
		// 		panic("Failed to call ctor!\n");
		// 	}
		// }

		/* set the replica pgd poiter */
		p2 = p2->replica;
	}

	/* finish the loop: last -> first replica */
	p2->replica = p;

	/* let's verify */
	#if 1
	p2 = p->replica;
	for (i = 0; i < nr_node_ids; i++) {
		//printk("page: %lx", (long)p2);
		check_page_node(p2, i);
		p2 = p2->replica;
	}
	if (p2 != p) {
		panic("%s:%d: PTREPL: NOT THE ASAME????\n", __FUNCTION__, __LINE__);
	}
	#endif
	return;

	cleanup:

	panic("%s:%d: PTREPL: FAILED!!!!\n", __FUNCTION__, __LINE__);
}

static inline void __pgtable_repl_release_one(unsigned long pfn)
{
	int i;
	struct page *p, *p2, *pcurrent;
	
	p = pfn_to_page(pfn);
	if (unlikely(p == NULL)) {
		return;
	}

	if (p->replica == NULL) {
		return;
	}

	p2 = p->replica;
	// int previusly_page_node = pfn_to_nid(pfn);
	// int current_node;
	for (i = 0; i < nr_node_ids; i++) {
		// current_node = page_to_nid(p2);
		// if(current_node == previusly_page_node)
		// {
		// 	p2 = p2->replica;
		// 	continue;
		// }
		check_page_node(p2, i);
		pcurrent = p2;
		// if (dtor) {
		// 	dtor(pcurrent);
		// }
		p2 = p2->replica;
		pgtable_cache_free(i, pcurrent);
	}

	p->replica = NULL;
}

static inline void __pgtable_repl_alloc_pmd(struct mm_struct *mm, unsigned long pfn)
{
	int i;
	struct page *p, *p2;
	if (unlikely(!pgtable_repl_initialized)) {
		return;
	}
	/* obtain the page for the pfn */
	p = pfn_to_page(pfn);
	if (p == NULL) {
		return;
	}
	p->replica_node_id = -1;
	if (!mm->repl_pgd_enabled) {
		p->replica = NULL;
		return;
	}

	if (p->replica) {
		printk("PTREP: Called alloc on an already allocated replica... verifying!\n");
		p2 = p->replica;
		for (i = 0; i < nr_node_ids; i++) {
			check_page_node(p2, i);
			p2 = p2->replica;
		}
		if (p2 != p) {
			printk("%s:%d: PTREPL: NOT THE ASAME????\n", __FUNCTION__, __LINE__);
		}
		return;
	}
	// printk("%s:%u pmd alloc =%lx , node = %i\n", __FUNCTION__, __LINE__, (long)page_to_virt(p),pfn_to_nid(pfn));
	
	p2 = p;
	for (i = 0; i < nr_node_ids; i++) {
		/* allocte a new page, and place it in the replica list */
		p2->replica  = pgtable_cache_alloc(i);
		p2->replica->replica_node_id = i;
		if (p2->replica == NULL) {
			goto cleanup;
		}
		
		// printk("[mitosis] __pgtable_repl_alloc_one origin pagep=%lx and new pagep = %lx\n",(long) page_to_virt(p),(long)page_to_virt(p2->replica));
		check_page_node(p2->replica, i);

		if (!pgtable_pmd_page_ctor(p2->replica)) {
			// __free_page(page);
			panic("Failed to call ctor!\n");
		}
		/* set the replica pgd poiter */
		p2 = p2->replica;
	}

	/* finish the loop: last -> first replica */
	p2->replica = p;

	/* let's verify */
	#if 0
	p2 = p->replica;
	for (i = 0; i < nr_node_ids; i++) {
		//printk("page: %lx", (long)p2);
		check_page_node(p2, i);
		p2 = p2->replica;
	}
	if (p2 != p) {
		panic("%s:%d: PTREPL: NOT THE ASAME????\n", __FUNCTION__, __LINE__);
	}
	#endif
	return;

	cleanup:

	panic("%s:%d: PTREPL: FAILED!!!!\n", __FUNCTION__, __LINE__);
}
static inline void __pgtable_repl_release_pmd(unsigned long pfn)
{
	int i;
	struct page *p, *p2, *pcurrent;
	
	p = pfn_to_page(pfn);
	if (unlikely(p == NULL)) {
		return;
	}

	if (p->replica == NULL) {
		return;
	}
	p2 = p->replica;
	for (i = 0; i < nr_node_ids; i++) {
		check_page_node(p2, i);
		pcurrent = p2;
		pgtable_pmd_page_dtor(pcurrent);
		p2 = p2->replica;
		pgtable_cache_free(i, pcurrent);
	}

	p->replica = NULL;
}
static inline void __pgtable_repl_alloc_pte(struct mm_struct *mm, unsigned long pfn)
{
	int i;
	struct page *p, *p2;
	if (unlikely(!pgtable_repl_initialized)) {
		return;
	}
	/* obtain the page for the pfn */
	p = pfn_to_page(pfn);
	if (p == NULL) {
		return;
	}
	p->replica_node_id = -1;
	if (!mm->repl_pgd_enabled) {
		p->replica = NULL;
		return;
	}

	if (p->replica) {
		printk("PTREP: Called alloc on an already allocated replica... verifying!\n");
		p2 = p->replica;
		for (i = 0; i < nr_node_ids; i++) {
			check_page_node(p2, i);
			p2 = p2->replica;
		}
		if (p2 != p) {
			printk("%s:%d: PTREPL: NOT THE ASAME????\n", __FUNCTION__, __LINE__);
		}
		return;
	}
	// printk("%s:%u pte alloc =%lx , node = %i\n", __FUNCTION__, __LINE__, (long)page_to_virt(p),pfn_to_nid(pfn));
	
	p2 = p;
	for (i = 0; i < nr_node_ids; i++) {
		/* allocte a new page, and place it in the replica list */
		p2->replica  = pgtable_cache_alloc(i);
		p2->replica->replica_node_id = i;
		if (p2->replica == NULL) {
			goto cleanup;
		}
		
		// printk("[mitosis] __pgtable_repl_alloc_one origin pagep=%lx and new pagep = %lx\n",(long) page_to_virt(p),(long)page_to_virt(p2->replica));
		check_page_node(p2->replica, i);

		if (!pgtable_pte_page_ctor(p2->replica)) {
			// __free_page(page);
			panic("Failed to call ctor!\n");
		}
		/* set the replica pgd poiter */
		p2 = p2->replica;
	}

	/* finish the loop: last -> first replica */
	p2->replica = p;

	/* let's verify */
	#if 0
	p2 = p->replica;
	for (i = 0; i < nr_node_ids; i++) {
		//printk("page: %lx", (long)p2);
		check_page_node(p2, i);
		p2 = p2->replica;
	}
	if (p2 != p) {
		panic("%s:%d: PTREPL: NOT THE ASAME????\n", __FUNCTION__, __LINE__);
	}
	#endif
	return;

	cleanup:

	panic("%s:%d: PTREPL: FAILED!!!!\n", __FUNCTION__, __LINE__);
}
static inline void __pgtable_repl_release_pte(unsigned long pfn)
{
	int i;
	struct page *p, *p2, *pcurrent;
	
	p = pfn_to_page(pfn);
	if (unlikely(p == NULL)) {
		return;
	}

	if (p->replica == NULL) {
		return;
	}
	p2 = p->replica;
	for (i = 0; i < nr_node_ids; i++) {
		check_page_node(p2, i);
		pcurrent = p2;
		pgtable_pte_page_dtor(pcurrent);
		p2 = p2->replica;
		pgtable_cache_free(i, pcurrent);
	}

	p->replica = NULL;
}
void pgtable_repl_alloc_pte(struct mm_struct *mm, unsigned long pfn)
{
	__pgtable_repl_alloc_pte(mm, pfn);
	// printk("------PTREPL: alloc pte start------\n");
	// __pgtable_repl_alloc_one(mm, pfn);
	// printk("------PTREPL: alloc pte done------\n");
}

void pgtable_repl_alloc_pmd(struct mm_struct *mm, unsigned long pfn)
{
	__pgtable_repl_alloc_pmd(mm, pfn);
	// printk("------PTREPL: alloc pmd start------\n");
	// __pgtable_repl_alloc_one(mm, pfn);
	// printk("------PTREPL: alloc pmd done------\n");
}

void pgtable_repl_alloc_pud(struct mm_struct *mm, unsigned long pfn)
{
	// printk("------PTREPL: alloc pud start------\n");
	__pgtable_repl_alloc_one(mm, pfn);
	// printk("------PTREPL: alloc pud done------\n");
}

void pgtable_repl_release_pte(unsigned long pfn)
{
	__pgtable_repl_release_pte(pfn);
	// printk("------PTREPL: release pte start------\n");
	// __pgtable_repl_release_one(pfn);
	// printk("------PTREPL: release pte done------\n");
}

void pgtable_repl_release_pmd(unsigned long pfn)
{
	__pgtable_repl_release_pmd(pfn);
	// printk("------PTREPL: release pmd start------\n");
	// __pgtable_repl_release_one(pfn);
	// printk("------PTREPL: release pmd done------\n");
}

void pgtable_repl_release_pud(unsigned long pfn)
{
	// printk("------PTREPL: release pud start------\n");
	__pgtable_repl_release_one(pfn);
	// printk("------PTREPL: release pud done------\n");
}

/*
 * ===============================================================================
 * Set Page Table Entries
 * ===============================================================================
 */


void pgtable_repl_set_pte(pte_t *ptep, pte_t pteval)
{
	
	// printk("PTREP: Called pgtable_repl_set_pte\n");
	int i;
	long offset;
	struct page *page_pte,*page_tmp;

	if (unlikely(!pgtable_repl_initialized)) {
		return;
	}
	
	//因为ptep 是 pte表中的一个entry的地址，我们为了获取这个entry 对于这个pte表的offset，所以需要获取这个表的page，然后通过page得到这个page的虚拟地址， 然后就能用ptep和这个虚拟地址计算offset
	page_pte = page_of_ptable_entry(ptep);
	check_page(page_pte);
	if (page_pte->replica == NULL) {
		return;
	}
	
	// printk("------PTREPL: set_pte start------\n");
	
	offset = (long)ptep - (long)page_to_virt(page_pte);
	check_offset(offset);
	// printk("------ 1 . page_pte->replica_node_id = %d------\n",page_pte->replica_node_id);
	while(page_pte->replica_node_id != -1)
	{
		page_tmp = page_pte->replica;
		page_pte = page_tmp;
		// ptep = (pte_t *)((long)page_to_virt(page_pte) + offset);
		// native_set_pte(ptep, pteval);
		printk("------2 . page_pte->replica_node_id = %d------\n",page_pte->replica_node_id);
	}

	for (i = 0; i < nr_node_ids; i++) {
		page_pte = page_pte->replica;
		check_page_node(page_pte, i);

		ptep = (pte_t *)((long)page_to_virt(page_pte) + offset);
		// printk("PTREP: set_pte offset=%lx and node0 origin pte=%lx  and pte+offset=%lx  and pteval=%lx\n",offset,(long)page_to_virt(page_pte), (long)ptep,(long)pte_val(pteval));
		native_set_pte(ptep, pteval);
	}
	// printk("------PTREPL: set_pte done------\n");
}

void pgtable_repl_set_pte_with_log(pte_t *ptep, pte_t pteval)
{
	// printk("PTREP: Called pgtable_repl_set_pte\n");
	int i;
	long offset;
	struct page *page_pte;

	if (unlikely(!pgtable_repl_initialized)) {
		return;
	}
	//因为ptep 是 pte表中的一个entry的地址，我们为了获取这个entry 对于这个pte表的offset，所以需要获取这个表的page，然后通过page得到这个page的虚拟地址， 然后就能用ptep和这个虚拟地址计算offset
	page_pte = page_of_ptable_entry(ptep);
	check_page(page_pte);

	if (page_pte->replica == NULL) {
		return;
	}
	printk("------PTREPL: set_pte start with log------\n");
	
	offset = (long)ptep - (long)page_to_virt(page_pte);
	check_offset(offset);
	// printk("------ 1 . page_pte->replica_node_id = %d------\n",page_pte->replica_node_id);
	// while(page_pte->replica_node_id != -1)
	// {
	// 	page_tmp = page_pte->replica;
	// 	page_pte = page_tmp;
	// 	// ptep = (pte_t *)((long)page_to_virt(page_pte) + offset);
	// 	// native_set_pte(ptep, pteval);
	// 	printk("------2 . page_pte->replica_node_id = %d------\n",page_pte->replica_node_id);
	// }

	for (i = 0; i < nr_node_ids; i++) {
		page_pte = page_pte->replica;
		check_page_node(page_pte, i);

		ptep = (pte_t *)((long)page_to_virt(page_pte) + offset);
		printk("PTREP: set_pte offset=%lx and node0 origin pte=%lx  and pte+offset=%lx  and pteval=%lx\n",offset,(long)page_to_virt(page_pte), (long)ptep,(long)pte_val(pteval));
		native_set_pte(ptep, pteval);
	}
	printk("------PTREPL: set_pte done------\n");
}


void pgtable_repl_set_pte_at(struct mm_struct *mm, unsigned long addr,
							 pte_t *ptep, pte_t pteval)
{
	pgtable_repl_set_pte(ptep, pteval);
}

// static inline pmd_t native_make_pmd(pmdval_t val)
// {
// 	return (pmd_t) { val };
// }

void pgtable_repl_set_pmd(pmd_t *pmdp, pmd_t pmdval)
{
	// printk("PTREP: Called pgtable_repl_set_pmd \n");
	int i;
	long offset;
	struct page *page_pmd, *page_pte,*page_tmp;

	if (unlikely(!pgtable_repl_initialized)) {
		return;
	}
	
	page_pmd = page_of_ptable_entry(pmdp);
	check_page(page_pmd);

	if (page_pmd->replica == NULL) {
		return;
	}
	// printk("------PTREPL: set_pmd start------\n");
	page_pte = pmd_page(pmdval);

	offset = ((long)pmdp & ~PAGE_MASK);
	check_offset(offset);
	// printk("------ 1 . page_pmd->replica_node_id = %d------\n",page_pmd->replica_node_id);
	while(page_pmd->replica_node_id != -1)
	{
		page_tmp = page_pmd->replica;
		page_pmd = page_tmp;
		printk("------2 . page_pmd->replica_node_id = %d------\n",page_pmd->replica_node_id);
	}

	/* the entry is a large entry i.e. pointing to a frame, or the entry is not valid */
	if (!page_pte || pmd_none(pmdval) || !pmd_present(pmdval)) {
		// printk("PTREP: set_pmd  origin pmd=%lx  and pmdval=%lx\n",(long)pmdp, (long)pmd_val(pmdval));
		// printk("PTREP: Called pgtable_repl_set_pmd  !page_te \n");
		// BUG_ON(1);
		for (i = 0; i < nr_node_ids; i++) {
			page_pmd = page_pmd->replica;
			check_page_node(page_pmd, i);
			pmdp = (pmd_t *)((long)page_to_virt(page_pmd) + offset);
			native_set_pmd(pmdp, pmdval);
		}
		return;
	}
	

	/* where the entry points to */
	for (i = 0; i < nr_node_ids; i++) {
		page_pmd = page_pmd->replica;
		page_pte = page_pte->replica;

		check_page_node(page_pmd, i);
		check_page_node(page_pte, i);

		pmdp = (pmd_t *)((long)page_to_virt(page_pmd) + offset);
		pmdval = __pmd(__phys_to_pmd_val(page_to_phys(page_pte)) | PMD_TYPE_TABLE);
		// pmdval = native_make_pmd((page_to_pfn(page_pte) << PAGE_SHIFT) | pmd_flags(pmdval));
		// printk("PTREP: set_pmd offset=%lx and node0 origin pmd=%lx  and pmd+offset=%lx  and pte=%lx and pmdval=%lx\n",offset,(long)page_to_virt(page_pmd), (long)pmdp, (long)page_to_virt(page_pte),(long)pmd_val(pmdval));
		native_set_pmd(pmdp, pmdval);
	}
	// printk("------PTREPL: set_pmd done------\n");
}

// static inline pud_t native_make_pud(pmdval_t val)
// {
// 	return (pud_t) { val };
// }
void pgtable_repl_set_pud(pud_t *pudp, pud_t pudval)
{
	// printk("PTREP: Called pgtable_repl_set_pud\n");
	int i;
	long offset;
	struct page *page_pud, *page_pmd ,*page_tmp;

	if (unlikely(!pgtable_repl_initialized)) {
		return;
	}
	
	page_pud = page_of_ptable_entry(pudp);
	check_page(page_pud);

	if (page_pud->replica == NULL) {
		return;
	}
	// printk("------PTREPL: set_pud start------\n");
	offset = ((long)pudp & ~PAGE_MASK);
	check_offset(offset);
// printk("------ 1 . page_pud->replica_node_id = %d------\n",page_pud->replica_node_id);
	page_pmd = pud_page(pudval);
	while(page_pud->replica_node_id != -1)
	{
		page_tmp = page_pud->replica;
		page_pud = page_tmp;
		printk("------2 . page_pud->replica_node_id = %d------\n",page_pud->replica_node_id);
	}

	/* there is no age for this entry or the entry is huge or the entry is not present */
	if (!page_pmd || !pud_present(pudval) || pud_none(pudval)) {
		// printk("PTREP: set_pud  origin pud=%lx  and pudval=%lx\n",(long)pudp, (long)pud_val(pudval));
		// printk("PTREP: Called pgtable_repl_set_pud  !page_pmd \n");
		// BUG_ON(1);
		for (i = 0; i < nr_node_ids; i++) {
			page_pud = page_pud->replica;
			check_page_node(page_pud, i);
			pudp = (pud_t *)((long)page_to_virt(page_pud) + offset);
			native_set_pud(pudp, pudval);
		}
		return;
	}

	
	
	for (i = 0; i < nr_node_ids; i++) {
		page_pud = page_pud->replica;
		page_pmd = page_pmd->replica;

		check_page_node(page_pud, i);
		check_page_node(page_pmd, i);

		pudp = (pud_t *)((long)page_to_virt(page_pud) + offset);
		pudval = __pud(__phys_to_pud_val(page_to_phys(page_pmd)) | PMD_TYPE_TABLE);
		// pudval = native_make_pud((page_to_pfn(page_pmd) << PAGE_SHIFT) | pud_flags(pudval));
		// printk("PTREP: set_pud offset=%lx and node0 origin pud=%lx  and pud+offset=%lx  and pmd=%lx and pudval=%lx\n",offset,(long)page_to_virt(page_pud), (long)pudp, (long)page_to_virt(page_pmd),(long)pud_val(pudval));
		native_set_pud(pudp, pudval);
	}
	// printk("------PTREPL: set_pud done------\n");
}

void pgtable_repl_set_pgd(pgd_t *pgdp, pgd_t pgdval)
{
	// panic("PTREPL: %s:%d:  not yet implemented by Mitosis\n", __FUNCTION__, __LINE__);
	int i;
	long offset;
	struct page *page_pgd, *page_pud,*page_tmp;

	if (unlikely(!pgtable_repl_initialized)) {
		return;
	}
	
	page_pgd = page_of_ptable_entry(pgdp);
	check_page(page_pgd);
	//这里是判断这个进程有没有被允许开启页表复制，因为没有mm,所以只能用页表的链表是否为空来判断
	if (page_pgd->replica == NULL) {
		return;
	}
	// printk("------PTREPL: set_pgd start------\n");
	//取出pgdp 在pgd 中的偏移 offset
	offset = ((long)pgdp & ~PAGE_MASK);
	check_offset(offset);
	// printk("------ 1 . page_pgd->replica_node_id = %d------\n",page_pgd->replica_node_id);
	page_pud = pgd_page(pgdval);
	while(page_pgd->replica_node_id != -1)
	{
		page_tmp = page_pgd->replica;
		page_pgd = page_tmp;
		printk("------2 . page_pgd->replica_node_id = %d------\n",page_pgd->replica_node_id);	
	}
	//如果pud 的page 还没有被放入内存中，那么就直接把pgdval这个地址值设置到各节点的副本pgd表中。
	if (!page_pud || pgd_none(pgdval) || !pgd_present(pgdval)) {
		// printk("PTREP: set_pgd  origin pgd=%lx  and pgdval=%lx\n",(long)pgdp, (long)pgd_val(pgdval));
		// printk("PTREP: Called pgtable_repl_set_pgd  !page_pud \n");
		//  BUG_ON(1);
		for (i = 0; i < nr_node_ids; i++) {
			page_pgd = page_pgd->replica;
			check_page_node(page_pgd, i);
			pgdp = (pgd_t *)((long)page_to_virt(page_pgd) + offset);
			native_set_pgd(pgdp, pgdval);
		}
		return;
	}
	
	//如果pud 的page 存在，那就重新计算各节点副本pud的地址值，并放入副本的pgd表中。
	for (i = 0; i < nr_node_ids; i++) {
		page_pud = page_pud->replica;
		page_pgd = page_pgd->replica;

		check_page_node(page_pgd, i);
		check_page_node(page_pud, i);

		pgdp = (pgd_t *)((long)page_to_virt(page_pgd) + offset);
		
		//参考了pgd_populate 中生成pudp的方法
		pgdval = __pgd(__phys_to_pgd_val(page_to_phys(page_pud)) | PUD_TYPE_TABLE);
		
		// pgdval = native_make_pgd((page_to_pfn(page_pud) << PAGE_SHIFT) | pgd_flags(pgdval));
		// printk("PTREP: set_pgd offset=%lx and node0 origin pgd=%lx  and pgd+offset=%lx  and pud=%lx and pdgval=%lx\n",offset,(long)page_to_virt(page_pgd), (long)pgdp, (long)page_to_virt(page_pud),(long)pgd_val(pgdval));
		// printk("PTREP: set_pgd  origin pgdval=%lx  and another func pgdval=%lx\n",(long)pgd_val(pgdval),(long)pgd_val(__pgd(__phys_to_pgd_val(virt_to_phys(page_to_virt(page_pud))) | PUD_TYPE_TABLE)));
		native_set_pgd(pgdp, pgdval);
	}
	// printk("------PTREPL: set_pgd done------\n");
}

// void pgtable_ptep_set_wrprotect(struct mm_struct *mm, unsigned long addr, pte_t *ptep)
// {
// 	int i;
// 	long offset;
// 	struct page *page_pte;

// 	if (unlikely(!pgtable_repl_initialized)) {
// 		return;
// 	}

// 	if (!mm->repl_pgd_enabled) {
// 		return;
// 	}

// 	page_pte = page_of_ptable_entry(ptep);
// 	check_page(page_pte);

// 	if (page_pte->replica == NULL) {
// 		return;
// 	}

// 	offset = ((long)ptep & ~PAGE_MASK);
// 	check_offset(offset);

// 	for (i = 0; i < nr_node_ids; i++) {
// 		page_pte = page_pte->replica;
// 		check_page_node(page_pte, i);

// 		ptep = (pte_t *)((long)page_to_virt(page_pte) + offset);

// 		clear_bit(_PAGE_BIT_RW, (unsigned long *)&ptep->pte);
// 	}
// }
/*
 * ==================================================================
 * Page Table Cache
 * ==================================================================
 */

#define PGALLOC_GFP (GFP_KERNEL | __GFP_ZERO)

int pgtable_cache_populate(size_t numpgtables)
{
	size_t i, j;
	size_t num_nodes = MAX_SUPPORTED_NODE;
	struct page *p;
	nodemask_t nm = NODE_MASK_NONE;

	printk("PGREPL: populating pgtable cache with %zu tables per node\n",
			numpgtables);

	spin_lock(&pgtable_cache_lock);

	if (nr_node_ids < num_nodes) {
		num_nodes = nr_node_ids;
	}

	for (i = 0; i < num_nodes; i++) {

		printk("PGREPL: populating pgtable cache node[%zu] with %zu tables\n",
				i, numpgtables);

		nodes_clear(nm);
		node_set(i, nm);

		for (j = 0; j < numpgtables; j++) {
			/* allocte a new page, and place it in the replica list */
			p = __alloc_pages_nodemask(PGALLOC_GFP, 0, i, &nm);
			if (p) {
				check_page_node(p, i);
				p->replica = pgtable_cache[i];
				pgtable_cache[i] = p;
				pgtable_cache_size[i]++;
			} else {
				break;
			}
		}

		printk("PGREPL: node[%lu] populated with %zu  tables\n",
				i, pgtable_cache_size[i]);

	}

	spin_unlock(&pgtable_cache_lock);

	return 0;
}

int pgtable_cache_drain(void)
{
	int i;
	struct page *p;
	spin_lock(&pgtable_cache_lock);

	for (i = 0; i < MAX_SUPPORTED_NODE; i++) {
		p = pgtable_cache[i];
		while(p) {
			pgtable_cache[i] = p->replica;
			pgtable_cache_size[i]--;
			p->replica = NULL;
			// __free_page(p);
			__free_pages((p), 0);
			p = pgtable_cache[i];

		}
	}

	spin_unlock(&pgtable_cache_lock);

	return 0;
}

struct page *pgtable_cache_alloc(int node)
{
	struct page *p;
	nodemask_t nm;

	if (unlikely(node >= MAX_SUPPORTED_NODE)) {
		panic("PTREPL: WARNING NODE ID %u >= %u. Override to 0 \n",
				node, nr_node_ids);
		node = 0;
	}

	if (pgtable_cache[node] == NULL) {
		nm = NODE_MASK_NONE;
		node_set(node, nm);

		/* allocte a new page, and place it in the replica list */
		p = __alloc_pages_nodemask(PGALLOC_GFP, 0, node, &nm);
		check_page_node(p, node);
		return p;
	}

	spin_lock(&pgtable_cache_lock);
	p = pgtable_cache[node];
	pgtable_cache[node] = p->replica;
	pgtable_cache_size[node]--;
	p->replica = NULL;
	spin_unlock(&pgtable_cache_lock);

	/* need to clear the page */
	clear_page(page_to_virt(p));

	check_page_node(p, node);

	return p;
}

void pgtable_cache_free(int node, struct page *p)
{
	check_page_node(p, node);
	spin_lock(&pgtable_cache_lock);
	/* set the replica to NULL */
	p->replica = NULL;

	p->replica = pgtable_cache[node];
	pgtable_cache[node] = p;
	pgtable_cache_size[node]++;
	spin_unlock(&pgtable_cache_lock);
}

struct page *pgtable_page_alloc(gfp_t gfp_mask,int node)
{
	if(migration_test)
	{
		if (pgtable_fixed_node<0||pgtable_fixed_node>3)
		{
			printk("Mitosis migration node number wrong \n");
			pgtable_fixed_node=0;
		}
		struct page *p;
		nodemask_t nm;

		nm = NODE_MASK_NONE;
		node_set(pgtable_fixed_node, nm);
		p = __alloc_pages_nodemask(gfp_mask, 0, pgtable_fixed_node, &nm);
		if (!p)
		{
			return 0;
		}
		return p;
	}else
	{
		return alloc_page(gfp_mask);
	}
	// check_page_node(p, node);
}
unsigned long pgtable_page_alloc_2(gfp_t gfp_mask,int node)
{
	if(migration_test)
	{
		struct page *p;
		nodemask_t nm;
		if (pgtable_fixed_node<0||pgtable_fixed_node>3)
		{
			printk("Mitosis migration node number wrong \n");
			pgtable_fixed_node=0;
		}
		
		nm = NODE_MASK_NONE;
		node_set(pgtable_fixed_node, nm);
		p = __alloc_pages_nodemask(gfp_mask, 0, pgtable_fixed_node, &nm);
		if (!p)
		{
			return 0;
		}
		return (unsigned long)page_address(p);
	}else
	{
		return (unsigned long)__get_free_page(gfp_mask);
	}
	// check_page_node(p, node);
}
/*
 * ==================================================================
 * Prepare Replication
 * ==================================================================
 */
// #include <linux/sched/task.h>
#define __PHYSICAL_MASK_SHIFT	52
#define __PHYSICAL_MASK		((phys_addr_t)((1ULL << __PHYSICAL_MASK_SHIFT) - 1))
#define PHYSICAL_PAGE_MASK	(((signed long)PAGE_MASK) & __PHYSICAL_MASK)
#define PTE_PFN_MASK		((pteval_t)PHYSICAL_PAGE_MASK)
static inline unsigned long pgd_page_vaddr(pgd_t pgd)
{
	return (unsigned long)__va((unsigned long)pgd_val(pgd) & PTE_PFN_MASK);
}
// static inline unsigned long pud_page_vaddr(pud_t pud)
// {
// 	return (unsigned long)__va(pud_val(pud) & pud_pfn_mask(pud));
// }

//这个函数的作用是，在已经运行的进程中，开启页表复制功能。  那么会遍历已存在的页表，全部进行复制操作。
int pgtbl_repl_prepare_replication(struct mm_struct *mm, nodemask_t nodes)
{
	int err = 0;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	size_t pgd_idx, pud_idx, pmd_idx, pte_idx;
	int pud_num = 0;
	int pmd_num = 0;
	int pte_num = 0;

	/* check if the subsystem is initialized. this should actually be the case */
	if (unlikely(!pgtable_repl_initialized)) {
		panic("PTREPL: %s:%u - subsystem should be enabled by now! \n", __FUNCTION__, __LINE__);
		printk("PTREP: pgtable_repl_initialized = no\n");
	}

	/* if it already has been enbaled, don't do anything */
	if (unlikely(mm->repl_pgd_enabled)) {
		printk("PTREP: already has been enbaled\n");
		return 0;
	}
	printk("PTREP: Called pgtbl_repl_prepare_replication version 2\n");
	pgd = (pgd_t *)mm->pgd;
	task_lock(current);
	spin_lock(&mm->page_table_lock);

	/* we need to talk the page table */
	mm->repl_pgd_nodes = nodes;
	mm->repl_pgd_enabled = true;

	printk("[mitosis] pgtbl_repl_prepare_replication  for mm=%lx.\n",(long)mm);
	/* this will replicate the pgd */
	pgtable_repl_pgd_alloc(mm);
	//	if (!mm->repl_pgd_enabled) {panic("FOOOF");}
		printk("%s:%u pgd=%lx..%lx\n", __FUNCTION__, __LINE__, (long)pgd, (long)pgd + 4095);
	for (pgd_idx = 0; pgd_idx < 512; pgd_idx++) {
		if (pgd_none(pgd[pgd_idx])) {
			continue;
		}
		printk("PTREP: pgd_idx = %ld，and pgd=%lx  and pgd[%ld]=%lx\n",pgd_idx,(long)(pgd + pgd_idx),pgd_idx, (long)pgd_val(pgd[pgd_idx]));
		// pud = (pud_t *)pgd_page_vaddr(pgd[pgd_idx]);  //origin
		pud = (pud_t *)page_to_virt(pgd_page(pgd[pgd_idx])); //first version
		printk("%s:%u pgd[%ld]'s pud=%lx..%lx\n", __FUNCTION__, __LINE__, pgd_idx,(long)pud, (long)pud + 4095);
		
		// pud = (pud_t *)__va(pgd_val(pgd[pgd_idx]));
		//这个换算方法结果时错误的，有偏移// 
		printk("%s:%u another func __va pud=%lx..%lx\n", __FUNCTION__, __LINE__, (long)(pud_t *)__va(__pgd_to_phys(pgd[pgd_idx])), (long)(pud_t *)__va(__pgd_to_phys(pgd[pgd_idx])) + 4095);
		printk("%s:%u 1 pfn=%lx   2 pfn=%lx\n", __FUNCTION__, __LINE__, (long)page_to_pfn(page_of_ptable_entry(pud)), (long)virt_to_pfn(pud));
		pgtable_repl_alloc_pud(mm, (unsigned long)virt_to_pfn(pud));
		//	printk("%s:%u set_p4d(p4d[%zu], 0x%lx, 0x%lx\n",__FUNCTION__, __LINE__,  p4d_idx, _PAGE_TABLE | __pa(pud_new), p4d_val(__p4d(_PAGE_TABLE | __pa(pud_new))));
		// pgtable_repl_set_pgd(pgd + pgd_idx, pgd[pgd_idx]);
		set_pgd(pgd + pgd_idx, pgd[pgd_idx]);
		printk("[mitosis] start search pud .......\n");
		for (pud_idx = 0; pud_idx < 512; pud_idx++) {
			if (pud_none(pud[pud_idx])) {
				continue;
			}
			pud_num++;
			// if (pud_huge(pud[pud_idx])) {
			// 	set_pud(pud + pud_idx, pud[pud_idx]);
			// 	continue;
			// }
			printk("PTREP: pud_idx = %ld，and pud=%lx  and pud[%ld]=%lx\n",pud_idx,(long)(pud + pud_idx),pud_idx, (long)pud_val(pud[pud_idx]));
			//  pmd =  (pmd_t *)pud_page_vaddr(pud[pud_idx]);
			//pmd =  (pmd_t *)page_to_virt(pud_page(pud[pud_idx]));
			pmd =  (pmd_t *)page_to_virt(pud_page(pud[pud_idx]));
			printk("%s:%u pud[%ld]'s pmd=%lx..%lx\n", __FUNCTION__, __LINE__, pud_idx,(long)pmd, (long)pmd + 4095);
			printk("%s:%u 1 pfn=%lx   2 pfn=%lx\n", __FUNCTION__, __LINE__, (long)page_to_pfn(page_of_ptable_entry(pmd)), (long)virt_to_pfn(pmd));
			pgtable_repl_alloc_pmd(mm, (unsigned long)virt_to_pfn(pmd));
			set_pud(pud + pud_idx,pud[pud_idx]);
			// pgtable_repl_set_pud(pud + pud_idx,pud[pud_idx]);

			for (pmd_idx = 0; pmd_idx < 512; pmd_idx++) {

				if (pmd_none(pmd[pmd_idx])) {
					continue;
				}
				pmd_num++;
				// if (pmd_huge(pmd[pmd_idx])) {
				// 	set_pmd(pmd + pmd_idx, pmd[pmd_idx]);
				// 	continue;
				// }
				printk("PTREP: pmd_idx = %ld，and pmd=%lx  and pmd[%ld]=%lx\n",pmd_idx,(long)(pmd + pmd_idx),pmd_idx, (long)pmd_val(pmd[pmd_idx]));
				/* get the pte page */
				//  pte = (pte_t *)pmd_page_vaddr(pmd[pmd_idx]);
				pte = (pte_t *)page_to_virt(pmd_page(pmd[pmd_idx]));
				printk("%s:%u pmd[%ld]'s pte=%lx..%lx\n", __FUNCTION__, __LINE__, pmd_idx,(long)pte, (long)pte + 4095);
				printk("%s:%u 1 pfn=%lx   2 pfn=%lx\n", __FUNCTION__, __LINE__, (long)page_to_pfn(page_of_ptable_entry(pte)), (long)virt_to_pfn(pte));

				pgtable_repl_alloc_pte(mm, page_to_pfn(page_of_ptable_entry(pte)));
				// pgtable_repl_set_pmd(pmd + pmd_idx, pmd[pmd_idx]);
				set_pmd(pmd + pmd_idx, pmd[pmd_idx]);

				for (pte_idx = 0; pte_idx < 512; pte_idx++) {
					if (pte_none(pte[pte_idx])) {
						continue;
					}
					pte_num++;
					// if (pte_num<10)
					// {
					// 	printk("PTREP: pte_idx = %ld，and pte=%lx  and pte[%ld]=%lx\n",pte_idx,(long)(pte + pte_idx),pte_idx, (long)pte_val(pte[pte_idx]));
					// 	pgtable_repl_set_pte_with_log(pte + pte_idx, pte[pte_idx]);
					// }
					// else
					// {
						// pgtable_repl_set_pte(pte + pte_idx, pte[pte_idx]);
					// }
					set_pte(pte + pte_idx, pte[pte_idx]);				
				}
			}
		}
		printk("===================================== end of a page\n");
	}
	printk("%s:%u all: pud_num=%d, pmd_num=%d, pte_num=%d\n", __FUNCTION__, __LINE__, pud_num, pmd_num,pte_num);
	spin_unlock(&mm->page_table_lock);
	task_unlock(current);
	if (err) {
		mm->repl_pgd_enabled = false;
		printk("PGREPL: DISABLE MITOSIS DUE TO ERROR\n");

	}
	
	unsigned int cpu = smp_processor_id();
	check_and_switch_context(mm, cpu);
	// cpu_switch_mm(mm->pgd, mm);
	// cpu_do_switch_mm(mm->pgd,mm);
	// cpu_set_reserved_ttbr0();
	// local_flush_tlb_all();
	// cpu_set_default_tcr_t0sz();

	// if (mm != &init_mm && !system_uses_ttbr0_pan())
	// {
	// 	cpu_switch_mm(mm->pgd, mm);
	// }
		
	// pgtable_repl_write_cr3(__native_read_cr3());
	printk("PTREP: Called pgtbl_repl_prepare_replication  done\n");
	return err;
}

int pgtbl_repl_prepare_replication_for_autoconfig(struct mm_struct *mm, nodemask_t nodes)
{
	int err = 0;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	size_t pgd_idx, pud_idx, pmd_idx, pte_idx;
	int pud_num = 0;
	int pmd_num = 0;
	int pte_num = 0;
	
	// mm = newtask->mm;
	pgtable_repl_custom_activated = true;
	pgtable_repl_initialized = true;

	if (mm->repl_pgd_enabled) {
		printk("[mitosis] NOTE: pgtable replication already enabled...\n");
		return 0;
	}


	/* check if the subsystem is initialized. this should actually be the case */
	if (unlikely(!pgtable_repl_initialized)) {
		panic("PTREPL: %s:%u - subsystem should be enabled by now! \n", __FUNCTION__, __LINE__);
		printk("PTREP: pgtable_repl_initialized = no\n");
	}

	/* if it already has been enbaled, don't do anything */
	if (unlikely(mm->repl_pgd_enabled)) {
		printk("PTREP: already has been enbaled\n");
		return 0;
	}
	printk("PTREP: Called pgtbl_repl_prepare_replication version 2\n");
	spin_lock(&mm->page_table_lock);
	pgd = (pgd_t *)mm->pgd;

	/* we need to talk the page table */
	mm->repl_pgd_nodes = nodes;
	mm->repl_pgd_enabled = true;

	printk("[mitosis] pgtbl_repl_prepare_replication  for mm=%lx.\n",(long)mm);
	/* this will replicate the pgd */
	pgtable_repl_pgd_alloc(mm);
	//	if (!mm->repl_pgd_enabled) {panic("FOOOF");}
		printk("%s:%u pgd=%lx..%lx\n", __FUNCTION__, __LINE__, (long)pgd, (long)pgd + 4095);
	for (pgd_idx = 0; pgd_idx < 512; pgd_idx++) {
		if (pgd_none(pgd[pgd_idx])) {
			continue;
		}
		printk("PTREP: pgd_idx = %ld，and pgd=%lx  and pgd[%ld]=%lx\n",pgd_idx,(long)(pgd + pgd_idx),pgd_idx, (long)pgd_val(pgd[pgd_idx]));
		// pud = (pud_t *)pgd_page_vaddr(pgd[pgd_idx]);  //origin
		pud = (pud_t *)page_to_virt(pgd_page(pgd[pgd_idx])); //first version
		printk("%s:%u pgd[%ld]'s pud=%lx..%lx\n", __FUNCTION__, __LINE__, pgd_idx,(long)pud, (long)pud + 4095);
		
		// pud = (pud_t *)__va(pgd_val(pgd[pgd_idx]));
		//这个换算方法结果时错误的，有偏移// 
		printk("%s:%u another func __va pud=%lx..%lx\n", __FUNCTION__, __LINE__, (long)(pud_t *)__va(__pgd_to_phys(pgd[pgd_idx])), (long)(pud_t *)__va(__pgd_to_phys(pgd[pgd_idx])) + 4095);
		printk("%s:%u 1 pfn=%lx   2 pfn=%lx\n", __FUNCTION__, __LINE__, (long)page_to_pfn(page_of_ptable_entry(pud)), (long)virt_to_pfn(pud));
		pgtable_repl_alloc_pud(mm, (unsigned long)virt_to_pfn(pud));
		//	printk("%s:%u set_p4d(p4d[%zu], 0x%lx, 0x%lx\n",__FUNCTION__, __LINE__,  p4d_idx, _PAGE_TABLE | __pa(pud_new), p4d_val(__p4d(_PAGE_TABLE | __pa(pud_new))));
		// pgtable_repl_set_pgd(pgd + pgd_idx, pgd[pgd_idx]);
		set_pgd(pgd + pgd_idx, pgd[pgd_idx]);
		printk("[mitosis] start search pud .......\n");
		for (pud_idx = 0; pud_idx < 512; pud_idx++) {
			if (pud_none(pud[pud_idx])) {
				continue;
			}
			pud_num++;
			// if (pud_huge(pud[pud_idx])) {
			// 	set_pud(pud + pud_idx, pud[pud_idx]);
			// 	continue;
			// }
			printk("PTREP: pud_idx = %ld，and pud=%lx  and pud[%ld]=%lx\n",pud_idx,(long)(pud + pud_idx),pud_idx, (long)pud_val(pud[pud_idx]));
			//  pmd =  (pmd_t *)pud_page_vaddr(pud[pud_idx]);
			//pmd =  (pmd_t *)page_to_virt(pud_page(pud[pud_idx]));
			pmd =  (pmd_t *)page_to_virt(pud_page(pud[pud_idx]));
			printk("%s:%u pud[%ld]'s pmd=%lx..%lx\n", __FUNCTION__, __LINE__, pud_idx,(long)pmd, (long)pmd + 4095);
			printk("%s:%u 1 pfn=%lx   2 pfn=%lx\n", __FUNCTION__, __LINE__, (long)page_to_pfn(page_of_ptable_entry(pmd)), (long)virt_to_pfn(pmd));
			pgtable_repl_alloc_pmd(mm, (unsigned long)virt_to_pfn(pmd));
			set_pud(pud + pud_idx,pud[pud_idx]);
			// pgtable_repl_set_pud(pud + pud_idx,pud[pud_idx]);

			for (pmd_idx = 0; pmd_idx < 512; pmd_idx++) {

				if (pmd_none(pmd[pmd_idx])) {
					continue;
				}
				pmd_num++;
				// if (pmd_huge(pmd[pmd_idx])) {
				// 	set_pmd(pmd + pmd_idx, pmd[pmd_idx]);
				// 	continue;
				// }
				printk("PTREP: pmd_idx = %ld，and pmd=%lx  and pmd[%ld]=%lx\n",pmd_idx,(long)(pmd + pmd_idx),pmd_idx, (long)pmd_val(pmd[pmd_idx]));
				/* get the pte page */
				//  pte = (pte_t *)pmd_page_vaddr(pmd[pmd_idx]);
				pte = (pte_t *)page_to_virt(pmd_page(pmd[pmd_idx]));
				printk("%s:%u pmd[%ld]'s pte=%lx..%lx\n", __FUNCTION__, __LINE__, pmd_idx,(long)pte, (long)pte + 4095);
				printk("%s:%u 1 pfn=%lx   2 pfn=%lx\n", __FUNCTION__, __LINE__, (long)page_to_pfn(page_of_ptable_entry(pte)), (long)virt_to_pfn(pte));

				pgtable_repl_alloc_pte(mm, page_to_pfn(page_of_ptable_entry(pte)));
				// pgtable_repl_set_pmd(pmd + pmd_idx, pmd[pmd_idx]);
				set_pmd(pmd + pmd_idx, pmd[pmd_idx]);

				for (pte_idx = 0; pte_idx < 512; pte_idx++) {
					if (pte_none(pte[pte_idx])) {
						continue;
					}
					pte_num++;
					// if (pte_num<10)
					// {
					// 	printk("PTREP: pte_idx = %ld，and pte=%lx  and pte[%ld]=%lx\n",pte_idx,(long)(pte + pte_idx),pte_idx, (long)pte_val(pte[pte_idx]));
					// 	pgtable_repl_set_pte_with_log(pte + pte_idx, pte[pte_idx]);
					// }
					// else
					// {
						// pgtable_repl_set_pte(pte + pte_idx, pte[pte_idx]);
					// }
					set_pte(pte + pte_idx, pte[pte_idx]);				
				}
			}
		}
		printk("===================================== end of a page\n");
	}
	printk("%s:%u all: pud_num=%d, pmd_num=%d, pte_num=%d\n", __FUNCTION__, __LINE__, pud_num, pmd_num,pte_num);
	spin_unlock(&mm->page_table_lock);
	// task_unlock(newtask);
	// if (err) {
	// 	mm->repl_pgd_enabled = false;
	// 	printk("PGREPL: DISABLE MITOSIS DUE TO ERROR\n");

	// }
	
	// unsigned int cpu = smp_processor_id();
	// check_and_switch_context(mm, cpu);
	
	printk("PTREP: Called pgtbl_repl_prepare_replication  done\n");
	return err;
}
// int pgtbl_repl_prepare_replication_for_autoconfig(struct task_struct *newtask, nodemask_t nodes)
// {
// 	int err = 0;
// 	pgd_t *pgd;
// 	pud_t *pud;
// 	pmd_t *pmd;
// 	pte_t *pte;
// 	size_t pgd_idx, pud_idx, pmd_idx, pte_idx;
// 	int pud_num = 0;
// 	int pmd_num = 0;
// 	int pte_num = 0;
// 	struct mm_struct *mm;
	
// 	task_lock(newtask);
	
// 	// mm = newtask->mm;

// 	// if (mm->repl_pgd_enabled) {
			

// 	// 		printk("[mitosis] NOTE: pgtable replication already enabled...\n");

// 	// 		return 0;
// 	// }


// 	// /* check if the subsystem is initialized. this should actually be the case */
// 	// if (unlikely(!pgtable_repl_initialized)) {
// 	// 	panic("PTREPL: %s:%u - subsystem should be enabled by now! \n", __FUNCTION__, __LINE__);
// 	// 	printk("PTREP: pgtable_repl_initialized = no\n");
// 	// }

// 	// /* if it already has been enbaled, don't do anything */
// 	// if (unlikely(mm->repl_pgd_enabled)) {
// 	// 	printk("PTREP: already has been enbaled\n");
// 	// 	return 0;
// 	// }
// 	// printk("PTREP: Called pgtbl_repl_prepare_replication version 2\n");
// 	// spin_lock(&mm->page_table_lock);
// 	// pgd = (pgd_t *)mm->pgd;

// 	// /* we need to talk the page table */
// 	// mm->repl_pgd_nodes = nodes;
// 	// mm->repl_pgd_enabled = true;

// 	// printk("[mitosis] pgtbl_repl_prepare_replication  for mm=%lx.\n",(long)mm);
// 	// /* this will replicate the pgd */
// 	// pgtable_repl_pgd_alloc(mm);
// 	// //	if (!mm->repl_pgd_enabled) {panic("FOOOF");}
// 	// 	printk("%s:%u pgd=%lx..%lx\n", __FUNCTION__, __LINE__, (long)pgd, (long)pgd + 4095);
// 	// for (pgd_idx = 0; pgd_idx < 512; pgd_idx++) {
// 	// 	if (pgd_none(pgd[pgd_idx])) {
// 	// 		continue;
// 	// 	}
// 	// 	printk("PTREP: pgd_idx = %ld，and pgd=%lx  and pgd[%ld]=%lx\n",pgd_idx,(long)(pgd + pgd_idx),pgd_idx, (long)pgd_val(pgd[pgd_idx]));
// 	// 	// pud = (pud_t *)pgd_page_vaddr(pgd[pgd_idx]);  //origin
// 	// 	pud = (pud_t *)page_to_virt(pgd_page(pgd[pgd_idx])); //first version
// 	// 	printk("%s:%u pgd[%ld]'s pud=%lx..%lx\n", __FUNCTION__, __LINE__, pgd_idx,(long)pud, (long)pud + 4095);
		
// 	// 	// pud = (pud_t *)__va(pgd_val(pgd[pgd_idx]));
// 	// 	//这个换算方法结果时错误的，有偏移// 
// 	// 	printk("%s:%u another func __va pud=%lx..%lx\n", __FUNCTION__, __LINE__, (long)(pud_t *)__va(__pgd_to_phys(pgd[pgd_idx])), (long)(pud_t *)__va(__pgd_to_phys(pgd[pgd_idx])) + 4095);
// 	// 	printk("%s:%u 1 pfn=%lx   2 pfn=%lx\n", __FUNCTION__, __LINE__, (long)page_to_pfn(page_of_ptable_entry(pud)), (long)virt_to_pfn(pud));
// 	// 	pgtable_repl_alloc_pud(mm, (unsigned long)virt_to_pfn(pud));
// 	// 	//	printk("%s:%u set_p4d(p4d[%zu], 0x%lx, 0x%lx\n",__FUNCTION__, __LINE__,  p4d_idx, _PAGE_TABLE | __pa(pud_new), p4d_val(__p4d(_PAGE_TABLE | __pa(pud_new))));
// 	// 	// pgtable_repl_set_pgd(pgd + pgd_idx, pgd[pgd_idx]);
// 	// 	set_pgd(pgd + pgd_idx, pgd[pgd_idx]);
// 	// 	printk("[mitosis] start search pud .......\n");
// 	// 	for (pud_idx = 0; pud_idx < 512; pud_idx++) {
// 	// 		if (pud_none(pud[pud_idx])) {
// 	// 			continue;
// 	// 		}
// 	// 		pud_num++;
// 	// 		// if (pud_huge(pud[pud_idx])) {
// 	// 		// 	set_pud(pud + pud_idx, pud[pud_idx]);
// 	// 		// 	continue;
// 	// 		// }
// 	// 		printk("PTREP: pud_idx = %ld，and pud=%lx  and pud[%ld]=%lx\n",pud_idx,(long)(pud + pud_idx),pud_idx, (long)pud_val(pud[pud_idx]));
// 	// 		//  pmd =  (pmd_t *)pud_page_vaddr(pud[pud_idx]);
// 	// 		//pmd =  (pmd_t *)page_to_virt(pud_page(pud[pud_idx]));
// 	// 		pmd =  (pmd_t *)page_to_virt(pud_page(pud[pud_idx]));
// 	// 		printk("%s:%u pud[%ld]'s pmd=%lx..%lx\n", __FUNCTION__, __LINE__, pud_idx,(long)pmd, (long)pmd + 4095);
// 	// 		printk("%s:%u 1 pfn=%lx   2 pfn=%lx\n", __FUNCTION__, __LINE__, (long)page_to_pfn(page_of_ptable_entry(pmd)), (long)virt_to_pfn(pmd));
// 	// 		pgtable_repl_alloc_pmd(mm, (unsigned long)virt_to_pfn(pmd));
// 	// 		set_pud(pud + pud_idx,pud[pud_idx]);
// 	// 		// pgtable_repl_set_pud(pud + pud_idx,pud[pud_idx]);

// 	// 		for (pmd_idx = 0; pmd_idx < 512; pmd_idx++) {

// 	// 			if (pmd_none(pmd[pmd_idx])) {
// 	// 				continue;
// 	// 			}
// 	// 			pmd_num++;
// 	// 			// if (pmd_huge(pmd[pmd_idx])) {
// 	// 			// 	set_pmd(pmd + pmd_idx, pmd[pmd_idx]);
// 	// 			// 	continue;
// 	// 			// }
// 	// 			printk("PTREP: pmd_idx = %ld，and pmd=%lx  and pmd[%ld]=%lx\n",pmd_idx,(long)(pmd + pmd_idx),pmd_idx, (long)pmd_val(pmd[pmd_idx]));
// 	// 			/* get the pte page */
// 	// 			//  pte = (pte_t *)pmd_page_vaddr(pmd[pmd_idx]);
// 	// 			pte = (pte_t *)page_to_virt(pmd_page(pmd[pmd_idx]));
// 	// 			printk("%s:%u pmd[%ld]'s pte=%lx..%lx\n", __FUNCTION__, __LINE__, pmd_idx,(long)pte, (long)pte + 4095);
// 	// 			printk("%s:%u 1 pfn=%lx   2 pfn=%lx\n", __FUNCTION__, __LINE__, (long)page_to_pfn(page_of_ptable_entry(pte)), (long)virt_to_pfn(pte));

// 	// 			pgtable_repl_alloc_pte(mm, page_to_pfn(page_of_ptable_entry(pte)));
// 	// 			// pgtable_repl_set_pmd(pmd + pmd_idx, pmd[pmd_idx]);
// 	// 			set_pmd(pmd + pmd_idx, pmd[pmd_idx]);

// 	// 			for (pte_idx = 0; pte_idx < 512; pte_idx++) {
// 	// 				if (pte_none(pte[pte_idx])) {
// 	// 					continue;
// 	// 				}
// 	// 				pte_num++;
// 	// 				// if (pte_num<10)
// 	// 				// {
// 	// 				// 	printk("PTREP: pte_idx = %ld，and pte=%lx  and pte[%ld]=%lx\n",pte_idx,(long)(pte + pte_idx),pte_idx, (long)pte_val(pte[pte_idx]));
// 	// 				// 	pgtable_repl_set_pte_with_log(pte + pte_idx, pte[pte_idx]);
// 	// 				// }
// 	// 				// else
// 	// 				// {
// 	// 					// pgtable_repl_set_pte(pte + pte_idx, pte[pte_idx]);
// 	// 				// }
// 	// 				set_pte(pte + pte_idx, pte[pte_idx]);				
// 	// 			}
// 	// 		}
// 	// 	}
// 	// 	printk("===================================== end of a page\n");
// 	// }
// 	// printk("%s:%u all: pud_num=%d, pmd_num=%d, pte_num=%d\n", __FUNCTION__, __LINE__, pud_num, pmd_num,pte_num);
// 	// spin_unlock(&mm->page_table_lock);
// 	task_unlock(newtask);
// 	// if (err) {
// 	// 	mm->repl_pgd_enabled = false;
// 	// 	printk("PGREPL: DISABLE MITOSIS DUE TO ERROR\n");

// 	// }
	
// 	// unsigned int cpu = smp_processor_id();
// 	// check_and_switch_context(mm, cpu);
	
// 	printk("PTREP: Called pgtbl_repl_prepare_replication  done\n");
// 	return err;
// }
/*
 * procfs control files
 */
#ifdef CONFIG_PROC_SYSCTL
#include <linux/capability.h>
#include <linux/sysctl.h>
#ifdef CONFIG_Migration_test //迁移测试
int sysctl_numa_pgtable_replication(struct ctl_table *table, int write, void __user *buffer,
                                    size_t *lenp, loff_t *ppos)
{
	struct ctl_table t;
	int err;
	int state = (pgtable_repl_activated ? 1 : pgtable_fixed_node);

	if (write && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	t = *table;
	t.data = &state;
	err = proc_dointvec_minmax(&t, write, buffer, lenp, ppos);
	if (err < 0)
		return err;
	if (write) {
		printk("Page table CONFIG_Migration_test\n");
		if (state == -1) {
			/* the default behavior */
			migration_test = false;
			printk("Page table allocation set to normal behavior -1\n");
			pgtable_repl_custom_activated = false;
			pgtable_repl_activated = false;
			pgtable_fixed_node = -1;
			pgtable_fixed_nodemask = NODE_MASK_NONE;
		} else if (state == -2) {
			if (migration_test)
			{
				printk("Page table CONFIG_Migration_test is true\n");
			}else
			{
				printk("Page table CONFIG_Migration_test is false\n");
			}
		} else if (state == -3) {
			migration_test = true;
			printk("Page table allocation set to normal behavior -3\n");
			pgtable_repl_custom_activated = false;
			pgtable_repl_activated = false;
			pgtable_fixed_node = 0;
			pgtable_fixed_nodemask = NODE_MASK_NONE;
			node_set(pgtable_fixed_node, pgtable_fixed_nodemask);
		} else if (state == -4) {
			migration_test = true;
			printk("Page table allocation set to normal behavior -4\n");
			pgtable_repl_custom_activated = false;
			pgtable_repl_activated = false;
			pgtable_fixed_node = 1;
			pgtable_fixed_nodemask = NODE_MASK_NONE;
			node_set(pgtable_fixed_node, pgtable_fixed_nodemask);
		} else if (state == -5) {
			migration_test = true;
			printk("Page table allocation set to normal behavior -5\n");
			pgtable_repl_custom_activated = false;
			pgtable_repl_activated = false;
			pgtable_fixed_node = 2;
			pgtable_fixed_nodemask = NODE_MASK_NONE;
			node_set(pgtable_fixed_node, pgtable_fixed_nodemask);
		} else if (state == -6) {
			migration_test = true;
			printk("Page table allocation set to normal behavior -6\n");
			pgtable_repl_custom_activated = false;
			pgtable_repl_activated = false;
			pgtable_fixed_node = 3;
			pgtable_fixed_nodemask = NODE_MASK_NONE;
			node_set(pgtable_fixed_node, pgtable_fixed_nodemask);
		} else if (state == 0) {
			/* fixed on node 0 */
			migration_test = true;
			printk("Page table allocation set to fixed on node 0\n");
			pgtable_repl_custom_activated = true;
			pgtable_repl_activated = false;
			pgtable_fixed_node = 0;
			pgtable_fixed_nodemask = NODE_MASK_NONE;
			node_set(pgtable_fixed_node, pgtable_fixed_nodemask);
		} else {
			/* replication enabled */
			printk("Page table allocation set to replicated\n");
			pgtable_repl_custom_activated = true;
			pgtable_repl_activated = false;
			pgtable_fixed_node = state;
			pgtable_fixed_nodemask = NODE_MASK_NONE;
			node_set(pgtable_fixed_node, pgtable_fixed_nodemask);
		}
	}
	return err;
}		
#else
		//正常测试
	int sysctl_numa_pgtable_replication(struct ctl_table *table, int write, void __user *buffer,
                                    size_t *lenp, loff_t *ppos)
{
	struct ctl_table t;
	int err;
	int state = (pgtable_repl_activated ? 1 : pgtable_fixed_node);

	if (write && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	t = *table;
	t.data = &state;
	err = proc_dointvec_minmax(&t, write, buffer, lenp, ppos);
	if (err < 0)
		return err;
	if (write) {
		if (state == -1) {
			/* the default behavior */
			printk("Page table allocation set to normal behavior\n");
			pgtable_repl_custom_activated = false;
			pgtable_repl_activated = false;
			pgtable_fixed_node = -1;
			pgtable_fixed_nodemask = NODE_MASK_NONE;
		} else if (state == 0) {
			/* fixed on node 0 */
			migration_test = true;
			printk("Page table allocation set to fixed on node 0\n");
			pgtable_repl_custom_activated = true;
			pgtable_repl_activated = false;
			pgtable_fixed_node = 0;
			pgtable_fixed_nodemask = NODE_MASK_NONE;
			node_set(pgtable_fixed_node, pgtable_fixed_nodemask);
		} else {
			/* replication enabled */
			printk("Page table allocation set to replicated\n");
			pgtable_repl_custom_activated = true;
			pgtable_repl_activated = true;
			pgtable_fixed_node = 0;
			pgtable_fixed_nodemask = NODE_MASK_NONE;
			node_set(pgtable_fixed_node, pgtable_fixed_nodemask);
		}
	}
	return err;
}	
#endif



int sysctl_numa_pgtable_replication_cache_ctl(struct ctl_table *table, int write, void __user *buffer,
                                              size_t *lenp, loff_t *ppos)
{
	struct ctl_table t;
	int err;
	int state = 0;

	if (write && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	t = *table;
	t.data = &state;
	err = proc_dointvec_minmax(&t, write, buffer, lenp, ppos);
	if (err < 0)
		return err;
	if (write) {
		if (state < 0) {
			/* the default behavior */
			printk("PROCFS: Command ot drain the pgtable cache\n");
			pgtable_cache_drain();
		} else if (state > 0) {
			printk("PROCFS: Command ot populate the pgtable cache\n");
			pgtable_cache_populate(state);
		}
	}
	return err;
}
#endif /* CONFIG_PROC_SYSCTL */

//#include <linux/topology.h>
//extern int ptrepl_numa_node_id(void);

pgd_t *mm_get_pgd_for_node(struct mm_struct *mm)
{
	pgd_t *pgd;
	pgd = mm->repl_pgd[numa_node_id()];
	return (pgd != NULL ? pgd : mm->pgd);
}


#endif /* CONFIG_PGTABLE_REPLICATION */