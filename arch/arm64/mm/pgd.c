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
		return 0;
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

	if (unlikely(!pgtable_repl_initialized)) {
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

	p2 = p;
	// int previusly_pgd_node = pfn_to_nid(pfn);
	for (i = 0; i < nr_node_ids; i++) {
		// //分配原始pgd的节点就不要复制新pgd了
		// if(i == previusly_pgd_node)
		// {
		// 	continue;
		// }
		/* allocte a new page, and place it in the replica list */
		p2->replica  = pgtable_cache_alloc(i);
		if (p2->replica == NULL) {
			goto cleanup;
		}

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
	#if 0
	p2 = p->replica;
	for (i = 0; i < nr_node_ids; i++) {
		printk("page: %lx", (long)p2);
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
	if (unlikely(!pgtable_repl_initialized)) {
		return;
	}
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


void pgtable_repl_alloc_pte(struct mm_struct *mm, unsigned long pfn)
{
	__pgtable_repl_alloc_one(mm, pfn);
}

void pgtable_repl_alloc_pmd(struct mm_struct *mm, unsigned long pfn)
{
	__pgtable_repl_alloc_one(mm, pfn);
}

void pgtable_repl_alloc_pud(struct mm_struct *mm, unsigned long pfn)
{
	__pgtable_repl_alloc_one(mm, pfn);
}

void pgtable_repl_release_pte(unsigned long pfn)
{
	__pgtable_repl_release_one(pfn);
}

void pgtable_repl_release_pmd(unsigned long pfn)
{
	__pgtable_repl_release_one(pfn);
}

void pgtable_repl_release_pud(unsigned long pfn)
{
	__pgtable_repl_release_one(pfn);
}

/*
 * ===============================================================================
 * Set Page Table Entries
 * ===============================================================================
 */


void pgtable_repl_set_pte(pte_t *ptep, pte_t pteval)
{
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

	offset = (long)ptep - (long)page_to_virt(page_pte);
	check_offset(offset);

	for (i = 0; i < nr_node_ids; i++) {
		page_pte = page_pte->replica;
		check_page_node(page_pte, i);

		ptep = (pte_t *)((long)page_to_virt(page_pte) + offset);
		native_set_pte(ptep, pteval);
	}
}


void pgtable_repl_set_pte_at(struct mm_struct *mm, unsigned long addr,
							 pte_t *ptep, pte_t pteval)
{
	pgtable_repl_set_pte(ptep, pteval);
}

static inline pmd_t native_make_pmd(pmdval_t val)
{
	return (pmd_t) { val };
}

void pgtable_repl_set_pmd(pmd_t *pmdp, pmd_t pmdval)
{
	int i;
	long offset;
	struct page *page_pmd, *page_pte;

	if (unlikely(!pgtable_repl_initialized)) {
		return;
	}

	page_pmd = page_of_ptable_entry(pmdp);
	check_page(page_pmd);

	if (page_pmd->replica == NULL) {
		return;
	}

	page_pte = pmd_page(pmdval);

	offset = ((long)pmdp & ~PAGE_MASK);
	check_offset(offset);

	/* the entry is a large entry i.e. pointing to a frame, or the entry is not valid */
	if (!page_pte || pmd_none(pmdval) || !pmd_present(pmdval)) {
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
		native_set_pmd(pmdp, pmdval);
	}
}

// static inline pud_t native_make_pud(pmdval_t val)
// {
// 	return (pud_t) { val };
// }
void pgtable_repl_set_pud(pud_t *pudp, pud_t pudval)
{
	int i;
	long offset;
	struct page *page_pud, *page_pmd;

	if (unlikely(!pgtable_repl_initialized)) {
		return;
	}

	page_pud = page_of_ptable_entry(pudp);
	check_page(page_pud);

	if (page_pud->replica == NULL) {
		return;
	}

	offset = ((long)pudp & ~PAGE_MASK);
	check_offset(offset);

	page_pmd = pud_page(pudval);

	/* there is no age for this entry or the entry is huge or the entry is not present */
	if (!page_pmd || !pud_present(pudval) || pud_none(pudval)) {
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
		native_set_pud(pudp, pudval);
	}
}

void pgtable_repl_set_pgd(pgd_t *pgdp, pgd_t pgdval)
{
	// panic("PTREPL: %s:%d:  not yet implemented by Mitosis\n", __FUNCTION__, __LINE__);
	int i;
	long offset;
	struct page *page_pgd, *page_pud;

	if (unlikely(!pgtable_repl_initialized)) {
		return;
	}

	page_pgd = page_of_ptable_entry(pgdp);
	check_page(page_pgd);

	if (page_pgd->replica == NULL) {
		return;
	}
	//取出pgdp 在pgd 中的偏移 offset
	offset = ((long)pgdp & ~PAGE_MASK);
	check_offset(offset);

	page_pud = pgd_page(pgdval);
	//如果pud 的page 还没有被放入内存中，那么就直接把pgdval这个地址值设置到各节点的副本pgd表中。
	if (!page_pud || pgd_none(pgdval) || !pgd_present(pgdval)) {
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
		native_set_pgd(pgdp, pgdval);
	}
}

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


	/* check if the subsystem is initialized. this should actually be the case */
	if (unlikely(!pgtable_repl_initialized)) {
		panic("PTREPL: %s:%u - subsystem should be enabled by now! \n", __FUNCTION__, __LINE__);
	}

	/* if it already has been enbaled, don't do anything */
	if (unlikely(mm->repl_pgd_enabled)) {
		return 0;
	}

	pgd = (pgd_t *)mm->pgd;
	task_lock(current);
	spin_lock(&mm->page_table_lock);

	/* we need to talk the page table */
	mm->repl_pgd_nodes = nodes;
	mm->repl_pgd_enabled = true;


	/* this will replicate the pgd */
	pgtable_repl_pgd_alloc(mm);
	//	if (!mm->repl_pgd_enabled) {panic("FOOOF");}
	//	printk("%s:%u p4d=%lx..%lx\n", __FUNCTION__, __LINE__, (long)p4d, (long)p4d + 4095);
	for (pgd_idx = 0; pgd_idx < 512; pgd_idx++) {
		if (pgd_none(pgd[pgd_idx])) {
			continue;
		}

		// pud = (pud_t *)pgd_page_vaddr(pgd[pgd_idx]);
		pud = (pud_t *)page_to_virt(pgd_page(pgd[pgd_idx]));
	
		pgtable_repl_alloc_pud(mm, page_to_pfn(page_of_ptable_entry(pud)));
		//	printk("%s:%u set_p4d(p4d[%zu], 0x%lx, 0x%lx\n",__FUNCTION__, __LINE__,  p4d_idx, _PAGE_TABLE | __pa(pud_new), p4d_val(__p4d(_PAGE_TABLE | __pa(pud_new))));
		set_pgd(pgd + pgd_idx, pgd[pgd_idx]);

		for (pud_idx = 0; pud_idx < 512; pud_idx++) {
			if (pud_none(pud[pud_idx])) {
				continue;
			}

			// if (pud_huge(pud[pud_idx])) {
			// 	set_pud(pud + pud_idx, pud[pud_idx]);
			// 	continue;
			// }

			//  pmd =  (pmd_t *)pud_page_vaddr(pud[pud_idx]);
			pmd =  (pmd_t *)page_to_virt(pud_page(pud[pud_idx]));
			 
			pgtable_repl_alloc_pmd(mm, page_to_pfn(page_of_ptable_entry(pmd)));
			set_pud(pud + pud_idx,pud[pud_idx]);

			for (pmd_idx = 0; pmd_idx < 512; pmd_idx++) {

				if (pmd_none(pmd[pmd_idx])) {
					continue;
				}

				// if (pmd_huge(pmd[pmd_idx])) {
				// 	set_pmd(pmd + pmd_idx, pmd[pmd_idx]);
				// 	continue;
				// }

				/* get the pte page */
				//  pte = (pte_t *)pmd_page_vaddr(pmd[pmd_idx]);
				pte = (pte_t *)page_to_virt(pmd_page(pmd[pmd_idx]));

				pgtable_repl_alloc_pte(mm, page_to_pfn(page_of_ptable_entry(pte)));

				set_pmd(pmd + pmd_idx, pmd[pmd_idx]);

				for (pte_idx = 0; pte_idx < 512; pte_idx++) {
					if (pte_none(pte[pte_idx])) {
						continue;
					}
					set_pte(pte + pte_idx, pte[pte_idx]);
				}
			}
		}
	}

	spin_unlock(&mm->page_table_lock);
	task_unlock(current);
	if (err) {
		mm->repl_pgd_enabled = false;
		printk("PGREPL: DISABLE MITOSIS DUE TO ERROR\n");

	}
	// cpu_do_switch_mm(mm->pgd,mm);
	cpu_switch_mm(mm->pgd,mm);
	// pgtable_repl_write_cr3(__native_read_cr3());
	return err;
}

/*
 * procfs control files
 */
#ifdef CONFIG_PROC_SYSCTL
#include <linux/capability.h>
#include <linux/sysctl.h>
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
			pgtable_repl_activated = false;
			pgtable_fixed_node = -1;
			pgtable_fixed_nodemask = NODE_MASK_NONE;
		} else if (state == 0) {
			/* fixed on node 0 */
			printk("Page table allocation set to fixed on node 0\n");
			pgtable_repl_activated = false;
			pgtable_fixed_node = 0;
			pgtable_fixed_nodemask = NODE_MASK_NONE;
			node_set(pgtable_fixed_node, pgtable_fixed_nodemask);
		} else {
			/* replication enabled */
			printk("Page table allocation set to replicated\n");
			pgtable_repl_initialized = true;
			pgtable_repl_activated = true;
			pgtable_fixed_node = 0;
			pgtable_fixed_nodemask = NODE_MASK_NONE;
			node_set(pgtable_fixed_node, pgtable_fixed_nodemask);
		}
	}
	return err;
}


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