/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Based on arch/arm/include/asm/pgalloc.h
 *
 * Copyright (C) 2000-2001 Russell King
 * Copyright (C) 2012 ARM Ltd.
 */
#ifndef __ASM_PGALLOC_H
#define __ASM_PGALLOC_H

#include <asm/pgtable-hwdef.h>
#include <asm/processor.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>

#include <asm-generic/pgalloc.h>	/* for pte_{alloc,free}_one */

#define PGD_SIZE	(PTRS_PER_PGD * sizeof(pgd_t))

#if CONFIG_PGTABLE_LEVELS > 2

static inline pmd_t *pmd_alloc_one(struct mm_struct *mm, unsigned long addr)
{
	gfp_t gfp = GFP_PGTABLE_USER;
	struct page *page;

	if (mm == &init_mm)
		gfp = GFP_PGTABLE_KERNEL;

	// page = alloc_page(gfp);
	#ifdef CONFIG_PGTABLE_REPLICATION

	#ifdef CONFIG_Migration_test //迁移测试
	page = pgtable_page_alloc(gfp,0);
	#else
	//正常测试
	page = alloc_page(gfp);
	#endif
	
	
	// page->replica_node_id = -1;
	pgtable_repl_alloc_pmd(mm, page_to_pfn(page));
	#endif
	if (!page)
		return NULL;
	if (!pgtable_pmd_page_ctor(page)) {
		__free_page(page);
		return NULL;
	}
	return page_address(page);
}

static inline void pmd_free(struct mm_struct *mm, pmd_t *pmdp)
{
	BUG_ON((unsigned long)pmdp & (PAGE_SIZE-1));
	#ifdef CONFIG_PGTABLE_REPLICATION
	pgtable_repl_release_pmd(virt_to_pfn(pmdp));
	#endif
	pgtable_pmd_page_dtor(virt_to_page(pmdp));
	free_page((unsigned long)pmdp);
}

static inline void __pud_populate(pud_t *pudp, phys_addr_t pmdp, pudval_t prot)
{
	set_pud(pudp, __pud(__phys_to_pud_val(pmdp) | prot));
}

static inline void pud_populate(struct mm_struct *mm, pud_t *pudp, pmd_t *pmdp)
{
	// #ifdef CONFIG_PGTABLE_REPLICATION
	// pgtable_repl_alloc_pmd(mm, virt_to_pfn(pmdp));
	// #endif
	__pud_populate(pudp, __pa(pmdp), PMD_TYPE_TABLE);
}
#else
static inline void __pud_populate(pud_t *pudp, phys_addr_t pmdp, pudval_t prot)
{
	BUILD_BUG();
}
#endif	/* CONFIG_PGTABLE_LEVELS > 2 */

#if CONFIG_PGTABLE_LEVELS > 3

static inline pud_t *pud_alloc_one(struct mm_struct *mm, unsigned long addr)
{
	pud_t * pudp;
	struct page *page;
	// pudp = (pud_t *)__get_free_page(GFP_PGTABLE_USER);
	#ifdef CONFIG_PGTABLE_REPLICATION
	#ifdef CONFIG_Migration_test //迁移测试
	pudp = (pud_t *)pgtable_page_alloc_2(GFP_PGTABLE_USER,0);
	#else
	//正常测试
	pudp = (pud_t *)__get_free_page(GFP_PGTABLE_USER);
	#endif
	page = page_of_ptable_entry(pudp);
	// page->replica_node_id = -1;
	pgtable_repl_alloc_pud(mm, virt_to_pfn(pudp));
	#endif
	return pudp;
	// return (pud_t *)__get_free_page(GFP_PGTABLE_USER);
}

static inline void pud_free(struct mm_struct *mm, pud_t *pudp)
{
	BUG_ON((unsigned long)pudp & (PAGE_SIZE-1));
	#ifdef CONFIG_PGTABLE_REPLICATION
	pgtable_repl_release_pud(virt_to_pfn(pudp));
	#endif
	free_page((unsigned long)pudp);
}

static inline void __pgd_populate(pgd_t *pgdp, phys_addr_t pudp, pgdval_t prot)
{
	set_pgd(pgdp, __pgd(__phys_to_pgd_val(pudp) | prot));
}

static inline void pgd_populate(struct mm_struct *mm, pgd_t *pgdp, pud_t *pudp)
{
	// #ifdef CONFIG_PGTABLE_REPLICATION
	// pgtable_repl_alloc_pud(mm, virt_to_pfn(pudp));
	// #endif
	__pgd_populate(pgdp, __pa(pudp), PUD_TYPE_TABLE);
}
#else
static inline void __pgd_populate(pgd_t *pgdp, phys_addr_t pudp, pgdval_t prot)
{
	BUILD_BUG();
}
#endif	/* CONFIG_PGTABLE_LEVELS > 3 */

extern pgd_t *pgd_alloc(struct mm_struct *mm);
extern void pgd_free(struct mm_struct *mm, pgd_t *pgdp);

static inline void __pmd_populate(pmd_t *pmdp, phys_addr_t ptep,
				  pmdval_t prot)
{
	set_pmd(pmdp, __pmd(__phys_to_pmd_val(ptep) | prot));
}

/*
 * Populate the pmdp entry with a pointer to the pte.  This pmd is part
 * of the mm address space.
 */
static inline void
pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmdp, pte_t *ptep)
{
	// #ifdef CONFIG_PGTABLE_REPLICATION
	// pgtable_repl_alloc_pte(mm, virt_to_pfn(ptep));
	// #endif
	/*
	 * The pmd must be loaded with the physical address of the PTE table
	 */
	__pmd_populate(pmdp, __pa(ptep), PMD_TYPE_TABLE);
}

static inline void
pmd_populate(struct mm_struct *mm, pmd_t *pmdp, pgtable_t ptep)
{
	// #ifdef CONFIG_PGTABLE_REPLICATION
	// pgtable_repl_alloc_pte(mm, virt_to_pfn(page_to_virt(ptep)));
	// #endif
	__pmd_populate(pmdp, page_to_phys(ptep), PMD_TYPE_TABLE);
}

#ifdef CONFIG_PGTABLE_REPLICATION
static inline void __pmd_populate_no_rep(pmd_t *pmdp, phys_addr_t ptep,
				  pmdval_t prot)
{
	native_set_pmd(pmdp, __pmd(__phys_to_pmd_val(ptep) | prot));
}
static inline void pmd_populate_no_rep(struct mm_struct *mm, pmd_t *pmdp, pgtable_t ptep)
{
	unsigned long pfn = page_to_pfn(ptep);
	pgtable_repl_alloc_pte(mm, pfn);
	__pmd_populate_no_rep(pmdp, page_to_phys(ptep), PMD_TYPE_TABLE);
	
}
static inline void pmd_populate_no_rep_no_alloc_pte(struct mm_struct *mm, pmd_t *pmdp, pgtable_t ptep)
{
	__pmd_populate_no_rep(pmdp, page_to_phys(ptep), PMD_TYPE_TABLE);
	
}
#endif

#define pmd_pgtable(pmd) pmd_page(pmd)

#endif
