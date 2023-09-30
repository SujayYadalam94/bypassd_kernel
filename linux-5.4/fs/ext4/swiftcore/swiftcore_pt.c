#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/highmem.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/debugobjects.h>
#include <linux/kallsyms.h>
#include <linux/list.h>
#include <linux/notifier.h>
#include <linux/rbtree.h>
#include <linux/radix-tree.h>
#include <linux/rcupdate.h>
#include <linux/pfn.h>
#include <linux/kmemleak.h>
#include <linux/atomic.h>
#include <linux/compiler.h>
#include <linux/llist.h>
#include <linux/bitops.h>
#include <asm/pgalloc.h>
#include <linux/uaccess.h>
#include <asm/tlbflush.h>
#include <asm/shmparam.h>
#include <linux/swap.h>
#include "../ext4.h"
#include "swiftcore_pt.h"
#include <linux/pfn_t.h>

//Helper functions that allocate/maintain/attach file tables
//TODO:remove the volatile/persistent names -- leftover from DaxVM

atomic64_t ext4_swiftcore_dram_pages = ATOMIC64_INIT(0);

void ext4_clear_volatile_pte(handle_t *handle, struct inode *inode, struct super_block*sb, struct ext4_inode_info *sih, pte_t *ptep, unsigned long addr, unsigned long end)
{
	pte_t *pte;
    	unsigned long start;
      	unsigned long nr_to_flush = 0;
	unsigned long start_to_flush =0;

    	WARN_ON(!ptep);

    	if(!end) return;
    	start = addr;
    	pte = ptep;

	if(!(start & (~PMD_MASK))){
    		free_page_and_swap_cache(virt_to_page(ptep));
		atomic64_fetch_dec(&ext4_swiftcore_dram_pages);
		return;
      	}

    	do {
      		WARN_ON(!pte);
      		if (pte_none(*pte))
        		continue;
      		set_pte(pte, __pte(0));
    	} while (pte++, addr += PAGE_SIZE, addr != end);
		
}


void ext4_clear_volatile_pmd(handle_t *handle, struct inode *inode, struct super_block*sb, struct ext4_inode_info *sih,pmd_t *pmdp, unsigned long addr, unsigned long end)
{
    pmd_t *pmd;
    pte_t *pte;
    unsigned long next;
    unsigned long start;

    pmd = pmdp;
    start = addr;
    do {
    	next = pmd_addr_end(addr, end);
      	if (pmd_none(*pmd)){
        	continue;
        }
      	pte = pte_offset_kernel(pmd,addr);
      	ext4_clear_volatile_pte(handle, inode, sb, sih, pte, addr, next);
	if(!(addr & (~PMD_MASK)) && (start & (~PUD_MASK))) set_pmd(pmd, __pmd(0));
    } while (pmd++, addr = next, addr != end);
 
    if(!(start & (~PUD_MASK))){
    		free_page_and_swap_cache(virt_to_page(pmdp));
	    	atomic64_fetch_dec(&ext4_swiftcore_dram_pages);
    }
}


void ext4_clear_volatile_pud(handle_t *handle, struct inode *inode, struct super_block*sb, struct ext4_inode_info *sih,pud_t *pudp, unsigned long addr, unsigned long end)
{
    pud_t *pud;
    pmd_t *pmd;
    unsigned long next;
    unsigned long start;

    start = addr;
    pud = pudp;
    do {
      	next = pud_addr_end(addr, end);
      	if (pud_none(*pud))
        	continue;      
      	pmd = pmd_offset(pud,addr);
      	ext4_clear_volatile_pmd(handle, inode, sb, sih, pmd, addr, next);
	if(!(addr & (~PUD_MASK)) && (start & (~PGDIR_MASK))) set_pud(pud, __pud(0));
    } while (pud++, addr = next, addr != end);

    if(!(start & (~PGDIR_MASK))){
	free_page_and_swap_cache(virt_to_page(pudp));
	atomic64_fetch_dec(&ext4_swiftcore_dram_pages);
    }
}


void ext4_clear_volatile_page_tables(handle_t *handle, struct inode *inode, struct super_block*sb, struct ext4_inode_info *sih,pgd_t * pgdp, unsigned long pgoff, unsigned long end) {

  	pgd_t * pgd;
  	pud_t * pud;
  	unsigned long next;
  	unsigned long start;
	
	start = pgoff;
  	pgd = pgd_offset_pgd(pgdp, pgoff);
  	do {
    		next = pgd_addr_end(pgoff, end);
    		if (pgd_none(*pgd))
     			 continue;

    		pud = (pud_t*) pgd; //4 level paging
    		ext4_clear_volatile_pud(handle, inode, sb, sih, pud, pgoff, next);
		    if(!(pgoff & (~PGDIR_MASK))){
      			set_pgd(pgd, __pgd(0));
    		}
  	} while (pgd++, pgoff = next, pgoff != end);

  	if(start == 0){
      		kfree(pgdp);
      		atomic64_fetch_dec(&ext4_swiftcore_dram_pages);
  	}

}

static int ext4_set_volatile_pte(handle_t *handle, struct inode *inode, struct super_block*sb, struct ext4_inode_info *sih,pte_t *ptep, unsigned long addr, unsigned long end, pgprot_t prot, pfn_t pfn_begin, int *nr)
{
	pte_t entry;
	pfn_t pfn;
  	pte_t *pte = ptep;

	unsigned long nr_to_flush = 0;
	unsigned long start_to_flush =0;
	
	do {
    		pfn = pfn_to_pfn_t(pfn_t_to_pfn(pfn_begin)+(*nr));
    		//if(!pfn_t_valid(pfn)) BUG();
	      	entry = pfn_t_pte(pfn, prot);	
		entry=pte_mkwrite(entry);
        	entry=pte_mkyoung(entry);
        	entry=pte_mkdirty(entry);
		set_pte(pte, entry);
		(*nr)++;

	} while (pte++, addr += PAGE_SIZE, addr != end);
	return 0;
}

static int ext4_set_volatile_pmd(handle_t *handle, struct inode *inode, struct super_block*sb, struct ext4_inode_info *sih,pmd_t *pmdp, unsigned long addr, unsigned long end, pgprot_t prot, pfn_t pfn, int *nr)
{
  pte_t *pte;
  unsigned long next;
  pmd_t *pmd = pmdp;

  do {
	next = pmd_addr_end(addr, end);
	pte = volatile_pte_alloc_ext4(handle, inode, pmd, addr);
	if (!pte)
		return -ENOMEM;

    	//hugepage
	//if (!(addr & (PMD_SIZE-1)) && !(next & (PMD_SIZE-1)) && !((pfn_t_to_pfn(pfn)+(*nr)) & 511)){
	//	set_pmd(pmd,pmd_mkdevmap(*pmd));
	//}

	if (ext4_set_volatile_pte(handle, inode, sb, sih, pte, addr, next, prot, pfn, nr))
		return -ENOMEM;
				
  } while (pmd++, addr = next, addr != end);
  return 0;
}

static int ext4_set_volatile_pud(handle_t * handle, struct inode *inode, struct super_block*sb, struct ext4_inode_info *sih,pud_t *pudp, unsigned long addr, unsigned long end, pgprot_t prot, pfn_t pfn, int *nr)
{
	pmd_t *pmd;
	unsigned long next;
	pud_t *pud = pudp;

	do {
	 	next = pud_addr_end(addr, end);
    		pmd = volatile_pmd_alloc_ext4(handle, inode, pud, addr);

	  	  if (!pmd)
		 	 return -ENOMEM;

		  if (ext4_set_volatile_pmd(handle, inode, sb, sih, pmd, addr, next, prot, pfn, nr))
			  return -ENOMEM;

	} while (pud++, addr = next, addr != end);
	return 0;
}

static int ext4_set_volatile_p4d(handle_t *handle, struct inode *inode,  struct super_block*sb, struct ext4_inode_info *sih, p4d_t *p4dp, unsigned long addr,
														unsigned long end, pgprot_t prot, pfn_t pfn, int *nr)
{
	pud_t *pud;
	unsigned long next;
  	p4d_t *p4d = p4dp;

	do {
		next = p4d_addr_end(addr, end);
    		pud = volatile_pud_alloc_ext4(handle, inode, p4d, addr);
	  	if (!pud)
			return -ENOMEM;

		if (ext4_set_volatile_pud(handle, inode, sb, sih, pud, addr, next, prot, pfn, nr))
			return -ENOMEM;

	} while (p4d++, addr = next, addr != end);
	return 0;
}


static int ext4_set_volatile_pgd(handle_t *handle, struct inode *inode, struct super_block*sb, struct ext4_inode_info *sih,pgd_t *pgd1, unsigned long start, unsigned long end, pgprot_t prot, pfn_t pfn, int *nr)
{
	pgd_t *pgd;
	p4d_t *p4d;
	unsigned long next;
	unsigned long addr = start;
	int err = 0;

	BUG_ON(addr >= end);
	pgd = pgd_offset_pgd(pgd1, addr);
	do {
		next = pgd_addr_end(addr, end);
	  	p4d = volatile_p4d_alloc_ext4(handle, inode, pgd, addr);
	  	if (!p4d)
			  return -ENOMEM;

		  err = ext4_set_volatile_p4d(handle, inode, sb, sih, p4d, addr, next, prot, pfn, nr);
		  if (err)
			  return err;

	} while (pgd++, addr = next, addr != end);
	return 0;
}

//entry helper function that triggers the built of new file table entries (allocation/setup)
//the pt_level and pt_ceiling attributes declare the depth of the already existing file table tree -- it is built bottom-up
int ext4_update_volatile_page_table(handle_t *handle, struct inode *inode, struct super_block*sb, struct ext4_inode_info *sih, unsigned long count, pgprot_t prot, pfn_t pfn, unsigned long pgoff)
{
	int ret;
	unsigned long start;
	unsigned long size;
  	int nr = 0;

 	pgd_t *pgd=NULL;
	pud_t *pud=NULL;
	pmd_t *pmd=NULL;
  	pte_t *pte=NULL;
	
	start = pgoff << PAGE_SHIFT;
  	size = (unsigned long)count << PAGE_SHIFT;
  	ret=-1;

  	//hugepage
  	//while ((start+size) > sih->pt_ceiling || ((((start+size)==PMD_SIZE)) && (sih->pt_level > PMD_LEVEL))) {
  	while ((start+size) > sih->pt_ceiling) {
    		sih->pt_level--;
  
    		if(sih->pt_level == PTE_LEVEL){
      			pte = (pte_t*) __r_v_pte_alloc_ext4(handle, inode, NULL, 0);
      			WARN_ON(!pte);
      			sih->pgd=pte;
      			sih->pt_ceiling=PMD_SIZE;
    		}	

    		if(sih->pt_level == PMD_LEVEL){ 
      			pmd = (pmd_t*) __r_v_pmd_alloc_ext4(handle, inode, NULL,0);
      			WARN_ON(!pmd);
      			if(sih->pgd) volatile_pmd_populate_ext4(pmd,(pte_t*)sih->pgd);
      			sih->pgd=pmd;
      			sih->pt_ceiling=PUD_SIZE;
    		}

    		if(sih->pt_level == PUD_LEVEL){ 
      			pud = (pud_t*) __r_v_pud_alloc_ext4(handle, inode, NULL, 0);
      			WARN_ON(!pud);
      			if(sih->pgd)  volatile_pud_populate_ext4(pud,(pmd_t *)sih->pgd);
      			sih->pgd=pud;
      			sih->pt_ceiling=PGDIR_SIZE;
    		}

    		if(sih->pt_level == PGD_LEVEL){
            		//FIXME
      			pgd = (pgd_t *)__get_free_page(GFP_KERNEL_ACCOUNT|__GFP_ZERO);
      			WARN_ON(!pgd);
      			if(sih->pgd)  volatile_pgd_populate_ext4((pgd_t*) pgd,(p4d_t *)sih->pgd);
      			sih->pgd=pgd;
      			sih->pt_ceiling=0xffffffff;
    		}	 
  	}

  	WARN_ON(sih->pgd==NULL);

  	if (sih->pt_level==PTE_LEVEL) {
		  ret = ext4_set_volatile_pte(handle, inode, sb,sih,((pte_t*)sih->pgd)+pte_index(start), start, start+size, prot, pfn, &nr);
  	}
  	else if (sih->pt_level==PMD_LEVEL) {
	  	ret = ext4_set_volatile_pmd(handle, inode, sb,sih,((pmd_t*)sih->pgd)+pmd_index(start), start, start+size, prot, pfn, &nr);
  	}
  	else if(sih->pt_level==PUD_LEVEL) {
		  ret = ext4_set_volatile_pud(handle, inode, sb,sih,((pud_t*)sih->pgd)+pud_index(start), start, start+size, prot, pfn, &nr);
  	}
  	else if(sih->pt_level==PGD_LEVEL) {
		  ret = ext4_set_volatile_pgd(handle, inode, sb,sih,sih->pgd, start, start+size, prot, pfn, &nr);
  	}
  	return ret;
}

// entry helper function that retrieves the PMD entry for a specific file offset (addr) from the file tables
pmd_t ext4_get_volatile_pmd(struct ext4_inode_info *sih, unsigned long addr, bool *huge)
{

	pgd_t *pgd=NULL;
	p4d_t *p4d=NULL;
	pud_t *pud=NULL;
	pmd_t *pmd=NULL;
  	pmd_t ret;

	if (sih->pt_level==PGD_LEVEL){
  		pgd = pgd_offset_pgd((pgd_t *)sih->pgd,addr);
      		if(pgd && !pgd_none(*pgd))
    	  		p4d = p4d_offset(pgd, addr);
	    	if(p4d && !p4d_none(*p4d))
    			pud = pud_offset(p4d, addr);
	    	if(pud && !pud_none(*pud))
    			pmd = pmd_offset(pud, addr);
	    	ret = *pmd;
	}    
  	else if (sih->pt_level==PUD_LEVEL){
	    	pud = ((pud_t*)sih->pgd) + pud_index(addr);
  	    	if(pud && !pud_none(*pud)) {
            		pmd = pmd_offset(pud, addr);
            		if (pmd) {
              			ret = *pmd;
            		} else {
                		ret.pmd = 0;
            		}
            	} else {
            		ret.pmd = 0;
            	}
	}
  	else if (sih->pt_level==PMD_LEVEL){
  	  	pmd = ((pmd_t*)sih->pgd) + pmd_index(addr);
  	  	ret = *pmd;
	}
  	else if (sih->pt_level==PTE_LEVEL) {
      		pmd_populate_kernel(NULL, &ret, (pte_t*) sih->pgd);
  	}
  	else
	    BUG();

  	/*
  	if(*huge) {	
		if (pmd_devmap(ret)) *huge=1;
	  	else *huge=0;
  	}
  	*/
  	return ret;
}

//helper functions to allocate pages for the file tables
void *ext4_pt_alloc(handle_t *handle, struct inode *inode){
 
  unsigned long ret = __get_free_page(GFP_KERNEL_ACCOUNT|__GFP_ZERO);
  struct page *page = virt_to_page(ret);  
  atomic_set(&page->_mapcount,1);
  get_page(page);
  atomic64_fetch_inc(&ext4_swiftcore_dram_pages);
  return ret;
}


int __v_pte_alloc_ext4(handle_t *handle, struct inode *inode, pmd_t *pmd, unsigned long address)
{
        pte_t *new = (pte_t*)ext4_pt_alloc(handle, inode);
        if (!new)
          return -ENOMEM;
        smp_wmb();
        if(pmd)
          	volatile_pmd_populate_ext4(pmd, new); 
        return 0;
}

pte_t * __r_v_pte_alloc_ext4(handle_t *handle, struct inode *inode, pmd_t *pmd, unsigned long address)
{
        pte_t *new = (pte_t*)ext4_pt_alloc(handle, inode);
        if (!new)
          return NULL;
        smp_wmb(); 
        if(pmd)
          volatile_pmd_populate_ext4(pmd, new);
        return new;
}


int __v_pud_alloc_ext4(handle_t *handle, struct inode *inode, p4d_t *p4d, unsigned long address)
{
        pud_t *new = (pud_t*) ext4_pt_alloc(handle, inode);
        if (!new)
          return -ENOMEM;
        smp_wmb();
        if(p4d)
          volatile_p4d_populate_ext4(p4d, new);
        return 0;
}


pud_t * __r_v_pud_alloc_ext4(handle_t *handle, struct inode *inode, p4d_t *p4d, unsigned long address)
{
        pud_t *new = (pud_t*) ext4_pt_alloc(handle, inode);
        if (!new)
          return NULL;
        smp_wmb(); 
        if(p4d)
          volatile_p4d_populate_ext4(p4d, new);
        return new;
}

int __v_pmd_alloc_ext4(handle_t *handle, struct inode *inode, pud_t *pud, unsigned long address)
{
        pmd_t *new = (pmd_t*)ext4_pt_alloc(handle, inode);
        if (!new)
          return -ENOMEM;
        smp_wmb(); 
        if(pud)
          volatile_pud_populate_ext4(pud, new);
        return 0;
}

pmd_t* __r_v_pmd_alloc_ext4(handle_t *handle, struct inode *inode, pud_t *pud, unsigned long address)
{
        pmd_t *new = (pmd_t*)ext4_pt_alloc(handle, inode);
        if (!new)
          return NULL;
        smp_wmb(); 
        if(pud)
          volatile_pud_populate_ext4(pud, new);
        return new;
}
