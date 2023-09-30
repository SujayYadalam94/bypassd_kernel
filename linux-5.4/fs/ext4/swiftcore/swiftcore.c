#include <linux/module.h>
#include <linux/buffer_head.h>
#include <linux/cpufeature.h>
#include <asm/pgtable.h>
#include <linux/version.h>
#include "../ext4.h"

#include "swiftcore.h"

//walking a process page table to get pmd pointer
//debug purposes consider to TODO:REMOVE (it is not currently used)
pmd_t * ext4_swiftcore_page_walk(struct vm_fault *vmf){
	
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	pgd = pgd_offset(vmf->vma->vm_mm, vmf->address);
	if(!pgd) goto out;
	
  	p4d = p4d_offset(pgd, vmf->address);
	if (!p4d) goto out;

	pud = pud_offset(p4d, vmf->address);
	if (!pud) goto out;

	pmd = pmd_offset(pud, vmf->address);
	return pmd;
out:
	return NULL;
}

//make a 2MB region writable by changing the permissions on the pmd
//BypassD attaches file tables to process page tables at the pmd level (2MB granularities).
//Again not currently used anywhere -- consider to TODO:REMOVE 
//I suppose it was in case we wanted to support changing permissions at 2MB granularity. 
bool ext4_swiftcore_file_mkwrite(struct vm_fault *vmf){
	
	struct vm_area_struct *vma = vmf->vma;	
	unsigned long address = vma->vm_start;
	unsigned long end = vma->vm_end;
	struct mm_struct *mm = vma->vm_mm;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	bool ret=0;

	while (address < end){
    		pgd = pgd_offset(mm, address);
		if(!pgd) break;
			
    		p4d = p4d_alloc(mm, pgd, address);
		if (!p4d) break;

		pud = pud_alloc(mm, p4d, address);
		if (!pud) break;

		pmd = pmd_alloc(mm, pud, address);
		if (!pmd) break;
	
		*pmd=pmd_mkwrite(pmd_mkdirty(*pmd));
		
		if((vmf->address&PMD_MASK)==address){
			if(is_pmd_swiftcore(*pmd))
				ret = pte_present(*pte_offset_kernel(pmd,vmf->address));
			else
				ret=1;
		}

		address+=PMD_SIZE; 
	}
out: 
	return ret;
}

//This is a helper function to expose the page tables to user-space
//for ByppasD prototype to work (no real HW so the user-space needs to find quickly the LBAs-to-PBLK translations to issue IO from user-space)
//The vma address range can be used to read the file's page tables.
void ext4_swiftcore_expose_tables(struct vm_area_struct *vma, struct inode *inode){

  unsigned long pgoff = vma->vm_pgoff;
  unsigned long address = vma->vm_start;
  unsigned long end = vma->vm_end;
  struct mm_struct *mm = vma->vm_mm;
  struct ext4_inode_info *sih = EXT4_I(inode);
  bool huge_page;
  loff_t size = PAGE_SIZE;
  pmd_t ext4_pmd;
  pte_t *pte;
  pte_t entry;
  pte_t *phys_pte;
  spinlock_t *ptl;
  struct page *page;

  if(sih->pgd){
	while (address < end){
		ext4_pmd = ext4_get_volatile_pmd(sih, pgoff<<PAGE_SHIFT, &huge_page);
      		if(!pmd_none(ext4_pmd)){
        		pte = get_locked_pte(mm,address,&ptl);
        		if (!pte) break;
        		phys_pte = pte_offset_kernel(&ext4_pmd,0);
        		page = pfn_to_page(__pa(phys_pte)>>PAGE_SHIFT);
        		entry = pfn_pte(__pa(phys_pte)>>PAGE_SHIFT, PAGE_READONLY);	
        		entry=pte_mkyoung(entry);
		    	set_pte(pte, entry);
        		pte_unmap_unlock(pte, ptl);
      		}
      		else break;
		address+=PAGE_SIZE; 
		pgoff+=(PMD_SIZE>>PAGE_SHIFT); 
	}
  }
out: 
	return;
}

//Attach a file table PMD to a process private page table PMD
bool ext4_swiftcore_set_pmd(struct vm_area_struct *vma, pmd_t *pmd, unsigned long address, unsigned long pgoff, bool wrprotect, struct ext4_inode_info *sih, loff_t size){

	pmd_t ext4_pmd;
	spinlock_t *ptl;
	bool ret = 0;
	struct mm_struct *mm=vma->vm_mm;
	bool huge_page = 0;
  	unsigned long long i;
	
	//if(size==PMD_SIZE)
	//	huge_page=1;

	if(!pmd) goto out;

	if(!pmd_none(*pmd)){
		if(!is_pmd_swiftcore(*pmd)){
			goto out;
		}
		ptl = pmd_lock(mm, pmd);
		goto already_set;
	}


	if(sih->pgd){
		ext4_pmd = ext4_get_volatile_pmd(sih, (round_down(pgoff, PMD_SIZE>>PAGE_SHIFT))<<PAGE_SHIFT, &huge_page);
	}
	else {
    		//pr_crit("Unfortunately we somehow have missed a file\n");
		goto out;
	}
	
	if(pmd_none(ext4_pmd))
		goto out;
		
	ptl = pmd_lock(mm, pmd);

	//potentially support huge pages?
	/*
	if(huge_page && __transparent_hugepage_enabled(vma)){ 
		pfn = pte_pfn(*pte_offset_kernel(&ext4_pmd,round_down(address, PMD_SIZE)));
		ext4_pmd = pmd_mkhuge(pfn_pmd(pfn, vma->vm_page_prot));
		ext4_pmd = pmd_mkdevmap(ext4_pmd);
		goto set;
	}
	*/

	//annotate this PMD as special -- used in the mm subsystem when process PT are maintained
	ext4_pmd = pmd_mk_swiftcore(ext4_pmd);

set:
	set_pmd_at(mm, round_down(address,PMD_SIZE), pmd, ext4_pmd);

already_set:
	if(is_pmd_swiftcore(*pmd)){
		if (wrprotect) {
			*pmd=pmd_wrprotect(*pmd);
		}
		else *pmd=pmd_mkwrite(pmd_mkdirty(*pmd));
    		ret =1;
	}
	spin_unlock(ptl);
	return ret;
 
out:
	return 0;
}

//helper function to get the Physical Block Number from the file page tables
//TODO:REMOVE -- I think no codepath uses this
int ext4_swiftcore_get_pblk(struct inode *inode, loff_t pos, size_t size, ext4_fsblk_t *pblk){
  	struct ext4_inode_info *sih = EXT4_I(inode);
	pmd_t ext4_pmd;
	bool huge_page = 0;
	if(sih->pgd){
		if(size == PMD_SIZE)
			huge_page=1;
		ext4_pmd = ext4_get_volatile_pmd(sih, round_down(pos, PMD_SIZE), &huge_page);
	}
	else {
    		//pr_crit("Unfortunately we somehow have missed a file\n");
		return -1;
	}
	if(pmd_none(ext4_pmd) || !pte_present(*pte_offset_kernel(&ext4_pmd,pos)))
		return -1;

	if ((size == PMD_SIZE) && !huge_page)
		return -1;

	*pblk = pte_pfn(*pte_offset_kernel(&ext4_pmd,pos));
	return 0;
}

/* Track them as bugs? TODO:REMOVE
bool ext4_swiftcore_fault(struct vm_fault *vmf, struct inode *inode){

	bool wrprotect = 0; 
	int ret = 0;
  struct ext4_inode_info *sih = EXT4_I(inode);
	loff_t size = PMD_SIZE;

	if (!((vmf->vma->vm_flags & (VM_WRITE|VM_SHARED))==(VM_WRITE|VM_SHARED)) || (!(vmf->flags & FAULT_FLAG_WRITE)))
		wrprotect=1;

	ret = ext4_swiftcore_set_pmd(vmf->vma, ext4_swiftcore_page_walk(vmf), vmf->address, vmf->pgoff, 1, wrprotect, sih, size);
	return ret;	
}
*/

//helper function that removes a VMA from the per-file tree that holds all swiftcore mappings (e.g. multiple processes) of the file
//it is called during swiftcore close
void ext4_swiftcore_remove_vma(struct vm_area_struct *vma){
  
  struct inode *inode = vma->vm_file->f_mapping->host;
  struct ext4_inode_info *sih = EXT4_I(inode);
  struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);
  struct dax_device *dax_dev = sbi->s_daxdev;
  struct swiftcore_vma_item *curr =NULL;
  struct rb_node *temp;

  if (!sbi->ext4_swiftcore_page_tables) return;

  inode_lock(inode);
  temp = sih->swiftcore_vma_tree.rb_node;
  while (temp) {
    curr = container_of(temp, struct swiftcore_vma_item, node);
    if (vma < curr->vma) {
      temp = temp->rb_left;
    } else if (vma > curr->vma) {
      temp = temp->rb_right;
    } else {
      rb_erase(&curr->node, &sih->swiftcore_vma_tree);
      kfree(curr);
      sih->num_swiftcore_vmas--;
      break;
    }
  }
  inode_unlock(inode);

}

//if a file extends -- we silently map the new file pages to user-space VAs by sub-attaching the new file tables to the private page tables of all processes that already map the file.
//currently (for the proof of concept) we assume the VMA is already large enough to fit extensions
void ext4_swiftcore_subattach_tables(struct inode *inode, ext4_lblk_t m_lblk, unsigned int m_len){

  unsigned long pgoff = m_lblk;
  struct mm_struct *mm = current->mm;
  struct ext4_inode_info *sih = EXT4_I(inode);
  struct swiftcore_vma_item *item;
  struct rb_node *temp;
  
  pgd_t *pgd;
  p4d_t *p4d;
  pud_t *pud;
  pmd_t *pmd;
  bool wrprotect=0; 
  int ret;
  loff_t size = PAGE_SIZE;

  bool huge_page;
  pmd_t ext4_pmd;
  pte_t *pte;
  pte_t entry;
  pte_t *phys_pte;
  spinlock_t *ptl;
  struct page *page;

  temp = rb_first(&sih->swiftcore_vma_tree);
  while (temp) {
    item = container_of(temp, struct swiftcore_vma_item, node);
    temp = rb_next(temp);
    struct vm_area_struct *vma = item->vma;
    BUG_ON(!vma);
 
    unsigned long address = vma->vm_start + (pgoff<<PAGE_SHIFT);
    unsigned long end = address + (m_len<<PAGE_SHIFT);
	  
    unsigned long expose_address = 0;

    if(item->vma_expose) 
       expose_address = item->vma_expose->vm_start + (pgoff/512)*PAGE_SIZE;
    
    if (end>vma->vm_end){
      	pr_crit("What is going on 0x%llx 0x%llx 0x%llx-0x%llx %llu\n", address, end, vma->vm_start, vma->vm_end, m_len);
      	goto out;
    }
    while (address < end){
      	pgd = pgd_offset(mm, address);
	if(!pgd) break;
    	p4d = p4d_alloc(mm, pgd, address);
	if (!p4d) break;

	pud = pud_alloc(mm, p4d, address);
	if (!pud) break;

	pmd = pmd_alloc(mm, pud, address);
	if (!pmd) break;
	
	if ((end-address) >= PMD_SIZE) size=PMD_SIZE;
		  
   
      	ret = ext4_swiftcore_set_pmd(vma, pmd, address, pgoff, wrprotect, sih, size); 
      	if(!ret || ret<0) {
        	pr_crit("Found nothing and breaking 0x%llx\n", address);
		break;
      	}

	//hack -- expose also the new file tables themselves to user-space (used by user-space for the PoC to get fast LBA to PBLK translations and issue IO since the proposed IOMMU extensions that would do this in HW do not currently exist)
      	if(item->vma_expose) {
        	ext4_pmd = ext4_get_volatile_pmd(sih, pgoff<<PAGE_SHIFT, &huge_page);
        	if(!pmd_none(ext4_pmd)){
          		pte = get_locked_pte(mm,expose_address,&ptl);
          		if (!pte) BUG();
          		phys_pte = pte_offset_kernel(&ext4_pmd,0);
          		page = pfn_to_page(__pa(phys_pte)>>PAGE_SHIFT);
          		entry = pfn_pte(__pa(phys_pte)>>PAGE_SHIFT, PAGE_READONLY);	
          		entry=pte_mkyoung(entry);
		      	set_pte(pte, entry);
          		pte_unmap_unlock(pte, ptl);
        	}
		expose_address+=PAGE_SIZE; 
      	}

	address+=PMD_SIZE; 
	pgoff+=(PMD_SIZE>>PAGE_SHIFT); 
    }
  }
out: 
	return;
}

//the routine that attaches file tables to process address space during swiftcore_open 
//FIXME:different r/w permissions -- currently we always allow bith R and W -- it is just a matter of passing down the info during open and mmap!
void ext4_swiftcore_attach_tables(struct vm_area_struct *vma, struct inode *inode){

  unsigned long pgoff = vma->vm_pgoff;
  unsigned long address = vma->vm_start;
  unsigned long end = vma->vm_end;
  struct mm_struct *mm = vma->vm_mm;
  struct ext4_inode_info *sih = EXT4_I(inode);
  pgd_t *pgd;
  p4d_t *p4d;
  pud_t *pud;
  pmd_t *pmd;
  bool wrprotect=0; 
  int ret;
  loff_t size = PAGE_SIZE;

  //FIXME //wrprotect=1;
	
  if ((address + PMD_SIZE) > end){
	BUG();
	goto out;	
  }

  while (address < end){
  	pgd = pgd_offset(mm, address);
  	if(!pgd) break;
			
  	p4d = p4d_alloc(mm, pgd, address);
  	if (!p4d) break;

  	pud = pud_alloc(mm, p4d, address);
  	if (!pud) break;

  	pmd = pmd_alloc(mm, pud, address);
  	if (!pmd) break;
	
  	if ((end-address) >= PMD_SIZE){	
		size=PMD_SIZE;
  	}
    
  	ret = ext4_swiftcore_set_pmd(vma, pmd, address, pgoff, wrprotect, sih, size); 
  	if(!ret) break;
  	
  	address+=PMD_SIZE; 
  	pgoff+=(PMD_SIZE>>PAGE_SHIFT); 
  }
out: 
	return;
}

//the main wrapper function that builds the file tables for a file when new blocks are allocated
//TODO:clean-up the persistent arguments -- they are left-overs from DaxVM -- same with the names of the functions (e.g. update_volatile_page_tables --> update_page_tables -- they are always volatile in BypassD)
void ext4_swiftcore_build_tables(handle_t *handle, struct inode *inode, unsigned long num_pages, ext4_fsblk_t m_pblk, ext4_lblk_t m_lblk, bool persist){
      	
  struct super_block *sb = inode->i_sb;
  struct ext4_sb_info *sbi = EXT4_SB(sb);
  struct ext4_inode_info *sih = EXT4_I(inode);
  int ret=0;	
  
  ret = ext4_update_volatile_page_table(handle, inode, sb, sih, num_pages, PAGE_SHARED_EXEC, pfn_to_pfn_t(m_pblk), m_lblk);
}

//the main wrapper function that deletes the file tables as the file shrinks
void ext4_swiftcore_delete_tables( handle_t *handle, struct inode*inode, struct super_block *sb, unsigned long start, unsigned long end, bool delete){

	struct ext4_inode_info *sih = EXT4_I(inode);
	
	if(start==end) return;
	
	if(sih->pgd && delete){
    		if (sih->pt_level==PTE_LEVEL) {
            		if(end > (start + PMD_SIZE)) end=PMD_SIZE;
	      			ext4_clear_volatile_pte(handle, inode, sb, sih, ((pte_t*)sih->pgd) + pte_index(start), start, end);
   	 	  	}
    		else if (sih->pt_level==PMD_LEVEL) {
            		if(end > (start + PUD_SIZE)) end=PUD_SIZE;
	      			ext4_clear_volatile_pmd(handle, inode, sb, sih, ((pmd_t*)sih->pgd) + pmd_index(start), start, end);
    		}
    		else if(sih->pt_level==PUD_LEVEL) {
          		if(end > (start + PGDIR_SIZE)) end=PGDIR_SIZE;
	     			ext4_clear_volatile_pud(handle, inode, sb, sih, ((pud_t*)sih->pgd) + pud_index(start), start, end);
    			}
    		else if(sih->pt_level==PGD_LEVEL) {
	      		ext4_clear_volatile_page_tables(handle, inode, sb, sih, ((pgd_t*)sih->pgd), start, end);
    		}

    		if(start == 0) {
    			sih->pgd=NULL;
    			sih->pt_ceiling=0; 
    			sih->pt_level=4;
   	 	}		
  	}
}
