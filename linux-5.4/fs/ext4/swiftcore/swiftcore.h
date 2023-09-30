#include <linux/spinlock.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/llist.h>
#include <asm/page.h>		/* pgprot_t */
#include <linux/rbtree.h>
#include <linux/overflow.h>
#include <linux/pfn_t.h>
#include <linux/module.h>
#include <linux/buffer_head.h>
#include <linux/cpufeature.h>
#include <asm/pgtable.h>
#include <linux/version.h>

#include "../ext4.h" 
#include "swiftcore_pt.h"

extern atomic64_t ext4_swiftcore_dram_pages;
extern bool ext4_swiftcore_page_tables;
pmd_t * ext4_swiftcore_page_walk(struct vm_fault *vmf);
bool ext4_swiftcore_set_pmd(struct vm_area_struct *vma, pmd_t *pmd, unsigned long address, unsigned long pgoff, bool wrprotect, struct ext4_inode_info *sih, loff_t size);
void ext4_swiftcore_attach_tables(struct vm_area_struct *vma, struct inode *inode);
void ext4_swiftcore_subattach_tables(struct inode *inode, ext4_lblk_t m_lblk, unsigned int m_len);
void ext4_swiftcore_expose_tables(struct vm_area_struct *vma, struct inode *inode);
void ext4_swiftcore_remove_vma(struct vm_area_struct *vma);
void ext4_swiftcore_delete_tables( handle_t *handle, struct inode*inode, struct super_block *sb, unsigned long start, unsigned long end, bool _delete);
void ext4_swiftcore_build_tables(handle_t *handle, struct inode *inode, unsigned long num_pages, ext4_fsblk_t m_pblk, ext4_lblk_t m_lblk, bool persist);
int ext4_swiftcore_get_pblk(struct inode *inode, loff_t pos, size_t size, ext4_fsblk_t *pblk);
