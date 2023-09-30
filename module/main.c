#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/cdev.h>
#include <linux/cred.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/nvme.h>
#include <linux/pci.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/types.h>

#include "main.h"
#include "linux.h"

/*
 * Queue creation functions
 */
static int alloc_cq(struct bypassd_dev *dev_entry, u16 qid,
            struct nvme_queue *nvmeq) {
    struct nvme_dev *ndev = dev_entry->ndev;
    struct nvme_command c;
    int flags = NVME_QUEUE_PHYS_CONTIG;

    /*
     * Note: we (ab)use the fact the the prp fields survive if no data
     * is attached to the request.
     */
    memset(&c, 0, sizeof(c));
    c.create_cq.opcode     = nvme_admin_create_cq;
    c.create_cq.prp1       = cpu_to_le64(nvmeq->cq_dma_addr);
    c.create_cq.cqid       = cpu_to_le16(qid);
    c.create_cq.qsize      = cpu_to_le16(nvmeq->q_depth - 1);
    c.create_cq.cq_flags   = cpu_to_le16(flags);
    c.create_cq.irq_vector = 0;

    return nvme_submit_sync_cmd(ndev->ctrl.admin_q, &c, NULL, 0);
}

static int alloc_sq(struct bypassd_dev *dev_entry, u16 qid,
            struct nvme_queue *nvmeq) {
    struct nvme_dev *ndev = dev_entry->ndev;
    struct nvme_command c;
    int flags = NVME_QUEUE_PHYS_CONTIG;

    memset(&c, 0, sizeof(c));
    c.create_sq.opcode   = nvme_admin_create_sq;
    c.create_sq.prp1     = cpu_to_le64(nvmeq->sq_dma_addr);
    c.create_sq.sqid     = cpu_to_le16(qid);
    c.create_sq.qsize    = cpu_to_le16(nvmeq->q_depth - 1);
    c.create_sq.sq_flags = cpu_to_le16(flags);
    c.create_sq.cqid     = cpu_to_le16(qid);

    return nvme_submit_sync_cmd(ndev->ctrl.admin_q, &c, NULL, 0);
}

static struct nvme_queue *bypassd_alloc_queue(struct bypassd_dev *dev_entry,
                int qid, int depth) {
    struct nvme_dev   *ndev = dev_entry->ndev;
    struct nvme_queue *nvmeq;
    int ret;

    nvmeq = kzalloc(sizeof(*nvmeq), GFP_KERNEL);
    if(!nvmeq) return NULL;

    nvmeq->sqes    = 6;
    nvmeq->q_depth = depth;
    nvmeq->dev     = ndev;
    // Allocate DMA memory for CQ
    nvmeq->cqes    = dma_alloc_coherent(&dev_entry->pdev->dev, CQ_SIZE(depth),
                            &nvmeq->cq_dma_addr, GFP_KERNEL);
    if(!nvmeq->cqes) {
        pr_err("[bypassd]: No memory for CQ allocation\n");
        ret = -ENOMEM;
        goto free_nvmeq;
    }

    // Allocate DMA memory for SQ
    nvmeq->sq_cmds = dma_alloc_coherent(&dev_entry->pdev->dev, SQ_SIZE(depth),
                            &nvmeq->sq_dma_addr, GFP_KERNEL);
    if(!nvmeq->sq_cmds) {
        pr_err("[bypassd]: No memory for SQ allocation\n");
        ret = -ENOMEM;
        goto free_cqdma;
    }

    // TODO: Currently 4K alloated for db. Each db entry is 4 bytes
    //       Therefore 1K queues can be created. To create more than
    //       1K, need to remap bar by calling nvme_remap_bar()
    nvmeq->dev = ndev;
    spin_lock_init(&nvmeq->sq_lock);
    spin_lock_init(&nvmeq->cq_poll_lock);
    nvmeq->cq_head  = 0;
    nvmeq->cq_phase = 1;
    nvmeq->q_db     = &ndev->dbs[qid * 2 * ndev->db_stride];
    nvmeq->qid      = qid;

    // Register CQ with device
    ret = alloc_cq(dev_entry, qid, nvmeq);
    if (ret != 0) {
        pr_err("[bypassd]: Alloc CQ failed %d\n", ret);
        ret = -ENOSPC;
        goto free_sqdma;
    }

    // Register SQ with device
    ret = alloc_sq(dev_entry, qid, nvmeq);
    if (ret != 0) {
        pr_err("[bypassd]: Alloc SQ failed %d\n", ret);
        delete_queue(dev_entry, nvme_admin_delete_cq, qid);
        goto free_sqdma;
    }

    nvmeq->sq_tail      = 0;
    nvmeq->last_sq_tail = 0;
    memset((void *)nvmeq->cqes, 0, CQ_SIZE(nvmeq->q_depth));
    return nvmeq;

free_sqdma:
    dma_free_coherent(&dev_entry->pdev->dev, SQ_SIZE(depth), (void *)nvmeq->sq_cmds,
                        nvmeq->sq_dma_addr);
free_cqdma:
    dma_free_coherent(&dev_entry->pdev->dev, CQ_SIZE(depth), (void *)nvmeq->cqes,
                        nvmeq->cq_dma_addr);
free_nvmeq:
    kfree(nvmeq);
    return NULL;
}

// This function maps the created queues to userspace
static void* bypassd_map_to_userspace(struct bypassd_dev *dev_entry,
                struct nvme_queue *nvmeq, int type) { 
    struct nvme_dev       *ndev = dev_entry->ndev;
    struct pci_dev        *pdev;
    unsigned long         addr;
    void                  *cpu_addr;
    dma_addr_t            dma_addr;
    struct vm_area_struct *vma, *prev;
    struct rb_node        **rb_link, *rb_parent;
    int                   vm_len;
    int                   ret = 0;

    switch(type) {
        case MAP_SQ:
            vm_len   = SQ_SIZE(ndev->q_depth);
            cpu_addr = nvmeq->sq_cmds;
            dma_addr = nvmeq->sq_dma_addr;
            break;

        case MAP_CQ:
            vm_len   = CQ_SIZE(ndev->q_depth);
            cpu_addr = (void *)nvmeq->cqes;
            dma_addr = nvmeq->cq_dma_addr;
            break;

        case MAP_DB:
            vm_len   = PAGE_SIZE;
            cpu_addr = ndev->dbs;
            pdev     = to_pci_dev(&dev_entry->pdev->dev);
            dma_addr = (pci_resource_start(pdev, 0) + PAGE_SIZE) >> PAGE_SHIFT;
            break;

        default:
            pr_err("Invalid map type\n");
            return NULL;
    }

    /* TODO: dma_alloc_coherent calls dma_direct_alloc() which allocates PAGE_ALIGN(size)
     *       but if dma_alloc_from_dev_coherent is called, then get_order(size)
     */
    vm_len = PAGE_ALIGN(vm_len);
    addr   = get_unmapped_area(NULL, 0, vm_len, 0, 0);
    ret    = find_vma_links(current->mm, addr, addr + vm_len, &prev, &rb_link, &rb_parent);
    if (ret != 0) {
        return NULL;
    }
    vma = vm_area_alloc(current->mm);
    if (!vma) {
        return NULL;
    }
    vma->vm_start     = addr;
    vma->vm_end       = addr + vm_len;
    vma->vm_flags     = VM_READ | VM_WRITE | VM_MAYWRITE | VM_MAYREAD | VM_SHARED | VM_MAYSHARE;
    vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);
    vma->vm_pgoff = 0;
    if (type == MAP_DB) {
        vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
        ret = remap_pfn_range(vma, vma->vm_start, dma_addr, vm_len, vma->vm_page_prot);
    } else {
        ret = dma_mmap_attrs(&dev_entry->pdev->dev, vma, cpu_addr, dma_addr, vm_len, 0);
    }
    if (ret < 0) {
        pr_err("[bypassd]: Error mapping queues\n");
        return NULL;
    }

    vma_link(current->mm, vma, prev, rb_link, rb_parent);
    // TODO: Need to include this flag for some reason. Doens't work without it.
    //       Need to figure out why.
    vma->vm_flags |= VM_SOFTDIRTY;

    return (void *)vma->vm_start;
}

/*****************************************************************************/

/*
 * Queue deletion functions
 */
static int delete_queue(struct bypassd_dev *dev_entry, u8 opcode, u16 qid) {
    struct nvme_dev *ndev = dev_entry->ndev;
    struct nvme_command c;

    memset(&c, 0, sizeof(c));
    c.delete_queue.opcode = opcode;
    c.delete_queue.qid    = cpu_to_le16(qid);

    return nvme_submit_sync_cmd(ndev->ctrl.admin_q, &c, NULL, 0);
}

static int __bypassd_delete_queue_pair(struct bypassd_ns *ns_entry, int qid) {
    struct bypassd_dev *dev_entry = ns_entry->bypassd_dev_entry;
    struct bypassd_queue_pair *queue_pair;
    struct nvme_queue         *nvmeq;

    spin_lock(&dev_entry->ctrl_lock);

    queue_pair = bypassd_get_queue_from_qid(ns_entry, qid);
    if (!queue_pair) {
        spin_unlock(&dev_entry->ctrl_lock);
        return -EINVAL;
    }

    //pr_info("[bypassd]: Deleting queue %d\n", qid);
    delete_queue(dev_entry, nvme_admin_delete_sq, qid);
    delete_queue(dev_entry, nvme_admin_delete_cq, qid);

    nvmeq = queue_pair->nvmeq;
    dma_free_coherent(&dev_entry->pdev->dev, SQ_SIZE(nvmeq->q_depth), nvmeq->sq_cmds, nvmeq->sq_dma_addr);
    dma_free_coherent(&dev_entry->pdev->dev, CQ_SIZE(nvmeq->q_depth), (void *)nvmeq->cqes, nvmeq->cq_dma_addr);

    clear_bit(qid, dev_entry->queue_bmap);
    dev_entry->num_user_queue--;

    list_del(&queue_pair->list);

    kfree(nvmeq);
    kfree(queue_pair);

    // TODO: delete VMAs
    spin_unlock(&dev_entry->ctrl_lock);

    return 0;
}

void bypassd_cleanup_queues(struct bypassd_ns *ns_entry) {
    struct bypassd_queue_pair *qp, *qp_next;
    list_for_each_entry_safe(qp, qp_next, &ns_entry->queue_list, list) {
        __bypassd_delete_queue_pair(ns_entry, qp->nvmeq->qid);
    }
}

/*****************************************************************************/

/*
 * IOCTL handling functions
 */
static int bypassd_get_ns_info(struct bypassd_ns *ns_entry,
            struct bypassd_ns_info  __user *__ns_info) {
    struct bypassd_ns_info ns_info;

    ns_info.ns_id     = ns_entry->ns->head->ns_id;
    ns_info.lba_start = ns_entry->start_sect;
    ns_info.lba_shift = ns_entry->ns->lba_shift;

    copy_to_user(__ns_info, &ns_info, sizeof(ns_info));
    return 0;
}

static int bypassd_setup_queue_pair(struct bypassd_ns *ns_entry,
                struct bypassd_user_queue_info __user *__queue_info) {
    struct bypassd_dev *dev_entry = ns_entry->bypassd_dev_entry;
    struct bypassd_queue_pair     *queue_pair;
    struct bypassd_user_queue_info queue_info;
    unsigned int                   queue_count;
    int                            result;
    int                            err;
    int                            qid;

    spin_lock(&dev_entry->ctrl_lock);

    queue_count = dev_entry->ndev->ctrl.queue_count + (++dev_entry->num_user_queue);
    result      = set_queue_count(dev_entry, queue_count, &err);
    if (result < 0) {
        pr_err("[bypassd]: Error on set queue count\n");
        dev_entry->num_user_queue--;
        spin_unlock(&dev_entry->ctrl_lock);
        return -ENOSPC;
    } else if (result == 0 && err == 6) { //If queue count set to other value
        result = get_queue_count(dev_entry);
    }

    // TODO: On some SSD, we can set the queue count only once.
    //       For example, Dell Ent SSD. We ignore this and proceed with creating queues
    //if (result < queue_count) {
        //pr_err("[bypassd]: Number of queues exceeded res=%d queue_count=%d\n", result, queue_count);
    //    dev_entry->num_user_queue--;
    //    spin_unlock(&dev_entry->ctrl_lock);
    //    return -ENOSPC;
    //}

    queue_pair = kzalloc(sizeof(*queue_pair), GFP_KERNEL);
    qid = find_first_zero_bit(dev_entry->queue_bmap, 256);
    set_bit(qid, dev_entry->queue_bmap);

    // Allocate and create queues
    queue_pair->nvmeq = bypassd_alloc_queue(dev_entry, qid, dev_entry->ndev->q_depth);
    if (!queue_pair->nvmeq) {
        pr_err("Queue alloc failed\n");
        goto free_queue_pair;
    }

    // Owner is currently unused; Can be used to restrict number of queues per process
    queue_pair->owner = current->pid;
    list_add(&queue_pair->list, &ns_entry->queue_list);

    // Map the queues to userspace
    queue_info.sq_addr = bypassd_map_to_userspace(dev_entry, queue_pair->nvmeq, MAP_SQ);
    if(!queue_info.sq_addr) {
        goto free_nvmeq;
    }
    queue_info.cq_addr = bypassd_map_to_userspace(dev_entry, queue_pair->nvmeq, MAP_CQ);
    if(!queue_info.cq_addr) {
        pr_err("[bypassd]: Weird error! Cannot map CQ.\n");
        goto free_nvmeq;
    }
    queue_info.db_addr = bypassd_map_to_userspace(dev_entry, queue_pair->nvmeq, MAP_DB);
    if(!queue_info.db_addr) {
        pr_err("[bypassd]: Weird error! Cannot map doorbell.\n");
        goto free_nvmeq;
    }
    queue_info.qid       = qid;
    queue_info.q_depth   = dev_entry->ndev->q_depth;
    queue_info.db_stride = dev_entry->ndev->db_stride;

    spin_unlock(&dev_entry->ctrl_lock);

    copy_to_user(__queue_info, &queue_info, sizeof(queue_info));
    return 0;

free_nvmeq:
    // TODO: need to delete the queue and free dma as well
    kfree(queue_pair->nvmeq);
free_queue_pair:
    clear_bit(qid, dev_entry->queue_bmap);
    dev_entry->num_user_queue--;
    kfree(queue_pair);
    spin_unlock(&dev_entry->ctrl_lock);
    return -1;
}

static int bypassd_delete_queue_pair(struct bypassd_ns *ns_entry, int __user * __qid) {
    int qid;

    copy_from_user(&qid, __qid, sizeof(qid));

    return  __bypassd_delete_queue_pair(ns_entry, qid);
}

static int bypassd_get_user_buf(struct bypassd_ns *ns_entry, void __user *__buf) {
    struct bypassd_dev *dev_entry = ns_entry->bypassd_dev_entry;
    struct bypassd_user_buf buf;
    struct page **pages;
    unsigned int flags;
    unsigned long ret;
    phys_addr_t phys;
    dma_addr_t *dma_addr_list;
    int i;

    copy_from_user(&buf, __buf, sizeof(buf));

    flags         = FOLL_WRITE;
    pages         = kvmalloc_array(buf.nr_pages, sizeof(struct page *),
                        GFP_KERNEL);
    dma_addr_list = kmalloc (sizeof(__u64) * buf.nr_pages, GFP_KERNEL);

    ret = get_user_pages_fast((unsigned long)buf.vaddr, buf.nr_pages, flags, pages);
    if (ret <= 0) {
        kvfree(pages);
        kfree(dma_addr_list);
        pr_err("[bypassd]: get_user_pages_fast failed.\n");
        return -ENOMEM;
    }

    buf.nr_pages = ret;

    for (i=0; i<ret; ++i) {
        phys              = page_to_phys(pages[i]);
        dma_addr_list[i]  = (dma_addr_t)phys;
        dma_addr_list[i] -= ((dma_addr_t)dev_entry->pdev->dev.dma_pfn_offset << PAGE_SHIFT);
        if (dma_addr_list[i] == 0) {
            pr_err("[bypassd]: Invalid page address while allocating DMA pages.\n");
            buf.nr_pages--;
        }
    }

    copy_to_user(__buf, &buf, sizeof(buf));
    copy_to_user(buf.dma_addr_list, dma_addr_list, sizeof(__u64) * ret);

    kvfree(pages);
    kfree(dma_addr_list);

    return 0;
}

static int bypassd_put_user_buf(struct bypassd_ns *ns_entry, void __user *__buf) {
    struct bypassd_dev *dev_entry = ns_entry->bypassd_dev_entry;
    struct bypassd_user_buf buf;
    dma_addr_t *dma_addr_list;

    struct page **pages;
    phys_addr_t phys;
    unsigned long pfn;

    int i;

    copy_from_user(&buf, __buf, sizeof(buf));
    dma_addr_list = kzalloc(sizeof(__u64) * buf.nr_pages, GFP_KERNEL);

    copy_from_user(dma_addr_list, buf.dma_addr_list, sizeof(__u64) * buf.nr_pages);
    pages = kvmalloc_array(buf.nr_pages, sizeof(struct page *), GFP_KERNEL);

    for (i=0; i<buf.nr_pages; ++i) {
        phys     = (phys_addr_t)dma_addr_list[i];
        phys    += (dma_addr_t)dev_entry->pdev->dev.dma_pfn_offset << PAGE_SHIFT;
        pfn      = phys >> PAGE_SHIFT;
        pages[i] = pfn_to_page(pfn);
        if (!pages[i]) {
            pr_err("[bypassd]: Can't find DMA page for freeing.\n");
            break;
        }
    }
    put_user_pages(pages, i);

    kvfree(pages);
    kfree(dma_addr_list);

    return 0;
}

static int bypassd_get_buf_addr(struct bypassd_ns *ns_entry, void __user *__buf) {
    struct mm_struct *mm;
    struct bypassd_user_buf buf;

    unsigned long vaddr, start_addr;
    u64          *pfnList;
    int           ret = 0;
    int           i;

    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    copy_from_user(&buf, __buf, sizeof(buf));
    start_addr = (unsigned long)buf.vaddr;

    pfnList = kmalloc(sizeof(u64) * buf.nr_pages, GFP_KERNEL);

    mm = current->mm;
    down_read(&mm->mmap_sem);
    for(i=0; i<buf.nr_pages; ++i) {
        vaddr = start_addr + (i * PAGE_SIZE);

        pgd = pgd_offset(mm, vaddr);
        if (pgd_none(*pgd) || pgd_bad(*pgd)) {
            ret = -EFAULT;
            goto end;
        }

        p4d = p4d_offset(pgd, vaddr);
        if (p4d_none(*p4d) || p4d_bad(*p4d)) {
            ret = -EFAULT;
            goto end;
        }

        pud = pud_offset(p4d, vaddr);
        if (pud_none(*pud) || pud_bad(*pud)) {
            ret = -EFAULT;
            goto end;
        }

        pmd = pmd_offset(pud, vaddr);
        if (!pmd_none(*pmd) &&
                (pmd_val(*pmd) & (_PAGE_PRESENT|_PAGE_PSE)) != _PAGE_PRESENT) {
            pfnList[i] = pmd_pfn(*pmd) << PAGE_SHIFT;
            continue;
        } else if (pmd_none(*pmd) || pmd_bad(*pmd)) {
            ret = -EFAULT;
            goto end;
        }

        pte = pte_offset_kernel(pmd, vaddr);
        if (!pte || !pte_present(*pte)) {
            ret = -EFAULT;
            goto end;
        }

        pfnList[i] = pte_pfn(*pte) << PAGE_SHIFT;
    }
    copy_to_user(buf.dma_addr_list, pfnList, sizeof(u64)*buf.nr_pages);

end:
    up_read(&mm->mmap_sem);
    kfree(pfnList);
    return ret;
}


/*
 * IOCTL handler
 */
static long bypassd_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct bypassd_ns *ns_entry = PDE_DATA(file->f_inode);
    int ret;

    switch (cmd) {
        case BYPASSD_IOCTL_GET_NS_INFO:
            ret = bypassd_get_ns_info(ns_entry, (void __user *)arg);
            break;

        case BYPASSD_IOCTL_CREATE_QUEUE_PAIR:
            ret = bypassd_setup_queue_pair(ns_entry, (void __user *)arg);
            break;

        case BYPASSD_IOCTL_DELETE_QUEUE_PAIR:
            ret = bypassd_delete_queue_pair(ns_entry, (void __user *)arg);
            break;

        case BYPASSD_IOCTL_GET_USER_BUF:
            ret = bypassd_get_user_buf(ns_entry, (void __user *)arg);
            break;

        case BYPASSD_IOCTL_PUT_USER_BUF:
            ret = bypassd_put_user_buf(ns_entry, (void __user *)arg);
            break;

        case BYPASSD_IOCTL_GET_BUF_ADDR:
            ret = bypassd_get_buf_addr(ns_entry, (void __user *)arg);
            break;

        default:
            ret = -EINVAL;
            pr_err("[bypassd]: Invalid IOCTL\n");
            break;
    }
    return ret;
}

/*****************************************************************************/

static const struct file_operations bypassd_ns_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = bypassd_ioctl,
};

static int find_nvme_devices(void) {
    struct bypassd_dev *dev_entry;
    struct pci_dev     *pdev = NULL;
    struct nvme_dev    *ndev;
    struct nvme_ns     *ns;

    struct bypassd_ns    *ns_entry;
    struct disk_part_iter piter;
    struct hd_struct     *part;

    char dev_name[32];
    int  i;

    while ((pdev = pci_get_class(PCI_CLASS_STORAGE_EXPRESS, pdev))) {
        ndev = pci_get_drvdata(pdev);
        if (ndev == NULL)
            continue;

        dev_entry = kzalloc(sizeof(*dev_entry), GFP_KERNEL);
        dev_entry->ndev = ndev;
        dev_entry->pdev = pdev;
        dev_entry->num_user_queue = 0;
        spin_lock_init(&dev_entry->ctrl_lock);
        for(i=0; i<ndev->ctrl.queue_count; ++i) {
            set_bit(i, dev_entry->queue_bmap);
        }
        list_add(&dev_entry->list, &bypassd_dev_list);

        INIT_LIST_HEAD(&dev_entry->ns_list);

        list_for_each_entry(ns, &ndev->ctrl.namespaces, list) {
            disk_part_iter_init(&piter, ns->disk, DISK_PITER_INCL_PART0);
            while ((part = disk_part_iter_next(&piter))) {
                if(part != &ns->disk->part0 && !part->info)
                    continue;

                ns_entry = kzalloc(sizeof(*ns_entry), GFP_KERNEL);
                ns_entry->bypassd_dev_entry = dev_entry;
                ns_entry->ns = ns;
                ns_entry->start_sect = part->start_sect;

                if(part == &ns->disk->part0)
                    sprintf(dev_name, "nvme%dn%u", ndev->ctrl.instance, ns->head->ns_id);
                else
                    sprintf(dev_name, "nvme%dn%up%u", ndev->ctrl.instance, ns->head->ns_id, part->partno);

                ns_entry->ns_proc_root = proc_mkdir(dev_name, bypassd_proc_root);
                if(!ns_entry->ns_proc_root) {
                    pr_err("[bypassd]: Error creating proc directory - %s\n", dev_name);
                    kfree(ns_entry);
                    continue;
                }

                ns_entry->ns_proc_ioctl = proc_create_data("ioctl", S_IRUSR|S_IRGRP|S_IROTH,
                        ns_entry->ns_proc_root, &bypassd_ns_fops, ns_entry);

                if(!ns_entry->ns_proc_ioctl) {
                    pr_err("[bypassd]: Error creating proc ioctl file - %s\n", dev_name);
                    proc_remove(ns_entry->ns_proc_root);
                    kfree(ns_entry);
                    continue;
                }

                INIT_LIST_HEAD(&ns_entry->queue_list);

                list_add(&ns_entry->list, &dev_entry->ns_list);
            }
            disk_part_iter_exit(&piter);
        }
    }
    return 0;
}

static int __init bypassd_init(void)
{
    int ret;

    ret = request_module("nvme");
    if (ret < 0) {
        pr_err("[bypassd]: Cannot find NVMe driver\n");
        return -1;
    }

    bypassd_proc_root = proc_mkdir("bypassd", NULL);
    if (!bypassd_proc_root) {
        pr_err("[bypassd]: Couldn't create proc entry\n");
        return -1;
    }

    if (find_nvme_devices() != 0) {
        pr_err("[bypassd]: Couldn't find NVMe device\n");
        return -1;
    }

    pr_info("[bypassd]: Initialized module\n");
    return 0;
}

static void __exit bypassd_exit(void)
{
    struct bypassd_dev *dev_entry, *dev_next;
    struct bypassd_ns  *ns_entry, *ns_next;
    pr_info("[bypassd]: Exiting module\n");

    list_for_each_entry_safe(dev_entry, dev_next, &bypassd_dev_list, list) {
        list_for_each_entry_safe(ns_entry, ns_next, &dev_entry->ns_list, list) {
            bypassd_cleanup_queues(ns_entry);

            proc_remove(ns_entry->ns_proc_ioctl);
            proc_remove(ns_entry->ns_proc_root);

            list_del(&ns_entry->list);
            kfree(ns_entry);
        }
        list_del(&dev_entry->list);
        kfree(dev_entry);
    }
    proc_remove(bypassd_proc_root); 
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sujay Yadalam");
MODULE_DESCRIPTION("NVME module to support user-space direct access");

module_init(bypassd_init);
module_exit(bypassd_exit);
