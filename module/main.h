#ifndef MAIN_H
#define MAIN_H

#include "linux.h"

/* IOCTLs between userLib and the kernel to
   1) Manage (create/delete) NVMe queues
   2) Request pinned DMA buffers
*/
#define BYPASSD_IOCTL_GET_NS_INFO        _IOR('N', 0x50, struct bypassd_ns_info)
#define BYPASSD_IOCTL_CREATE_QUEUE_PAIR  _IOR('N', 0x51, struct bypassd_user_queue_info)
#define BYPASSD_IOCTL_DELETE_QUEUE_PAIR  _IOW('N', 0x52, int)
#define BYPASSD_IOCTL_GET_USER_BUF       _IOWR('N', 0x53, struct bypassd_user_buf)
#define BYPASSD_IOCTL_PUT_USER_BUF       _IOW('N', 0x54, struct bypassd_user_buf)
#define BYPASSD_IOCTL_GET_BUF_ADDR       _IOWR('N', 0x55, struct bypassd_user_buf)

#define SQ_SIZE(len) (len * sizeof(struct nvme_command))
#define CQ_SIZE(len) (len * sizeof(struct nvme_completion))

enum map_type {
    MAP_SQ, // Submission queue
    MAP_CQ, // Completion queue
    MAP_DB  // Doorbell
};

// Store information about the NVMe device
struct bypassd_dev {
    struct nvme_dev *ndev;
    struct pci_dev *pdev;

    spinlock_t ctrl_lock;

    unsigned int num_user_queue;
    DECLARE_BITMAP(queue_bmap, 65536);

    struct list_head list;
    struct list_head ns_list;
};

static LIST_HEAD(bypassd_dev_list);

struct bypassd_ns {
    struct bypassd_dev *bypassd_dev_entry;

    struct nvme_ns *ns;
    unsigned int start_sect;

    struct proc_dir_entry *ns_proc_root;
    struct proc_dir_entry *ns_proc_ioctl;

    struct list_head list;
    struct list_head queue_list;
};

struct bypassd_ns_info {
    unsigned int ns_id;
    unsigned int lba_start;
    int lba_shift;
};

struct bypassd_queue_pair {
    struct proc_dir_entry *queue_proc_root;

    struct nvme_queue* nvmeq;
    pid_t owner;

    struct list_head list;
};

struct bypassd_user_queue_info {
    void *sq_addr;
    unsigned long *cq_addr;
    __u32 *db_addr;

    int qid;
    int q_depth;
    int db_stride;
};

// Pinned buffers used for DMA
// Buffers can be of varying sizes (multiple of PAGE_SIZE)
// dma_addr_list stores the physical addresses of the pages
struct bypassd_user_buf {
    void *vaddr;
    unsigned int nr_pages;
    __u64 *dma_addr_list;
};

struct proc_dir_entry *bypassd_proc_root;

extern void nvme_submit_cmd(struct nvme_queue *nvmeq, struct nvme_command *cmd,
                bool write_sq);

struct bypassd_queue_pair* bypassd_get_queue_from_qid(struct bypassd_ns *ns_entry, int qid) {
    struct bypassd_queue_pair *queue_pair, *ret = NULL;

    list_for_each_entry(queue_pair, &ns_entry->queue_list, list) {
        if (queue_pair->nvmeq->qid == qid) {
            ret = queue_pair;
            break;
        }
    }

    return ret;
}

static int get_queue_count(struct bypassd_dev *dev_entry)
{
    int status;
    u32 result = 0;

    status = nvme_get_features(&dev_entry->ndev->ctrl, NVME_FEAT_NUM_QUEUES, 0, NULL, 0, &result);

    if (status < 0) {
        return status;
    } else if (status > 0) {
        dev_err(&dev_entry->pdev->dev, "Could not get queue count (%d)\n", status);
        return 0;
    }
    return min(result & 0xffff, result >> 16) + 1;
}

static int set_queue_count(struct bypassd_dev *dev_entry, int count, int *err)
{
    int status;
    u32 result = 0;
    u32 q_count = (count - 1) | ((count - 1) << 16);

    status = nvme_set_features(&(dev_entry->ndev->ctrl), NVME_FEAT_NUM_QUEUES, q_count, NULL, 0,
                                &result);
    if (status < 0) {
        return status;
    } else if (status > 0) {
        *err = status;
        return 0;
    }
    return min(result & 0xffff, result >> 16) + 1;
}

static int delete_queue(struct bypassd_dev *dev_entry, u8 opcode, u16 qid);
#endif
