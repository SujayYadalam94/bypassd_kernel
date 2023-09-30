#ifndef LINUX_H
#define LINUX_H

/* The data structures in this file are replicas from linux-5.4.
   They coudn't be included directly. So created this file.
   Note: The structures might be different in different versions of linux.
         Need to update this file if using different linux versions.
*/

enum nvme_ctrl_state {
    NVME_CTRL_NEW,
    NVME_CTRL_LIVE,
    NVME_CTRL_RESETTING,
    NVME_CTRL_CONNECTING,
    NVME_CTRL_DELETING,
    NVME_CTRL_DEAD,
};

struct nvme_fault_inject {
#ifdef CONFIG_FAULT_INJECTION_DEBUG_FS
    struct fault_attr attr;
    struct dentry *parent;
    bool dont_retry;    /* DNR, do not retry */
    u16 status;     /* status code */
#endif
};

struct nvme_ns_ids {
    u8  eui64[8];
    u8  nguid[16];
    uuid_t  uuid;
};

struct nvme_ns_head {
    struct list_head    list;
    struct srcu_struct      srcu;
    struct nvme_subsystem   *subsys;
    unsigned        ns_id;
    struct nvme_ns_ids  ids;
    struct list_head    entry;
    struct kref     ref;
    int         instance;
#ifdef CONFIG_NVME_MULTIPATH
    struct gendisk      *disk;
    struct bio_list     requeue_list;
    spinlock_t      requeue_lock;
    struct work_struct  requeue_work;
    struct mutex        lock;
    unsigned long       flags;
#define NVME_NSHEAD_DISK_LIVE   0
    struct nvme_ns __rcu    *current_path[];
#endif
};

struct nvme_ns {
    struct list_head list;

    struct nvme_ctrl *ctrl;
    struct request_queue *queue;
    struct gendisk *disk;
#ifdef CONFIG_NVME_MULTIPATH
    enum nvme_ana_state ana_state;
    u32 ana_grpid;
#endif
    struct list_head siblings;
    struct nvm_dev *ndev;
    struct kref kref;
    struct nvme_ns_head *head;

    int lba_shift;
    u16 ms;
    u16 sgs;
    u32 sws;
    bool ext;
    u8 pi_type;
    unsigned long flags;
#define NVME_NS_REMOVING    0
#define NVME_NS_DEAD        1
#define NVME_NS_ANA_PENDING 2

    struct nvme_fault_inject fault_inject;
};

/*
 * An NVM Express queue.  Each device has at least two (one for admin
 * commands and one for I/O commands).
 */
struct nvme_queue {
    struct nvme_dev *dev;
    spinlock_t sq_lock;
    void *sq_cmds;
     /* only used for poll queues: */
    spinlock_t cq_poll_lock ____cacheline_aligned_in_smp;
    volatile struct nvme_completion *cqes;
    dma_addr_t sq_dma_addr;
    dma_addr_t cq_dma_addr;
    u32 __iomem *q_db;
    u16 q_depth;
    u16 cq_vector;
    u16 sq_tail;
    u16 last_sq_tail;
    u16 cq_head;
    u16 last_cq_head;
    u16 qid;
    u8 cq_phase;
    u8 sqes;
    unsigned long flags;
#define NVMEQ_ENABLED       0
#define NVMEQ_SQ_CMB        1
#define NVMEQ_DELETE_ERROR  2
#define NVMEQ_POLLED        3
    u32 *dbbuf_sq_db;
    u32 *dbbuf_cq_db;
    u32 *dbbuf_sq_ei;
    u32 *dbbuf_cq_ei;
    struct completion delete_done;
};

struct nvme_ctrl {
	bool comp_seen;
	enum nvme_ctrl_state state;
	bool identified;
	spinlock_t lock;
	struct mutex scan_lock;
	const struct nvme_ctrl_ops *ops;
	struct request_queue *admin_q;
	struct request_queue *connect_q;
	struct request_queue *fabrics_q;
	struct device *dev;
	int instance;
	int numa_node;
	struct blk_mq_tag_set *tagset;
	struct blk_mq_tag_set *admin_tagset;
	struct list_head namespaces;
	struct rw_semaphore namespaces_rwsem;
	struct device ctrl_device;
	struct device *device;	/* char device */
	struct cdev cdev;
	struct work_struct reset_work;
	struct work_struct delete_work;
	wait_queue_head_t state_wq;

	struct nvme_subsystem *subsys;
	struct list_head subsys_entry;

	struct opal_dev *opal_dev;

	char name[12];
	u16 cntlid;

	u32 ctrl_config;
	u16 mtfa;
	u32 queue_count;

	u64 cap;
	u32 page_size;
	u32 max_hw_sectors;
	u32 max_segments;
	u16 crdt[3];
	u16 oncs;
	u16 oacs;
	u16 nssa;
	u16 nr_streams;
	u16 sqsize;
	u32 max_namespaces;
	atomic_t abort_limit;
	u8 vwc;
	u32 vs;
	u32 sgls;
	u16 kas;
	u8 npss;
	u8 apsta;
	u32 oaes;
	u32 aen_result;
	u32 ctratt;
	unsigned int shutdown_timeout;
	unsigned int kato;
	bool subsystem;
	unsigned long quirks;
	struct nvme_id_power_state psd[32];
	struct nvme_effects_log *effects;
	struct work_struct scan_work;
	struct work_struct async_event_work;
	struct delayed_work ka_work;
	struct nvme_command ka_cmd;
	struct work_struct fw_act_work;
	unsigned long events;
	bool created;

#ifdef CONFIG_NVME_MULTIPATH
	/* asymmetric namespace access: */
	u8 anacap;
	u8 anatt;
	u32 anagrpmax;
	u32 nanagrpid;
	struct mutex ana_lock;
	struct nvme_ana_rsp_hdr *ana_log_buf;
	size_t ana_log_size;
	struct timer_list anatt_timer;
	struct work_struct ana_work;
#endif

	/* Power saving configuration */
	u64 ps_max_latency_us;
	bool apst_enabled;

	/* PCIe only: */
	u32 hmpre;
	u32 hmmin;
	u32 hmminds;
	u16 hmmaxd;

	/* Fabrics only */
	u32 ioccsz;
	u32 iorcsz;
	u16 icdoff;
	u16 maxcmd;
	int nr_reconnects;
	struct nvmf_ctrl_options *opts;

	struct page *discard_page;
	unsigned long discard_page_busy;

	struct nvme_fault_inject fault_inject;
};

/*
 * Represents an NVM Express device.  Each nvme_dev is a PCI function.
 */
struct nvme_dev {
    struct nvme_queue *queues;
    struct blk_mq_tag_set tagset;
    struct blk_mq_tag_set admin_tagset;
    u32 __iomem *dbs;
    struct device *dev;
    struct dma_pool *prp_page_pool;
    struct dma_pool *prp_small_pool;
    unsigned online_queues;
    unsigned max_qid;
    unsigned io_queues[HCTX_MAX_TYPES];
    unsigned int num_vecs;
    int q_depth;
    int io_sqes;
    u32 db_stride;
    void __iomem *bar;
    unsigned long bar_mapped_size;
    struct work_struct remove_work;
    struct mutex shutdown_lock;
    bool subsystem;
    u64 cmb_size;
    bool cmb_use_sqes;
    u32 cmbsz;
    u32 cmbloc;
    struct nvme_ctrl ctrl;
    u32 last_ps;

    mempool_t *iod_mempool;

    /* shadow doorbell buffer support: */
    u32 *dbbuf_dbs;
    dma_addr_t dbbuf_dbs_dma_addr;
    u32 *dbbuf_eis;
    dma_addr_t dbbuf_eis_dma_addr;

    /* host memory buffer support: */
    u64 host_mem_size;
    u32 nr_host_mem_descs;
    dma_addr_t host_mem_descs_dma;
    struct nvme_host_mem_buf_desc *host_mem_descs;
    void **host_mem_desc_bufs;
    unsigned int nr_allocated_queues;
    unsigned int nr_write_queues;
    unsigned int nr_poll_queues;
};

extern int nvme_submit_sync_cmd(struct request_queue *nvmeq, struct nvme_command *cmd,
        void *buffer, unsigned buffLen);
extern int nvme_set_features(struct nvme_ctrl *dev, unsigned int fid,
              unsigned int dword11, void *buffer, size_t buflen,
              u32 *result);
extern int nvme_get_features(struct nvme_ctrl *dev, unsigned int fid,
              unsigned int dword11, void *buffer, size_t buflen,
              u32 *result);
extern int find_vma_links(struct mm_struct *mm, unsigned long addr,
        unsigned long end, struct vm_area_struct **pprev,
        struct rb_node ***rb_link, struct rb_node **rb_parent);
extern void vma_link(struct mm_struct *mm, struct vm_area_struct *vma,
            struct vm_area_struct *prev, struct rb_node **rb_link,
            struct rb_node *rb_parent);


#endif
