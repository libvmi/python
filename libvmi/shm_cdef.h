typedef int            pid_t;

status_t vmi_shm_snapshot_create(
    vmi_instance_t vmi);

status_t vmi_shm_snapshot_destroy(
    vmi_instance_t vmi);

size_t vmi_get_dgpma(
    vmi_instance_t vmi,
    addr_t paddr,
    void **buf_ptr,
    size_t count);

size_t vmi_get_dgvma(
    vmi_instance_t vmi,
    addr_t vaddr,
    pid_t pid,
    void **buf_ptr,
    size_t count);
