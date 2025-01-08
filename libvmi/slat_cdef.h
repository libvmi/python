status_t vmi_slat_get_domain_state (
    vmi_instance_t vmi,
    bool *state);

status_t vmi_slat_set_domain_state (
    vmi_instance_t vmi,
    bool state);

status_t vmi_slat_create (
    vmi_instance_t vmi,
    uint16_t *slat_id);

status_t vmi_slat_destroy (
    vmi_instance_t vmi,
    uint16_t slat_idx);

status_t vmi_slat_switch (
    vmi_instance_t vmi,
    uint16_t slat_idx);

status_t vmi_slat_change_gfn (
    vmi_instance_t vmi,
    uint16_t slat_idx,
    addr_t old_gfn,
    addr_t new_gfn);

status_t vmi_slat_control (
    vmi_instance_t vmi, 
    bool *state);