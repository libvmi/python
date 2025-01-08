#define VMI_EVENTS_VERSION 0x00000009

typedef uint16_t vmi_event_type_t;

#define VMI_EVENT_INVALID           0
#define VMI_EVENT_MEMORY            1   /**< Read/write/execute on a region of memory */
#define VMI_EVENT_REGISTER          2   /**< Read/write of a specific register */
#define VMI_EVENT_SINGLESTEP        3   /**< Instructions being executed on a set of VCPUs */
#define VMI_EVENT_INTERRUPT         4   /**< Interrupts being delivered */
#define VMI_EVENT_GUEST_REQUEST     5   /**< Guest-requested event */
#define VMI_EVENT_CPUID             6   /**< CPUID event */
#define VMI_EVENT_DEBUG_EXCEPTION   7   /**< Debug exception event */
#define VMI_EVENT_PRIVILEGED_CALL   8   /**< Privileged call (ie. SMC on ARM) */
#define VMI_EVENT_DESCRIPTOR_ACCESS 9   /**< A descriptor table register was accessed */
#define VMI_EVENT_FAILED_EMULATION  10  /**< Emulation failed when requested by VMI_EVENT_RESPONSE_EMULATE */
#define VMI_EVENT_DOMAIN_WATCH      11  /**< Watch create/destroy events */


typedef uint8_t vmi_reg_access_t;

#define VMI_REGACCESS_INVALID   0
#define VMI_REGACCESS_N         ...
#define VMI_REGACCESS_R         ...
#define VMI_REGACCESS_W         ...
#define VMI_REGACCESS_RW        ...

// reg_event_t
typedef struct {
    reg_t reg;
    reg_t equal;
    uint8_t async;
    uint8_t onchange;
    vmi_reg_access_t in_access;
    vmi_reg_access_t out_access;
    ...;
    reg_t value;
    reg_t previous;
    uint32_t msr;
    ...;
} reg_event_t;


typedef uint8_t vmi_mem_access_t;

#define VMI_MEMACCESS_INVALID     ...
#define VMI_MEMACCESS_N           ...
#define VMI_MEMACCESS_R           ...
#define VMI_MEMACCESS_W           ...
#define VMI_MEMACCESS_X           ...
#define VMI_MEMACCESS_RW          ...
#define VMI_MEMACCESS_RX          ...
#define VMI_MEMACCESS_WX          ...
#define VMI_MEMACCESS_RWX         ...
#define VMI_MEMACCESS_W2X         ...
#define VMI_MEMACCESS_RWX2N       ...

// mem_access_event_t
typedef struct {
    addr_t gfn;
    uint8_t generic;
    vmi_mem_access_t in_access;
    vmi_mem_access_t out_access;
    uint8_t gptw;
    uint8_t gla_valid;
    ...;
    addr_t gla;
    addr_t offset;
} mem_access_event_t;

typedef uint8_t interrupts_t;

#define INT_INVALID     0
#define INT3            1
#define INT_NEXT        2

// interrupt_event_t
typedef struct {
    interrupts_t intr;
    ...;

    union {
        /* INT3 */
        struct {
            /* IN/OUT */
            uint32_t insn_length; /**< The instruction length to be used when reinjecting */

            /**
             * OUT
             *
             * Toggle, controls whether interrupt is re-injected after callback.
             *   Set reinject to 1 to deliver it to guest ("pass through" mode)
             *   Set reinject to 0 to swallow it silently without
             */
            int8_t reinject;
            ...;

            addr_t gla;         /**< (Global Linear Address) == RIP of the trapped instruction */
            addr_t gfn;         /**< (Guest Frame Number) == 'physical' page where trap occurred */
            addr_t offset;      /**< Offset in bytes (relative to GFN) */

            ...;
        };

        /* INT_NEXT */
        struct {
            /* OUT */
            uint32_t vector;
            uint32_t type;
            uint32_t error_code;
            ...;
            uint64_t cr2;
        };
    };
} interrupt_event_t;

// single_step_event_t
typedef struct {
    uint32_t vcpus;
    uint8_t enable;
    ...;
    addr_t gla;
    addr_t gfn;
    addr_t offset;
} single_step_event_t;

// debug_event_t
typedef struct {
    addr_t gla;
    addr_t gfn;
    addr_t offset;
    uint32_t insn_length;
    uint8_t type;
    int8_t reinject;
    ...;
} debug_event_t;

// cpuid_event_t
typedef struct {
    uint32_t insn_length; /**< Length of the reported instruction */
    uint32_t leaf;
    uint32_t subleaf;
    ...;
} cpuid_event_t;

// descriptor_event_t
typedef struct desriptor_event {
    union {
        struct {
            uint32_t instr_info;         /* VMX: VMCS Instruction-Information */
            ...;
            uint64_t exit_qualification; /* VMX: VMCS Exit Qualification */
        };
        uint64_t exit_info;              /* SVM: VMCB EXITINFO */
    };
    uint8_t descriptor;                  /* VMI_DESCRIPTOR_* */
    uint8_t is_write;
    ...;
} descriptor_event_t;

// vmi_event_t
struct vmi_event;
typedef struct vmi_event vmi_event_t;

typedef uint32_t event_response_flags_t;

#define VMI_EVENT_RESPONSE_NONE                 0
#define VMI_EVENT_RESPONSE_EMULATE              ...
#define VMI_EVENT_RESPONSE_EMULATE_NOWRITE      ...
#define VMI_EVENT_RESPONSE_SET_EMUL_READ_DATA   ...
#define VMI_EVENT_RESPONSE_DENY                 ...
#define VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP    ...
#define VMI_EVENT_RESPONSE_SLAT_ID              ...
#define VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID     ...
#define VMI_EVENT_RESPONSE_SET_REGISTERS        ...
#define VMI_EVENT_RESPONSE_SET_EMUL_INSN        ...
#define VMI_EVENT_RESPONSE_GET_NEXT_INTERRUPT   ...
#define __VMI_EVENT_RESPONSE_MAX 9

typedef uint32_t event_response_t;

typedef event_response_t (*event_callback_t)(vmi_instance_t vmi, vmi_event_t *event);

typedef void (*vmi_event_free_t)(vmi_event_t *event, status_t rc);

// vmi_event
struct vmi_event {
    uint32_t version;
    vmi_event_type_t type;
    uint16_t slat_id;
    uint16_t next_slat_id;
    ...;
    void *data;
    event_callback_t callback;
    uint32_t vcpu_id;
    page_mode_t page_mode;
    union {
        reg_event_t reg_event;
        mem_access_event_t mem_event;
        single_step_event_t ss_event;
        interrupt_event_t interrupt_event;
        cpuid_event_t cpuid_event;
        debug_event_t debug_event;
        descriptor_event_t descriptor_event;
    };
    union {
        union {
            x86_registers_t *x86_regs;
            arm_registers_t *arm_regs;
        };
        ...;
    };
};

// functions
status_t vmi_register_event(
    vmi_instance_t vmi,
    vmi_event_t *event);
    
status_t vmi_set_mem_event(
    vmi_instance_t vmi,
    addr_t gfn,
    vmi_mem_access_t access,
    uint16_t slat_id);

status_t vmi_events_listen(
    vmi_instance_t vmi,
    uint32_t timeout);

int vmi_are_events_pending(
    vmi_instance_t vmi);

status_t vmi_toggle_single_step_vcpu(
    vmi_instance_t vmi,
    vmi_event_t* event,
    uint32_t vcpu,
    bool enabled);

status_t vmi_clear_event(
    vmi_instance_t vmi,
    vmi_event_t *event,
    vmi_event_free_t free_routine);

// our generic callback
extern "Python" event_response_t generic_event_callback(
    vmi_instance_t vmi,
    vmi_event_t *event);
