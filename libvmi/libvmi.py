from builtins import bytes, object, str
from enum import Enum

from _libvmi import ffi, lib
from future.utils import raise_from

# export libvmi defines
INIT_DOMAINNAME = lib.VMI_INIT_DOMAINNAME
INIT_DOMAINID = lib.VMI_INIT_DOMAINID
INIT_EVENTS = lib.VMI_INIT_EVENTS


class LibvmiError(Exception):
    pass


class X86Reg(Enum):
    RAX = lib.RAX
    RBX = lib.RBX
    RCX = lib.RCX
    RDX = lib.RDX
    RBP = lib.RBP
    RSI = lib.RSI
    RDI = lib.RDI
    RSP = lib.RSP
    RIP = lib.RIP
    RFLAGS = lib.RFLAGS
    R8 = lib.R8
    R9 = lib.R9
    R10 = lib.R10
    R11 = lib.R11
    R12 = lib.R12
    R13 = lib.R13
    R14 = lib.R14
    R15 = lib.R15

    CR0 = lib.CR0
    CR2 = lib.CR2
    CR3 = lib.CR3
    CR4 = lib.CR4

    DR0 = lib.DR0
    DR1 = lib.DR1
    DR2 = lib.DR2
    DR3 = lib.DR3
    DR6 = lib.DR6
    DR7 = lib.DR7


class MSR(Enum):
    ANY = lib.MSR_ANY
    ALL = lib.MSR_ALL
    FLAGS = lib.MSR_FLAGS
    LSTAR = lib.MSR_LSTAR
    CSTAR = lib.MSR_CSTAR
    SYSCALL_MASK = lib.MSR_SYSCALL_MASK
    EFER = lib.MSR_EFER
    TSC_AUX = lib.MSR_TSC_AUX
    STAR = lib.MSR_STAR
    SHADOW_GS_BASE = lib.MSR_SHADOW_GS_BASE
    MTRRfix64K_00000 = lib.MSR_MTRRfix64K_00000
    MTRRfix16K_80000 = lib.MSR_MTRRfix16K_80000
    MTRRfix16K_A0000 = lib.MSR_MTRRfix16K_A0000
    MTRRfix4K_C0000 = lib.MSR_MTRRfix4K_C0000
    MTRRfix4K_C8000 = lib.MSR_MTRRfix4K_C8000
    MTRRfix4K_D0000 = lib.MSR_MTRRfix4K_D0000
    MTRRfix4K_D8000 = lib.MSR_MTRRfix4K_D8000
    MTRRfix4K_E0000 = lib.MSR_MTRRfix4K_E0000
    MTRRfix4K_E8000 = lib.MSR_MTRRfix4K_E8000
    MTRRfix4K_F0000 = lib.MSR_MTRRfix4K_E8000
    MTRRfix4K_F8000 = lib.MSR_MTRRfix4K_F8000
    MTRRdefType = lib.MSR_MTRRdefType
    IA32_MC0_CTL = lib.MSR_IA32_MC0_CTL
    IA32_MC0_STATUS = lib.MSR_IA32_MC0_STATUS
    IA32_MC0_ADDR = lib.MSR_IA32_MC0_ADDR
    IA32_MC0_MISC = lib.MSR_IA32_MC0_MISC
    IA32_MC1_CTL = lib.MSR_IA32_MC1_CTL
    IA32_MC0_CTL2 = lib.MSR_IA32_MC0_CTL2
    AMD_PATCHLEVEL = lib.MSR_AMD_PATCHLEVEL
    AMD64_TSC_RATIO = lib.MSR_AMD64_TSC_RATIO
    IA32_P5_MC_ADDR = lib.MSR_IA32_P5_MC_ADDR
    IA32_P5_MC_TYPE = lib.MSR_IA32_P5_MC_TYPE
    IA32_TSC = lib.MSR_IA32_TSC
    IA32_PLATFORM_ID = lib.MSR_IA32_PLATFORM_ID
    IA32_EBL_CR_POWERON = lib.MSR_IA32_EBL_CR_POWERON
    IA32_EBC_FREQUENCY_ID = lib.MSR_IA32_EBC_FREQUENCY_ID
    IA32_FEATURE_CONTROL = lib.MSR_IA32_FEATURE_CONTROL
    IA32_SYSENTER_CS = lib.MSR_IA32_SYSENTER_CS
    IA32_SYSENTER_ESP = lib.MSR_IA32_SYSENTER_ESP
    IA32_SYSENTER_EIP = lib.MSR_IA32_SYSENTER_EIP
    IA32_MISC_ENABLE = lib.MSR_IA32_MISC_ENABLE
    HYPERVISOR = lib.MSR_HYPERVISOR


class Registers:
    """
    This class acts as a wrapper on top of
    vmi.get_vcpuregs and vmi.set_vcpuregs methods, only for x86.

    It is meant to be used as a dictionary:
    regs = vmi.get_vcpuregs(0)
    regs[X86Reg.RIP]

    regs = Registers()
    regs[X86Reg.RAX] = 0x42
    regs[X86Reg.RSP] = 0xabcd
    vmi.set_vcpuregs(regs, 0)

    for ARM architecture, there is no wrapper yet,
    use directly the cffi struct:
    regs = vmi.get_vcpuregs(0)
    regs.cffi_regs.arm.xxx
    """

    def __init__(self, regs=None):
        self.cffi_regs = regs
        if not self.cffi_regs:
            self.cffi_regs = ffi.new('registers_t *')

    def __getitem__(self, index):
        # index should be an enum
        # only x86regs supported for now
        if not isinstance(index, X86Reg):
            raise RuntimeError('Must be an X86Reg enum value')
        try:
            return getattr(self.cffi_regs.x86, index.name.lower())
        except AttributeError as e:
            raise_from(RuntimeError('Unknown field {} in regs.x86'
                                    .format(index.name.lower())), e)

    def __setitem__(self, index, value):
        # index should be an enum
        # only x86regs supported for now
        if not isinstance(index, X86Reg):
            raise RuntimeError('Must be an X86Reg enum value')
        try:
            setattr(self.cffi_regs.x86, index.name.lower(), value)
        except AttributeError as e:
            raise_from(RuntimeError('Unknown field {} in regs.x86'
                                    .format(index.name.lower())), e)


class VMIMode(Enum):
    XEN = lib.VMI_XEN
    KVM = lib.VMI_KVM
    FILE = lib.VMI_FILE


class VMIConfig(Enum):
    GLOBAL_FILE_ENTRY = lib.VMI_CONFIG_GLOBAL_FILE_ENTRY
    STRING = lib.VMI_CONFIG_STRING
    DICT = lib.VMI_CONFIG_GHASHTABLE


class VMIStatus(Enum):
    SUCCESS = lib.VMI_SUCCESS
    FAILURE = lib.VMI_FAILURE


class LibvmiInitError(Enum):
    NONE = lib.VMI_INIT_ERROR_NONE
    DRIVER_NOT_DETECTED = lib.VMI_INIT_ERROR_DRIVER_NOT_DETECTED
    DRIVER = lib.VMI_INIT_ERROR_DRIVER
    VM_NOT_FOUND = lib.VMI_INIT_ERROR_VM_NOT_FOUND
    PAGING = lib.VMI_INIT_ERROR_PAGING
    OS = lib.VMI_INIT_ERROR_OS
    EVENTS = lib.VMI_INIT_ERROR_EVENTS
    NO_CONFIG = lib.VMI_INIT_ERROR_NO_CONFIG
    NO_CONFIG_ENTRY = lib.VMI_INIT_ERROR_NO_CONFIG_ENTRY


class PageMode(Enum):
    UNKNOWN = lib.VMI_PM_UNKNOWN
    LEGACY = lib.VMI_PM_LEGACY
    PAE = lib.VMI_PM_PAE
    IA32E = lib.VMI_PM_IA32E
    AARCH32 = lib.VMI_PM_AARCH32
    AARCH64 = lib.VMI_PM_AARCH64


class VMIArch(Enum):
    VMI_ARCH_UNKNOWN = lib.VMI_PM_UNKNOWN
    VMI_ARCH_X86 = lib.VMI_ARCH_X86
    VMI_ARCH_X86_64 = lib.VMI_ARCH_X86_64
    VMI_ARCH_ARM32 = lib.VMI_ARCH_ARM32
    VMI_ARCH_ARM64 = lib.VMI_ARCH_ARM64


class VMIOS(Enum):
    UNKNOWN = lib.VMI_OS_UNKNOWN
    LINUX = lib.VMI_OS_LINUX
    WINDOWS = lib.VMI_OS_WINDOWS


class VMIWinVer(Enum):
    OS_WINDOWS_NONE = lib.VMI_OS_WINDOWS_NONE
    OS_WINDOWS_UNKNOWN = lib.VMI_OS_WINDOWS_UNKNOWN
    OS_WINDOWS_2000 = lib.VMI_OS_WINDOWS_2000
    OS_WINDOWS_XP = lib.VMI_OS_WINDOWS_XP
    OS_WINDOWS_2003 = lib.VMI_OS_WINDOWS_2003
    OS_WINDOWS_VISTA = lib.VMI_OS_WINDOWS_VISTA
    OS_WINDOWS_2008 = lib.VMI_OS_WINDOWS_2008
    OS_WINDOWS_7 = lib.VMI_OS_WINDOWS_7
    OS_WINDOWS_8 = lib.VMI_OS_WINDOWS_8
    OS_WINDOWS_10 = lib.VMI_OS_WINDOWS_10


class TranslateMechanism(Enum):
    INVALID = lib.VMI_TM_INVALID
    NONE = lib.VMI_TM_NONE
    PROCESS_DTB = lib.VMI_TM_PROCESS_DTB
    PROCESS_PID = lib.VMI_TM_PROCESS_PID
    KERNEL_SYMBOL = lib.VMI_TM_KERNEL_SYMBOL


class VMIInitData(Enum):
    XEN_EVTCHN = lib.VMI_INIT_DATA_XEN_EVTCHN
    MEMMAP = lib.VMI_INIT_DATA_MEMMAP
    KVMI_SOCKET = lib.VMI_INIT_DATA_KVMI_SOCKET


class AccessContext(object):

    def __init__(self, tr_mechanism=TranslateMechanism.NONE, addr=0,
                 ksym=None, dtb=0, pid=0):
        if not isinstance(tr_mechanism, TranslateMechanism):
            raise RuntimeError('must specify a valid TranslateMechanism')

        self.tr_mechanism = tr_mechanism
        if self.tr_mechanism == TranslateMechanism.KERNEL_SYMBOL:
            if not isinstance(ksym, str):
                raise RuntimeError("ksym must be a string")
            self.ksym = ksym
        self.addr = addr
        self.dtb = dtb
        self.pid = pid

    def to_ffi(self):
        ffi_ctx = ffi.new("access_context_t *")
        ffi_ctx.translate_mechanism = self.tr_mechanism.value
        if self.tr_mechanism == TranslateMechanism.KERNEL_SYMBOL:
            ffi_ctx.ksym = ffi.new("char []", self.ksym.encode())
        else:
            ffi_ctx.addr = self.addr
            ffi_ctx.dtb = self.dtb
            ffi_ctx.pid = self.pid
        return ffi_ctx


class PageInfo(object):

    def __init__(self, cffi_pageinfo):
        self.vaddr = cffi_pageinfo.vaddr
        self.dtb = cffi_pageinfo.dtb
        self.paddr = cffi_pageinfo.paddr
        self.size = cffi_pageinfo.size
        # TODO page mode


def check(status, error='VMI_FAILURE'):
    if VMIStatus(status) != VMIStatus.SUCCESS:
        raise LibvmiError(error)


class Libvmi(object):
    __slots__ = (
        'opaque_vmi',
        'vmi',
    )

    def __init__(self, domain, init_flags=INIT_DOMAINNAME, init_data=None,
                 config_mode=VMIConfig.GLOBAL_FILE_ENTRY, config=ffi.NULL,
                 mode=None, partial=False):
        self.vmi = ffi.NULL
        self.opaque_vmi = ffi.new("vmi_instance_t *")
        init_error = ffi.new("vmi_init_error_t *")
        # avoid GC to free ghashtable inserted values
        ghash_ref = dict()
        ghash = None
        # keep references on ffi buffers, avoid issues with GC
        ffi_refs = {
            'init_data': []
        }
        init_data_ffi = ffi.NULL
        if init_data:
            init_data_ffi = ffi.new("vmi_init_data_t *", {"entry": len(init_data)})
            init_data_ffi.count = len(init_data)
            for i, (e_type, e_value) in enumerate(init_data.items()):
                init_data_ffi.entry[i].type = e_type.value
                if not isinstance(e_value, str):
                    raise RuntimeError("Passing anything else than a string as init_data value is not implemented")
                ref = e_value.encode()
                init_data_ffi.entry[i].data = ffi.from_buffer(ref)
                # keep a ref !
                ffi_refs['init_data'].append(ref)
        if partial:
            # vmi_init
            if not mode:
                # calling vmi_get_access_mode to auto determine vmi_mode
                mode = self.get_access_mode(domain, init_flags, init_data_ffi)
            if not isinstance(mode, VMIMode):
                raise RuntimeError("mode is not an instance of VMIMode")
            if (not init_flags & INIT_DOMAINNAME and
                    not init_flags & INIT_DOMAINID):
                raise RuntimeError("Partial init, init_flags must be either"
                                   "INIT_DOMAINAME or INIT_DOMAINID")
            domain = domain.encode()

            status = lib.vmi_init(self.opaque_vmi,
                                  mode.value,
                                  domain,
                                  init_flags,
                                  init_data_ffi,
                                  init_error)
        else:
            # vmi_init_complete
            # if INIT_DOMAINNAME, we need to encode the string
            # from str to bytes
            if init_flags & INIT_DOMAINNAME or init_flags & INIT_DOMAINID:
                domain = domain.encode()
            # same for VMI_CONFIG_STRING
            if config_mode == VMIConfig.STRING:
                config = config.encode()
            elif config_mode == VMIConfig.DICT:
                # need to convert config to a GHashTable
                g_str_hash_addr = ffi.addressof(lib, "g_str_hash")
                g_str_equal_addr = ffi.addressof(lib, "g_str_equal")
                ghash = lib.g_hash_table_new(g_str_hash_addr,
                                             g_str_equal_addr)

                for k, v in list(config.items()):
                    key = k.encode()
                    if isinstance(v, str):
                        value = v.encode()
                    elif isinstance(v, int):
                        value = ffi.new("int*", v)
                    else:
                        raise RuntimeError("Invalid value {} in config"
                                           .format(v))
                    lib.g_hash_table_insert(ghash, key, value)
                    # keep a reference to avoid GC
                    ghash_ref[key] = value

                config = ghash

            # init libvmi
            status = lib.vmi_init_complete(self.opaque_vmi,
                                           domain,
                                           init_flags,
                                           init_data_ffi,
                                           config_mode.value,
                                           config,
                                           init_error)
        error_msg = LibvmiInitError(init_error[0]).name
        check(status, error_msg)
        # store handle to real vmi_instance_t
        self.vmi = self.opaque_vmi[0]
        # destroy ghashtable if necessary
        if ghash is not None:
            lib.g_hash_table_destroy(ghash)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.destroy()

    def init_paging(self, flags):
        page_mode = lib.vmi_init_paging(self.vmi, flags)
        return PageMode(page_mode)

    def init_os(self, config_mode=VMIConfig.GLOBAL_FILE_ENTRY,
                config=ffi.NULL):
        init_error = ffi.new("vmi_init_error_t *")
        ghash_ref = dict()
        if config_mode == VMIConfig.STRING:
            config = config.encode()
        elif config_mode == VMIConfig.DICT:
            # need to convert config to a GHashTable
            g_str_hash_addr = ffi.addressof(lib, "g_str_hash")
            g_str_equal_addr = ffi.addressof(lib, "g_str_equal")
            ghash = lib.g_hash_table_new(g_str_hash_addr, g_str_equal_addr)

            for k, v in list(config.items()):
                key = k.encode()
                if isinstance(v, str):
                    value = v.encode()
                elif isinstance(v, int):
                    value = ffi.new("int*", v)
                else:
                    raise RuntimeError("Invalid value {} in config".format(v))
                lib.g_hash_table_insert(ghash, key, value)
                # keep a reference to avoid GC
                ghash_ref[key] = value

            config = ghash
        os = lib.vmi_init_os(self.vmi, config_mode.value, config, init_error)
        return VMIOS(os), init_error[0]

    def destroy(self):
        if self.vmi:
            status = lib.vmi_destroy(self.vmi)
            check(status)
        self.opaque_vmi = None
        self.vmi = None

    def get_library_arch(self):
        arch = lib.vmi_get_library_arch()
        return VMIArch(arch)

    def get_rekall_path(self):
        value = lib.vmi_get_rekall_path(self.vmi)
        if value == ffi.NULL:
            return None
        return ffi.string(value).decode()

    # memory translations
    def translate_kv2p(self, vaddr):
        paddr = ffi.new("addr_t *")
        status = lib.vmi_translate_kv2p(self.vmi, vaddr, paddr)
        check(status)
        return paddr[0]

    def translate_uv2p(self, vaddr, pid):
        paddr = ffi.new("addr_t *")
        status = lib.vmi_translate_uv2p(self.vmi, vaddr, pid, paddr)
        check(status)
        return paddr[0]

    def translate_ksym2v(self, symbol):
        vaddr = ffi.new("addr_t *")
        status = lib.vmi_translate_ksym2v(self.vmi, symbol.encode(), vaddr)
        check(status)
        return vaddr[0]

    def translate_sym2v(self, ctx, symbol):
        vaddr = ffi.new("addr_t *")
        status = lib.vmi_translate_sym2v(self.vmi, ctx.to_ffi(),
                                         symbol.encode(), vaddr)
        check(status)
        return vaddr[0]

    def translate_v2sym(self, ctx, addr):
        symbol = lib.vmi_translate_v2sym(self.vmi, ctx.to_ffi(), addr)
        if symbol == ffi.NULL:
            raise LibvmiError('VMI_FAILURE')
        return ffi.string(symbol).decode()

    def translate_v2ksym(self, ctx, addr):
        symbol = lib.vmi_translate_v2ksym(self.vmi, ctx.to_ffi(), addr)
        if symbol == ffi.NULL:
            raise LibvmiError('VMI_FAILURE')
        return ffi.string(symbol).decode()

    def pid_to_dtb(self, pid):
        dtb = ffi.new('addr_t *')
        status = lib.vmi_pid_to_dtb(self.vmi, pid, dtb)
        check(status)
        return dtb[0]

    def dtb_to_pid(self, dtb):
        pid = ffi.new("vmi_pid_t *")
        status = lib.vmi_dtb_to_pid(self.vmi, dtb, pid)
        check(status)
        return pid[0]

    def pagetable_lookup(self, dtb, vaddr):
        paddr = ffi.new("addr_t *")
        status = lib.vmi_pagetable_lookup(self.vmi, dtb, vaddr, paddr)
        check(status)
        return paddr[0]

    def pagetable_lookup_extended(self, dtb, vaddr):
        page_info = ffi.new("page_info_t *")
        status = lib.vmi_pagetable_lookup_extended(self.vmi, dtb, vaddr,
                                                   page_info)
        check(status)
        return page_info

    # read
    def read(self, ctx, count):
        buffer = ffi.new("char[]", count)
        bytes_read = ffi.new("size_t *")
        status = lib.vmi_read(self.vmi, ctx.to_ffi(), count, buffer,
                              bytes_read)
        check(status)
        # transform into Python bytes
        buffer = ffi.unpack(buffer, bytes_read[0])
        return buffer, bytes_read[0]

    def read_8(self, ctx):
        value = ffi.new("uint8_t *")
        status = lib.vmi_read_8(self.vmi, ctx.to_ffi(), value)
        check(status)
        return value[0]

    def read_16(self, ctx):
        value = ffi.new("uint16_t *")
        status = lib.vmi_read_16(self.vmi, ctx.to_ffi(), value)
        check(status)
        return value[0]

    def read_32(self, ctx):
        value = ffi.new("uint32_t *")
        status = lib.vmi_read_32(self.vmi, ctx.to_ffi(), value)
        check(status)
        return value[0]

    def read_64(self, ctx):
        value = ffi.new("uint64_t *")
        status = lib.vmi_read_64(self.vmi, ctx.to_ffi(), value)
        check(status)
        return value[0]

    def read_addr(self, ctx):
        value = ffi.new("addr_t *")
        status = lib.vmi_read_addr(self.vmi, ctx.to_ffi(), value)
        check(status)
        return value[0]

    def read_str(self, ctx):
        value = lib.vmi_read_str(self.vmi, ctx.to_ffi())
        if value == ffi.NULL:
            raise LibvmiError('VMI_FAILURE')
        return ffi.string(value).decode()

    def read_unicode_str(self, ctx):
        value = lib.vmi_read_unicode_str(self.vmi, ctx.to_ffi())
        if value == ffi.NULL:
            raise LibvmiError('VMI_FAILURE')
        encoding = ffi.string(value.encoding).decode()
        buffer = ffi.string(value.contents, value.length)
        self.free_unicode_str(value)
        return buffer.decode(encoding)

    def read_ksym(self, symbol, count):
        buffer = ffi.new("char[]", count)
        bytes_read = ffi.new("size_t *")
        status = lib.vmi_read_ksym(self.vmi, symbol.encode(), count, buffer,
                                   bytes_read)
        check(status)
        # transform into Python bytes
        buffer = ffi.string(buffer, bytes_read[0])
        return buffer, bytes_read[0]

    def read_va(self, vaddr, pid, count):
        buffer = ffi.new("char[]", count)
        bytes_read = ffi.new("size_t *")
        status = lib.vmi_read_va(self.vmi, vaddr, pid, count, buffer,
                                 bytes_read)
        check(status)
        # transform into Python bytes
        buffer = ffi.unpack(buffer, bytes_read[0])
        return buffer, bytes_read[0]

    def read_pa(self, paddr, count, padding=False):
        buffer = ffi.new("char[]", count)
        bytes_read = ffi.new("size_t *")
        status = lib.vmi_read_pa(self.vmi, paddr, count, buffer, bytes_read)
        # transform into Python bytes
        buffer = ffi.unpack(buffer, bytes_read[0])
        if padding:
            if VMIStatus(status) == VMIStatus.FAILURE:
                # pad with zeroes
                pad_size = count - bytes_read[0]
                buffer += bytes(pad_size)
        else:
            check(status)
        return buffer, bytes_read[0]

    def read_8_ksym(self, symbol):
        value = ffi.new("uint8_t *")
        status = lib.vmi_read_8_ksym(self.vmi, symbol.encode(), value)
        check(status)
        return value[0]

    def read_16_ksym(self, symbol):
        value = ffi.new("uint16_t *")
        status = lib.vmi_read_16_ksym(self.vmi, symbol.encode(), value)
        check(status)
        return value[0]

    def read_32_ksym(self, symbol):
        value = ffi.new("uint32_t *")
        status = lib.vmi_read_32_ksym(self.vmi, symbol.encode(), value)
        check(status)
        return value[0]

    def read_64_ksym(self, symbol):
        value = ffi.new("uint64_t *")
        status = lib.vmi_read_64_ksym(self.vmi, symbol.encode(), value)
        check(status)
        return value[0]

    def read_addr_ksym(self, symbol):
        value = ffi.new("addr_t *")
        status = lib.vmi_read_addr_ksym(self.vmi, symbol.encode(), value)
        check(status)
        return value[0]

    def read_8_va(self, vaddr, pid):
        value = ffi.new("uint8_t *")
        status = lib.vmi_read_8_va(self.vmi, vaddr, pid, value)
        check(status)
        return value[0]

    def read_16_va(self, vaddr, pid):
        value = ffi.new("uint16_t *")
        status = lib.vmi_read_16_va(self.vmi, vaddr, pid, value)
        check(status)
        return value[0]

    def read_32_va(self, vaddr, pid):
        value = ffi.new("uint32_t *")
        status = lib.vmi_read_32_va(self.vmi, vaddr, pid, value)
        check(status)
        return value[0]

    def read_64_va(self, vaddr, pid):
        value = ffi.new("uint64_t *")
        status = lib.vmi_read_64_va(self.vmi, vaddr, pid, value)
        check(status)
        return value[0]

    def read_addr_va(self, vaddr, pid):
        value = ffi.new("addr_t *")
        status = lib.vmi_read_addr_va(self.vmi, vaddr, pid, value)
        check(status)
        return value[0]

    def read_str_va(self, vaddr, pid):
        value = lib.vmi_read_str_va(self.vmi, vaddr, pid)
        if value == ffi.NULL:
            raise LibvmiError('VMI_FAILURE')
        return ffi.string(value).decode()

    def read_unicode_str_va(self, vaddr, pid):
        value = lib.vmi_read_unicode_str_va(self.vmi, vaddr, pid)
        if value == ffi.NULL:
            raise LibvmiError('VMI_FAILURE')
        encoding = ffi.string(value.encoding).decode()
        buffer = ffi.string(value.contents, value.length)
        self.free_unicode_str(value)
        return buffer.decode(encoding)

    # TODO convert_str_encoding

    def free_unicode_str(self, unicode_str):
        lib.vmi_free_unicode_str(unicode_str)

    def read_8_pa(self, paddr):
        value = ffi.new("uint8_t *")
        status = lib.vmi_read_8_pa(self.vmi, paddr, value)
        check(status)
        return value[0]

    def read_16_pa(self, paddr):
        value = ffi.new("uint16_t *")
        status = lib.vmi_read_16_pa(self.vmi, paddr, value)
        check(status)
        return value[0]

    def read_32_pa(self, paddr):
        value = ffi.new("uint32_t *")
        status = lib.vmi_read_32_pa(self.vmi, paddr, value)
        check(status)
        return value[0]

    def read_64_pa(self, paddr):
        value = ffi.new("uint64_t *")
        status = lib.vmi_read_64_pa(self.vmi, paddr, value)
        check(status)
        return value[0]

    def read_addr_pa(self, paddr):
        value = ffi.new("addr_t *")
        status = lib.vmi_read_addr_pa(self.vmi, paddr, value)
        check(status)
        return value[0]

    def read_str_pa(self, paddr):
        value = lib.vmi_read_str_pa(self.vmi, paddr)
        if value == ffi.NULL:
            raise LibvmiError('VMI_FAILURE')
        return ffi.string(value).decode()

    # write
    def write(self, ctx, buffer):
        cffi_buffer = ffi.from_buffer(buffer)
        bytes_written = ffi.new("size_t *")
        count = len(buffer)
        status = lib.vmi_write(self.vmi, ctx.to_ffi(), count, cffi_buffer,
                               bytes_written)
        check(status)
        return bytes_written[0]

    def write_ksym(self, symbol, buffer):
        cffi_buffer = ffi.from_buffer(buffer)
        bytes_written = ffi.new("size_t *")
        count = len(buffer)
        status = lib.vmi_write_ksym(self.vmi, symbol, count, cffi_buffer,
                                    bytes_written)
        check(status)
        return bytes_written[0]

    def write_va(self, vaddr, pid, buffer):
        cffi_buffer = ffi.from_buffer(buffer)
        bytes_written = ffi.new("size_t *")
        count = len(buffer)
        status = lib.vmi_write_va(self.vmi, vaddr, pid, count, cffi_buffer,
                                  bytes_written)
        check(status)
        return bytes_written[0]

    def write_pa(self, paddr, buffer):
        cffi_buffer = ffi.from_buffer(buffer)
        bytes_written = ffi.new("size_t *")
        count = len(buffer)
        status = lib.vmi_write_pa(self.vmi, paddr, count, cffi_buffer,
                                  bytes_written)
        check(status)
        return bytes_written[0]

    def write_8(self, ctx, value):
        cffi_value = ffi.new("uint8_t *", value)
        status = lib.vmi_write_8(self.vmi, ctx.to_ffi(), cffi_value)
        check(status)

    def write_16(self, ctx, value):
        cffi_value = ffi.new("uint16_t *", value)
        status = lib.vmi_write_16(self.vmi, ctx.to_ffi(), cffi_value)
        check(status)

    def write_32(self, ctx, value):
        cffi_value = ffi.new("uint32_t *", value)
        status = lib.vmi_write_32(self.vmi, ctx.to_ffi(), cffi_value)
        check(status)

    def write_64(self, ctx, value):
        cffi_value = ffi.new("uint64_t *", value)
        status = lib.vmi_write_64(self.vmi, ctx.to_ffi(), cffi_value)
        check(status)

    def write_addr(self, ctx, value):
        cffi_value = ffi.new("addr_t *", value)
        status = lib.vmi_write_addr(self.vmi, ctx.to_ffi(), cffi_value)
        check(status)

    def write_8_ksym(self, symbol, value):
        cffi_value = ffi.new("uint8_t *", value)
        status = lib.vmi_write_8_ksym(self.vmi, symbol.encode(), cffi_value)
        check(status)

    def write_16_ksym(self, symbol, value):
        cffi_value = ffi.new("uint16_t *", value)
        status = lib.vmi_write_16_ksym(self.vmi, symbol.encode(), cffi_value)
        check(status)

    def write_32_ksym(self, symbol, value):
        cffi_value = ffi.new("uint32_t *", value)
        status = lib.vmi_write_32_ksym(self.vmi, symbol.encode(), cffi_value)
        check(status)

    def write_64_ksym(self, symbol, value):
        cffi_value = ffi.new("uint64_t *", value)
        status = lib.vmi_write_64_ksym(self.vmi, symbol.encode(), cffi_value)
        check(status)

    def write_addr_ksym(self, symbol, value):
        cffi_value = ffi.new("addr_t *", value)
        status = lib.vmi_write_addr_ksym(self.vmi, symbol.encode(), cffi_value)
        check(status)

    def write_8_va(self, vaddr, pid, value):
        cffi_value = ffi.new("uint8_t *", value)
        status = lib.vmi_write_8_va(self.vmi, vaddr, pid, cffi_value)
        check(status)

    def write_16_va(self, vaddr, pid, value):
        cffi_value = ffi.new("uint16_t *", value)
        status = lib.vmi_write_16_va(self.vmi, vaddr, pid, cffi_value)
        check(status)

    def write_32_va(self, vaddr, pid, value):
        cffi_value = ffi.new("uint32_t *", value)
        status = lib.vmi_write_32_va(self.vmi, vaddr, pid, cffi_value)
        check(status)

    def write_64_va(self, vaddr, pid, value):
        cffi_value = ffi.new("uint64_t *", value)
        status = lib.vmi_write_64_va(self.vmi, vaddr, pid, cffi_value)
        check(status)

    def write_addr_va(self, vaddr, pid, value):
        cffi_value = ffi.new("addr_t *", value)
        status = lib.vmi_write_addr_va(self.vmi, vaddr, pid, cffi_value)
        check(status)

    def write_8_pa(self, paddr, value):
        cffi_value = ffi.new("uint8_t *", value)
        status = lib.vmi_write_8_pa(self.vmi, paddr, cffi_value)
        check(status)

    def write_16_pa(self, paddr, value):
        cffi_value = ffi.new("uint16_t *", value)
        status = lib.vmi_write_16_pa(self.vmi, paddr, cffi_value)
        check(status)

    def write_32_pa(self, paddr, value):
        cffi_value = ffi.new("uint32_t *", value)
        status = lib.vmi_write_32_pa(self.vmi, paddr, cffi_value)
        check(status)

    def write_64_pa(self, paddr, value):
        cffi_value = ffi.new("uint64_t *", value)
        status = lib.vmi_write_64_pa(self.vmi, paddr, cffi_value)
        check(status)

    def write_addr_pa(self, paddr, value):
        cffi_value = ffi.new("addr_t *", value)
        status = lib.vmi_write_addr_pa(self.vmi, paddr, cffi_value)
        check(status)

    # print functions
    # TODO vmi_print_hex
    # TODO vmi_print_hex_ksym
    # TODO vmi_print_hex_va
    # TODO vmi_print_hex_pa

    # get_*
    def get_name(self):
        value = lib.vmi_get_name(self.vmi)
        if value == ffi.NULL:
            raise LibvmiError('VMI_FAILURE')
        return ffi.string(value).decode()

    def get_vmid(self):
        return lib.vmi_get_vmid(self.vmi)

    def get_access_mode(self, domain, init_flags, init_data):
        if not init_flags & INIT_DOMAINNAME and not init_flags & INIT_DOMAINID:
            raise RuntimeError(
                "init_flags must be either INIT_DOMAINAME or INIT_DOMAINID")
        domain = domain.encode()
        cffi_mode = ffi.new("vmi_mode_t *")
        status = lib.vmi_get_access_mode(self.vmi, domain, init_flags,
                                         init_data, cffi_mode)
        check(status)
        return VMIMode(cffi_mode[0])

    def get_page_mode(self, vcpu):
        page_mode = lib.vmi_get_page_mode(self.vmi, vcpu)
        return PageMode(page_mode)

    def get_address_width(self):
        return lib.vmi_get_address_width(self.vmi)

    def get_ostype(self):
        os = lib.vmi_get_ostype(self.vmi)
        return VMIOS(os)

    def get_winver(self):
        win_ver = lib.vmi_get_winver(self.vmi)
        return VMIWinVer(win_ver)

    def get_winver_str(self):
        value = lib.vmi_get_winver_str(self.vmi)
        if value == ffi.NULL:
            raise LibvmiError('VMI_FAILURE')
        return ffi.string(value).decode()

    def get_winver_manual(self, kdvb_pa):
        win_ver = lib.vmi_get_winver_manual(self.vmi, kdvb_pa)
        return VMIWinVer(win_ver)

    def get_offset(self, offset_name):
        offset = ffi.new("addr_t *")
        status = lib.vmi_get_offset(self.vmi, offset_name.encode(), offset)
        check(status)
        return offset[0]

    def get_kernel_struct_offset(self, struct_name, member):
        value = ffi.new("addr_t *")
        status = lib.vmi_get_kernel_struct_offset(self.vmi,
                                                  struct_name.encode(),
                                                  member.encode(), value)
        check(status)
        return value[0]

    def get_memsize(self):
        return lib.vmi_get_memsize(self.vmi)

    def get_max_physical_memory_address(self):
        return lib.vmi_get_max_physical_memory_address(self.vmi)

    def get_num_vcpus(self):
        return lib.vmi_get_num_vcpus(self.vmi)

    def request_page_fault(self, vcpu, vaddr, error_code):
        status = lib.vmi_request_page_fault(self.vmi, vcpu, vaddr, error_code)
        check(status)

    # TODO needs a reg_t
    def get_vcpureg(self, reg, vcpu):
        value = ffi.new("uint64_t *")
        status = lib.vmi_get_vcpureg(self.vmi, value, reg, vcpu)
        check(status)
        return value[0]

    def get_vcpuregs(self, vcpu):
        registers_t = ffi.new("registers_t *")
        status = lib.vmi_get_vcpuregs(self.vmi, registers_t, vcpu)
        check(status)
        return Registers(registers_t)

    # TODO same thing, needs a wrapper
    def set_vcpureg(self, value, reg, vcpu):
        status = lib.vmi_set_vcpureg(self.vmi, value, reg, vcpu)
        check(status)

    def set_vcpuregs(self, regs, vcpu):
        status = lib.vmi_set_vcpuregs(self.vmi, regs.cffi_regs, vcpu)
        check(status)

    def pause_vm(self):
        status = lib.vmi_pause_vm(self.vmi)
        check(status)

    def resume_vm(self):
        status = lib.vmi_resume_vm(self.vmi)
        check(status)

    # caches
    def v2pcache_flush(self, dtb=0):
        lib.vmi_v2pcache_flush(self.vmi, dtb)

    def v2pcache_add(self, va, dtb, pa):
        lib.vmi_v2pcache_add(self.vmi, va, dtb, pa)

    def symcache_flush(self):
        lib.vmi_symcache_flush(self.vmi)

    def symcache_add(self, base_addr, pid, symbol, va):
        lib.vmi_symcache_add(self.vmi, base_addr, pid, symbol.encode(), va)

    def rvacache_flush(self):
        lib.vmi_rvacache_flush(self.vmi)

    def rvacache_add(self, base_addr, pid, rva, symbol):
        lib.vmi_symcache_add(self.vmi, base_addr, pid, rva, symbol.encode())

    def pidcache_flush(self):
        lib.vmi_pidcache_flush(self.vmi)

    def pidcache_add(self, pid, dtb):
        lib.vmi_pidcache_add(self.vmi, pid, dtb)

    # events
    def register_event(self, event):
        event.vmi = self
        cffi_event = event.to_cffi()
        status = lib.vmi_register_event(self.vmi, cffi_event)
        check(status)

    def clear_event(self, event):
        cffi_event = event.to_cffi()
        status = lib.vmi_clear_event(self.vmi, cffi_event, ffi.NULL)
        check(status)

    def listen(self, timeout):
        status = lib.vmi_events_listen(self.vmi, timeout)
        check(status)

    def are_events_pending(self):
        events_pending = lib.vmi_are_events_pending(self.vmi)
        return events_pending

    def toggle_single_step_vcpu(self, event, vcpu, enabled):
        cffi_event = event.to_cffi()
        status = lib.vmi_toggle_single_step_vcpu(self.vmi, cffi_event, vcpu, enabled)
        check(status)

    # extra
    def get_va_pages(self, dtb):
        cffi_va_pages = lib.vmi_get_va_pages(self.vmi, dtb)
        loop = cffi_va_pages
        va_pages = []
        while loop:
            cffi_page_info = ffi.cast("page_info_t *", loop.data)
            page_info = PageInfo(cffi_page_info)
            va_pages.append(page_info)
            # free data
            lib.g_free(loop.data)
            loop = loop.next
        lib.g_slist_free(cffi_va_pages)
        return va_pages

    # slat
    def slat_get_domain_state(self):
        state = ffi.new("bool *")
        status = lib.vmi_slat_get_domain_state(self.vmi, state)
        check(status)
        return bool(state[0])

    def slat_create(self):
        slat_id = ffi.new("uint16_t *")
        status = lib.vmi_slat_create(self.vmi, slat_id)
        check(status)
        return slat_id[0]

    def slat_destroy(self, slat_idx):
        status = lib.vmi_slat_destroy(self.vmi, slat_idx)
        check(status)

    def slat_switch(self, slat_idx):
        status = lib.vmi_slat_switch(self.vmi, slat_idx)
        check(status)

    def slat_change_gfn(self, slat_idx, old_gfn, new_gfn):
        status = lib.vmi_slat_change_gfn(self.vmi, slat_idx, old_gfn, new_gfn)
        check(status)
