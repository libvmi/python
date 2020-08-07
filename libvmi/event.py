import ctypes
from builtins import object, super
from enum import Enum

from _libvmi import ffi, lib

EVENTS_VERSION = lib.VMI_EVENTS_VERSION


class EventType(Enum):
    INVALID = lib.VMI_EVENT_INVALID
    MEMORY = lib.VMI_EVENT_MEMORY
    REGISTER = lib.VMI_EVENT_REGISTER
    SINGLESTEP = lib.VMI_EVENT_SINGLESTEP
    INTERRUPT = lib.VMI_EVENT_INTERRUPT
    GUEST_REQUEST = lib.VMI_EVENT_GUEST_REQUEST
    CPUID = lib.VMI_EVENT_CPUID
    DEBUG_EXCEPTION = lib.VMI_EVENT_DEBUG_EXCEPTION
    PRIVILEGED_CALL = lib.VMI_EVENT_PRIVILEGED_CALL
    DESCRIPTOR_ACCESS = lib.VMI_EVENT_DESCRIPTOR_ACCESS


class EventResponse(Enum):
    NONE = lib.VMI_EVENT_RESPONSE_NONE
    EMULATE = lib.VMI_EVENT_RESPONSE_EMULATE
    EMULATE_NOWRITE = lib.VMI_EVENT_RESPONSE_EMULATE_NOWRITE
    SET_EMUL_READ_DATA = lib.VMI_EVENT_RESPONSE_SET_EMUL_READ_DATA
    DENY = lib.VMI_EVENT_RESPONSE_DENY
    TOGGLE_SINGLESTEP = lib.VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP
    SLAT_ID = lib.VMI_EVENT_RESPONSE_SLAT_ID
    VMM_PAGETABLE_ID = lib.VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID
    SET_REGISTERS = lib.VMI_EVENT_RESPONSE_SET_REGISTERS
    SET_EMUL_INSN = lib.VMI_EVENT_RESPONSE_SET_EMUL_INSN
    GET_NEXT_INTERRUPT = lib.VMI_EVENT_RESPONSE_GET_NEXT_INTERRUPT


class MemAccess(Enum):
    INVALID = lib.VMI_MEMACCESS_INVALID
    N = lib.VMI_MEMACCESS_N
    R = lib.VMI_MEMACCESS_R
    W = lib.VMI_MEMACCESS_W
    X = lib.VMI_MEMACCESS_X
    RW = lib.VMI_MEMACCESS_RW
    RX = lib.VMI_MEMACCESS_RX
    WX = lib.VMI_MEMACCESS_WX
    RWX = lib.VMI_MEMACCESS_RWX
    W2X = lib.VMI_MEMACCESS_W2X
    RWX2N = lib.VMI_MEMACCESS_RWX2N


class RegAccess(Enum):
    INVALID = lib.VMI_REGACCESS_INVALID
    N = lib.VMI_REGACCESS_N
    R = lib.VMI_REGACCESS_R
    W = lib.VMI_REGACCESS_W
    RW = lib.VMI_REGACCESS_RW


class InterruptType(Enum):
    INVALID = lib.INT_INVALID
    INT3 = lib.INT3
    NEXT = lib.INT_NEXT


@ffi.def_extern()
def generic_event_callback(cffi_vmi, cffi_event):
    # get generic event data dict
    generic_data = ffi.from_handle(cffi_event.data)
    # get event object
    event = generic_data['event']
    # call callback with the right Python args
    event_response = event.py_callback(event.vmi, event)
    if event_response is None:
        event_response = EventResponse.NONE
    return event_response.value


class Event(object):

    version = EVENTS_VERSION
    type = None

    def __init__(self, callback, slat_id=0, data=None):
        self.slat_id = slat_id
        self.data = data
        self._py_callback = callback
        self._vmi = None
        self.generic_data = {
            'event': self,
        }
        self.generic_handle = None
        self._cffi_event = ffi.new("vmi_event_t *")

    @property
    def vcpu_id(self):
        return self._cffi_event.vcpu_id

    @property
    def x86_regs(self):
        return self._cffi_event.x86_regs

    @property
    def vmi(self):
        return self._vmi

    @vmi.setter
    def vmi(self, vmi):
        self._vmi = vmi

    @property
    def py_callback(self):
        return self._py_callback

    @py_callback.setter
    def py_callback(self, callback):
        self._py_callback = callback

    @property
    def cffi_event(self):
        return self._cffi_event

    def to_cffi(self):
        self._cffi_event.version = self.version
        self._cffi_event.type = self.type.value
        self._cffi_event.slat_id = self.slat_id
        # convert our generic_data dict to a CFFI void* handle
        # and keep a reference to the handle in self.generic_handle
        self.generic_handle = ffi.new_handle(self.generic_data)
        # assign the handle to the event data
        self._cffi_event.data = self.generic_handle
        self._cffi_event.callback = lib.generic_event_callback

    def to_dict(self):
        return {
            'version': self.version,
            'type': self.type.name,
            'slat_id': self.slat_id,
            'data': self.data,
            'vcpu_id': self.vcpu_id,
            'x86_regs': {
                'rax': hex(self.x86_regs.rax),
                'rsp': hex(self.x86_regs.rsp),
                'rip': hex(self.x86_regs.rip),
            }
        }


class MemEvent(Event):

    type = EventType.MEMORY

    def __init__(self, in_access, callback, gfn=0, generic=False, slat_id=0,
                 data=None):
        super().__init__(callback, slat_id, data)
        # IN
        self.in_access = in_access
        # IN
        self.generic = generic
        # IN/OUT
        self._gfn = gfn

    @property
    def gfn(self):
        return self._cffi_event.mem_event.gfn

    @property
    def out_access(self):
        return MemAccess(self._cffi_event.mem_event.out_access)

    @property
    def gptw(self):
        return bool(self._cffi_event.mem_event.gptw)

    @property
    def gla_valid(self):
        return bool(self._cffi_event.mem_event.gla_valid)

    @property
    def gla(self):
        return self._cffi_event.mem_event.gla

    @property
    def offset(self):
        return self._cffi_event.mem_event.offset

    def to_cffi(self):
        super().to_cffi()
        self._cffi_event.mem_event.in_access = self.in_access.value
        self._cffi_event.mem_event.generic = int(self.generic)
        if self.generic:
            self._cffi_event.mem_event.gfn = ctypes.c_ulonglong(~0).value
        else:
            self._cffi_event.mem_event.gfn = self._gfn
        return self._cffi_event

    def to_dict(self):
        d = super().to_dict()
        d['gfn'] = self.gfn
        d['in_access'] = self.in_access.name
        d['out_access'] = self.out_access.name
        d['gptw'] = self.gptw
        d['gla_valid'] = self.gla_valid
        d['gla'] = hex(self._cffi_event.mem_event.gla)
        d['offset'] = hex(self._cffi_event.mem_event.offset)
        return d


class SingleStepEvent(Event):

    type = EventType.SINGLESTEP

    def __init__(self, vcpus, callback, enable=True, slat_id=0, data=None):
        super().__init__(callback, slat_id, data)
        self.vcpus = 0
        for vcpu in vcpus:
            mask = 1 << vcpu
            self.vcpus |= mask
        self.enable = enable

    @property
    def gla(self):
        return self._cffi_event.ss_event.gla

    @property
    def gfn(self):
        return self._cffi_event.ss_event.gfn

    @property
    def offset(self):
        return self._cffi_event.ss_event.offset

    def to_cffi(self):
        super().to_cffi()
        self._cffi_event.ss_event.vcpus = self.vcpus
        self._cffi_event.ss_event.enable = int(self.enable)
        return self._cffi_event

    def to_dict(self):
        d = super().to_dict()
        d['vcpus'] = self.vcpus
        d['enable'] = self.enable
        d['gla'] = hex(self.gla)
        d['gfn'] = hex(self.gfn)
        d['offset'] = hex(self.offset)
        return d


class RegEvent(Event):

    type = EventType.REGISTER

    def __init__(self, register, in_access, callback, equal=None, slat_id=0,
                 data=None):
        super().__init__(callback, slat_id, data)
        self.register = register
        self.in_access = in_access
        self.equal = equal
        if self.equal is None:
            self.equal = 0

    @property
    def value(self):
        return self._cffi_event.reg_event.value

    @value.setter
    def value(self, v):
        self._cffi_event.reg_event.value = v

    @property
    def previous(self):
        return self._cffi_event.reg_event.previous

    @property
    def msr(self):
        return self._cffi_event.reg_event.msr

    def to_cffi(self):
        super().to_cffi()
        self._cffi_event.reg_event.reg = self.register.value
        self._cffi_event.reg_event.in_access = self.in_access.value
        self._cffi_event.reg_event.equal = self.equal
        return self._cffi_event

    def to_dict(self):
        d = super().to_dict()
        d['in_access'] = self.in_access.name
        d['out_access'] = RegAccess(self._cffi_event.reg_event.out_access).name
        d['value'] = hex(self.value)
        d['previous'] = hex(self.previous)
        d['msr'] = hex(self.msr)
        return d


class IntEvent(Event):

    type = EventType.INTERRUPT

    def __init__(self, callback, intr=InterruptType.INT3, reinject=-1,
                 slat_id=0, data=None):
        super().__init__(callback, slat_id, data)
        self.intr = intr
        self._reinject = reinject

    @property
    def reinject(self):
        return self._reinject

    @reinject.setter
    def reinject(self, value):
        # the event callback needs to set the reinjection
        # behavior
        self._reinject = value
        self._cffi_event.interrupt_event.reinject = self._reinject

    @property
    def gla(self):
        return self._cffi_event.interrupt_event.gla

    @property
    def gfn(self):
        return self._cffi_event.interrupt_event.gfn

    @property
    def offset(self):
        return self._cffi_event.interrupt_event.offset

    def to_cffi(self):
        super().to_cffi()
        self._cffi_event.interrupt_event.intr = self.intr.value
        self._cffi_event.interrupt_event.reinject = self._reinject
        return self._cffi_event

    def to_dict(self):
        d = super().to_dict()
        d['intr'] = self.intr.name
        d['reinject'] = self._reinject
        d['gla'] = hex(self.gla)
        d['gfn'] = hex(self.gfn)
        d['offset'] = hex(self.offset)
        return d


class DebugEvent(Event):

    type = EventType.DEBUG_EXCEPTION

    def __init__(self, callback, reinject=-1,
                 slat_id=0, data=None):
        super().__init__(callback, slat_id, data)
        self._reinject = reinject

    @property
    def reinject(self):
        return self._reinject

    @reinject.setter
    def reinject(self, value):
        # the event callback needs to set the reinjection
        # behavior
        self._reinject = value
        self._cffi_event.debug_event.reinject = self._reinject

    def to_cffi(self):
        super().to_cffi()
        self._cffi_event.debug_event.reinject = self._reinject
        return self._cffi_event

    def to_dict(self):
        d = super().to_dict()
        d['gla'] = hex(self._cffi_event.debug_event.gla)
        d['gfn'] = hex(self._cffi_event.debug_event._gfn)
        d['offset'] = hex(self._cffi_event.debug_event.offset)
        d['type'] = hex(self._cffi_event.debug_event.type)
        d['reinject'] = self._reinject
        return d
