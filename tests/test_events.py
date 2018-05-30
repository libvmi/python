from contextlib import contextmanager

from libvmi import X86Reg
from libvmi.event import SingleStepEvent, RegEvent, RegAccess


@contextmanager
def pause(vmi):
    vmi.pause_vm()
    try:
        yield
    finally:
        vmi.resume_vm()


def test_singlestep(vmiev):
    def callback(vmi, event):
        event.data['counter'] += 1

        if event.data['counter'] == 50000:
            vmi.clear_event(event)
            event.data['interrupted'] = True

    event_data = {
        'interrupted': False,
        'counter': 0
    }
    num_vcpus = vmiev.get_num_vcpus()
    ss_event = SingleStepEvent(range(num_vcpus), callback, data=event_data)
    with pause(vmiev):
        vmiev.register_event(ss_event)
    while not event_data['interrupted']:
        vmiev.listen(500)


def test_singlestep_loop(vmiev):
    def callback(vmi, event):
        event.data['counter'] += 1

        if event.data['counter'] == 5000:
            vmi.clear_event(event)
            event.data['interrupted'] = True

    for i in range(10):
        event_data = {
            'interrupted': False,
            'counter': 0
        }
        num_vcpus = vmiev.get_num_vcpus()
        ss_event = SingleStepEvent(range(num_vcpus), callback,
                                   data=event_data)
        with pause(vmiev):
            vmiev.register_event(ss_event)
        while not event_data['interrupted']:
            vmiev.listen(500)


def test_regaccess(vmiev):
    def callback(vmi, event):
        event.data['counter'] += 1

        if event.data['counter'] == 1000:
            vmi.clear_event(event)
            event.data['interrupted'] = True

    event_data = {
        'interrupted': False,
        'counter': 0
    }
    reg_event = RegEvent(X86Reg.CR3, RegAccess.W, callback,
                         data=event_data)
    with pause(vmiev):
        vmiev.register_event(reg_event)
    while not event_data['interrupted']:
        vmiev.listen(500)


def test_regaccess_loop(vmiev):
    def callback(vmi, event):
        event.data['counter'] += 1

        if event.data['counter'] == 100:
            vmi.clear_event(event)
            event.data['interrupted'] = True

    for i in range(10):
        event_data = {
            'interrupted': False,
            'counter': 0
        }
        reg_event = RegEvent(X86Reg.CR3, RegAccess.W, callback,
                             data=event_data)
        with pause(vmiev):
            vmiev.register_event(reg_event)
        while not event_data['interrupted']:
            vmiev.listen(500)
