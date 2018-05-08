#!/usr/bin/env python3


import sys
import signal
from pprint import pprint

from libvmi import Libvmi, INIT_DOMAINNAME, INIT_EVENTS
from libvmi.event import MemEvent, MemAccess, EventResponse, SingleStepEvent
from utils import dtb_to_pname


# This script is similar to memaccess-event.py
# except that it watch continuously for new events,
# and use singlestepping events instead of Emulation.
# reason is because the Xen emulator is incomplete
# and can crash the guest

# catch SIGINT
# we cannot rely on KeyboardInterrupt when we are in
# the vmi.listen() call
listen_interrupted = False
watch_interrupted = False


def signal_handler(signal, frame):
    print('signal handler')
    global watch_interrupted
    global listen_interrupted
    watch_interrupted = True
    listen_interrupted = True


def cb_mem_event(vmi, event):
    global listen_interrupted
    # pprint(event.to_dict())
    if event.cffi_event.x86_regs.rip != event.data['target_vaddr']:
        # not at the targeted vaddr
        # unregister memory event to lift page permissions
        # allow single step to execute
        vmi.clear_event(event)
        # toggle singlestep ON
        return EventResponse.TOGGLE_SINGLESTEP
    # we are lucky, hit the targeted on the first call to the callback
    pname = dtb_to_pname(vmi, event.cffi_event.x86_regs.cr3)
    print('At {}: {}, handle: {}'.format(event.data['symbol'], pname,
                                         hex(event.cffi_event.x86_regs.rcx)))
    listen_interrupted = True


def cb_single_step_event(vmi, event):
    global listen_interrupted
    #pprint(event.to_dict())
    if event.cffi_event.ss_event.gfn != event.data['target_gfn']:
        # out of the target page
        # reregister mem_event
        vmi.register_event(event.data['mem_event'])
        # toggle singlestep OFF
        return EventResponse.TOGGLE_SINGLESTEP
    # our target vaddr ?
    if event.cffi_event.x86_regs.rip == event.data['target_vaddr']:
        pname = dtb_to_pname(vmi, event.cffi_event.x86_regs.cr3)
        print('At {}: {}'.format(event.data['symbol'], pname))
        listen_interrupted = True
        # toggle singlestep OFF
        return EventResponse.TOGGLE_SINGLESTEP


def continue_until(vmi, addr, symbol):
    global listen_interrupted
    # get page
    paddr = vmi.translate_kv2p(addr)
    gfn = paddr >> 12
    # prepare callback data
    user_data = {
        'symbol': symbol,
        'mem_event': None,
        'target_vaddr': addr,
        'target_gfn': gfn,
    }
    # register singlestep events
    nb_vcpu = vmi.get_num_vcpus()
    ss_event_list = []
    for vcpu in range(nb_vcpu):
        ss_event = SingleStepEvent([vcpu], cb_single_step_event, enable=False,
                                   data=user_data)
        # register
        vmi.register_event(ss_event)
        ss_event_list.append(ss_event)
    # register memory event on vaddr's frame
    mem_event = MemEvent(MemAccess.X, cb_mem_event, gfn, data=user_data)
    # add mem_event to user_data
    user_data['mem_event'] = mem_event
    vmi.register_event(mem_event)
    # listen
    listen_interrupted = False
    while not listen_interrupted:
        # print("Waiting for events")
        vmi.listen(1000)
    # print("Stop listening")
    vmi.clear_event(mem_event)
    for ss_event in ss_event_list:
        vmi.clear_event(ss_event)


def main(args):
    if len(args) != 3:
        print('./watch-symbol.py <vm_name> <symbol>')
        return 1

    global watch_interrupted
    vm_name = args[1]
    symbol = args[2]

    # register SIGINT
    signal.signal(signal.SIGINT, signal_handler)

    with Libvmi(vm_name, INIT_DOMAINNAME | INIT_EVENTS) as vmi:
        # get address
        try:
            addr = int(symbol)
        except ValueError:
            addr = vmi.translate_ksym2v(symbol)

        watch_interrupted = False
        while not watch_interrupted:
            continue_until(vmi, addr, symbol)


if __name__ == '__main__':
    ret = main(sys.argv)
    sys.exit(ret)
