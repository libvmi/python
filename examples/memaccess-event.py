#!/usr/bin/env python3

"""Memory Access example.

Usage:
  memaccess-event.py [options] <vm_name> <symbol>

Options:
  -h --help     Show this screen.
  --sstep       Use singlestepping instead of emulation
"""

import sys
import signal

from docopt import docopt
from libvmi import Libvmi, INIT_DOMAINNAME, INIT_EVENTS
from libvmi.event import MemEvent, MemAccess, SingleStepEvent, EventResponse
from utils import dtb_to_pname, pause


# catch SIGINT
# we cannot rely on KeyboardInterrupt when we are in
# the vmi.listen() call
interrupted = False


def signal_handler(signal, frame):
    global interrupted
    interrupted = True


def cb_mem_event(vmi, event):
    # pprint(event.to_dict())
    if event.cffi_event.x86_regs.rip != event.data['target_vaddr']:
        # page hit, but we are not at the right address
        if event.data['sstep']:
            # lift page permissions
            print("lift page permissions")
            vmi.clear_event(event.data['mem_event'])
            # toogle singlestep ON
            return EventResponse.TOGGLE_SINGLESTEP
        else:
            # emulate this instruction and continue
            return EventResponse.EMULATE
    else:
        # hit
        pname = dtb_to_pname(vmi, event.cffi_event.x86_regs.cr3)
        print('At {}: {}'.format(event.data['symbol'], pname))
    return EventResponse.EMULATE


def cb_ss_event(vmi, event):
    # out of the frame ?
    if event.cffi_event.ss_event._gfn != event.data['target_gfn']:
        print("reregister event")
        # reregister mem event
        vmi.register_event(event.data['mem_event'])
        # toggle singlestep OFF
        return EventResponse.TOGGLE_SINGLESTEP


def main(args):
    vm_name = args['<vm_name>']
    symbol = args['<symbol>']
    sstep_enabled = args['--sstep']

    # register SIGINT
    signal.signal(signal.SIGINT, signal_handler)

    with Libvmi(vm_name, INIT_DOMAINNAME | INIT_EVENTS) as vmi:
        vaddr = vmi.translate_ksym2v(symbol)
        paddr = vmi.translate_kv2p(vaddr)
        frame = paddr >> 12
        print("symbol: {} vaddr: {} paddr: {} frame: {}".format(
            symbol, hex(vaddr), hex(paddr), hex(frame)))

        user_data = {
            'symbol': symbol,
            'target_vaddr': vaddr,
            'target_gfn': frame,
            'mem_event': None,
            'sstep': sstep_enabled
        }
        num_vcpus = vmi.get_num_vcpus()
        ss_event = SingleStepEvent(range(num_vcpus), cb_ss_event,
                                   data=user_data, enable=False)
        mem_event = MemEvent(MemAccess.X, cb_mem_event, gfn=frame,
                             data=user_data)
        user_data['mem_event'] = mem_event
        with pause(vmi):
            vmi.register_event(ss_event)
            vmi.register_event(mem_event)
        # listen
        while not interrupted:
            print("Waiting for events ({})".format(vmi.are_events_pending()))
            vmi.listen(3000)
        print("Stop listening")
        with pause(vmi):
            vmi.clear_event(mem_event)


if __name__ == '__main__':
    args = docopt(__doc__)
    ret = main(args)
    sys.exit(ret)
