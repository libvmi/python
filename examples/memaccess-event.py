#!/usr/bin/env python3


import sys
import signal
from pprint import pprint

from libvmi import Libvmi, INIT_DOMAINNAME, INIT_EVENTS
from libvmi.event import MemEvent, MemAccess, EventResponse
from utils import dtb_to_pname


# catch SIGINT
# we cannot rely on KeyboardInterrupt when we are in
# the vmi.listen() call
interrupted = False


def signal_handler(signal, frame):
    global interrupted
    interrupted = True


def callback(vmi, event):
    pprint(event.to_dict())
    if (event.cffi_event.x86_regs.rip != event.data['symbol_addr']):
        # page hit, but we are not at the right address
        # emulate this instruction and continue
        return EventResponse.EMULATE
    pname = dtb_to_pname(vmi, event.cffi_event.x86_regs.cr3)
    print('At {}: {}'.format(event.data['symbol'], pname))


def main(args):
    if len(args) != 3:
        print('./memaccess-event.py <vm_name> <symbol>')
        return 1

    vm_name = args[1]
    symbol = args[2]

    # register SIGINT
    signal.signal(signal.SIGINT, signal_handler)

    with Libvmi(vm_name, INIT_DOMAINNAME | INIT_EVENTS) as vmi:
        vaddr = vmi.translate_ksym2v(symbol)
        print("symbol {} at {}".format(symbol, hex(vaddr)))
        user_data = {
            'symbol': symbol,
            'symbol_addr': vaddr
        }
        paddr = vmi.translate_kv2p(vaddr)
        page = paddr >> 12
        print("paddr: {}".format(hex(paddr)))
        print("page: {}".format(hex(page)))
        mem_event = MemEvent(MemAccess.X, callback, gfn=page, data=user_data)
        vmi.register_event(mem_event)
        # listen
        while not interrupted:
            print("Waiting for events")
            vmi.listen(3000)
        print("Stop listening")


if __name__ == '__main__':
    ret = main(sys.argv)
    sys.exit(ret)
