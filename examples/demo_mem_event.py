#!/usr/bin/env python3

"""Memory Access example.

Usage:
  memaccess-event.py [options] <vm_name>

Options:
  -h --help     Show this screen.
  -k SOCKET --kvmi-socket SOCKET        If hypervisor is KVM, specify the KVMi socket
"""

import sys
import signal
import logging

from docopt import docopt
from libvmi import Libvmi, INIT_DOMAINNAME, INIT_EVENTS, VMIInitData, X86Reg
from libvmi.event import MemEvent, MemAccess
from utils import pause

# catch SIGINT
# we cannot rely on KeyboardInterrupt when we are in
# the vmi.listen() call
interrupted = False


def signal_handler(signal, frame):
    global interrupted
    interrupted = True


def main(args):
    logging.basicConfig(level=logging.INFO)
    vm_name = args['<vm_name>']

    # register SIGINT
    signal.signal(signal.SIGINT, signal_handler)

    kvm_socket = {VMIInitData.KVMI_SOCKET: args['--kvmi-socket']} if args['--kvmi-socket'] else None
    with Libvmi(vm_name, INIT_DOMAINNAME | INIT_EVENTS, init_data=kvm_socket, partial=True) as vmi:
        # init paging to translate virtual addresses
        vmi.init_paging(0)
        with pause(vmi):
            # get current RIP on VCPU 0
            rip = vmi.get_vcpureg(X86Reg.RIP.value, 0)
            # get DTB
            cr3 = vmi.get_vcpureg(X86Reg.CR3.value, 0)
            dtb = cr3 & ~0xfff
            # get gpa
            paddr = vmi.pagetable_lookup(dtb, rip)
            gfn = paddr >> 12

            # define callback
            def cb_mem_event(vmi, event):
                logging.info("Mem event at RIP: %s, frame: %s, offset: %s, permissions: %s",
                             hex(event.x86_regs.rip), hex(event.gla), hex(event.offset), event.out_access.name)

            mem_event = MemEvent(MemAccess.X, cb_mem_event, gfn=gfn)
            vmi.register_event(mem_event)
        # listen
        while not interrupted:
            vmi.listen(3000)
        logging.info("stop listening")


if __name__ == '__main__':
    args = docopt(__doc__)
    ret = main(args)
    sys.exit(ret)
