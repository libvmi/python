#!/usr/bin/env python3

"""CR3 example.

Usage:
  cr3-event.py [options] <vm_name>

Options:
  -h --help     Show this screen.
  -k SOCKET --kvmi-socket SOCKET        If hypervisor is KVM, specify the KVMi socket
"""

import sys
import signal
import logging
from collections import Counter

from docopt import docopt

from libvmi import Libvmi, X86Reg, INIT_DOMAINNAME, INIT_EVENTS, VMIInitData
from libvmi.event import RegEvent, RegAccess

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

    # 1 - init LibVMI
    kvm_socket = {VMIInitData.KVMI_SOCKET: args['--kvmi-socket']} if args['--kvmi-socket'] else None
    with Libvmi(vm_name, INIT_DOMAINNAME | INIT_EVENTS, init_data=kvm_socket, partial=True) as vmi:
        counter = Counter()

        # 2 - define CR3 callback
        def cr3_callback(vmi, event):
            cr3_value = event.value
            logging.info("CR3 change: %s", hex(cr3_value))
            counter[hex(cr3_value)] += 1

        # 3 - define and register CR3-write event
        with pause(vmi):
            # register CR3-write event
            reg_event = RegEvent(X86Reg.CR3, RegAccess.W, cr3_callback)
            vmi.register_event(reg_event)

        # 4 - listen for events
        for i in range(0, 100):
            vmi.listen(500)
        logging.info(counter)


if __name__ == '__main__':
    args = docopt(__doc__)
    ret = main(args)
    sys.exit(ret)
