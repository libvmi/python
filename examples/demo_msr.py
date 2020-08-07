#!/usr/bin/env python3

"""MSR example.

Usage:
  msr-event.py [options] <vm_name>

Options:
  -h --help     Show this screen.
  -k SOCKET --kvmi-socket SOCKET        If hypervisor is KVM, specify the KVMi socket
"""

import sys
import signal
import logging
from collections import Counter

from utils import pause

from docopt import docopt
from libvmi import Libvmi, INIT_DOMAINNAME, INIT_EVENTS, VMIInitData, MSR
from libvmi.event import RegEvent, RegAccess


# catch SIGINT
# we cannot rely on KeyboardInterrupt when we are in
# the vmi.listen() call
interrupted = False

MSR_NAME = {
    0x174: 'MSR_IA32_SYSENTER_CS',
    0x175: 'MSR_IA32_SYSENTER_ESP',
    0x176: 'MSR_IA32_SYSENTER_EIP'
}


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
        msr_counter = Counter()

        def msr_callback(vmi, event):
            try:
                name = MSR_NAME[event.msr]
            except KeyError:
                name = 'MSR'

            logging.info("%s %s = %s", name, hex(event.msr), hex(event.value))
            msr_counter[event.msr] += 1
            # EternalBlue exploitation ?
            if msr_counter[0x176] > 1:
                logging.warn('MSR 0x176 modified %s times !', msr_counter[0x176])

        with pause(vmi):
            # register MSR event
            reg_event = RegEvent(MSR.ALL, RegAccess.W, msr_callback)
            vmi.register_event(reg_event)
        logging.info("listening")
        while not interrupted:
            vmi.listen(500)


if __name__ == '__main__':
    args = docopt(__doc__)
    ret = main(args)
    sys.exit(ret)
