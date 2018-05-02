#!/usr/bin/env python3


import sys
import signal

from libvmi import Libvmi, X86Reg, INIT_DOMAINNAME, INIT_EVENTS
from libvmi.event import RegEvent, RegAccess

from pprint import pprint


# catch SIGINT
# we cannot rely on KeyboardInterrupt when we are in
# the vmi.listen() call
interrupted = False


def signal_handler(signal, frame):
    global interrupted
    interrupted = True


def callback(vmi, event):
    pprint(event.to_dict())


def main(args):
    if len(args) != 2:
        print('./memaccess-event.py <vm_name>')
        return 1

    vm_name = args[1]

    # register SIGINT
    signal.signal(signal.SIGINT, signal_handler)

    with Libvmi(vm_name, INIT_DOMAINNAME | INIT_EVENTS) as vmi:
        reg_event = RegEvent(X86Reg.CR3, RegAccess.W, callback)
        vmi.register_event(reg_event)
        # listen
        while not interrupted:
            print("Waiting for events")
            vmi.listen(3000)
        print("Stop listening")


if __name__ == '__main__':
    ret = main(sys.argv)
    sys.exit(ret)
