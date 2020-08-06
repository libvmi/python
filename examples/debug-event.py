#!/usr/bin/env python3

"""Debug Event example.

Usage:
  debug-event.py [options] <vm_name> <symbol>

Options:
  -h --help     Show this screen.
"""

# This example works until the guest decides to reset DR7
# We need to catch MOV-TO-DRx event to improve it

import sys
import signal
from pprint import pprint

from docopt import docopt
from libvmi import Libvmi, INIT_DOMAINNAME, INIT_EVENTS, X86Reg
from libvmi.event import DebugEvent, SingleStepEvent, EventResponse
from utils import pause


# catch SIGINT
# we cannot rely on KeyboardInterrupt when we are in
# the vmi.listen() call
interrupted = False


def set_bit(value, index, enabled):
    mask = 1 << index
    if enabled:
        value |= mask
    else:
        value &= ~mask
    return value


def toggle_dr0(vmi, enabled):
    # enable dr0 globally
    value = set_bit(0, 1, enabled)
    vmi.set_vcpureg(value, X86Reg.DR7.value, 0)


def signal_handler(signal, frame):
    global interrupted
    interrupted = True


def sstep_callback(vmi, event):
    toggle_dr0(vmi, True)
    # disable singlestep
    return EventResponse.TOGGLE_SINGLESTEP


def debug_callback(vmi, event):
    pprint(event.to_dict())
    event.reinject = 0
    toggle_dr0(vmi, False)
    # enable singlestep
    return EventResponse.TOGGLE_SINGLESTEP


def main(args):
    vm_name = args['<vm_name>']
    symbol = args['<symbol>']

    # register SIGINT
    signal.signal(signal.SIGINT, signal_handler)

    with Libvmi(vm_name, INIT_DOMAINNAME | INIT_EVENTS) as vmi:
        vaddr = vmi.translate_ksym2v(symbol)

        debug_event = DebugEvent(debug_callback)

        num_vcpus = vmi.get_num_vcpus()
        sstep_event = SingleStepEvent(range(num_vcpus), enable=False,
                                      callback=sstep_callback)
        with pause(vmi):
            vmi.register_event(debug_event)
            vmi.register_event(sstep_event)
            # set dr0 to our address
            vmi.set_vcpureg(vaddr, X86Reg.DR0.value, 0)
            toggle_dr0(vmi, True)

        # listen
        while not interrupted:
            print("Waiting for events")
            vmi.listen(1000)
        print("Stop listening")

        with pause(vmi):
            vmi.clear_event(debug_event)
            vmi.clear_event(sstep_event)


if __name__ == '__main__':
    args = docopt(__doc__)
    ret = main(args)
    sys.exit(ret)
