import logging
from contextlib import contextmanager


def init_logger():
    logger = logging.getLogger()
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.INFO)


@contextmanager
def pause(vmi):
    vmi.pause_vm()
    try:
        yield
    finally:
        vmi.resume_vm()


def dtb_to_pname(vmi, dtb):
    tasks_off = vmi.get_offset('win_tasks')
    pdb_off = vmi.get_offset('win_pdbase')
    name_off = vmi.get_offset('win_pname')
    ps_head = vmi.translate_ksym2v('PsActiveProcessHead')
    flink = vmi.read_addr_ksym('PsActiveProcessHead')

    while flink != ps_head:
        start_proc = flink - tasks_off
        value = vmi.read_addr_va(start_proc + pdb_off, 0)
        if value == dtb:
            return vmi.read_str_va(start_proc + name_off, 0)
        flink = vmi.read_addr_va(flink, 0)
    return None
