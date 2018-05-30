import pytest

from libvmi import AccessContext, TranslateMechanism


def test_kv2p(vmi):
    va = vmi.translate_ksym2v("PsInitialSystemProcess")
    assert va != 0


def test_ksym2v(vmi):
    va = vmi.translate_ksym2v("PsInitialSystemProcess")
    pa = vmi.translate_kv2p(va)
    assert pa != 0


def test_invalid_pid(vmi):
    ctx = AccessContext(TranslateMechanism.PROCESS_PID,
                        addr=0x8000000,
                        pid=0xfeedbeef)
    with pytest.raises(OverflowError, message="invalid pid accepted"):
        vmi.read(ctx, 8)
