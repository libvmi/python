SYMBOL = "PsInitialSystemProcess"


def test_read_ksym(vmi):
    vmi.read_ksym(SYMBOL, 100)


def test_read_va(vmi):
    va = vmi.translate_ksym2v(SYMBOL)
    vmi.read_va(va, 0, 100)


def test_read_pa(vmi):
    va = vmi.translate_ksym2v(SYMBOL)
    pa = vmi.translate_kv2p(va)
    vmi.read_pa(pa, 100)


def test_read_8_ksym(vmi):
    vmi.read_8_ksym(SYMBOL)


def test_read_16_ksym(vmi):
    vmi.read_16_ksym(SYMBOL)


def test_read_32_ksym(vmi):
    vmi.read_32_ksym(SYMBOL)


def test_read_64_ksym(vmi):
    vmi.read_64_ksym(SYMBOL)


def test_read_8_va(vmi):
    va = vmi.translate_ksym2v(SYMBOL)
    vmi.read_8_va(va, 0)


def test_read_16_va(vmi):
    va = vmi.translate_ksym2v(SYMBOL)
    vmi.read_16_va(va, 0)


def test_read_32_va(vmi):
    va = vmi.translate_ksym2v(SYMBOL)
    vmi.read_32_va(va, 0)


def test_read_64_va(vmi):
    va = vmi.translate_ksym2v(SYMBOL)
    vmi.read_64_va(va, 0)


def test_read_8_pa(vmi):
    va = vmi.translate_ksym2v(SYMBOL)
    pa = vmi.translate_kv2p(va)
    vmi.read_8_pa(pa)


def test_read_16_pa(vmi):
    va = vmi.translate_ksym2v(SYMBOL)
    pa = vmi.translate_kv2p(va)
    vmi.read_16_pa(pa)


def test_read_32_pa(vmi):
    va = vmi.translate_ksym2v(SYMBOL)
    pa = vmi.translate_kv2p(va)
    vmi.read_32_pa(pa)


def test_read_64_pa(vmi):
    va = vmi.translate_ksym2v(SYMBOL)
    pa = vmi.translate_kv2p(va)
    vmi.read_64_pa(pa)
