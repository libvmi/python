WINDOWS_SYSTEM_PID = 4


def test_pause_resume(vmi):
    # assume Windows
    dtb = vmi.pid_to_dtb(WINDOWS_SYSTEM_PID)
    va_pages = vmi.get_va_pages(dtb)
    for page in va_pages:
        assert page.vaddr != 0
        # TODO bug dtb is NULL
        # assert page.dtb != 0
        assert page.size != 0
