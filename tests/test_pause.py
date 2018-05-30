def test_pause_resume(vmi):
    for i in range(100):
        vmi.pause_vm()
        vmi.resume_vm()
