import logging
import socket
import time
import xml.etree.ElementTree as tree

import pytest
import libvirt

from libvmi import Libvmi, VMIConfig, INIT_DOMAINNAME, INIT_EVENTS

WINRM_PORT = 5985

LIBV_URI = "xen:///"

TEST_DOMAINS = [
    # "test-libvmi-winxp",
    "test-libvmi-win7",
    # "test-libvmi-win81",
    # "test-libvmi-win10",
]

DOMAIN_CONFIGS = {
    "test-libvmi-win7":
        {
            'ostype': 'Windows',
            'win_pdbase': 0x28,
            'win_pid': 0x180,
            'win_tasks': 0x188,
            'win_pname': 0x2e0
        }
}


def wait_for_ip(domain, network_name='default'):
    # find MAC address
    dom_elem = tree.fromstring(domain.XMLDesc())
    mac_addr = dom_elem.find("./devices/interface[@type='network']/mac").get(
        'address')
    logging.debug('MAC address: {}'.format(mac_addr))
    while True:
        net = domain.connect().networkLookupByName(network_name)
        leases = net.DHCPLeases()
        found = [lease for lease in leases if lease['mac'] == mac_addr]
        if found:
            return found[0]['ipaddr']
        time.sleep(1)


def wait_service(ip_addr, port, sleep=1):
    logging.info(
        "Waiting for the monitored service on port %d to become available",
        port)
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        state = sock.connect_ex((ip_addr, port))
        if state == 0:
            break
        time.sleep(sleep)


@pytest.fixture(scope='session')
def libvirt_con():
    # find VM in libvirt connexion
    con = libvirt.open(LIBV_URI)
    yield con
    con.close()


@pytest.fixture(scope='session',
                params=TEST_DOMAINS)
def domain(request, libvirt_con):
    dom = libvirt_con.lookupByName(request.param)
    if dom.isActive():
        dom.destroy()
    # Xen cannot restore to a libvirt snapshot
    # revert VM to 'Base' snapshot
    # snap = dom.snapshotLookupByName(BASE_SNAPSHOT)
    # dom.revertToSnapshot(snap)
    # start domain
    dom.create()
    # wait for winrm service to be available
    dom_ip = wait_for_ip(dom)
    wait_service(dom_ip, WINRM_PORT)
    yield dom
    # teardown
    # shutdown domain
    dom.shutdown()
    while dom.state()[0] != libvirt.VIR_DOMAIN_SHUTOFF:
        time.sleep(1)


@pytest.fixture(scope='session')
def vmi(domain):
    vm_config = DOMAIN_CONFIGS[domain.name()]
    with Libvmi(domain.name(), config_mode=VMIConfig.DICT,
                config=vm_config) as vmi:
        yield vmi


@pytest.fixture(scope='session')
def vmiev(domain):
    vm_config = DOMAIN_CONFIGS[domain.name()]
    with Libvmi(domain.name(), INIT_DOMAINNAME | INIT_EVENTS,
                config_mode=VMIConfig.DICT,
                config=vm_config) as vmi:
        yield vmi
