from ctypes import *
from typing import Callable

from C_type import PCAP_ERRBUF_SIZE, pcap_t_p, c_ubyte_p, pcap_pkthdr_p, bpf_program_p, \
    bpf_program, pcap_if_t_p
import sys

_pcap = cdll.LoadLibrary("wpcap")

def pcap_open_live(device, snaplen, promisc, to_ms, ignore_warn=True):
    errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
    _pcap.pcap_open_live.restype = pcap_t_p
    hpcap = _pcap.pcap_open_live(device.encode(), snaplen, int(promisc), to_ms, errbuf)
    if hpcap:
        warning = errbuf.raw.decode()
        if warning[0] != '\x00' and not ignore_warn:
            raise ValueError
        return hpcap
    else:
        raise ValueError(errbuf.raw.decode(errors='replace'))


def get_working_ifaces():
    dev_dict = {}
    all_devices = pcap_if_t_p()
    errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
    _pcap.pcap_findalldevs.restype = c_int
    _pcap.pcap_findalldevs.argtypes = [POINTER(pcap_if_t_p), c_char_p]
    _pcap.pcap_findalldevs(all_devices, errbuf)
    dev = all_devices
    while dev:
        dev_dict[dev.contents.name.decode('utf8')] = dev.contents.description.decode('utf8')
        dev = dev.contents.next
    return dev_dict


def pcap_open_live(device, snaplen, promisc, to_ms, ignore_warn=True):
    errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
    _pcap.pcap_open_live.restype = pcap_t_p
    hpcap = _pcap.pcap_open_live(device.encode(), snaplen, int(promisc), to_ms, errbuf)
    if hpcap:
        warning = errbuf.raw.decode()
        if warning[0] != '\x00' and not ignore_warn:
            raise ValueError(errbuf.raw.decode())
        return hpcap
    else:
        raise ValueError(errbuf.raw.decode(errors='replace'))


def pcap_breakloop(handle):
    _pcap.pcap_breakloop(handle)


def pcap_geterr(hpcap):
    _pcap.pcap_geterr.restype = c_char_p
    return _pcap.pcap_geterr(hpcap).decode()


def pcap_compile(hpcap, buf, optimize, netmask):
    bpf_p = bpf_program_p(bpf_program())
    retcode = _pcap.pcap_compile(hpcap, bpf_p, buf.encode(), int(optimize), c_uint32(netmask))
    if retcode == -1:
        raise ValueError(pcap_geterr(hpcap))
    return bpf_p


def pcap_setfilter(hpcap, fp):
    retcode = _pcap.pcap_setfilter(hpcap, fp)
    if retcode == -1:
        raise ValueError(pcap_geterr(hpcap))


def sniff(iface, prn, limit=0, filter=""):
    def packet_handler(param, header, pkt_pointer):
        if not isinstance(prn, Callable):
            raise ValueError('NO prn')
        pkt_data = string_at(pkt_pointer, header.contents.len)
        return prn(pkt_data)

    callback_func = CFUNCTYPE(None, c_ubyte_p,
                              pcap_pkthdr_p,
                              c_ubyte_p)(packet_handler)

    errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
    hpcap = pcap_open_live(iface, 65535, True, 0)
    bpf_fp = pcap_compile(hpcap, filter, 1, 0)
    pcap_setfilter(hpcap, bpf_fp)
    _pcap.pcap_loop(hpcap, limit, callback_func, None)


def pcap_close(hpcap):
    _pcap.pcap_close(hpcap)
