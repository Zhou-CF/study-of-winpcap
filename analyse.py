import dpkt


def jie(eth_frame_data):
    s, info = '', ''
    eth_frame = dpkt.ethernet.Ethernet(eth_frame_data)

    # 解析以太网头部信息
    src_mac = dpkt.utils.mac_to_str(eth_frame.src)
    dst_mac = dpkt.utils.mac_to_str(eth_frame.dst)
    eth_type = eth_frame.type

    s += f"源MAC地址: {src_mac}\n"
    s += f"目的MAC地址: {dst_mac}\n"
    s += f"以太网类型: {eth_type}\n"

    # 判断是否为IPv4数据包
    if isinstance(eth_frame.data, dpkt.ip.IP):
        ip_pkt = eth_frame.data

        # 解析IP头部信息
        src_ip = dpkt.utils.inet_to_str(ip_pkt.src)
        dst_ip = dpkt.utils.inet_to_str(ip_pkt.dst)
        ip_proto = ip_pkt.p

        s += f"源IP地址: {src_ip}\n"
        s += f"目的IP地址: {dst_ip}\n"
        s += f"IP 协议号: {ip_proto}\n"

        # 判断传输层协议
        if isinstance(ip_pkt.data, dpkt.tcp.TCP):
            tcp_pkt = ip_pkt.data
            src_port = tcp_pkt.sport
            dst_port = tcp_pkt.dport

            s += f"源地址端口: {src_port}\n"
            s += f"目的地址端口: {dst_port}\n"

            s += f"TCP 头部: {tcp_pkt.data[:20].hex()}\n"
            s += f"TCP 数据: {tcp_pkt.data[20:].hex()}\n"
        elif isinstance(ip_pkt.data, dpkt.udp.UDP):
            udp_pkt = ip_pkt.data
            src_port = udp_pkt.sport
            dst_port = udp_pkt.dport
            s += f"源地址端口: {src_port}\n"
            s += f"目的地址端口: {dst_port}\n"

            udp_data_binary = bin(int.from_bytes(udp_pkt, byteorder='big'))
            print(udp_data_binary)
            s += f"UDP 头部: {udp_pkt.data[:8].hex()}\n"
            s += f"UDP 数据: {udp_pkt.data[8:].hex()}\n"

        info += f"{src_ip}:{src_port} -- > {dst_ip}:{dst_port}"
        return s, info
    else:
        return "Not an IP packet.", "Not an IP packet."


if __name__ == '__main__':
    pcap = b'|*1fg\x820{\xaci8\x02\x08\x00E\x00\x004\x00\x00@\x005\x06o!\xaf\x18\x9aB\n\xcf\x82y\x03U\xf5\nzT\xf0+v\xd2\xa5\xe3\x80\x12\xfa\xf0\x1d\xeb\x00\x00\x02\x04\x05\xa0\x01\x01\x04\x02\x01\x03\x03\x07'
    print(jie(pcap))
