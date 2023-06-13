import pyshark


def get_ip(pkt, type: str):
    if type == 'src':
        if 'ip' in pkt:
            return pkt.ip.src
        elif 'ipv6' in pkt:
            return pkt.ipv6.src
        else:
            return None
    elif type == 'dst':
        if 'ip' in pkt:
            return pkt.ip.dst
        elif 'ipv6' in pkt:
            return pkt.ipv6.dst
        else:
            return None
    return None


def filter_ip(ip: str, type: str):
    if ':' in ip:
        return 'ipv6.{type} == {ip}'.format(type=type, ip=ip)
    else:
        return 'ip.{type} == {ip}'.format(type=type, ip=ip)


def is_data_pkt(pkt, min_size=0, src=None, dst=None):
    data_pkt_flag = False
    if 'tls' in pkt:
        if 'Application Data' in str(pkt.tls) and is_pkt(pkt, src=src, dst=dst):
            return True
        # If TLS version is 1.2, then for larger packets, assume it's a data packet.
        if is_pkt(pkt, min_size, src=src, dst=dst):
            return True
    return False


def is_ack_pkt(pkt, min_size=0, src=None, dst=None):
    ack_pkt_flag = 'TCP' in pkt and int(pkt.tcp.flags_ack) == 1 and int(pkt.tcp.len) == 0
    return ack_pkt_flag and is_pkt(pkt, min_size, src, dst)


def is_pkt(pkt, min_size=0, src=None, dst=None):
    # Convert src and dst to set to check membership.
    if isinstance(src, str):
        src = {src}
    if isinstance(dst, str):
        dst = {dst}

    size_filter = True
    src_filter = True
    dst_filter = True
    if min_size > 0:
        size_filter = int(pkt.length) > min_size
    if src is not None:
        src_filter = get_ip(pkt, type='src') in src
    if dst is not None:
        dst_filter = get_ip(pkt, type='dst') in dst
    return size_filter and src_filter and dst_filter


def get_timestamp(pkt):
    return pkt.sniff_time


def display_filter_for_ip(ip, type='src'):
    if ':' in ip:
        return 'ipv6.{type} == {ip}'.format(ip=ip, type=type)
    else:
        return 'ip.{type} == {ip}'.format(ip=ip, type=type)


def extract_phone_ip(pcap_file):
    phone_ip = ''
    cap_host_syn = pyshark.FileCapture(
        pcap_file,
        only_summaries=False,
        display_filter="tcp.flags.syn == 1 && tcp.flags.ack == 0"
    )
    for pkt in cap_host_syn:
        phone_ip = get_ip(pkt, type='src')
        break
    return phone_ip
