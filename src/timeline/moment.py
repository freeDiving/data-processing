import unittest
from datetime import datetime
from typing import Any, Dict, Set
import pyshark

from src.constants import YEAR, DATETIME_FORMAT
from src.utils.pcap import get_ip, is_data_pkt, get_timestamp, is_ack_pkt, filter_ip
from src.utils.strings import has_prefix, extract_timestamp, extract_stroke_id


class Moment:
    name: str
    source: str
    time: datetime
    metadata: dict
    raw_data: Any

    def __init__(self, **kwargs):
        self.name = kwargs.get("name") or ""
        self.source = kwargs.get("source") or ""
        self.action_from = kwargs.get("action_from") or ""
        self.action_to = kwargs.get("action_to") or ""
        self.time = kwargs.get("time") or ""
        self.metadata = kwargs.get("metadata") or dict()
        self.raw_data = kwargs.get("raw_data") or None


class AppInfo:
    log_moments: list[Moment]
    pcap_moments: list[Moment]
    sync_start_time: datetime
    sync_end_time: datetime
    phone_ip: str
    arcore_ip_set: set
    ip_ver_is_six: bool

    def __init__(self, **kwargs):
        self.log_moments = kwargs.get("log_moments") or []
        self.pcap_moments = kwargs.get("pcap_moments") or []
        self.sync_start_time = kwargs.get("sync_start_time")
        self.sync_end_time = kwargs.get("action_to")
        self.phone_ip = kwargs.get("phone_ip")
        self.arcore_ip_set = kwargs.get("arcore_ip_set") or set()
        self.ip_ver_is_six = kwargs.get("ip_ver_is_six")


def create_essential_metadata(pkt, type: str):
    src_ip = get_ip(pkt, type='src')
    dst_ip = get_ip(pkt, type='dst')
    pkt_size = pkt.length
    return {'src_ip': src_ip, 'dst_ip': dst_ip, 'type': type, 'size': pkt_size}


def prepare_host_log_info(host_app_log):
    """
    Parse each line of the host's application log, and return necessary information.
    Args:
        host_app_log: Path to the host app log
    Returns:
        A map that contains a list of host moments, host's synchronization start time,
        and host's synchronization end time.
    """
    touch_start_regexp = lambda x: has_prefix(x, prefix=r'\[\[1a start\] touch screen')
    stroke_was_added_regexp = lambda x: has_prefix(x, prefix=r'stroke \(id: .*?\) was added at')
    add_points_to_stroke_regexp = lambda x: has_prefix(x, prefix=r'send stroke to firebase')
    cloud_finish_processing_regexp = lambda x: has_prefix(x, prefix=r'\[\[2a end - 2d start\] onChildChanged')
    sync_start_regexp = lambda x: has_prefix(x, prefix=r'SET ANCHOR')
    sync_end_regexp = lambda x: has_prefix(x, prefix=r'SYNCED')

    moments = []
    sync_start_time = None
    sync_end_time = None
    with open(host_app_log, 'r') as f:
        while True:
            line = f.readline()
            if not line:
                break
            # process line by line
            if touch_start_regexp(line):
                moments.append(Moment(
                    source='host',
                    name='user touches screen',
                    time=extract_timestamp(line, year=YEAR),
                    raw_data=line,
                    action_from='host',
                    action_to='host',
                ))
                continue
            if stroke_was_added_regexp(line):
                stroke_id = extract_stroke_id(line)
                moments.append(Moment(
                    source='host',
                    name='add a stroke',
                    time=extract_timestamp(line, year=YEAR),
                    raw_data=line,
                    metadata={'stroke_id': stroke_id},
                    action_from='host',
                    action_to='host',
                ))
                continue
            if add_points_to_stroke_regexp(line):
                moments.append(Moment(
                    source='host',
                    name='add points to stroke',
                    time=extract_timestamp(line, year=YEAR),
                    raw_data=line,
                    action_from='host',
                    action_to='host',
                ))
                continue
            if cloud_finish_processing_regexp(line):
                moments.append(Moment(
                    source='host',
                    name='notified by finish of cloud processing',
                    time=extract_timestamp(line, year=YEAR),
                    raw_data=line,
                    action_from='host',
                    action_to='host',
                ))
                continue
            if sync_start_regexp(line) and (not sync_start_time):
                sync_start_time = extract_timestamp(line, YEAR)
                continue
            if sync_end_regexp(line):
                if sync_end_time is not None:
                    raise RuntimeError("Two successful synchronizations?")
                else:
                    sync_end_time = extract_timestamp(line, YEAR)
                continue

    if (not sync_start_time) or (not sync_end_time) or (sync_start_time > sync_end_time):
        raise RuntimeError("Invalid sync start and end time.")

    return {"moments": moments, 'sync_start_time': sync_start_time, 'sync_end_time': sync_end_time}


def prepare_host_pcap_info(
        host_pcap,
        start_time,
        end_time,
):
    # Apply filters.
    pyshark_filters = []
    pyshark_filters.append('frame.time >= "{st}"'.format(st=start_time.strftime(DATETIME_FORMAT)))
    pyshark_filters.append('frame.time <= "{et}"'.format(et=end_time.strftime(DATETIME_FORMAT)))
    pyshark_filters.append('tcp')
    display_filter = ' && '.join(pyshark_filters)
    cap_e2e = pyshark.FileCapture(host_pcap, display_filter=display_filter)

    moments = []
    ip_set = set()
    phone_ip = None
    database_ip = None
    for pkt in cap_e2e:
        # Push all IP addresses to a set (for debugging purposes)
        src_ip = get_ip(pkt, type='src')
        dst_ip = get_ip(pkt, type='dst')
        ip_set.add(src_ip)
        ip_set.add(dst_ip)

        # Get phone IP and Firebase IP.
        if phone_ip is None and is_data_pkt(pkt):
            phone_ip = src_ip
            database_ip = dst_ip

        # If this packet is associated with an event, then create a "moment" for it.
        if is_data_pkt(pkt, min_size=100, src=phone_ip, dst=database_ip):
            moments.append(Moment(
                source='host',
                name='send data pkt to cloud',
                time=get_timestamp(pkt),
                raw_data=pkt,
                metadata=create_essential_metadata(pkt, type='data'),
                action_from='host',
                action_to='cloud',
            ))
        elif is_ack_pkt(pkt, src=database_ip, dst=phone_ip):
            moments.append(Moment(
                source='host',
                name='receive ack pkt from cloud',
                time=get_timestamp(pkt),
                raw_data=pkt,
                metadata=create_essential_metadata(pkt, type='ack'),
                action_from='cloud',
                action_to='host',
            ))
        elif is_data_pkt(pkt, min_size=100, src=database_ip, dst=phone_ip):
            moments.append(Moment(
                source='host',
                name='receive data pkt from cloud',
                time=get_timestamp(pkt),
                raw_data=pkt,
                metadata=create_essential_metadata(pkt, type='data'),
                action_from='cloud',
                action_to='host',
            ))
    cap_e2e.close()
    return {
        'phone_ip': phone_ip,
        'database_ip': database_ip,
        'ip_set': ip_set,
        'moments': moments,
    }


def prepare_resolver_log_info(resolver_app_log):
    """
    Read each lines of the resolver's log.
    Check each line to see if it contains "onLineAdded" or "onLineChanged" keyword.
    If yes, construct a "moment" object, and add it to a list.
    Args:
        resolver_app_log: path to the resolver's log

    Returns:
        moments: the list of extracted moments.

    """
    on_line_added_regexp = lambda x: has_prefix(x, prefix=r'\[\[2a end - 2d start\] onChildAdded')
    on_line_changed_regexp = lambda x: has_prefix(x, prefix=r'\[\[2a end - 2d start\] onChildChanged')
    finish_rendering_regexp = lambda x: has_prefix(x, prefix=r'\[\[2d\] after update')
    sync_start_regexp = lambda x: has_prefix(x, prefix=r'SET ANCHOR')
    sync_end_regexp = lambda x: has_prefix(x, prefix=r'SYNCED')

    moments = []
    sync_start_time = None
    sync_end_time = None
    # Timestamp upon receiving the last group of point coordinates.
    last_points_time = None
    with open(resolver_app_log, 'r') as f:
        while True:
            line = f.readline()
            if not line:
                break
            # process line by line
            if on_line_changed_regexp(line) or on_line_added_regexp(line):
                stroke_id = extract_stroke_id(line)
                moments.append(Moment(
                    source='resolver',
                    name='receive point updates',
                    time=extract_timestamp(line, year=YEAR),
                    raw_data=line,
                    metadata={'stroke_id': stroke_id},
                    action_from='resolver',
                    action_to='resolver',
                ))
                if on_line_changed_regexp(line):
                    last_points_time = extract_timestamp(line, year=YEAR)
                continue
            if finish_rendering_regexp(line):
                moments.append(Moment(
                    source='resolver',
                    name='finish rendering',
                    time=extract_timestamp(line, year=YEAR),
                    raw_data=line,
                    action_from='resolver',
                    action_to='resolver',
                ))
                continue
            if sync_start_regexp(line) and (not sync_start_time):
                sync_start_time = extract_timestamp(line, YEAR)
            if sync_end_regexp(line):
                if sync_end_time is not None:
                    raise RuntimeError("Two successful synchronizations?")
                else:
                    sync_end_time = extract_timestamp(line, YEAR)

    # Error checking
    if (not sync_start_time) or (not sync_end_time) or (sync_start_time > sync_end_time):
        raise RuntimeError("Invalid sync start and end time.")

    return {
        "moments": moments,
        'sync_start_time': sync_start_time,
        'sync_end_time': sync_end_time,
    }


def prepare_resolver_pcap_info(
        resolver_pcap,
        start_time,
        end_time,
        database_ip,
):
    pyshark_filters = []
    pyshark_filters.append('frame.time >= "{st}"'.format(st=start_time.strftime(DATETIME_FORMAT)))
    pyshark_filters.append('frame.time <= "{et}"'.format(et=end_time.strftime(DATETIME_FORMAT)))
    pyshark_filters.append('tcp')
    # only deal with data pkt from or to the database IP
    pyshark_filters.append(
        '({a} || {b})'.format(a=filter_ip(database_ip, type='src'), b=filter_ip(database_ip, type='dst')))
    display_filter = ' && '.join(pyshark_filters)
    caps = pyshark.FileCapture(resolver_pcap, display_filter=display_filter)

    moments = []
    ip_set = set()
    resolver_phone_ip = None

    for pkt in caps:
        ip_set.add(get_ip(pkt, type='src'))
        ip_set.add(get_ip(pkt, type='dst'))
        # get the first pkt from database to resolver phone
        if resolver_phone_ip is None and is_data_pkt(pkt, src=database_ip):
            resolver_phone_ip = get_ip(pkt, type='dst')

        if is_data_pkt(pkt, min_size=100):
            moments.append(Moment(
                source='resolver',
                name='receive data pkt from cloud',
                time=get_timestamp(pkt),
                raw_data=pkt,
                metadata=create_essential_metadata(pkt, type='data'),
                action_from='cloud',
                action_to='resolver',
            ))
            continue
        if is_ack_pkt(pkt):
            moments.append(Moment(
                source='resolver',
                name='send ack pkt to cloud',
                time=get_timestamp(pkt),
                raw_data=pkt,
                metadata=create_essential_metadata(pkt, type='ack'),
                action_from='resolver',
                action_to='cloud',
            ))
            continue
    caps.close()
    return {
        'moments': moments,
        'ip_set': ip_set,
        'phone_ip': resolver_phone_ip,
    }


def is_ip_version_six(pcap_path) -> bool:
    """
    Check if the IP used by Just-a-Line is IPv6 or not.
    This is done by checking all the syn packets. If we don't have any IPv6 SYN,
    then the app only used IPv4 (This happens in WiFi environment).
    Otherwise, it uses IPv6 (This happens in cellular environment).
    Args:
        pcap_path: path of the pcap file.

    Returns:
        ip_version_is_six: a boolean indicates if the IP version is 6.
    """
    syn_pkts = pyshark.FileCapture(pcap_path, display_filter='tcp.flags.syn==1 && ipv6')
    for _ in syn_pkts:
        return True
    return False


def get_arcore_addresses(pcap_path, sync_start_ts, sync_end_ts, last_rendering_ts, phone_ip, database_ip,
                         ip_ver_is_six):
    """
    Find arcore servers used by the host/resolver.
    Args:
        pcap_path: path to the host's or the resolver's pcap file.
        sync_start_ts: synchronization start timestamp.
        sync_end_ts: synchronization end timestamp.
        last_rendering_ts: timestamp of the last 2d phase.
        phone_ip: IP of the phone.
        database_ip: IP of firebase.
        ip_ver_is_six: is IP version 6?
    Returns:
        A set containing ARCore servers.
    """

    # Apply a filter to get SYN-ACK packets between the start and the end of synchronization.
    syn_ack_filter = "tcp.flags.syn == 1 && tcp.flags.ack == 1"
    sync_start_ts_filter = 'frame.time >= "{st}"'.format(st=sync_start_ts.strftime(DATETIME_FORMAT))
    sync_end_ts_filter = 'frame.time <= "{et}"'.format(et=sync_end_ts.strftime(DATETIME_FORMAT))
    ip_filter = 'ipv6' if ip_ver_is_six else 'ip'
    pyshark_filter = [syn_ack_filter, sync_start_ts_filter, sync_end_ts_filter, ip_filter]
    display_filter = " && ".join(pyshark_filter)
    print(display_filter)
    syn_ack_packets = pyshark.FileCapture(pcap_path, display_filter=display_filter)

    # Check each SYN-ACK packet.
    possible_arcore_syn_ack_ip_set = set()
    for syn_ack_packet in syn_ack_packets:
        src_ip = get_ip(syn_ack_packet, 'src')
        possible_arcore_syn_ack_ip_set.add(src_ip)

    # In some cases, Just-a-Line can have a very long synchronization (a few minutes), during which the phone would
    # establish a connection with servers that are unrelated to the app.
    # So we also check the Fin packets that are generated after the last 2d phase.
    # The intersection between possible_arcore_syn_ack_ip_set and possible_arcore_fin_ip_set is very likely to be
    # the ARCore servers.
    fin_filter = "tcp.flags.fin == 1"
    last_rendering_ts_filter = 'frame.time >= "{et}"'.format(et=last_rendering_ts.strftime(DATETIME_FORMAT))
    src_ip_phone_filter = ('ipv6' if ip_ver_is_six else 'ip') + ".src == " + phone_ip
    exclude_database_ip_filter = ('ipv6' if ip_ver_is_six else 'ip') + ".dst != " + database_ip
    pyshark_filter = [fin_filter, last_rendering_ts_filter, exclude_database_ip_filter, src_ip_phone_filter]
    display_filter = " && ".join(pyshark_filter)
    fin_packets = pyshark.FileCapture(pcap_path, display_filter=display_filter)
    # Check each Fin packet.
    possible_arcore_fin_ip_set = set()
    for fin_packet in fin_packets:
        dst_ip = get_ip(fin_packet, 'dst')
        possible_arcore_fin_ip_set.add(dst_ip)

    if len(possible_arcore_fin_ip_set) > 0:
        arcore_ip_set = possible_arcore_syn_ack_ip_set.intersection(possible_arcore_fin_ip_set)
    else:
        # Hack: in some cases, we don't have Fin packets. Directly use possible_arcore_syn_ack_ip_set
        # in these cases.
        arcore_ip_set = possible_arcore_syn_ack_ip_set
        print("possible_arcore_fin_ip_set is empty. arcore_ip_set: " + str(arcore_ip_set))

    # TO-DO: add a log of INFO?
    if arcore_ip_set != possible_arcore_syn_ack_ip_set:
        print("arcore_ip_set != possible_arcore_syn_ack_ip_set")
        print("possible_arcore_syn_ack_ip_set: " + str(possible_arcore_syn_ack_ip_set))
        print("possible_arcore_fin_ip_set: " + str(possible_arcore_fin_ip_set))
        print("arcore_ip_set: " + str(arcore_ip_set))

    if not arcore_ip_set:
        raise Exception("Arcore IP is not found.")

    return arcore_ip_set


def parse_log_and_pcap(host_app_log, resolver_app_log, host_pcap, resolver_pcap) -> Dict[str, Any]:
    """
    Get necessary information, including moments, from logs by regexp matching and pcap by pyshark.
    :param host_app_log: path to the host's log file.
    :param resolver_app_log: path to the resolver's log file.
    :param host_pcap: path to the host's pcap file
    :param resolver_pcap: path to the resolver's pcap file
    :return: a map
    """

    # host app moments
    host_log_info_map = prepare_host_log_info(host_app_log)
    host_log_moments = host_log_info_map['moments']
    first_moment_touch_screen = host_log_moments[0]

    # resolver app moments
    resolver_log_info_map = prepare_resolver_log_info(resolver_app_log)
    resolver_log_moments = resolver_log_info_map['moments']
    last_moment_finish_rendering = resolver_log_moments[-1]

    # host pcap trace moments, within e2e time duration
    host_pcap_info = prepare_host_pcap_info(
        host_pcap,
        start_time=first_moment_touch_screen.time,
        end_time=last_moment_finish_rendering.time,
    )

    # resolver pcap trace moments, within the e2e time frame.
    resolver_pcap_info = prepare_resolver_pcap_info(
        resolver_pcap,
        start_time=first_moment_touch_screen.time,
        end_time=last_moment_finish_rendering.time,
        database_ip=host_pcap_info['database_ip'],
    )

    # Check if the host used IPv6, and set the firebase regex pattern we are looking for.
    ip_version_is_six = is_ip_version_six(host_pcap)

    # Find ARCore IP addresses used by the host.
    host_arcore_ip_set = get_arcore_addresses(host_pcap,
                                              host_log_info_map['sync_start_time'],
                                              host_log_info_map['sync_end_time'],
                                              last_moment_finish_rendering.time,
                                              host_pcap_info['phone_ip'],
                                              host_pcap_info['database_ip'],
                                              ip_version_is_six)

    # Find ARCore IP addresses used by the resolver.
    resolver_arcore_ip_set = get_arcore_addresses(resolver_pcap,
                                                  resolver_log_info_map['sync_start_time'],
                                                  resolver_log_info_map['sync_end_time'],
                                                  last_moment_finish_rendering.time,
                                                  resolver_pcap_info['phone_ip'],
                                                  host_pcap_info['database_ip'],
                                                  ip_version_is_six)

    host_app_info = AppInfo(log_moments=host_log_moments,
                            pcap_moments=host_pcap_info['moments'],
                            sync_start_time=host_log_info_map['sync_start_time'],
                            sync_end_time=host_log_info_map['sync_end_time'],
                            phone_ip=host_pcap_info['phone_ip'],
                            arcore_ip_set=host_arcore_ip_set,
                            ip_ver_is_six=ip_version_is_six)

    resolvers_app_info = AppInfo(log_moments=resolver_log_moments,
                                 pcap_moments=resolver_pcap_info['moments'],
                                 sync_start_time=resolver_log_info_map['sync_start_time'],
                                 sync_end_time=resolver_log_info_map['sync_end_time'],
                                 phone_ip=resolver_pcap_info['phone_ip'],
                                 arcore_ip_set=resolver_arcore_ip_set,
                                 ip_ver_is_six=ip_version_is_six)

    return {
        'host': host_app_info,
        'resolver': resolvers_app_info,
        'e2e_start_time': first_moment_touch_screen.time,
        'e2e_end_time': last_moment_finish_rendering.time,
        'ip_set': host_pcap_info['ip_set'].union(resolver_pcap_info['ip_set']),
        'database_ip': host_pcap_info['database_ip'],
    }


def prepare_moment_for_specified_ip_list(
        pcap_path: str,
        source: str,
        start_time: datetime,
        end_time: datetime,
        include_ip_set: Set[str] = None,
        exclude_ip_set: Set[str] = None,
):
    pyshark_filters = []
    pyshark_filters.append('frame.time >= "{st}"'.format(st=start_time.strftime(DATETIME_FORMAT)))
    pyshark_filters.append('frame.time <= "{et}"'.format(et=end_time.strftime(DATETIME_FORMAT)))
    pyshark_filters.append('tcp')
    display_filter = ' && '.join(pyshark_filters)
    cap_e2e = pyshark.FileCapture(pcap_path, display_filter=display_filter)

    moments = []
    for pkt in cap_e2e:
        src_ip = get_ip(pkt, type='src')
        dst_ip = get_ip(pkt, type='dst')

        if exclude_ip_set:
            if (src_ip in exclude_ip_set) or (dst_ip in exclude_ip_set):
                continue
        if include_ip_set:
            if (src_ip not in include_ip_set) and (dst_ip not in include_ip_set):
                continue

        if is_data_pkt(pkt, min_size=100):
            moments.append(Moment(
                source=source,
                name='TCP data pkt',
                time=get_timestamp(pkt),
                raw_data=pkt,
                metadata=create_essential_metadata(pkt, type='data'),
                action_from=src_ip,
                action_to=dst_ip,
            ))
        elif is_ack_pkt(pkt):
            moments.append(Moment(
                source=source,
                name='TCP ack pkt',
                time=get_timestamp(pkt),
                raw_data=pkt,
                metadata=create_essential_metadata(pkt, type='ack'),
                action_from=src_ip,
                action_to=dst_ip,
            ))
    cap_e2e.close()
    return {
        'moments': moments,
    }


class ProcessAppLogUnitTest(unittest.TestCase):
    def test_extract_timestamp(self):
        line = '04-07 15:34:34.421 10456 10592 D ar_activity: [Update ARCore frame time=2023-04-07 15:34:34.421]'
        self.assertEqual('2023-04-07 15:34:34.421', extract_timestamp(line, year='2023'))

    def test_match_prefix(self):
        line = '04-07 15:16:47.171  6297  6297 D ar_activity: [[1a start] touch screen time=2023-04-07 15:16:47.171]'
        self.assertEqual(True, has_prefix(line, r'\[\[1a start\] touch screen'))

        line = '04-07 15:16:47.171  6297  6297 D ar_activity: [[1b end] time=2023-04-07 15:16:47.171]'
        self.assertEqual(False, has_prefix(line, r'\[\[1a start\]'))

        line = '04-07 15:16:47.408 11056 11213 D ar_activity: [[2d] after update lines time=2023-04-07 15:16:47.407]'
        self.assertEqual(True, has_prefix(line, r'\[\[2d\]'))

        line = '04-07 15:34:36.196 10456 10592 D ar_activity: [[2d end] stroke time=2023-04-07 15:34:36.196]'
        self.assertEqual(True, has_prefix(line, r'\[\[2d end\]'))

        line = '04-07 15:35:34.304 10854 10854 D ar_activity: [[2a end - 2d start] onChildChanged stroke id=-NSSCsksd3t6Qrxa0fqY time=2023-04-07 15:35:34.303]'
        self.assertEqual(True, has_prefix(line, r'\[\[2a end - 2d start\] onChildChanged'))

        line = '04-07 15:35:34.221 10854 11002 D ar_activity: stroke (id: -NSSCsksd3t6Qrxa0fqY) was added at 2023-04-07 15:35:34.221'
        self.assertEqual(True, has_prefix(line, r'stroke \(id: .*?\) was added at'))
