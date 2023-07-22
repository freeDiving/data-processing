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


class RuntimeInfo:
    log_drawing_moments: list[Moment]
    log_sync_moments: list[Moment]
    pcap_drawing_moments: list[Moment]
    phone_ip: str
    arcore_ip_set: set
    ip_ver_is_six: bool

    def __init__(self, **kwargs):
        self.log_drawing_moments = kwargs.get("log_drawing_moments") or []
        self.log_sync_moments = kwargs.get("log_sync_moments") or []
        self.pcap_drawing_moments = kwargs.get("pcap_drawing_moments") or []
        self.first_sync_start_time = kwargs.get("first_sync_start_time")
        self.sync_end_time = kwargs.get("action_to")
        self.phone_ip = kwargs.get("phone_ip")
        self.arcore_ip_set = kwargs.get("arcore_ip_set") or set()
        self.ip_ver_is_six = kwargs.get("ip_ver_is_six")


def create_essential_metadata(pkt, type: str):
    src_ip = get_ip(pkt, type='src')
    dst_ip = get_ip(pkt, type='dst')
    pkt_size = pkt.length
    return {'src_ip': src_ip, 'dst_ip': dst_ip, 'type': type, 'size': pkt_size}


def parse_log(log, phone_type: str):
    """
    Parse each line of the host's application log, and return necessary information.
    Args:
        host_app_log: Path to the host app log
    Returns:
        A map that contains a list of host moments, host's synchronization start time,
        and host's synchronization end time.
    """
    # Host's regexp
    touch_start_regexp = lambda x: has_prefix(x, prefix=r'\[\[1a start\] touch screen')
    stroke_was_added_regexp = lambda x: has_prefix(x, prefix=r'stroke \(id: .*?\) was added at')
    add_points_to_stroke_regexp = lambda x: has_prefix(x, prefix=r'send stroke to firebase')
    cloud_finish_processing_regexp = lambda x: has_prefix(x, prefix=r'onComplete of doStrokeUpdate')
    sync_start_regexp = lambda x: has_prefix(x, prefix=r'SET ANCHOR')
    sync_success_regexp = lambda x: has_prefix(x, prefix=r'SYNCED')
    # sync_failed_regexp = lambda x: has_prefix(x, prefix=r'\[\[onAnchorResolutionError')

    # Resolver's regexp
    on_line_added_regexp = lambda x: has_prefix(x, prefix=r'\[\[2a end - 2d start\] onChildAdded')
    on_line_changed_regexp = lambda x: has_prefix(x, prefix=r'\[\[2a end - 2d start\] onChildChanged')
    finish_rendering_regexp = lambda x: has_prefix(x, prefix=r'\[\[2d\] after update')

    log_drawing_moments = []
    log_sync_moments = []
    sync_success_found = False
    first_add_points_moment_time = datetime.max
    with open(log, 'r') as f:
        while True:
            line = f.readline()
            if not line:
                break
            # process line by line
            if sync_success_found:
                if touch_start_regexp(line):
                    log_drawing_moments.append(Moment(
                        source=phone_type,
                        name='user touches screen',
                        time=extract_timestamp(line, year=YEAR),
                        raw_data=line,
                        action_from=phone_type,
                        action_to=phone_type,
                    ))
                elif stroke_was_added_regexp(line):
                    stroke_id = extract_stroke_id(line)
                    log_drawing_moments.append(Moment(
                        source=phone_type,
                        name='add a stroke',
                        time=extract_timestamp(line, year=YEAR),
                        raw_data=line,
                        metadata={'stroke_id': stroke_id},
                        action_from=phone_type,
                        action_to=phone_type,
                    ))
                elif add_points_to_stroke_regexp(line):
                    add_points_moment = Moment(
                        source=phone_type,
                        name='add points to stroke',
                        time=extract_timestamp(line, year=YEAR),
                        raw_data=line,
                        action_from=phone_type,
                        action_to=phone_type,
                    )
                    if first_add_points_moment_time == datetime.max:
                        first_add_points_moment_time = add_points_moment.time
                    log_drawing_moments.append(add_points_moment)
                elif cloud_finish_processing_regexp(line):
                    log_drawing_moments.append(Moment(
                        source=phone_type,
                        name='notified by finish of cloud processing',
                        time=extract_timestamp(line, year=YEAR),
                        raw_data=line,
                        action_from=phone_type,
                        action_to=phone_type,
                    ))
                elif on_line_changed_regexp(line) or on_line_added_regexp(line):
                    stroke_id = extract_stroke_id(line)
                    log_drawing_moments.append(Moment(
                        source=phone_type,
                        name='receive point updates',
                        time=extract_timestamp(line, year=YEAR),
                        raw_data=line,
                        metadata={'stroke_id': stroke_id},
                        action_from=phone_type,
                        action_to=phone_type,
                    ))
                elif finish_rendering_regexp(line):
                    log_drawing_moments.append(Moment(
                        source=phone_type,
                        name='finish rendering',
                        time=extract_timestamp(line, year=YEAR),
                        raw_data=line,
                        action_from=phone_type,
                        action_to=phone_type,
                    ))
                else:
                    continue  # Messages that we don't care.

            # Synchronization-related log messages.
            else:
                if sync_start_regexp(line) or sync_success_regexp(line):
                    if sync_start_regexp(line):
                        sync_event_name = "sync start"
                    # elif sync_failed_regexp(line):
                    #    sync_event_name = "sync failed"
                    #    if log_sync_moments[-1].name != "sync start":
                    #        raise Exception("No corresponding sync message")
                    else:
                        sync_event_name = "sync success"
                        sync_success_found = True
                        if log_sync_moments[-1].name != "sync start":
                            raise Exception("No corresponding sync message")
                    log_sync_moments.append(Moment(
                        source=phone_type,
                        name=sync_event_name,
                        time=extract_timestamp(line, year=YEAR),
                        raw_data=line,
                        action_from=phone_type,
                        action_to=phone_type,
                    ))
                continue

        # Error checking
        if not log_sync_moments:
            raise RuntimeError("Missing sync start or end message.")

    return {"log_drawing_moments": log_drawing_moments,
            "log_sync_moments": log_sync_moments,
            "first_add_points_moment_time": first_add_points_moment_time}


def get_phone_ip(pcap, ip_version_is_six: bool):
    # Get phone IP
    pyshark_filters = []
    pyshark_filters.append('tcp.flags.syn == 1')
    ip_filter = "ipv6" if ip_version_is_six else "ip"
    pyshark_filters.append(ip_filter)
    syn_filter = ' && '.join(pyshark_filters)
    syn_pkts = pyshark.FileCapture(pcap, display_filter=syn_filter)
    for syn_pkt in syn_pkts:
        phone_ip = get_ip(syn_pkt, type='src')
        break

    return phone_ip


def get_firebase_database_ip(host_pcap, resolver_pcap, host_phone_ip, resolver_phone_ip, host_first_add_points_time,
                             resolver_first_add_points_time):
    if host_first_add_points_time < resolver_first_add_points_time:
        first_add_points_moment_time = host_first_add_points_time
        pcap = host_pcap
        phone_ip = host_phone_ip
    else:
        first_add_points_moment_time = resolver_first_add_points_time
        pcap = resolver_pcap
        phone_ip = resolver_phone_ip

    # Error checking
    if first_add_points_moment_time == datetime.max:
        raise Exception("No valid 1a start found")

    pyshark_filters = []
    pyshark_filters.append('frame.time >= "{st}"'.format(st=first_add_points_moment_time.strftime(DATETIME_FORMAT)))
    pyshark_filters.append('tcp')
    display_filter = ' && '.join(pyshark_filters)
    pkts = pyshark.FileCapture(pcap, display_filter=display_filter)

    # Assume the first packet sent by the phone is to the firebase database.
    for pkt in pkts:
        src_ip = get_ip(pkt, type='src')
        if src_ip == phone_ip:
            database_ip = get_ip(pkt, type='dst')
            break
    return database_ip


def parse_pcap(
        pcap,
        e2e_filter: str,
        phone_ip: str,
        database_ip: str,
        phone_type: str,
        arcore_ip_set
):
    # Categorize all the packets.
    drawing_moments = []
    sync_moments = []
    ip_set = set()
    cap_e2e = pyshark.FileCapture(pcap, display_filter=e2e_filter)
    for pkt in cap_e2e:
        # Push all IP addresses to a set (for debugging purposes)
        src_ip = get_ip(pkt, type='src')
        dst_ip = get_ip(pkt, type='dst')
        ip_set.add(src_ip)
        ip_set.add(dst_ip)

        # Drawing moments. i.e., traffic from/to firebase database.
        if is_data_pkt(pkt, min_size=100, src=phone_ip, dst=database_ip):
            drawing_moments.append(Moment(
                source=phone_type,
                name='send data pkt to cloud',
                time=get_timestamp(pkt),
                raw_data=pkt,
                metadata=create_essential_metadata(pkt, type='data'),
                action_from=phone_type,
                action_to='cloud',
            ))
        elif is_ack_pkt(pkt, src=database_ip, dst=phone_ip):
            drawing_moments.append(Moment(
                source=phone_type,
                name='receive ack pkt from cloud',
                time=get_timestamp(pkt),
                raw_data=pkt,
                metadata=create_essential_metadata(pkt, type='ack'),
                action_from='cloud',
                action_to=phone_type,
            ))
        elif is_data_pkt(pkt, min_size=100, src=database_ip, dst=phone_ip):
            drawing_moments.append(Moment(
                source=phone_type,
                name='receive data pkt from cloud',
                time=get_timestamp(pkt),
                raw_data=pkt,
                metadata=create_essential_metadata(pkt, type='data'),
                action_from='cloud',
                action_to=phone_type,
            ))
        elif is_data_pkt(pkt, min_size=100, src=arcore_ip_set, dst=phone_ip):
            sync_moments.append(Moment(
                source=phone_type,
                name='receive SLAM pkt from cloud',
                time=get_timestamp(pkt),
                raw_data=pkt,
                metadata=create_essential_metadata(pkt, type='data'),
                action_from='cloud',
                action_to=phone_type,
            ))
        else:
            continue
    cap_e2e.close()
    return {
        'phone_ip': phone_ip,
        'database_ip': database_ip,
        'ip_set': ip_set,
        'drawing_moments': drawing_moments,
        'sync_moments': sync_moments,
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


def get_arcore_addresses(pcap_path, first_sync_start_ts, sync_end_ts, last_rendering_ts, phone_ip, database_ip,
                         ip_ver_is_six):
    """
    Find arcore servers used by the host/resolver.
    Args:
        pcap_path: path to the host's or the resolver's pcap file.
        first_sync_start_ts: synchronization start timestamp.
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
    first_sync_start_ts_filter = 'frame.time >= "{st}"'.format(st=first_sync_start_ts.strftime(DATETIME_FORMAT))
    sync_end_ts_filter = 'frame.time <= "{et}"'.format(et=sync_end_ts.strftime(DATETIME_FORMAT))
    ip_filter = 'ipv6' if ip_ver_is_six else 'ip'
    pyshark_filter = [syn_ack_filter, first_sync_start_ts_filter, sync_end_ts_filter, ip_filter]
    display_filter = " && ".join(pyshark_filter)
    print("get_arcore_addresses: " + display_filter)
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

    def get_e2e_filter(first_touch_screen_moment_time, last_finish_rendering_moment_time, ip_version_is_six: bool):
        pyshark_filters = []
        pyshark_filters.append(
            'frame.time >= "{st}"'.format(st=first_touch_screen_moment_time.strftime(DATETIME_FORMAT)))
        pyshark_filters.append(
            'frame.time <= "{et}"'.format(et=last_finish_rendering_moment_time.strftime(DATETIME_FORMAT)))
        ip_filter = "ipv6" if ip_version_is_six else "ip"
        tls_filter = "!tls.handshake"
        pyshark_filters.append('tcp')
        pyshark_filters.append(ip_filter)
        pyshark_filters.append(tls_filter)
        e2e_filter = ' && '.join(pyshark_filters)
        return e2e_filter

    # host app moments
    host_log_info_map = parse_log(host_app_log, "host")
    host_log_drawing_moments = host_log_info_map['log_drawing_moments']
    host_log_sync_moments = host_log_info_map['log_sync_moments']

    # resolver app moments
    resolver_log_info_map = parse_log(resolver_app_log, "resolver")
    resolver_log_drawing_moments = resolver_log_info_map['log_drawing_moments']
    resolver_log_sync_moments = host_log_info_map['log_sync_moments']

    # Check if the host used IPv6
    ip_version_is_six = is_ip_version_six(host_pcap)

    # Get phone IP
    host_phone_ip = get_phone_ip(host_pcap, ip_version_is_six)
    resolver_phone_ip = get_phone_ip(resolver_pcap, ip_version_is_six)

    # Get firebase database ip
    database_ip = get_firebase_database_ip(host_pcap, resolver_pcap, host_phone_ip, resolver_phone_ip,
                                           host_log_info_map["first_add_points_moment_time"],
                                           resolver_log_info_map["first_add_points_moment_time"])

    # host pcap trace moments, within e2e time duration
    # Get filters
    first_touch_screen_moment_time = min(host_log_drawing_moments[0].time, resolver_log_drawing_moments[0].time)
    last_finish_rendering_moment_time = max(host_log_drawing_moments[-1].time, resolver_log_drawing_moments[-1].time)
    e2e_filter = get_e2e_filter(first_touch_screen_moment_time, last_finish_rendering_moment_time, ip_version_is_six)

    # Find ARCore IP addresses used by the host.
    host_arcore_ip_set = get_arcore_addresses(host_pcap,
                                              # first sync start time.
                                              host_log_sync_moments[0].time,
                                              # sync end time.
                                              host_log_sync_moments[-1].time,
                                              last_finish_rendering_moment_time,
                                              host_phone_ip,
                                              database_ip,
                                              ip_version_is_six)

    # Find ARCore IP addresses used by the resolver.
    resolver_arcore_ip_set = get_arcore_addresses(resolver_pcap,
                                                  # first sync start time.
                                                  host_log_sync_moments[0].time,
                                                  # sync end time.
                                                  host_log_sync_moments[-1].time,
                                                  last_finish_rendering_moment_time,
                                                  resolver_phone_ip,
                                                  database_ip,
                                                  ip_version_is_six)

    # host pcap trace moments, within the e2e time frame.
    host_pcap_info = parse_pcap(
        host_pcap,
        e2e_filter,
        host_phone_ip,
        database_ip,
        "host",  # phone type
        host_arcore_ip_set,
    )

    # resolver pcap trace moments, within the e2e time frame.
    resolver_pcap_info = parse_pcap(
        resolver_pcap,
        e2e_filter,
        resolver_phone_ip,
        database_ip,
        "resolver",  # phone type
        resolver_arcore_ip_set,
    )

    host_runtime_info = RuntimeInfo(log_drawing_moments=host_log_drawing_moments,
                                    log_sync_moments=host_log_sync_moments,
                                    pcap_drawing_moments=host_pcap_info['drawing_moments'],
                                    phone_ip=host_pcap_info['phone_ip'],
                                    arcore_ip_set=host_arcore_ip_set,
                                    ip_ver_is_six=ip_version_is_six)

    resolvers_runtime_info = RuntimeInfo(log_drawing_moments=resolver_log_drawing_moments,
                                         log_sync_moments=resolver_log_sync_moments,
                                         pcap_drawing_moments=resolver_pcap_info['drawing_moments'],
                                         phone_ip=resolver_pcap_info['phone_ip'],
                                         arcore_ip_set=resolver_arcore_ip_set,
                                         ip_ver_is_six=ip_version_is_six)

    return {
        'host': host_runtime_info,
        'resolver': resolvers_runtime_info,
        'e2e_start_time': first_touch_screen_moment_time,
        'e2e_end_time': last_finish_rendering_moment_time,
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
