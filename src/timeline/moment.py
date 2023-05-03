import unittest
from datetime import datetime
from typing import Any, Dict, List, Set
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


def create_essential_metadata(pkt, type: str):
    src_ip = get_ip(pkt, type='src')
    dst_ip = get_ip(pkt, type='dst')
    pkt_size = pkt.length
    return {'src_ip': src_ip, 'dst_ip': dst_ip, 'type': type, 'size': pkt_size}


def prepare_host_app_moments(host_app_log):
    touch_start_regexp = lambda x: has_prefix(x, prefix=r'\[\[1a start\] touch screen')
    stroke_was_added_regexp = lambda x: has_prefix(x, prefix=r'stroke \(id: .*?\) was added at')
    add_points_to_stroke_regexp = lambda x: has_prefix(x, prefix=r'send stroke to firebase')
    cloud_finish_processing_regexp = lambda x: has_prefix(x, prefix=r'\[\[2a end - 2d start\] onChildChanged')

    res = []
    with open(host_app_log, 'r') as f:
        while True:
            line = f.readline()
            if not line:
                break
            # process line by line
            if touch_start_regexp(line):
                res.append(Moment(
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
                res.append(Moment(
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
                res.append(Moment(
                    source='host',
                    name='add points to stroke',
                    time=extract_timestamp(line, year=YEAR),
                    raw_data=line,
                    action_from='host',
                    action_to='host',
                ))
                continue
            if cloud_finish_processing_regexp(line):
                res.append(Moment(
                    source='host',
                    name='notified by finish of cloud processing',
                    time=extract_timestamp(line, year=YEAR),
                    raw_data=line,
                    action_from='host',
                    action_to='host',
                ))
                continue
    return res


def prepare_host_pcap_moments(
        host_pcap,
        start_time,
        end_time,
):
    pyshark_filters = []
    pyshark_filters.append('frame.time >= "{st}"'.format(st=start_time.strftime(DATETIME_FORMAT)))
    pyshark_filters.append('frame.time <= "{et}"'.format(et=end_time.strftime(DATETIME_FORMAT)))
    pyshark_filters.append('tcp')
    display_filter = ' && '.join(pyshark_filters)
    cap_e2e = pyshark.FileCapture(host_pcap, display_filter=display_filter)

    ip_set = set()
    phone_ip = None
    database_ip = None
    for pkt in cap_e2e:
        src_ip = get_ip(pkt, type='src')
        dst_ip = get_ip(pkt, type='dst')
        ip_set.add(src_ip)
        ip_set.add(dst_ip)
        # assume the first is data pkt from phone to database
        if phone_ip is None and is_data_pkt(pkt):
            phone_ip = src_ip
            database_ip = dst_ip

    moments = []
    for pkt in cap_e2e:
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


def prepare_resolver_app_moments(resolver_app_log):
    on_line_added_regexp = lambda x: has_prefix(x, prefix=r'\[\[2a end - 2d start\] onChildAdded')
    on_line_changed_regexp = lambda x: has_prefix(x, prefix=r'\[\[2a end - 2d start\] onChildChanged')
    finish_rendering_regexp = lambda x: has_prefix(x, prefix=r'\[\[2d\] after update')

    moments = []
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
    return moments


def prepare_resolver_pcap_moments(
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

    ip_set = set()
    resolver_phone_ip = None

    for pkt in caps:
        ip_set.add(get_ip(pkt, type='src'))
        ip_set.add(get_ip(pkt, type='dst'))
        # get the first pkt from database to resolver phone
        if resolver_phone_ip is None and is_data_pkt(pkt, src=database_ip):
            resolver_phone_ip = get_ip(pkt, type='dst')

    moments = []
    for pkt in caps:
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


def prepare_moment_data(host_app_log, resolver_app_log, host_pcap, resolver_pcap) -> Dict[str, Any]:
    """
    Filter out moments from logs by regexp matching and pcap by pyshark.
    :param host_app_log:
    :param resolver_app_log:
    :param host_pcap:
    :param resolver_pcap:
    :return:
    """
    # host app moments
    host_app_moments = prepare_host_app_moments(host_app_log)
    first_moment_touch_screen = host_app_moments[0]
    # resolver app moments
    resolver_app_moments = prepare_resolver_app_moments(resolver_app_log)
    last_moment_finish_rendering = resolver_app_moments[-1]
    # host pcap trace moments, within e2e time duration
    host_pcap_moments = prepare_host_pcap_moments(
        host_pcap,
        start_time=first_moment_touch_screen.time,
        end_time=last_moment_finish_rendering.time,
    )
    # resolver pcap trace moments, within
    resolver_pcap_moments = prepare_resolver_pcap_moments(
        resolver_pcap,
        start_time=first_moment_touch_screen.time,
        end_time=last_moment_finish_rendering.time,
        database_ip=host_pcap_moments['database_ip'],
    )
    return {
        'host_app': host_app_moments,
        'resolver_app': resolver_app_moments,
        'host_pcap': host_pcap_moments['moments'],
        'resolver_pcap': resolver_pcap_moments['moments'],
        'e2e_start_time': first_moment_touch_screen.time,
        'e2e_end_time': last_moment_finish_rendering.time,
        'ip_set': host_pcap_moments['ip_set'].union(resolver_pcap_moments['ip_set']),
        'host_phone_ip': host_pcap_moments['phone_ip'],
        'resolver_phone_ip': resolver_pcap_moments['phone_ip'],
        'database_ip': host_pcap_moments['database_ip'],
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
