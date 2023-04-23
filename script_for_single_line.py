import csv
import glob
import json
import os.path
import re
from collections import deque
from typing import List, Dict
import pyshark

from calculate_phases import Phase
from constants import DATETIME_FORMAT, YEAR
from process_app_log import has_prefix, extract_timestamp, extract_stroke_id, Moment
from process_pcap import get_ip, is_data_pkt, get_timestamp, is_ack_pkt, filter_ip, display_filter_for_ip

OUTPUT_DIR = 'output'
ROOT_PATH = os.path.abspath(os.path.dirname(__file__))


def input_path(*file_path) -> str:
    return os.path.join(ROOT_PATH, *file_path)


def output_path(file_path: str) -> str:
    return os.path.join(ROOT_PATH, OUTPUT_DIR, file_path)


def is_app_log(line: str):
    return re.match(r'^\d{2}-\d{2}\s', line)


def diff_sec(t1, t2):
    if t1 is None or t2 is None:
        return 'NaN'
    return f'{(t2 - t1).total_seconds() * 1000: .0f}'


def get_run_file(date: str, subject: str, run_name: str, file: str):
    return './{date}/{subject}/{run_name}/{file}'.format(date=date, subject=subject, run_name=run_name, file=file)


def output_csv(rows: List, output_file: str):
    with open(output_file, 'w') as f:
        writer = csv.writer(f)
        for row in rows:
            writer.writerow(row)
    print("output file: {}".format(output_file))
    return


#
# def output_separate_csv():
#     date = 'wifi-static-point'
#     host_dirs = glob.glob(input_path('./{date}/host/*'.format(date=date)))
#     for host_path in host_dirs:
#         # if re.match(r".*[0-9]{2}$", host_path):
#         #     continue
#         resolver_path = host_path.replace('host', 'resolver')
#         run_name = host_path.split('/')[-1]
#         app_log = 'static_log.logcat'
#         pcap = 'capture.pcap'
#
#         try:
#             data = prepare_data(
#                 host_app_log=input_path(host_path, app_log),
#                 host_pcap=input_path(host_path, pcap),
#                 resolver_app_log=input_path(resolver_path, app_log),
#                 resolver_pcap=input_path(resolver_path, pcap)
#             )
#         except Exception as e:
#             print('run {run_name} failed'.format(run_name=run_name))
#             print(e)
#             continue
#
#         t1 = data.get('t1')
#         t2 = data.get('t2')
#         t3 = data.get('t3')
#         t4 = data.get('t4')
#         t5 = data.get('t5')
#         t6 = data.get('t6')
#         t7 = data.get('t7')
#         phone_ip = data.get('phone_ip')
#         database_ip = data.get('database_ip')
#         ip_set = data.get('ip_set')
#
#         phase_data = [
#             ['phase', 'duration (ms)', 'start', 'end', 'description'],
#             ['1a', diff_sec(t1, t2), t1, t2, 'from [touch screen] to [first data pkt sent by host to cloud]'],
#             ['1b', diff_sec(t2, t3), t2, t3,
#              'from [last ack received from cloud] to [first data pkt sent by host to cloud]'],
#             ['1c', diff_sec(t3, t4), t3, t4,
#              'from [first data pkt received from cloud] to [last ack received from cloud]'],
#             ['2x', diff_sec(t4, t5), t4, t5, 'description'],
#             ['2a', diff_sec(t5, t6), t5, t6,
#              'from [first data pkt received from cloud] to [last data pkt received from cloud]'],
#             ['2d', diff_sec(t6, t7), t6, t7, 'from [last data pkt received from cloud] to [resolver renders data]'],
#             ['e2e', diff_sec(t1, t7), t1, t7, 'from [touch screen] to [resolver renders data]'],
#         ]
#
#         misc_data = [
#             [],
#             ['ip_name', 'ip_addr'],
#             ['phone_ip', phone_ip],
#             ['database_ip', database_ip],
#             *list(map(lambda x: ['unknown', x], filter(lambda y: y != phone_ip and y != database_ip, ip_set))),
#         ]
#
#         output_csv([*phase_data, *misc_data], get_run_file(date, 'host', run_name, 'phase.csv'))


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


def create_essential_metadata(pkt, type: str):
    src_ip = get_ip(pkt, type='src')
    dst_ip = get_ip(pkt, type='dst')
    pkt_size = pkt.length
    return {'src_ip': src_ip, 'dst_ip': dst_ip, 'type': type, 'size': pkt_size}


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
    # for each receive point moment, find the nearest finish rendering moment
    recv_point_moment_that_waits_for_finish_moment = None
    res = []
    for moment in moments:
        if recv_point_moment_that_waits_for_finish_moment is None and moment.name == 'receive point updates':
            recv_point_moment_that_waits_for_finish_moment = moment
            res.append(moment)
            continue
        if recv_point_moment_that_waits_for_finish_moment is not None and moment.name == 'finish rendering':
            recv_point_moment_that_waits_for_finish_moment = None
            res.append(moment)
    return res


def prepare_resolver_pcap_moments(
        resolver_pcap,
        start_time,
        end_time,
        phone_ip,
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
    }


def prepare_moment_data(host_app_log, resolver_app_log, host_pcap, resolver_pcap) -> Dict[str, List[Moment]]:
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
        phone_ip=host_pcap_moments['phone_ip'],
        database_ip=host_pcap_moments['database_ip'],
    )
    return {
        'host_app': host_app_moments,
        'resolver_app': resolver_app_moments,
        'host_pcap': host_pcap_moments['moments'],
        'resolver_pcap': resolver_pcap_moments['moments'],
    }


def prepare_timeline(host_app_log, resolver_app_log, host_pcap, resolver_pcap):
    moment_map = prepare_moment_data(host_app_log, resolver_app_log, host_pcap, resolver_pcap)

    # combine all moments
    timeline = []
    timeline.extend(moment_map.get('host_app'))
    timeline.extend(moment_map.get('resolver_app'))
    timeline.extend(moment_map.get('host_pcap'))
    timeline.extend(moment_map.get('resolver_pcap'))
    # sort moments by time
    timeline.sort(key=lambda x: x.time)
    return timeline


def output_timeline(timeline: List[Moment], output_path: str):
    with open(output_path, 'w') as f:
        f.write('time,source,name,from,to,metadata (json)\n')
        for moment in timeline:
            f.write('{time},{source},{name},{action_from},{action_to},{metadata}\n'.format(
                time=moment.time,
                name=moment.name,
                source=moment.source,
                action_from=moment.action_from,
                action_to=moment.action_to,
                metadata=json.dumps(moment.metadata),
            ))
    print('output timeline to {}'.format(output_path))


def output_sequences(timeline: List[Moment], output_path: str):
    with open(output_path, 'w') as f:
        for moment in timeline:
            # interaction
            arrow = '->'
            if moment.action_from == 'cloud':
                arrow = '-->'
            f.write('{_from}{arrow}{_to}: {do}\n'.format(
                _from=moment.action_from,
                arrow=arrow,
                _to=moment.action_to,
                do=moment.name,
            ))
    print('output sequences to {}'.format(output_path))


def output_phases(timeline: List[Moment], output_path: str):
    phases = []
    queue = deque()
    found_start = False
    for moment in timeline:
        if not found_start:
            if moment.name != 'user touches screen':
                continue
            found_start = True

        q_size = len(queue)
        is_handled = False
        while q_size > 0:
            phase = queue.popleft()
            q_size -= 1
            event = '{}: {}'.format(moment.source, moment.name)
            if phase.is_next_valid_event(event):
                phase.transit(event, moment.time)
                if not phase.is_finished():
                    queue.append(phase)
                else:
                    phases.append(phase.output())
                is_handled = True
                break
            queue.append(phase)
        if not is_handled:
            if moment.name == 'user touches screen' or moment.name == 'add points to stroke':
                phase = Phase(moment.time)
                queue.append(phase)

    with open(output_path, 'w') as f:
        f.write('phase,state,duration,start_time,end_time\n')
        for index, phase in enumerate(phases):
            for state in phase:
                f.write('{phase},{state},{duration},{start_time},{end_time}\n'.format(
                    phase='phase {}'.format(index + 1),
                    state=state,
                    duration=diff_sec(phase[state]['start'], phase[state]['end']),
                    start_time=phase[state]['start'],
                    end_time=phase[state]['end'],
                ))
                if state == 'resolver: rendering':
                    e2e_start_time = phase['host: local action']['start']
                    e2e_end_time = phase['resolver: rendering']['end']
                    f.write('{phase},{state},{duration},{start_time},{end_time}\n'.format(
                        phase='phase {}'.format(index + 1) + ' (e2e)',
                        state='e2e',
                        duration=diff_sec(e2e_start_time, e2e_end_time),
                        start_time=e2e_start_time,
                        end_time=e2e_end_time,
                    ))

    print('output phases to {}'.format(output_path))


if __name__ == '__main__':
    host_dirs = glob.glob(input_path('./datasets/*/host/*'))

    for host_path in host_dirs:
        resolver_path = host_path.replace('host', 'resolver')
        run_name = host_path.split('/')[-1]
        app_log = 'static_log.logcat'
        pcap = 'capture.pcap'
        output_path = '/'.join(host_path.split('/')[:-2]) + '/output'
        if not os.path.exists(output_path):
            os.mkdir(output_path)
        try:
            timeline = prepare_timeline(
                host_app_log=input_path(host_path, app_log),
                host_pcap=input_path(host_path, pcap),
                resolver_app_log=input_path(resolver_path, app_log),
                resolver_pcap=input_path(resolver_path, pcap)
            )
            output_timeline(timeline, '{prefix}/{run}_timeline.csv'.format(prefix=output_path, run=run_name))
            output_phases(timeline, '{prefix}/{run}_phases.csv'.format(prefix=output_path, run=run_name))
            # output_sequences(timeline, './{date}/{run}_sequences.txt'.format(date=date, run=run_name))
        except Exception as e:
            print('run {run_name} failed'.format(run_name=run_name))
            print(e)
            continue
