import csv
import glob
import os.path
import datetime
import re
from collections import deque
from typing import List, Dict, TextIO, Any

import pyshark

from constants import DATETIME_FORMAT
from process_app_log import Phase, is_formal_log, has_prefix, extract_timestamp, generate_moment, \
    extract_stroke_id, Moment
from process_pcap import get_ip, is_data_pkt, get_timestamp, is_ack_pkt, filter_ip

OUTPUT_DIR = 'output'
ROOT_PATH = os.path.abspath(os.path.dirname(__file__))


def input_path(*file_path) -> str:
    return os.path.join(ROOT_PATH, *file_path)


def output_path(file_path: str) -> str:
    return os.path.join(ROOT_PATH, OUTPUT_DIR, file_path)


def process_app_with_firebase_log(file_path: str, type: str, metadata: Dict = None) -> List[Phase]:
    metadata = metadata if metadata is not None else {}
    with open(file_path, 'r') as f:
        if type == 'host':
            return process_app_with_firebase_log_for_host(file=f)
        elif type == 'resolver':
            return process_app_with_firebase_log_for_resolver(file=f, stroke_id=metadata.get('stroke_id'))
        return []


def process_app_with_firebase_log_for_host(file: TextIO) -> List[Phase]:
    phase_1a = Phase(phase='1a', desc='touch screen to first data pkt sent')
    task_queue = deque([phase_1a])
    res_phases = [phase_1a]
    lines = file.readlines()
    lines = filter(is_formal_log, lines)
    moments = list(map(generate_moment, lines))
    while task_queue:
        cur_phase = task_queue[0]
        if cur_phase.phase == '1a':
            filtered_moments = list(filter(lambda m: has_prefix(m.raw_data, prefix=r'\[\[1a start\]'), moments))

            if not len(filtered_moments):
                raise Exception("no result found for phase 1a")
            # get the first result
            res = filtered_moments[0]
            cur_phase.start_time = res.time
            cur_phase.start_raw_data = res.raw_data

            # get stroke id
            filtered_moments = list(filter(lambda m: m.time > cur_phase.start_time, moments))
            filtered_moments = list(
                filter(lambda m: has_prefix(m.raw_data, prefix=r'\[\[1b start\]'), filtered_moments))
            if not len(filtered_moments):
                raise Exception("no result found for phase 1b")
            # get the first result after 1a start
            res = filtered_moments[0]
            cur_phase.metadata['stroke_id'] = extract_stroke_id(res.raw_data)
            task_queue.popleft()
    return res_phases


def process_app_with_firebase_log_for_resolver(file: TextIO, stroke_id: str) -> List[Phase]:
    phase_2a = Phase(phase='2a', desc='first data pkt from cloud to last pkt from cloud')
    phase_2d = Phase(phase='2d', desc='end rendered time to last pkt from cloud')
    task_queue = deque([phase_2a, phase_2d])
    res_phases = [phase_2a, phase_2d]
    lines = file.readlines()
    lines = filter(is_formal_log, lines)
    moments = list(map(generate_moment, lines))
    while len(task_queue):
        cur_phase = task_queue[0]
        if cur_phase.phase == '2a':
            filtered_moments = list(
                filter(lambda m: has_prefix(m.raw_data, prefix=r'\[\[2a end - 2d start\] onChildAdded'), moments))
            for m in filtered_moments:
                extracted_stroke_id = extract_stroke_id(m.raw_data)
                if extracted_stroke_id == stroke_id:
                    cur_phase.metadata['stroke_id'] = stroke_id
                    cur_phase.start_time = m.time
                    cur_phase.start_raw_data = m.raw_data
                    break
        if cur_phase.phase == '2d':
            pass
            filtered_moments = list(
                filter(
                    lambda m: has_prefix(m.raw_data,
                                         prefix=r'\[\[2d\] after update lines') and m.time > phase_2a.start_time,
                    moments
                )
            )
            if len(filtered_moments):
                # raise Exception('no moments found for 2d')
                # print('no moments found for 2d')
                moment_2d = filtered_moments[-1]  # last 2d for the same stroke id
                cur_phase.end_time = moment_2d.time
                cur_phase.end_raw_data = moment_2d.raw_data
            else:
                cur_phase.end_time = datetime.datetime.now()
                cur_phase.end_raw_data = ''

        task_queue.popleft()
    return res_phases


# # accept a list of phases and output a csv file with columns: timestamp, phase
# def output_csv(phases: List[Phase], file_name: str):
#     # check file_name is existed, if not, create it
#     if not os.path.exists(os.path.dirname(file_name)):
#         os.makedirs(os.path.dirname(file_name))
#     with open(file_name, 'w') as f:
#         f.write('timestamp,phase\n')
#         for phase in phases:
#             f.write(f'{phase.timestamp},{phase.phase}\n')
#     print("output file: {}".format(file_name))


def process_pcap_trace(
        file_path: str,
        type: str,
        start_time: datetime,
        end_time: datetime,
        metadata: Dict = None
) -> Dict:
    metadata = metadata if metadata is not None else {}
    with open(file_path, 'r') as f:
        if type == 'host':
            return process_pcap_trace_for_host(file_path, start_time, end_time)
        elif type == 'resolver':
            return process_pcap_trace_for_resolver(file_path, start_time, end_time, metadata)
        return {}


def process_pcap_trace_for_host(file_path: str, start_time: datetime, end_time: datetime) -> Dict[str, Any]:
    # filter timestamp by e2e start and end, and filter out the data pkt & ack pkt
    # for the first data pkt, the source is phone, the destination is cloud
    # collect the data pkt and its ack as a pair
    #     if the source is phone and the content is Application Data, then it is 1b start
    #     if the source is cloud and the content is ACK, then it is 1b end
    #     if the source is cloud and the content is Application Data, then it is 1c start
    #     if the source is phone and the content is ACK, then it is 1c end
    # return all pairs
    pyshark_filters = []
    pyshark_filters.append('frame.time >= "{st}"'.format(st=start_time.strftime(DATETIME_FORMAT)))
    pyshark_filters.append('frame.time <= "{et}"'.format(et=end_time.strftime(DATETIME_FORMAT)))
    pyshark_filters.append('tcp')
    cap_e2e = pyshark.FileCapture(file_path, display_filter=' && '.join(pyshark_filters))
    ip_set = set()
    phone_ip = None
    database_ip = None
    for pkt in cap_e2e:
        ip_set.add(get_ip(pkt, type='src'))
        ip_set.add(get_ip(pkt, type='dst'))
        # assume the first is data pkt from phone to database
        if phone_ip is None and is_data_pkt(pkt):
            phone_ip = get_ip(pkt, type='src')
            database_ip = get_ip(pkt, type='dst')

    for pkt in cap_e2e:
        src_ip = get_ip(pkt, type='src')
        dst_ip = get_ip(pkt, type='dst')
        if src_ip != phone_ip and src_ip != database_ip:
            print('src ip not in ip set', src_ip, pkt.sniff_time)
        if dst_ip != phone_ip and dst_ip != database_ip:
            print('dst ip not in ip set', dst_ip, pkt.sniff_time)

    cap_e2e.close()

    cap = pyshark.FileCapture(file_path, display_filter=' && '.join(pyshark_filters))
    moments = []
    for pkt in cap:
        if is_data_pkt(pkt, min_size=100, src=phone_ip, dst=database_ip):
            moment_1b_start = Moment(name='1b_start', time=get_timestamp(pkt), raw_data=pkt)
            moments.append(moment_1b_start)
        elif is_ack_pkt(pkt, src=database_ip, dst=phone_ip):
            moment_1b_end = Moment(name='1b_end', time=get_timestamp(pkt), raw_data=pkt)
            moments.append(moment_1b_end)
        elif is_data_pkt(pkt, min_size=100, src=database_ip, dst=phone_ip):
            moment_1c_end = Moment(name='1c_end', time=get_timestamp(pkt), raw_data=pkt)
            moments.append(moment_1c_end)

    cap.close()
    return {
        'phone_ip': phone_ip,
        'database_ip': database_ip,
        'ip_set': ip_set,
        'moments': moments,
    }


def process_pcap_trace_for_resolver(
        file_path: str,
        start_time: datetime,
        end_time: datetime,
        metadata: Dict
) -> Dict:
    pyshark_filters = []
    pyshark_filters.append('frame.time >= "{st}"'.format(st=start_time.strftime(DATETIME_FORMAT)))
    pyshark_filters.append('frame.time <= "{et}"'.format(et=end_time.strftime(DATETIME_FORMAT)))
    pyshark_filters.append('tcp')
    pyshark_filters.append(
        '({a} || {b})'.format(
            a=filter_ip(metadata.get('database_ip'), type='src'),
            b=filter_ip(metadata.get('database_ip'), type='dst')
        )
    )
    display_filter = ' && '.join(pyshark_filters)
    cap = pyshark.FileCapture(file_path, display_filter=display_filter)
    moments = []
    for pkt in cap:
        if is_data_pkt(pkt, min_size=100):
            moment = Moment(name='2a_start', time=get_timestamp(pkt), raw_data=pkt)
            moments.append(moment)
        elif is_ack_pkt(pkt):
            moment = Moment(name='2a_end', time=get_timestamp(pkt), raw_data=pkt)
            moments.append(moment)

    cap.close()
    return {
        'moments': moments,
    }


def diff_sec(t1, t2):
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


def output_separate_csv():
    def prepare_data(host_app_log, resolver_app_log, host_pcap, resolver_pcap):
        host_app_phases = process_app_with_firebase_log(host_app_log, type='host')
        phase_1a = host_app_phases[0]

        resolver_app_phases = process_app_with_firebase_log(resolver_app_log, type='resolver', metadata={
            "stroke_id": phase_1a.metadata.get("stroke_id")
        })

        phase_2d = resolver_app_phases[-1]
        t1 = phase_1a.start_time
        t7 = phase_2d.end_time

        host_pcap_info = process_pcap_trace(
            host_pcap,
            type='host',
            start_time=t1,
            end_time=t7
        )
        phone_ip = host_pcap_info['phone_ip']
        database_ip = host_pcap_info['database_ip']
        ip_set = host_pcap_info['ip_set']

        t2 = None
        t3 = None
        t4 = None
        for moment in host_pcap_info['moments']:
            if t2 is None and moment.name == '1b_start':
                t2 = moment.time
            elif t3 is None and moment.name == '1b_end':
                t3 = moment.time
            elif t4 is None and moment.name == '1c_end':
                t4 = moment.time

        resolver_pcap_info = process_pcap_trace(
            resolver_pcap,
            type='resolver',
            start_time=t1,
            end_time=t7,
            metadata={
                'database_ip': database_ip,
            }
        )
        t5 = None
        t6 = None
        for moment in resolver_pcap_info['moments']:
            if t5 is None and moment.name == '2a_start':
                t5 = moment.time
            elif t6 is None and moment.name == '2a_end':
                t6 = moment.time

        return {
            't1': t1,
            't2': t2,
            't3': t3,
            't4': t4,
            't5': t5,
            't6': t6,
            't7': t7,
            'phone_ip': phone_ip,
            'database_ip': database_ip,
            'ip_set': ip_set,
        }

    date = 'wifi-static-point'
    host_dirs = glob.glob(input_path('./{date}/host/*'.format(date=date)))
    for host_path in host_dirs:
        # if re.match(r".*[0-9]{2}$", host_path):
        #     continue
        resolver_path = host_path.replace('host', 'resolver')
        run_name = host_path.split('/')[-1]
        app_log = 'static_log.logcat'
        pcap = 'capture.pcap'

        try:
            data = prepare_data(
                host_app_log=input_path(host_path, app_log),
                host_pcap=input_path(host_path, pcap),
                resolver_app_log=input_path(resolver_path, app_log),
                resolver_pcap=input_path(resolver_path, pcap)
            )
        except Exception as e:
            print('run {run_name} failed'.format(run_name=run_name))
            print(e)
            continue

        t1 = data.get('t1')
        t2 = data.get('t2')
        t3 = data.get('t3')
        t4 = data.get('t4')
        t5 = data.get('t5')
        t6 = data.get('t6')
        t7 = data.get('t7')
        phone_ip = data.get('phone_ip')
        database_ip = data.get('database_ip')
        ip_set = data.get('ip_set')

        phase_data = [
            ['phase', 'duration (ms)', 'start', 'end', 'description'],
            ['1a', diff_sec(t1, t2), t1, t2, 'from [touch screen] to [first data pkt sent by host to cloud]'],
            ['1b', diff_sec(t2, t3), t2, t3,
             'from [last ack received from cloud] to [first data pkt sent by host to cloud]'],
            ['1c', diff_sec(t3, t4), t3, t4,
             'from [first data pkt received from cloud] to [last ack received from cloud]'],
            ['2x', diff_sec(t4, t5), t4, t5, 'description'],
            ['2a', diff_sec(t5, t6), t5, t6,
             'from [first data pkt received from cloud] to [last data pkt received from cloud]'],
            ['2d', diff_sec(t6, t7), t6, t7, 'from [last data pkt received from cloud] to [resolver renders data]'],
            ['e2e', diff_sec(t1, t7), t1, t7, 'from [touch screen] to [resolver renders data]'],
        ]

        misc_data = [
            [],
            ['ip_name', 'ip_addr'],
            ['phone_ip', phone_ip],
            ['database_ip', database_ip],
            *list(map(lambda x: ['unknown', x], filter(lambda y: y != phone_ip and y != database_ip, ip_set))),
        ]

        output_csv([*phase_data, *misc_data], get_run_file(date, 'host', run_name, 'phase.csv'))


def output_combined_csv():
    pass


if __name__ == '__main__':
    output_separate_csv()
