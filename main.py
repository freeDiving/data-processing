import csv
import os.path
import datetime
from collections import deque
from typing import List, Dict, TextIO

import pyshark

from process_app_log import Phase, get_phases_from_lines, is_formal_log, has_prefix, extract_timestamp, generate_moment, \
    extract_stroke_id
from process_pcap import get_ip

OUTPUT_DIR = 'output'
ROOT_PATH = os.path.abspath(os.path.dirname(__file__))
DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S.%f'


def input_path(file_path: str) -> str:
    return os.path.join(ROOT_PATH, file_path)


def output_path(file_path: str) -> str:
    return os.path.join(ROOT_PATH, OUTPUT_DIR, file_path)


# accecpt a file path, open it and apply the get_phases_from_lines function, and output the list of phases
def process_app_log(file_path: str, type: str, metadata: Dict = None) -> List[Phase]:
    metadata = metadata if metadata is not None else {}
    with open(file_path, 'r') as f:
        if type == 'host':
            return process_app_log_for_host(file=f)
        elif type == 'resolver':
            return process_app_log_for_resolver(file=f, stroke_id=metadata.get('stroke_id'))
        return []


def process_app_log_for_host(file: TextIO) -> List[Phase]:
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


def process_app_log_for_resolver(file: TextIO, stroke_id: str) -> List[Phase]:
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
            filtered_moments = list(
                filter(
                    lambda m: has_prefix(m.raw_data,
                                         prefix=r'\[\[2d\] after update lines') and m.time > phase_2a.start_time,
                    moments
                )
            )
            if not len(filtered_moments):
                raise Exception('no moments found for 2d')
            moment_2d = filtered_moments[0]
            cur_phase.end_time = moment_2d.time
            cur_phase.end_raw_data = moment_2d.raw_data

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


def process_pcap_trace(file_path: str, type: str, start_time: datetime, end_time: datetime) -> List[Phase]:
    with open(file_path, 'r') as f:
        if type == 'host':
            return process_pcap_trace_for_host(file_path, start_time, end_time)
        elif type == 'resolver':
            return process_pcap_trace_for_resolver(file_path)
        return []


def process_pcap_trace_for_host(file_path: str, start_time: datetime, end_time: datetime) -> List[Phase]:
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
    cap_e2e = pyshark.FileCapture(file_path, display_filter='&&'.join(pyshark_filters))
    ip_set = set()
    phone_ip = None
    cloud_ip = None
    for pkt in cap_e2e:
        ip_set.add(get_ip(pkt, type='src'))
        ip_set.add(get_ip(pkt, type='dst'))

        # assume the first is data pkt from phone and the second is ack pkt from cloud
        if phone_ip is None:
            phone_ip = get_ip(pkt, type='src')
        elif phone_ip is not None and cloud_ip is None:
            cloud_ip = get_ip(pkt, type='src')
        pass
    return []


def process_pcap_trace_for_resolver(file_path: str) -> List[Phase]:
    return []


def merge_timeline(host_app_log, resolver_app_log, host_pcap, resolver_pcap):
    host_app_phases = process_app_log(input_path(host_app_log), type='host')
    phase_1a = host_app_phases[0]

    resolver_app_phases = process_app_log(input_path(resolver_app_log), type='resolver', metadata={
        "stroke_id": phase_1a.metadata.get("stroke_id")
    })

    phase_2d = resolver_app_phases[-1]
    t1 = phase_1a.start_time
    t7 = phase_2d.end_time

    host_pcap = process_pcap_trace(
        input_path(host_pcap),
        type='host',
        start_time=t1,
        end_time=t7
    )
    # resolver_pcap = process_app_log(input_path(resolver_pcap), ["1a start", "2a end - 2d start", "2d"])

    t3 = datetime.datetime()
    t4 = datetime.datetime()
    t5 = datetime.datetime()
    t6 = datetime.datetime()
    t7 = resolver_app_phases[-1].time

    data = [
        ['phase', 'duration', 'start', 'end', 'description'],
        ['1a', diff_sec(t1, t2), t1, t2, 'description'],
        ['1b', diff_sec(t2, t3), t2, t3, 'description'],
        ['1c', diff_sec(t3, t4), t3, t4, 'description'],
        ['2x', diff_sec(t4, t5), t4, t5, 'description'],
        ['2a', diff_sec(t5, t6), t5, t6, 'description'],
        ['2d', diff_sec(t6, t7), t6, t7, 'description'],
    ]

    with open('output.csv', 'w') as f:
        writer = csv.writer(f)
        for row in data:
            writer.writerow(row)
    print("output file: {}".format('output.csv'))
    return


def diff_sec(t1, t2):
    return (t2 - t1).total_seconds()


if __name__ == '__main__':
    merge_timeline(
        host_app_log='./0407/host/0407-run1/static_log.logcat',
        resolver_app_log='./0407/resolver/0407-run1/static_log.logcat',
        host_pcap='./0407/host/0407-run1/capture.pcap',
        resolver_pcap='./0407/resolver/0407-run1/capture.pcap',
    )
