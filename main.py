import csv
import os.path
import datetime
from collections import deque
from typing import List, Dict, TextIO

from process_app_log import Phase, get_phases_from_lines, is_formal_log, has_prefix, extract_timestamp, generate_moment, \
    extract_stroke_id

OUTPUT_DIR = 'output'
ROOT_PATH = os.path.abspath(os.path.dirname(__file__))


def input_path(file_path: str) -> str:
    return os.path.join(ROOT_PATH, file_path)


def output_path(file_path: str) -> str:
    return os.path.join(ROOT_PATH, OUTPUT_DIR, file_path)


# accecpt a file path, open it and apply the get_phases_from_lines function, and output the list of phases
def process_app_log(file_path: str, type: str, metadata: Dict = None) -> Dict[str, Phase]:
    metadata = metadata if metadata is not None else {}
    with open(file_path, 'r') as f:
        if type == 'host':
            return process_app_log_for_host(file=f)
        elif type == 'resolver':
            return process_app_log_for_resolver(file=f, stroke_id=metadata.get('stroke_id'))
        return []


def process_app_log_for_host(file: TextIO) -> Dict[str, Phase]:
    phase_1a = Phase(phase='1a', desc='touch screen to first data pkt sent')
    task_queue = deque([phase_1a])
    res_phases = {
        '1a': phase_1a
    }
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


def process_app_log_for_resolver(file: TextIO, stroke_id: str) -> Dict[str, Phase]:
    phase_2a = Phase(phase='2a', desc='first data pkt from cloud to last pkt from cloud')
    phase_2d = Phase(phase='2d', desc='end rendered time to last pkt from cloud')
    task_queue = deque([phase_2a, phase_2d])
    res_phases = {
        '2a': phase_2a,
        '2d': phase_2d,
    }
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


def merge_timeline(host_app_log, resolver_app_log):
    host_app_phases = process_app_log(input_path(host_app_log), type='host')
    resolver_app_phases = process_app_log(input_path(resolver_app_log), type='resolver', metadata={
        "stroke_id": host_app_phases.get('1a').metadata.get("stroke_id")
    })
    # host_pcap = process_app_log(input_path(host_pcap), ["1a start", "2a end - 2d start", "2d"])
    # resolver_pcap = process_app_log(input_path(resolver_pcap), ["1a start", "2a end - 2d start", "2d"])

    t1 = host_app_phases.get('1a').start_time
    t2 = datetime.datetime()
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
    merge_timeline('./0407/host/0407-run1/static_log.logcat', './0407/resolver/0407-run1/static_log.logcat')
