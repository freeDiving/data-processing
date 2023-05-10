import glob
import json
import os
from datetime import datetime
from typing import List, Dict, Any

from src.phase.phase import prepare_phases
from src.timeline.moment import Moment, prepare_moment_for_specified_ip_list, prepare_moment_data
from src.utils.time import diff_sec

ROOT_PATH = os.path.abspath(os.path.dirname(__file__))


def input_path(*file_path) -> str:
    return os.path.join(ROOT_PATH, *file_path)


def output_path(file_path: str) -> str:
    OUTPUT_DIR = 'output'
    return os.path.join(ROOT_PATH, '', OUTPUT_DIR, file_path)


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
    phases = prepare_phases(timeline)

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


def output_send_pkt_sequences(timeline: List[Moment], output_path: str):
    found_start = False
    found_user_touch_event = False
    with open(output_path, 'w') as f:
        f.write('time,pkt_size,src_ip,dst_ip\n')
        for moment in timeline:
            if not found_start:
                if not found_user_touch_event and moment.name == 'user touches screen':
                    found_user_touch_event = True
                if found_user_touch_event and moment.name == 'add a stroke':
                    found_start = True
                continue

            if moment.source == 'host' and moment.name == 'send data pkt to cloud':
                f.write('{time},{pkt_size},{src_ip},{dst_ip}\n'.format(
                    time=moment.time,
                    pkt_size=moment.metadata['size'],
                    src_ip=moment.metadata['src_ip'],
                    dst_ip=moment.metadata['dst_ip'],
                ))
    print('output send packet sequences to {}'.format(output_path))


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


def prepare_other_ip_summary_and_moments(
        host_pcap: str,
        resolver_pcap: str,
        e2e_start_time: datetime,
        e2e_end_time: datetime,
        database_ip: str,
):
    transmission_summation_map = {}
    host_moment_res = prepare_moment_for_specified_ip_list(
        pcap_path=host_pcap,
        source='host',
        exclude_ip_set={database_ip},
        start_time=e2e_start_time,
        end_time=e2e_end_time,
    )
    resolver_moment_res = prepare_moment_for_specified_ip_list(
        pcap_path=resolver_pcap,
        source='resolver',
        exclude_ip_set={database_ip},
        start_time=e2e_start_time,
        end_time=e2e_end_time,
    )
    moments = host_moment_res.get('moments') + resolver_moment_res.get('moments')
    moments.sort(key=lambda x: x.time)

    for moment in moments:
        key = '{}->{}'.format(moment.action_from, moment.action_to)
        if key not in transmission_summation_map:
            transmission_summation_map[key] = {
                'total_size': 0,
                'pkt_count': 0,
            }
        transmission_summation_map[key]['total_size'] += int(moment.metadata['size'])
        transmission_summation_map[key]['pkt_count'] += 1

    return {
        'moments': moments,
        'transmission_summation_map': transmission_summation_map,
    }


def output_other_ip_summary_and_timeline(
        res_of_other_ip: Dict[str, Any],
        output_path: str
):
    transmission_summation_map = res_of_other_ip.get('transmission_summation_map')
    moments = res_of_other_ip.get('moments')

    with open(output_path, 'w') as f:
        f.write('time,source,name,from,to,metadata (json)\n')

        for key in transmission_summation_map:
            from_ip, to_ip = key.split('->')
            f.write('{time},{source},{name},{action_from},{action_to},{metadata}\n'.format(
                time='',
                name='transmission summary',
                source='',
                action_from=from_ip,
                action_to=to_ip,
                metadata=json.dumps({
                    'total_pkt_count': transmission_summation_map[key]['pkt_count'],
                    'total_pkt_size': transmission_summation_map[key]['total_size'],
                }),
            ))
        for moment in moments:
            f.write('{time},{source},{name},{action_from},{action_to},{metadata}\n'.format(
                time=moment.time,
                name=moment.name,
                source=moment.source,
                action_from=moment.action_from,
                action_to=moment.action_to,
                metadata=json.dumps(moment.metadata),
            ))
    print('output other ip statistic to {}'.format(output_path))


def main():
    # clear output dirs
    output_dirs = glob.glob(input_path('../output/*/*'))
    for _path in output_dirs:
        for filename in os.listdir(_path):
            filepath = os.path.join(_path, filename)
            try:
                if os.path.isfile(filepath):
                    os.remove(filepath)
            except Exception as e:
                print(f"Error while deleting file: {filepath} ({e})")

    # host_dirs = [
    # input_path('../datasets/5g-static-line/host/run1'),
    # input_path('../datasets/5g-static-line/host/run2'),
    # input_path('../datasets/5g-static-line/host/run3'),
    # input_path('../datasets/5g-static-line/host/run4'),
    # input_path('../datasets/5g-static-line/host/run5'),
    # input_path('../datasets/5g-host_move-line/host/run1'),
    # input_path('../datasets/5g-host_move-line/host/run2'),
    # input_path('../datasets/5g-host_move-line/host/run3'),
    # input_path('../datasets/5g-host_move-line/host/run4'),
    # input_path('../datasets/5g-host_move-line/host/run5'),
    # input_path('../datasets/5g-resolver_move-line/host/run1'),
    # input_path('../datasets/5g-resolver_move-line/host/run2'),
    # input_path('../datasets/5g-resolver_move-line/host/run3'),
    # input_path('../datasets/5g-resolver_move-line/host/run4'),
    # input_path('../datasets/5g-resolver_move-line/host/run5'),
    # ]
    host_dirs = glob.glob(input_path('./datasets/*/host/*'))
    for index, host_path in enumerate(host_dirs):
        resolver_path = host_path.replace('/host/', '/resolver/')
        exp_name = host_path.split('/')[-3]
        run_name = host_path.split('/')[-1]
        app_log = 'static_log.logcat'
        pcap = 'capture.pcap'
        _output_path = output_path(exp_name + '/' + run_name)

        if not os.path.exists(_output_path):
            os.makedirs(_output_path)
        try:
            moment_map = prepare_moment_data(
                host_app_log=input_path(host_path, app_log),
                resolver_app_log=input_path(resolver_path, app_log),
                host_pcap=input_path(host_path, pcap),
                resolver_pcap=input_path(resolver_path, pcap),
            )

            # combine all moments
            timeline = []
            timeline.extend(moment_map.get('host_app'))
            timeline.extend(moment_map.get('resolver_app'))
            timeline.extend(moment_map.get('host_pcap'))
            timeline.extend(moment_map.get('resolver_pcap'))
            # sort moments by time
            timeline.sort(key=lambda x: x.time)

            # output_sequences(timeline, '{prefix}/sequences.txt'.format(prefix=_output_path))
            output_phases(timeline, '{prefix}/phases.csv'.format(prefix=_output_path))
            output_send_pkt_sequences(timeline,
                                      '{prefix}/send_pkt_sequences.csv'.format(prefix=_output_path))

            # collect data of ips that is not the ip of firebase database
            # including ips of arcore
            res_of_other_ip = prepare_other_ip_summary_and_moments(
                host_pcap=input_path(host_path, pcap),
                resolver_pcap=input_path(resolver_path, pcap),
                e2e_start_time=moment_map.get('e2e_start_time'),
                e2e_end_time=moment_map.get('e2e_end_time'),
                database_ip=moment_map.get('database_ip'),
            )
            output_other_ip_summary_and_timeline(
                res_of_other_ip,
                output_path='{prefix}/other_ip_statistics.csv'.format(prefix=_output_path)
            )

            timeline.extend(res_of_other_ip.get('moments'))
            timeline.sort(key=lambda x: x.time)
            output_timeline(timeline, '{prefix}/timeline.csv'.format(prefix=_output_path))


        except Exception as e:
            print('run {run_name} failed'.format(run_name=run_name))
            print(e)
            continue


if __name__ == '__main__':
    main()
    print('done')
