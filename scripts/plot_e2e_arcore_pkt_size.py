import os
from typing import List, Dict

import matplotlib.pyplot as plt

from src.main import prepare_other_ip_summary_and_moments
from src.phase.phase import prepare_phases
from src.timeline.moment import prepare_moment_data
from src.utils.time import diff_sec

ROOT_PATH = os.path.abspath(os.path.dirname(__file__))


def input_path(*file_path) -> str:
    return os.path.join(ROOT_PATH, *file_path)


def output_path(*paths: str) -> str:
    OUTPUT_DIR = 'output'
    return os.path.join(ROOT_PATH, '..', OUTPUT_DIR, *paths)


def output_chart(
        phase_to_arcore_pkg_size_map: Dict[int, int],
        phases: List[Dict],
        source: str,
        network_dir: str,
        output_file_path: str,
):
    # phase index as x-axis
    x_values = range(0, len(phases))
    # e2e latency as y-axis
    y1_values = []
    # arcore pkg size as y-axis
    y2_values = []
    for i in x_values:
        phase = phases[i]
        e2e_end, e2e_start = e2e_of_phase(phase)
        e2e = float(diff_sec(e2e_start, e2e_end))
        y1_values.append(e2e)

        y2_values.append(phase_to_arcore_pkg_size_map.get(i, 0))

    # Create a line chart figure and axis object
    fig, ax1 = plt.subplots()
    # set figure size
    fig.set_size_inches(10, 6)
    ax2 = ax1.twinx()

    ax1.plot(x_values, y1_values, color='blue', label='e2e latency')
    ax2.plot(x_values, y2_values, color='green', label='total arcore pkt size')

    # Set the chart title and axis labels
    ax1.set_title(
        'ARCore Package Size and E2E Latency of Each Phase ({src}: {dir})'.format(src=source, dir=network_dir))
    ax1.set_xlabel('Phase')
    ax1.set_ylabel('E2E Latency (ms)')
    ax2.set_ylabel('Total Arcore Pkt Size (Bytes)')
    # Add a legend
    ax1.legend(loc='upper left', bbox_to_anchor=(0, 1), ncol=2)
    ax2.legend(loc='upper left', bbox_to_anchor=(0, 0.90), ncol=2)
    # Draw the line chart
    # plt.show()
    # plt.clf()
    fig.savefig(output_file_path)
    print('saved to {}'.format(output_file_path))


def e2e_of_phase(phase):
    e2e_start = phase['host: local action']['start']
    e2e_end = phase['resolver: rendering']['end']
    return e2e_end, e2e_start


def main():
    host_dirs = [
        input_path('../datasets/5g-static-line/host/run1'),
        input_path('../datasets/5g-static-line/host/run2'),
        input_path('../datasets/5g-static-line/host/run3'),
        input_path('../datasets/5g-static-line/host/run4'),
        input_path('../datasets/5g-static-line/host/run5'),
        input_path('../datasets/5g-host_move-line/host/run1'),
        input_path('../datasets/5g-host_move-line/host/run2'),
        input_path('../datasets/5g-host_move-line/host/run3'),
        input_path('../datasets/5g-host_move-line/host/run4'),
        input_path('../datasets/5g-host_move-line/host/run5'),
        input_path('../datasets/5g-resolver_move-line/host/run1'),
        input_path('../datasets/5g-resolver_move-line/host/run2'),
        input_path('../datasets/5g-resolver_move-line/host/run3'),
        input_path('../datasets/5g-resolver_move-line/host/run4'),
        input_path('../datasets/5g-resolver_move-line/host/run5'),
    ]
    for index, host_path in enumerate(host_dirs):
        resolver_path = host_path.replace('/host/', '/resolver/')
        exp_name = host_path.split('/')[-3]
        run_name = host_path.split('/')[-1]
        app_log = 'static_log.logcat'
        pcap = 'capture.pcap'

        moment_map = prepare_moment_data(
            host_app_log=input_path(host_path, app_log),
            host_pcap=input_path(host_path, pcap),
            resolver_app_log=input_path(resolver_path, app_log),
            resolver_pcap=input_path(resolver_path, pcap)
        )
        # combine all moments
        timeline = []
        timeline.extend(moment_map.get('host_app'))
        timeline.extend(moment_map.get('resolver_app'))
        timeline.extend(moment_map.get('host_pcap'))
        timeline.extend(moment_map.get('resolver_pcap'))
        timeline.sort(key=lambda x: x.time)

        phases = prepare_phases(timeline)

        res_of_other_ip = prepare_other_ip_summary_and_moments(
            host_pcap=input_path(host_path, pcap),
            resolver_pcap=input_path(resolver_path, pcap),
            e2e_start_time=moment_map.get('e2e_start_time'),
            e2e_end_time=moment_map.get('e2e_end_time'),
            database_ip=moment_map.get('database_ip'),
        )
        timeline.extend(res_of_other_ip.get('moments'))
        timeline.sort(key=lambda x: x.time)

        # data_map = res_of_other_ip.get('transmission_summation_map')
        # host_map = {}
        # resolver_map = {}
        host_phone_ip = moment_map.get('host_phone_ip')
        resolver_phone_ip = moment_map.get('resolver_phone_ip')

        arcore_ip_prefix = '2607:f8b0:4006'
        host_uplink_map = {}
        host_downlink_map = {}
        resolver_uplink_map = {}
        resolver_downlink_map = {}

        phase_index = 0
        phase_start = None
        phase_end = None
        for moment in timeline:
            if phase_index > len(phases) - 1:
                break
            if phase_start is None or moment.time > phase_end:
                phase = phases[phase_index]
                e2e_end, e2e_start = e2e_of_phase(phase)
                phase_start = e2e_start
                phase_end = e2e_end
                phase_index += 1

            if phase_start <= moment.time <= phase_end:
                if moment.action_to.startswith(arcore_ip_prefix):
                    if moment.action_from == host_phone_ip:
                        host_uplink_map[phase_index] = host_uplink_map.get(phase_index, 0) + int(
                            moment.metadata['size'])
                    elif moment.action_from == resolver_phone_ip:
                        resolver_uplink_map[phase_index] = resolver_uplink_map.get(phase_index, 0) + int(
                            moment.metadata['size'])
                elif moment.action_from.startswith(arcore_ip_prefix):
                    if moment.action_to == host_phone_ip:
                        host_downlink_map[phase_index] = host_downlink_map.get(phase_index, 0) + int(
                            moment.metadata['size'])
                    elif moment.action_to == resolver_phone_ip:
                        resolver_downlink_map[phase_index] = resolver_downlink_map.get(phase_index, 0) + int(
                            moment.metadata['size'])

        output_dir = exp_name + '/' + run_name
        filename_tpl = 'e2e-vs-arcore_pkt_size-{src}-{dir}'

        output_chart(
            host_uplink_map,
            phases,
            source='host',
            network_dir='uplink',
            output_file_path=output_path(output_dir, filename_tpl.format(src='host', dir='uplink'))
        )
        output_chart(
            host_downlink_map,
            phases,
            source='host',
            network_dir='downlink',
            output_file_path=
            output_path(output_dir, filename_tpl.format(src='host', dir='downlink'))
        )
        output_chart(
            resolver_uplink_map,
            phases,
            source='resolver',
            network_dir='uplink',
            output_file_path=output_path(output_dir, filename_tpl.format(src='resolver', dir='uplink'))
        )
        output_chart(
            resolver_downlink_map,
            phases,
            source='resolver',
            network_dir='downlink',
            output_file_path=output_path(output_dir, filename_tpl.format(src='resolver', dir='downlink'))
        )


if __name__ == '__main__':
    main()
