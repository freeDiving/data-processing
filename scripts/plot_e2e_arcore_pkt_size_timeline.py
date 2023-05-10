import os
from typing import List

import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import pandas as pd

from main import prepare_other_ip_summary_and_moments
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
        x_time: list,
        y_e2e_latency: list,
        x_host_arcore_uplink_time: list,
        y_host_arcore_uplink_size: list,
        x_host_arcore_downlink_time: list,
        y_host_arcore_downlink_size: list,
        x_resolver_arcore_uplink_time: list,
        y_resolver_arcore_uplink_size: list,
        x_resolver_arcore_downlink_time: list,
        y_resolver_arcore_downlink_size: list,
        output_file_path: str,
):
    # Create a line chart figure and axis object
    fig, ax1 = plt.subplots()
    # set figure size
    fig.set_size_inches(12, 6)

    ax2 = ax1.twinx()

    e2e_start = x_time[0]
    e2e_end = x_time[-1]

    ax1.set_xticks(pd.date_range(e2e_start, e2e_end, freq='1 ms'))
    ax1.set_xlim(e2e_start, e2e_end)
    ax1.set_xticklabels(ax1.get_xticklabels())

    ax1.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
    ax1.xaxis.set_major_locator(plt.MaxNLocator(10))

    ax1.scatter(
        x_host_arcore_uplink_time,
        y_host_arcore_uplink_size,
        color='blue',
        label='host uplink',
        marker='x',
    )
    ax1.scatter(
        x_host_arcore_downlink_time,
        y_host_arcore_downlink_size,
        color='purple',
        label='host downlink',
        marker='x'
    )
    ax1.scatter(
        x_resolver_arcore_uplink_time,
        y_resolver_arcore_uplink_size,
        color='red',
        label='resolver uplink',
        marker='+'
    )
    ax1.scatter(
        x_resolver_arcore_downlink_time,
        y_resolver_arcore_downlink_size,
        color='orange',
        label='resolver downlink',
        marker='+'
    )

    ax2.scatter(
        x_time,
        y_e2e_latency,
        color='green',
        label='e2e latency',
        marker='_'
    )

    # Set the chart title and axis labels
    ax1.set_title('Arcore Pkt Size over time')
    ax1.set_xlabel('Timestamp')
    ax1.set_ylabel('Arcore Pkt Size (Bytes)')
    ax2.set_ylabel('E2E Latency (ms)')
    # Add a legend
    # ax1.legend(loc='upper right', bbox_to_anchor=(0, 0.6), ncol=2)
    # ax2.legend(loc='upper right', bbox_to_anchor=(0, 0.45), ncol=1)
    ax1.legend(loc='upper left', bbox_to_anchor=(1.1, 1))
    ax2.legend(loc='upper left', bbox_to_anchor=(1.1, 0.8))
    # ax2.legend(loc='center left',  ncol=1)
    # Draw the line chart
    # plt.show()
    # plt.clf()
    plt.subplots_adjust(right=0.75)  # adjust the right margin here
    fig.savefig(output_file_path)
    print('saved to {}'.format(output_file_path))


def e2e_of_phase(phase):
    e2e_start = phase['host: local action']['start']
    e2e_end = phase['resolver: rendering']['end']
    return e2e_start, e2e_end


def prepare_e2e_latency_data(phases: List):
    x = []
    y = []
    for phase in phases:
        e2e_start, e2e_end = e2e_of_phase(phase)
        e2e = float(diff_sec(e2e_start, e2e_end))
        x.append(e2e_end)
        y.append(e2e)
    return x, y


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

        # phases of interaction with Firebase database
        phases = prepare_phases(timeline)

        # e2e-time data
        x_time, y_e2e_latency = prepare_e2e_latency_data(phases)

        res_of_other_ip = prepare_other_ip_summary_and_moments(
            host_pcap=input_path(host_path, pcap),
            resolver_pcap=input_path(resolver_path, pcap),
            e2e_start_time=moment_map.get('e2e_start_time'),
            e2e_end_time=moment_map.get('e2e_end_time'),
            database_ip=moment_map.get('database_ip'),
        )
        #  time ticks of interaction with ips other than Firebase database
        other_ip_moments = res_of_other_ip.get('moments')

        host_phone_ip = moment_map.get('host_phone_ip')
        resolver_phone_ip = moment_map.get('resolver_phone_ip')
        arcore_ip_prefix = '2607:f8b0:4006'

        x_host_arcore_uplink_time = []
        y_host_arcore_uplink_size = []
        x_host_arcore_downlink_time = []
        y_host_arcore_downlink_size = []
        x_resolver_arcore_uplink_time = []
        y_resolver_arcore_uplink_size = []
        x_resolver_arcore_downlink_time = []
        y_resolver_arcore_downlink_size = []

        # prepare data for arcore uplink and downlink
        for moment in other_ip_moments:
            if moment.action_to.startswith(arcore_ip_prefix):
                if moment.action_from == host_phone_ip:
                    x_host_arcore_uplink_time.append(moment.time)
                    y_host_arcore_uplink_size.append(int(moment.metadata['size']))
                elif moment.action_from == resolver_phone_ip:
                    x_resolver_arcore_uplink_time.append(moment.time)
                    y_resolver_arcore_uplink_size.append(int(moment.metadata['size']))
            elif moment.action_from.startswith(arcore_ip_prefix):
                if moment.action_to == host_phone_ip:
                    x_host_arcore_downlink_time.append(moment.time)
                    y_host_arcore_downlink_size.append(int(moment.metadata['size']))
                elif moment.action_to == resolver_phone_ip:
                    x_resolver_arcore_downlink_time.append(moment.time)
                    y_resolver_arcore_downlink_size.append(int(moment.metadata['size']))

        output_dir = exp_name + '/' + run_name
        filename = 'arcore_pkt_size-vs-e2e-over-time'

        output_chart(
            x_time=x_time,
            y_e2e_latency=y_e2e_latency,
            x_host_arcore_uplink_time=x_host_arcore_uplink_time,
            y_host_arcore_uplink_size=y_host_arcore_uplink_size,
            x_host_arcore_downlink_time=x_host_arcore_downlink_time,
            y_host_arcore_downlink_size=y_host_arcore_downlink_size,
            x_resolver_arcore_uplink_time=x_resolver_arcore_uplink_time,
            y_resolver_arcore_uplink_size=y_resolver_arcore_uplink_size,
            x_resolver_arcore_downlink_time=x_resolver_arcore_downlink_time,
            y_resolver_arcore_downlink_size=y_resolver_arcore_downlink_size,
            output_file_path=output_path(output_dir, filename)
        )


if __name__ == '__main__':
    main()
