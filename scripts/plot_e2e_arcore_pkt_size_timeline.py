import os
from typing import List

import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import pandas as pd

from main import prepare_other_ip_summary_and_moments
from src.phase.phase import prepare_phases
from src.timeline.moment import parse_log_and_pcap
from src.timeline.timeline import get_timeline
from src.utils.time import diff_sec

ROOT_PATH = os.path.abspath(os.path.dirname(__file__))


def input_path(*file_path) -> str:
    res = os.path.join(ROOT_PATH, *file_path)
    return res


def output_path(*paths: str) -> str:
    OUTPUT_DIR = 'output'
    return os.path.join(ROOT_PATH, '..', OUTPUT_DIR, *paths)


def output_chart(
        x_host_draw_time: list,
        y_host_draw_e2e: list,
        x_resolver_draw_time: list,
        y_resolver_draw_e2e: list,
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

    e2e_start = min(x_host_draw_time[0], x_resolver_draw_time[0])
    e2e_end = max(x_host_draw_time[-1], x_resolver_draw_time[-1])

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
        x_host_draw_time,
        y_host_draw_e2e,
        color='green',
        label='e2e latency (host draw)',
        marker='_'
    )

    ax2.scatter(
        x_resolver_draw_time,
        y_resolver_draw_e2e,
        color='magenta',
        label='e2e latency \n(resolver draw)',
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


def prepare_e2e_latency_data(phases: List):
    x_host_draw_time = []
    x_resolver_draw_time = []
    y_host_draw_e2e = []
    y_resolver_draw_e2e = []
    for phase in phases:
        e2e_start = phase.get_e2e_start()
        e2e_end = phase.get_e2e_end()
        e2e = float(diff_sec(e2e_start, e2e_end))
        if phase.host_name == "host":
            x_host_draw_time.append(e2e_end)
            y_host_draw_e2e.append(e2e)
        else:
            x_resolver_draw_time.append(e2e_end)
            y_resolver_draw_e2e.append(e2e)
    return {"x_host_draw_time": x_host_draw_time,
            "y_host_draw_e2e": y_host_draw_e2e,
            'x_resolver_draw_time': x_resolver_draw_time,
            "y_resolver_draw_e2e": y_resolver_draw_e2e}


def main():
    """
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
    """
    host_dirs = [input_path('../datasets/0517-wifi/host/run1')]

    for index, host_path in enumerate(host_dirs):
        resolver_path = host_path.replace('/host/', '/resolver/')
        exp_name = host_path.split('/')[-3]
        run_name = host_path.split('/')[-1]
        app_log = 'static_log.logcat'
        pcap = 'capture.pcap'

        info_map = parse_log_and_pcap(
            host_app_log=input_path(host_path, app_log),
            host_pcap=input_path(host_path, pcap),
            resolver_app_log=input_path(resolver_path, app_log),
            resolver_pcap=input_path(resolver_path, pcap)
        )

        timeline = get_timeline(info_map)

        # phases of interaction with Firebase database
        phases = prepare_phases(timeline)

        # e2e-time data
        host_info = info_map["host"]
        resolver_info = info_map["resolver"]

        res_of_other_ip = prepare_other_ip_summary_and_moments(
            host_pcap=input_path(host_path, pcap),
            resolver_pcap=input_path(resolver_path, pcap),
            e2e_start_time=info_map.get('e2e_start_time'),
            e2e_end_time=info_map.get('e2e_end_time'),
            database_ip=info_map.get('database_ip'),
            host_arcore_ip_set=host_info.arcore_ip_set,
            resolver_arcore_ip_set=resolver_info.arcore_ip_set
        )

        #  time ticks of interaction with ips other than Firebase database
        other_ip_moments = res_of_other_ip.get('moments')

        host_phone_ip = host_info.phone_ip
        resolver_phone_ip = resolver_info.phone_ip

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
            if (moment.action_to in host_info.arcore_ip_set) or (moment.action_to in resolver_info.arcore_ip_set):
                if moment.action_from == host_phone_ip:
                    x_host_arcore_uplink_time.append(moment.time)
                    y_host_arcore_uplink_size.append(int(moment.metadata['size']))
                elif moment.action_from == resolver_phone_ip:
                    x_resolver_arcore_uplink_time.append(moment.time)
                    y_resolver_arcore_uplink_size.append(int(moment.metadata['size']))
            elif (moment.action_from in host_info.arcore_ip_set) or (moment.action_from in resolver_info.arcore_ip_set):
                if moment.action_to == host_phone_ip:
                    x_host_arcore_downlink_time.append(moment.time)
                    y_host_arcore_downlink_size.append(int(moment.metadata['size']))
                elif moment.action_to == resolver_phone_ip:
                    x_resolver_arcore_downlink_time.append(moment.time)
                    y_resolver_arcore_downlink_size.append(int(moment.metadata['size']))

        output_dir = exp_name + '/' + run_name
        filename = 'arcore_pkt_size-vs-e2e-over-time'
        res = prepare_e2e_latency_data(phases)
        x_host_draw_time = res["x_host_draw_time"]
        y_host_draw_e2e = res["y_host_draw_e2e"]
        x_resolver_draw_time = res["x_resolver_draw_time"]
        y_resolver_draw_e2e = res["y_resolver_draw_e2e"]

        output_chart(
            x_host_draw_time=x_host_draw_time,
            y_host_draw_e2e=y_host_draw_e2e,
            x_resolver_draw_time=x_resolver_draw_time,
            y_resolver_draw_e2e=y_resolver_draw_e2e,
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
        print()

if __name__ == '__main__':
    main()