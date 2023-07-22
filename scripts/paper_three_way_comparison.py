import copy
import numpy as np
import os
import pyshark
from src.constants import DATETIME_FORMAT
import matplotlib.pyplot as plt

from src.timeline.moment import parse_log_and_pcap
from src.utils.pcap import get_ip, get_timestamp, is_ack_pkt

ROOT_PATH = os.path.abspath(os.path.dirname(__file__))
OUTPUT_DIR = 'output'


def input_path(*file_path) -> str:
    return os.path.join(ROOT_PATH, *file_path)


def output_path(*paths: str) -> str:
    return os.path.join(ROOT_PATH, '..', OUTPUT_DIR, *paths)


def output_chart(
        sync_start,
        sync_end,
        x_host_arcore_uplink_time: list,
        y_host_arcore_uplink_size: list,
        x_host_arcore_downlink_time: list,
        y_host_arcore_downlink_size: list,
        x_resolver_arcore_uplink_time: list,
        y_resolver_arcore_uplink_size: list,
        x_resolver_arcore_downlink_time: list,
        y_resolver_arcore_downlink_size: list,
        output_file_path: str,
        sync_restart_timestamps: list,
):
    # Create a line chart figure and axis object
    fig, ax1 = plt.subplots()
    # set figure size
    fig.set_size_inches(12, 6)

    ax1.set_xticks(np.arange((sync_start-sync_start).total_seconds(), (sync_end - sync_start).total_seconds(), 10))
    ax1.set_xlim((sync_start-sync_start).total_seconds(), (sync_end - sync_start).total_seconds())

    ax1.scatter(
        [(x - sync_start).total_seconds() for x in x_host_arcore_uplink_time],
        y_host_arcore_uplink_size,
        color='blue',
        label='host uplink',
        marker='x',
    )
    ax1.scatter(
        [(x - sync_start).total_seconds() for x in x_host_arcore_downlink_time],
        y_host_arcore_downlink_size,
        color='purple',
        label='host downlink',
        marker='x'
    )
    ax1.scatter(
        [(x - sync_start).total_seconds() for x in x_resolver_arcore_uplink_time],
        y_resolver_arcore_uplink_size,
        color='red',
        label='resolver uplink',
        marker='+'
    )
    ax1.scatter(
        [(x - sync_start).total_seconds() for x in x_resolver_arcore_downlink_time],
        y_resolver_arcore_downlink_size,
        color='orange',
        label='resolver downlink',
        marker='+'
    )

    sync_restart_timestamps = [(x - sync_start).total_seconds() for x in sync_restart_timestamps]

    #for sync_restart_timestamp in sync_restart_timestamps:
    for sync_restart_timestamp in sync_restart_timestamps:
        ax1.axvline(x=sync_restart_timestamp)

    # Set the chart title and axis labels
    ax1.set_title('Arcore Pkt Size over time')
    ax1.set_xlabel('Timestamp (s)')
    ax1.set_ylabel('Arcore Pkt Size (Byte)')
    # Add a legend
    # ax1.legend(loc='upper right', bbox_to_anchor=(0, 0.6), ncol=2)
    # ax2.legend(loc='upper right', bbox_to_anchor=(0, 0.45), ncol=1)
    ax1.legend(loc='upper left', bbox_to_anchor=(1.1, 1))
    # ax2.legend(loc='center left',  ncol=1)
    # Draw the line chart
    # plt.show()
    # plt.clf()
    plt.subplots_adjust(right=0.75)  # adjust the right margin here
    fig.savefig(output_file_path)
    print('saved to {}'.format(output_file_path))


def calculate_sync_data(runtime_info, pcap_path):
    log_sync_moments = runtime_info.log_sync_moments

    sync_start_moment = log_sync_moments[0]
    sync_success_moment = log_sync_moments[-1]
    phone_ip = runtime_info.phone_ip
    # Construct the filter
    sync_start_filter = 'frame.time >= "{st}"'.format(st=sync_start_moment.time.strftime(DATETIME_FORMAT))
    sync_end_filter = 'frame.time <= "{et}"'.format(et=sync_success_moment.time.strftime(DATETIME_FORMAT))
    ip_ver_filter = "ipv6" if runtime_info.ip_ver_is_six else "ip"
    tls_filter = "!tls.handshake"
    display_filter = " && ".join([sync_start_filter, sync_end_filter, ip_ver_filter, tls_filter, "tcp"])
    # Get capture
    caps = pyshark.FileCapture(pcap_path, display_filter=display_filter)

    x_uplink_time = []
    y_uplink_size = []
    x_downlink_time = []
    y_downlink_size = []

    for pkt in caps:
        if is_ack_pkt(pkt):
            continue

        src_ip = get_ip(pkt, type='src')
        dst_ip = get_ip(pkt, type='dst')

        if (src_ip == phone_ip) and (dst_ip in runtime_info.arcore_ip_set):
            x_uplink_time.append(get_timestamp(pkt))
            y_uplink_size.append(int(pkt.length))

        if (dst_ip == phone_ip) and (src_ip in runtime_info.arcore_ip_set):
            x_downlink_time.append(get_timestamp(pkt))
            y_downlink_size.append(int(pkt.length))

    return {
        'x_uplink_time': x_uplink_time,
        'y_uplink_size': y_uplink_size,
        'x_downlink_time': x_downlink_time,
        'y_downlink_size': y_downlink_size
    }


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
    """
    host_dirs = [input_path('datasets/0522-static-wifi/host/run1'),
                 input_path('datasets/0522-static-wifi/host/run2'),
                 input_path('datasets/0522-static-wifi/host/run3'),
                 input_path('datasets/0522-static-wifi/host/run4'),
                 input_path('datasets/0522-static-wifi/host/run5'),
                 input_path('datasets/0522-static-wifi/host/run6')]
    """
    for index, host_path in enumerate(host_dirs):
        resolver_path = host_path.replace('/host/', '/resolver/')
        exp_name = host_path.split('/')[-3]
        run_name = host_path.split('/')[-1]
        app_log = 'static_log.logcat'
        pcap = 'capture.pcap'

        # Get paths
        host_app_log = input_path(host_path, app_log)
        host_pcap = input_path(host_path, pcap)
        resolver_app_log = input_path(resolver_path, app_log)
        resolver_pcap = input_path(resolver_path, pcap)

        info_map = parse_log_and_pcap(
            host_app_log=host_app_log,
            host_pcap=host_pcap,
            resolver_app_log=resolver_app_log,
            resolver_pcap=resolver_pcap
        )

        host_runtime_info = info_map['host']
        res = calculate_sync_data(host_runtime_info, host_pcap)
        x_host_arcore_uplink_time = res['x_uplink_time']
        y_host_arcore_uplink_size = res['y_uplink_size']
        x_host_arcore_downlink_time = res['x_downlink_time']
        y_host_arcore_downlink_size = res['y_downlink_size']

        resolver_runtime_info = info_map['resolver']
        res = calculate_sync_data(resolver_runtime_info, resolver_pcap)
        x_resolver_arcore_uplink_time = res['x_uplink_time']
        y_resolver_arcore_uplink_size = res['y_uplink_size']
        x_resolver_arcore_downlink_time = res['x_downlink_time']
        y_resolver_arcore_downlink_size = res['y_downlink_size']

        output_dir = exp_name + '/' + run_name
        filename = 'sync_pkt_size-vs-time'

        # Get all sync restart timestamps, i.e. every other elements (except for the last one)
        host_log_sync_moments_copy = copy.deepcopy(host_runtime_info.log_sync_moments)
        host_log_sync_moments_copy.pop()
        host_log_sync_moments_copy.pop(0)
        sync_restart_timestamps = [moment.time for moment in host_log_sync_moments_copy]

        output_chart(
            sync_start=min(host_runtime_info.log_sync_moments[0].time, resolver_runtime_info.log_sync_moments[0].time),
            sync_end=max(host_runtime_info.log_sync_moments[-1].time, resolver_runtime_info.log_sync_moments[-1].time),
            x_host_arcore_uplink_time=x_host_arcore_uplink_time,
            y_host_arcore_uplink_size=y_host_arcore_uplink_size,
            x_host_arcore_downlink_time=x_host_arcore_downlink_time,
            y_host_arcore_downlink_size=y_host_arcore_downlink_size,
            x_resolver_arcore_uplink_time=x_resolver_arcore_uplink_time,
            y_resolver_arcore_uplink_size=y_resolver_arcore_uplink_size,
            x_resolver_arcore_downlink_time=x_resolver_arcore_downlink_time,
            y_resolver_arcore_downlink_size=y_resolver_arcore_downlink_size,
            output_file_path=output_path(output_dir, filename),
            sync_restart_timestamps=sync_restart_timestamps
        )
        print()


if __name__ == '__main__':
    main()
