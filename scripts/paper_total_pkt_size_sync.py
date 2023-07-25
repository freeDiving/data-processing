# Plot figure 5 (b) and (c)
# i.e., the total uplink and downlink packet size during Just-a-Line initial synchronization

import numpy as np
import os
import pyshark
from src.constants import DATETIME_FORMAT
import matplotlib.pyplot as plt

from src.timeline.moment import parse_log_and_pcap
from src.utils.pcap import get_ip, get_timestamp, is_ack_pkt
from matplotlib.ticker import MaxNLocator

ROOT_PATH = os.path.abspath(os.path.dirname(__file__))
OUTPUT_DIR = 'output'


def input_path(*file_path) -> str:
    return os.path.join(ROOT_PATH, *file_path)


def output_path(*paths: str) -> str:
    return os.path.join(ROOT_PATH, '..', OUTPUT_DIR, *paths)


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


def plot_figures(*lists_to_plot_with_labels, xmax = int, output_name: str): # Pack arguments into a list.

    plt.figure(figsize=(8, 6)) # (8, 6) is ok, (6, 4) is too small
    plt.xlim(xmin=0, xmax=xmax)
    plt.ylim(ymin=0, ymax=1)
    plt.ylabel("CDF")
    plt.xlabel("KB")
    plt.gca().xaxis.set_major_locator(MaxNLocator(prune='lower'))

    for list_to_plot_with_label in lists_to_plot_with_labels:
        list_to_plot = np.sort(list_to_plot_with_label[0])
        print("Largest element: ", max(list_to_plot))
        list_to_plot_count, list_to_plot_bins_count = np.histogram(list_to_plot, bins=max(list_to_plot))
        list_to_plot_pdf = list_to_plot_count / sum(list_to_plot_count)
        list_to_plot_cdf = np.cumsum(list_to_plot_pdf)
        list_to_plot_bins_count = np.insert(list_to_plot_bins_count[1:], 0, 0)
        list_to_plot_bins_count = [x/1000 for x in list_to_plot_bins_count]
        list_to_plot_cdf = np.insert(list_to_plot_cdf, 0, 0)
        plt.plot(list_to_plot_bins_count, list_to_plot_cdf, label=list_to_plot_with_label[1])

    plt.legend(loc="lower right")
    plt.savefig(os.path.join(ROOT_PATH, output_name), format="pdf", bbox_inches="tight")
    plt.show()


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
    total_sync_host_downlink_size_all_run_list = []
    total_sync_host_uplink_size_all_run_list = []
    total_sync_resolver_downlink_size_all_run_list = []
    total_sync_resolver_uplink_size_all_run_list = []

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

        # Host arcore uplink/downlink packets during initial sync.
        host_runtime_info = info_map['host']
        res = calculate_sync_data(host_runtime_info, host_pcap)
        y_host_arcore_uplink_size = res['y_uplink_size']
        y_host_arcore_downlink_size = res['y_downlink_size']

        # Resolver arcore uplink/downlink packets during initial sync.
        resolver_runtime_info = info_map['resolver']
        res = calculate_sync_data(resolver_runtime_info, resolver_pcap)
        y_resolver_arcore_uplink_size = res['y_uplink_size']
        y_resolver_arcore_downlink_size = res['y_downlink_size']

        total_sync_host_uplink_size_all_run_list.append(sum(y_host_arcore_uplink_size))
        total_sync_host_downlink_size_all_run_list.append(sum(y_host_arcore_downlink_size))
        total_sync_resolver_uplink_size_all_run_list.append(sum(y_resolver_arcore_uplink_size))
        total_sync_resolver_downlink_size_all_run_list.append(sum(y_resolver_arcore_downlink_size))

        #host_to_cloud_pkt_count, host_to_cloud_pkt_bins_count = np.histogram(host_to_cloud_pkt_list,
        #                                                                     bins=max(host_to_cloud_pkt_list))

    plot_figures((total_sync_host_uplink_size_all_run_list, "Total Sync. Packet Size: Host Uplink"),
                 (total_sync_resolver_uplink_size_all_run_list, "Total Sync. Packet Size: Resolver Uplink"),
                 output_name="../Figures/Total_Init_Sync_Uplink_Packet_Size.pdf",
                 xmax=12300)

    plot_figures((total_sync_host_downlink_size_all_run_list, "Total Sync. Packet Size: Host Downlink"),
                 (total_sync_resolver_downlink_size_all_run_list, "Total Sync. Packet Size: Resolver Downlink"),
                 output_name="../Figures/Total_Init_Sync_downlink_Packet_Size.pdf",
                 xmax=150)

if __name__ == '__main__':
    main()
