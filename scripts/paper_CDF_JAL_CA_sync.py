# Plot figure 5(a): CDF for CloudAnchor E2E time, and Just-a-Line initial synchronization time.

import numpy as np
import os
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator

from src.timeline.moment import parse_log_and_pcap

ROOT_PATH = os.path.abspath(os.path.dirname(__file__))
OUTPUT_DIR = 'output'


def input_path(*file_path) -> str:
    return os.path.join(ROOT_PATH, *file_path)


def output_path(*paths: str) -> str:
    return os.path.join(ROOT_PATH, '..', OUTPUT_DIR, *paths)


def main():
    #jal_sync_elapsed_time_list = [5.57, 5.933, 5.937, 6.467, 6.778, 8.351, 12.7, 15.596, 15.707, 28.233, 45.596, 60.863, 68.097, 68.361, 68.496, 69.838, 70.1, 70.6, 70.645, 73.862, 77.507, 126.269, 136.343, 139.875, 148.188, 162.148, 166.719, 172.348, 309.481]
    jal_sync_elapsed_time_list = []
    # If the data become stale
    if len(jal_sync_elapsed_time_list) == 0:
        host_dirs = [
            # 5g-static-line
            input_path('../datasets/5g-static-line/host/run1'),
            input_path('../datasets/5g-static-line/host/run2'),
            input_path('../datasets/5g-static-line/host/run3'),
            input_path('../datasets/5g-static-line/host/run4'),
            input_path('../datasets/5g-static-line/host/run5'),
            # 5g-host_move-line
            input_path('../datasets/5g-host_move-line/host/run1'),
            input_path('../datasets/5g-host_move-line/host/run2'),
            input_path('../datasets/5g-host_move-line/host/run3'),
            input_path('../datasets/5g-host_move-line/host/run4'),
            input_path('../datasets/5g-host_move-line/host/run5'),
            # 5g-resolver_move-line
            input_path('../datasets/5g-resolver_move-line/host/run1'),
            input_path('../datasets/5g-resolver_move-line/host/run2'),
            input_path('../datasets/5g-resolver_move-line/host/run3'),
            input_path('../datasets/5g-resolver_move-line/host/run4'),
            input_path('../datasets/5g-resolver_move-line/host/run5'),
            # 5g-static-point
            input_path('../datasets/5g-static-point/host/run1'),
            input_path('../datasets/5g-static-point/host/run2'),
            input_path('../datasets/5g-static-point/host/run3'),
            input_path('../datasets/5g-static-point/host/run4'),
            input_path('../datasets/5g-static-point/host/run5'),
            # 5g-block line
            input_path('../datasets/5g-block-line/host/run1'),
            input_path('../datasets/5g-block-line/host/run2'),
            input_path('../datasets/5g-block-line/host/run3'),
            input_path('../datasets/5g-block-line/host/run4'),
            input_path('../datasets/5g-block-line/host/run5'),
            # 5g-blocked point
            input_path('../datasets/5g-block-point/host/run1'),
            input_path('../datasets/5g-block-point/host/run2'),
            input_path('../datasets/5g-block-point/host/run3'),
            input_path('../datasets/5g-block-point/host/run4'),
        ]
        for index, host_path in enumerate(host_dirs):
            resolver_path = host_path.replace('/host/', '/resolver/')
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
            resolver_runtime_info = info_map['resolver']

            sync_start = min(host_runtime_info.log_sync_moments[0].time, resolver_runtime_info.log_sync_moments[0].time)
            sync_end = max(host_runtime_info.log_sync_moments[-1].time, resolver_runtime_info.log_sync_moments[-1].time)

            sync_elapsed_time = (sync_end - sync_start).total_seconds()
            print("sync_elapsed_time: ", sync_elapsed_time)
            jal_sync_elapsed_time_list.append(sync_elapsed_time)

    jal_sync_elapsed_time_list_sorted = np.sort(jal_sync_elapsed_time_list)

    cloud_anchor_e2e_time_list = [6.459, 7.135, 4.831, 3.618, 3.849, 3.593, 8.214, 4.201, 5.242, 5.058]
    cloud_anchor_e2e_time_list_sorted = np.sort(cloud_anchor_e2e_time_list)
    plt.ylim(ymin=0.0)
    plt.xlim(xmin=0.0, xmax=350)
    plt.gca().xaxis.set_major_locator(MaxNLocator(prune='lower'))
    plt.ylabel("CDF")
    plt.xlabel("Time (s)")
    plt.plot(jal_sync_elapsed_time_list_sorted, np.linspace(0, 1, jal_sync_elapsed_time_list_sorted.size), label="Just-a-Line: Synchronization Time")
    plt.plot(cloud_anchor_e2e_time_list_sorted, np.linspace(0, 1, cloud_anchor_e2e_time_list_sorted.size), label="Cloud Anchor: E2E")
    plt.legend()
    plt.savefig(os.path.join(ROOT_PATH, f'../Figures/ca_e2e_jal_sync_CDF.pdf'), format="pdf", bbox_inches="tight")
    plt.show()

if __name__ == '__main__':
    main()
