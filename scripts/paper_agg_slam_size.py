# Plot
# Figure 3(c)
# 1. CDF of E2E
# 2. CDF of SLAM packet sizes
# 3. CDF of data packets sent by the host to the cloud
# 4. CDF of data packets sent by the cloud to the resolver.

import datetime
import os
from typing import List

import matplotlib.pyplot as plt
import numpy as np
import matplotlib.dates as mdates
import pandas as pd

from main import prepare_other_ip_summary_and_moments
from src.phase.phase import prepare_phases
from src.timeline.moment import parse_log_and_pcap
from src.timeline.timeline import get_timeline
from src.utils.time import diff_sec
from matplotlib.ticker import MaxNLocator

ROOT_PATH = os.path.abspath(os.path.dirname(__file__))


def input_path(*file_path) -> str:
    res = os.path.join(ROOT_PATH, *file_path)
    return res


def output_path(*paths: str) -> str:
    OUTPUT_DIR = 'output'
    return os.path.join(ROOT_PATH, '..', OUTPUT_DIR, *paths)


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


def get_aggregated_slam_update(host_path, x_resolver_arcore_uplink_times, y_resolver_arcore_uplink_size,
                               x_resolver_arcore_downlink_times, y_resolver_arcore_downlink_size, e2e_start):
    def should_exclude_first_aggregated_packets(host_path: str):
        """
        Hack
        Args:
            host_path:

        Returns:

        """
        exclude_list = ["5g-static-line/host/run1", "5g-static-line/host/run4", "5g-resolver_move-line/host/run4",
                        "5g-resolver_move-line/host/run1"]

        for exclude_dir in exclude_list:
            if exclude_dir in host_path:
                return True

        return False

    def should_exclude_last_aggregated_packets(host_path: str):
        exclude_list = ["5g-host_move-line/host/run2"]

        for exclude_dir in exclude_list:
            if exclude_dir in exclude_dir:
                return True

        return False

    period_start = None
    interval_sum = 0
    interval_cnt = 0
    max_interval = 0

    # Uplink
    periods_uplink_start_ts_list = []
    periods_uplink_pkt_size_aggregated_list = []
    current_pkt_size_sum = 0
    for idx, x_resolver_uplink_time in enumerate(x_resolver_arcore_uplink_times):
        # Ignore SLAM data took place before drawing lines.
        if x_resolver_uplink_time < e2e_start:
            continue

        if period_start is None:
            period_start = x_resolver_uplink_time  # First period
            periods_uplink_start_ts_list.append((period_start - e2e_start).total_seconds())
            current_pkt_size_sum = y_resolver_arcore_uplink_size[idx]
            continue

        interval_diff = (x_resolver_uplink_time - period_start).total_seconds()
        if interval_diff > 0.5:  # This packet is the start of a new period.
            interval_sum = interval_sum + interval_diff
            interval_cnt = interval_cnt + 1
            period_start = x_resolver_uplink_time
            max_interval = max(max_interval, interval_diff)
            periods_uplink_start_ts_list.append((period_start - e2e_start).total_seconds())
            periods_uplink_pkt_size_aggregated_list.append(current_pkt_size_sum)
            current_pkt_size_sum = y_resolver_arcore_uplink_size[idx]
        else:
            current_pkt_size_sum += y_resolver_arcore_uplink_size[idx]

        if idx == len(x_resolver_arcore_uplink_times) - 1:
            periods_uplink_pkt_size_aggregated_list.append(current_pkt_size_sum)

    # Downlink
    period_start = None
    periods_downlink_start_ts_list = []
    periods_downlink_pkt_size_aggregated_list = []
    current_pkt_size_sum = 0
    for idx, x_resolver_downlink_time in enumerate(x_resolver_arcore_downlink_times):
        # Ignore SLAM data took place before drawing lines.
        if x_resolver_downlink_time < e2e_start:
            continue

        if period_start is None:
            period_start = x_resolver_downlink_time  # First period
            periods_downlink_start_ts_list.append((period_start - e2e_start).total_seconds())
            current_pkt_size_sum = y_resolver_arcore_downlink_size[idx]
            continue

        interval_diff = (x_resolver_downlink_time - period_start).total_seconds()
        if interval_diff > 0.5:  # This packet is the start of a new period.
            interval_sum = interval_sum + interval_diff
            interval_cnt = interval_cnt + 1
            period_start = x_resolver_downlink_time
            max_interval = max(max_interval, interval_diff)

            periods_downlink_start_ts_list.append((period_start - e2e_start).total_seconds())
            periods_downlink_pkt_size_aggregated_list.append(current_pkt_size_sum)
            current_pkt_size_sum = y_resolver_arcore_downlink_size[idx]  # New period.
        else:
            current_pkt_size_sum += y_resolver_arcore_downlink_size[idx]

        # Last packet
        if idx == len(x_resolver_arcore_downlink_times) - 1:
            periods_downlink_pkt_size_aggregated_list.append(current_pkt_size_sum)

    if should_exclude_first_aggregated_packets(host_path):
        del periods_downlink_pkt_size_aggregated_list[0]
        del periods_uplink_pkt_size_aggregated_list[0]

    if should_exclude_last_aggregated_packets(host_path):
        periods_downlink_pkt_size_aggregated_list.pop()
        periods_uplink_pkt_size_aggregated_list.pop()

    return periods_downlink_pkt_size_aggregated_list, periods_uplink_pkt_size_aggregated_list


def get_coordinates_packets(drawing_moments, mode):
    res = []
    for drawing_moment in drawing_moments:
        if mode == "Host":
            if drawing_moment.name == "send data pkt to cloud":
                res.append(int(drawing_moment.metadata["size"]))
        else:  # Mode == "Resolver"
            if drawing_moment.name == "receive data pkt from cloud":
                res.append(int(drawing_moment.metadata["size"]))
    return res


def main():
    periods_downlink_pkt_size_aggregated_all_run_list = []
    periods_uplink_pkt_size_aggregated_all_run_list = []

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

        x_host_arcore_uplink_times = []
        y_host_arcore_uplink_size = []
        x_host_arcore_downlink_times = []
        y_host_arcore_downlink_size = []
        x_resolver_arcore_uplink_times = []
        y_resolver_arcore_uplink_size = []
        x_resolver_arcore_downlink_times = []
        y_resolver_arcore_downlink_size = []

        # prepare data for arcore uplink and downlink
        for moment in other_ip_moments:
            if moment.name == "TCP ack pkt":
                continue

            if (moment.action_to in host_info.arcore_ip_set) or (moment.action_to in resolver_info.arcore_ip_set):
                if moment.action_from == host_phone_ip:
                    x_host_arcore_uplink_times.append(moment.time)
                    y_host_arcore_uplink_size.append(int(moment.metadata['size']))
                elif moment.action_from == resolver_phone_ip:
                    x_resolver_arcore_uplink_times.append(moment.time)
                    y_resolver_arcore_uplink_size.append(int(moment.metadata['size']))
            elif (moment.action_from in host_info.arcore_ip_set) or (moment.action_from in resolver_info.arcore_ip_set):
                if moment.action_to == host_phone_ip:
                    x_host_arcore_downlink_times.append(moment.time)
                    y_host_arcore_downlink_size.append(int(moment.metadata['size']))
                elif moment.action_to == resolver_phone_ip:
                    x_resolver_arcore_downlink_times.append(moment.time)
                    y_resolver_arcore_downlink_size.append(int(moment.metadata['size']))

        res = prepare_e2e_latency_data(phases)
        x_host_draw_time = res["x_host_draw_time"]
        x_resolver_draw_time = res["x_resolver_draw_time"]

        if x_host_draw_time and x_resolver_draw_time:
            e2e_start = min(x_host_draw_time[0], x_resolver_draw_time[0])
        elif x_host_draw_time:
            e2e_start = min(x_host_draw_time)
        else:
            e2e_start = min(x_resolver_draw_time)

        downlink_list, uplink_list = get_aggregated_slam_update(host_path, x_resolver_arcore_uplink_times,
                                                                y_resolver_arcore_uplink_size,
                                                                x_resolver_arcore_downlink_times,
                                                                y_resolver_arcore_downlink_size, e2e_start)

        periods_downlink_pkt_size_aggregated_all_run_list += downlink_list
        periods_uplink_pkt_size_aggregated_all_run_list += uplink_list

    # Draw the first 2 CDF
    periods_downlink_pkt_size_aggregated_all_run_list = [x / 1000 for x in
                                                         periods_downlink_pkt_size_aggregated_all_run_list]
    periods_uplink_pkt_size_aggregated_all_run_list = [x / 1000 for x in
                                                       periods_uplink_pkt_size_aggregated_all_run_list]
    periods_downlink_pkt_size_aggregated_all_run_list = np.sort(periods_downlink_pkt_size_aggregated_all_run_list)
    periods_uplink_pkt_size_aggregated_all_run_list = np.sort(periods_uplink_pkt_size_aggregated_all_run_list)

    fig, ax = plt.subplots(figsize=(6, 3.5))
    my_font_size = 19
    ax.set_xlim(xmin=0, xmax=300)
    ax.set_ylim(ymin=0, ymax=1)
    plt.gca().xaxis.set_major_locator(MaxNLocator(prune='lower'))

    plt.plot(periods_downlink_pkt_size_aggregated_all_run_list,
             np.linspace(0, 1, periods_downlink_pkt_size_aggregated_all_run_list.size),
             label="Resolver downlink", linewidth=3, color="orange")
    plt.plot(periods_uplink_pkt_size_aggregated_all_run_list,
             np.linspace(0, 1, periods_uplink_pkt_size_aggregated_all_run_list.size),
             label="Resolver uplink", linewidth=3, color='#1f77b4')

    plt.xticks(fontsize=my_font_size)
    plt.yticks(fontsize=my_font_size)
    ax.set_xticks(ax.get_xticks()[::2])

    plt.ylabel("CDF", fontsize=my_font_size)
    plt.xlabel("Message size (KB)", fontsize=my_font_size)
    plt.legend(loc="lower right", fontsize=my_font_size)

    plt.savefig(os.path.join(ROOT_PATH, f'../Figures/CDF_aggregated_SLAM_update_all.pdf'), format="pdf", bbox_inches="tight")
    plt.show()


if __name__ == '__main__':
    main()
