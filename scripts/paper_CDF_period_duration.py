# Plot 3(d)

import os

import matplotlib.pyplot as plt
import numpy as np
from typing import List


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

        interval_avg_list = []
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

            timeline = get_timeline(info_map)
            phases = prepare_phases(timeline)
            res = prepare_e2e_latency_data(phases)
            x_host_draw_time = res["x_host_draw_time"]

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
                if moment.name == "TCP ack pkt" or moment.time <= x_host_draw_time[0]:
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


            period_start = None
            interval_sum = 0
            interval_cnt = 0
            max_interval = 0
            sync_start_time = x_resolver_arcore_uplink_times[0]
            period_duration = 0

            x_resolver_all_times = sorted(x_resolver_arcore_uplink_times + x_resolver_arcore_downlink_times)
            x_resolver_all_last_time = None
            for x_resolver_all_time in x_resolver_all_times:
                if period_start is None:
                    period_start = x_resolver_all_time # First period
                    continue

                interval_diff = (x_resolver_all_time - period_start).total_seconds()
                if interval_diff > 0.5:
                    print("x_resolver_uplink_time: ", (x_resolver_all_time-sync_start_time).total_seconds(), ", period start time: ", (period_start-sync_start_time).total_seconds())
                    print("x_resolver_uplink_time: ", x_resolver_all_time, ", period start time: ", period_start)
                    print("period: ", interval_diff)
                    interval_sum = interval_sum + interval_diff
                    interval_cnt = interval_cnt + 1
                    max_interval = max(max_interval, interval_diff)
                    if period_duration > 0.1:
                        period_duration_list.append(period_duration)
                        print("duration: ", period_duration)
                        print("last time: ", x_resolver_all_last_time)
                    period_start = x_resolver_all_time
                else:
                    period_duration = (x_resolver_all_time - period_start).total_seconds()

                x_resolver_all_last_time = x_resolver_all_time

            interval_avg = interval_sum / interval_cnt
            interval_avg_list.append(interval_avg)
            if period_duration > 0.1:
                period_duration_list.append(period_duration)
            print("========Internal interval of " , host_path, " is: ========", interval_avg)


    period_duration_list = np.sort(period_duration_list)
    fig, ax = plt.subplots(figsize=(6, 3.5))
    my_font_size = 20
    ax.set_ylim(ymin=0, ymax=1)
    ax.set_xlim(xmin=0, xmax=0.5)
    plt.xticks(fontsize=my_font_size)
    plt.yticks(fontsize=my_font_size)
    ax.set_ylabel("CDF", fontsize=my_font_size)
    ax.set_xlabel("Duration of SLAM update \ntransactions (s)", fontsize=my_font_size)
    ax.plot(period_duration_list, np.linspace(0, 1, period_duration_list.size), linewidth=5)
    plt.gca().xaxis.set_major_locator(MaxNLocator(prune='lower'))
    ax.set_xticks([0.1, 0.2, 0.3, 0.4, 0.5])
    plt.xticks(fontsize=my_font_size)
    plt.yticks(fontsize=my_font_size)
    fig.savefig(os.path.join(ROOT_PATH, f'../Figures/SLAM_data_period_duration_cdf.pdf'), format="pdf", bbox_inches="tight")
    #Plot the CDF
    fig.show()

if __name__ == '__main__':
    main()