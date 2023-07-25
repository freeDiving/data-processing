# Plot 3(a)

import os

import matplotlib.pyplot as plt
import numpy as np

from main import prepare_other_ip_summary_and_moments
from src.timeline.moment import parse_log_and_pcap
from matplotlib.ticker import MaxNLocator

ROOT_PATH = os.path.abspath(os.path.dirname(__file__))

def input_path(*file_path) -> str:
    res = os.path.join(ROOT_PATH, *file_path)
    return res

def main():
    # Uncomment the line below, and comment out the line after it, to recalculate everything.
    #interval_avg_list = []
    interval_avg_list = [3.2096174, 0.7044605217391305, 3.2213651249999997, 0.672940035714286, 3.251666, 3.1662763333333337, 3.206519333333333, 3.186882833333333, 0.6796149473684211, 0.7057408857142855, 3.15552375, 0.9372554761904762, 0.6814988421052632, 3.2528272, 3.2448035]
    if len(interval_avg_list) == 0:
        host_dirs = [
            input_path('../datasets/5g-static-line/host/run1'),
            input_path('../datasets/5g-static-line/host/run2'),
            input_path('../datasets/5g-static-line/host/run3'),
            input_path('../datasets/5g-static-line/host/run4'),
            input_path('../datasets/5g-static-line/host/run5'), # 3.2528272
            input_path('../datasets/5g-host_move-line/host/run1'), # 3.2448035
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


            period_start = None
            interval_sum = 0
            interval_cnt = 0
            max_interval = 0
            sync_start_time = x_resolver_arcore_uplink_times[0]
            for x_resolver_uplink_time in x_resolver_arcore_uplink_times:
                if period_start is None:
                    period_start = x_resolver_uplink_time # First period
                    continue

                interval_diff = (x_resolver_uplink_time - period_start).total_seconds()
                if interval_diff > 0.5:
                    print("x_resolver_uplink_time: ", (x_resolver_uplink_time-sync_start_time).total_seconds(), ", period start time: ", (period_start-sync_start_time).total_seconds())
                    interval_sum = interval_sum + interval_diff
                    interval_cnt = interval_cnt + 1
                    period_start = x_resolver_uplink_time
                    max_interval = max(max_interval, interval_diff)

            interval_avg = interval_sum / interval_cnt
            interval_avg_list.append(interval_avg)
            print("========Internal interval of " , host_path, " is: ========", interval_avg)

    my_font_size = 20
    interval_avg_list_sorted = np.sort(interval_avg_list)
    plt.figure(figsize=(6, 3.5))
    plt.ylim(ymin=0)
    plt.xlim(xmin=0, xmax=3.5)
    plt.xticks(fontsize=my_font_size)
    plt.yticks(fontsize=my_font_size)
    plt.ylabel("CDF", fontsize=my_font_size)
    plt.xlabel("Period length (s)", fontsize=my_font_size)
    plt.gca().xaxis.set_major_locator(MaxNLocator(prune='lower'))
    plt.plot(interval_avg_list_sorted, np.linspace(0, 1, interval_avg_list_sorted.size), linewidth=5)
    plt.savefig(os.path.join(ROOT_PATH, f'../Figures/SLAM_data_period_cdf.pdf'), format="pdf", bbox_inches="tight")
    #Plot the CDF
    plt.show()

if __name__ == '__main__':
    main()