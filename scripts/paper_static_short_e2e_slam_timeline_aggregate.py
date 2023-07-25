# Plot figure 4(a)

import datetime
import os
from typing import List

import matplotlib.pyplot as plt
import numpy as np

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
        e2e_start,
        e2e_end
):
    # Create a line chart figure and axis object
    fig, ax1 = plt.subplots()
    # set figure size
    fig.set_size_inches(12, 6)

    ax2 = ax1.twinx() # Create a twin Axes sharing the xaxis.

    ax1.set_xticks(np.arange(datetime.timedelta(0).total_seconds(), (e2e_end - e2e_start).total_seconds(), 1.0))
    ax1.set_xlim((e2e_start - e2e_start).total_seconds(), (e2e_end - e2e_start).total_seconds())

    ax1.scatter(
        [(x - e2e_start).total_seconds() for x in x_host_arcore_uplink_time],
        y_host_arcore_uplink_size,
        color='blue',
        marker='x',
    )
    ax1.scatter(
        [(x - e2e_start).total_seconds() for x in x_host_arcore_downlink_time],
        y_host_arcore_downlink_size,
        color='purple',
        marker='x'
    )
    ax1.scatter(
        [(x - e2e_start).total_seconds() for x in x_resolver_arcore_uplink_time],
        y_resolver_arcore_uplink_size,
        color='red',
        marker='+'
    )
    ax1.scatter(
        [(x - e2e_start).total_seconds() for x in x_resolver_arcore_downlink_time],
        y_resolver_arcore_downlink_size,
        color='orange',
        label='Packet Size: Resolver Downlink',
        marker='+'
    )
    # Create a dummy legend for ax2
    ax1.scatter(
        [],
        [],
        color='green',
        marker='_'
    )
    # Create a dummy legend for ax2
    ax1.scatter(
        [],
        [],
        color='magenta',
        marker='_'
    )
    ax2.scatter(
        [(x - e2e_start).total_seconds() for x in x_host_draw_time],
        y_host_draw_e2e,
        color='green',
        marker='_'
    )
    # This will not be plotted.
    ax2.scatter(
        [(x - e2e_start).total_seconds() for x in x_resolver_draw_time],
        y_resolver_draw_e2e,
        color='magenta',
        marker='_'
    )
    # Set the chart title and axis labels
    ax1.set_xlabel('Time (s)')
    ax1.set_ylabel('SLAM Packet Size (byte)')
    ax2.set_ylabel('E2E Latency (ms)')
    ax1.set_ylim(ymax=2300)

    plt.subplots_adjust(right=0.75)  # adjust the right margin here
    plt.scatter([], [], color='red', marker='+', label='SLAM Packet Size: Resolver Uplink')
    plt.scatter([], [], color='orange', marker='+', label='SLAM Packet Size: Resolver Downlink')
    plt.scatter([], [], color='green', marker='_', label='SLAM E2E Latency')
    plt.legend(loc="upper left")
    #fig.savefig(output_file_path, format="pdf", bbox_inches="tight"))
    plt.savefig(output_file_path, format="pdf", bbox_inches="tight")
    #plt.show()
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
    host_dirs = [
        input_path('../datasets/5g-static-line/host/run4'),
    ]
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

        output_dir = exp_name + '/' + run_name
        res = prepare_e2e_latency_data(phases)
        x_host_draw_time = res["x_host_draw_time"]
        y_host_draw_e2e = res["y_host_draw_e2e"]
        x_resolver_draw_time = res["x_resolver_draw_time"]
        y_resolver_draw_e2e = res["y_resolver_draw_e2e"]

        if x_host_draw_time and x_resolver_draw_time:
            e2e_start = min(x_host_draw_time[0], x_resolver_draw_time[0])
            e2e_end = max(x_host_draw_time[-1], x_resolver_draw_time[-1])
        elif x_host_draw_time:
            e2e_start = min(x_host_draw_time)
            e2e_end = max(x_host_draw_time)
        else:
            e2e_start = min(x_resolver_draw_time)
            e2e_end = max(x_resolver_draw_time)

        period_start = None
        interval_sum = 0
        interval_cnt = 0
        max_interval = 0
        x_prev_resolver_uplink_time = None

        periods_uplink_start_ts_list = []
        periods_uplink_pkt_size_sum_list = []
        current_pkt_size_sum = 0
        for idx, x_resolver_uplink_time in enumerate(x_resolver_arcore_uplink_times):
            # Ignore SLAM data took place before drawing lines.
            if x_resolver_uplink_time < e2e_start:
                continue

            if period_start is None:
                period_start = x_resolver_uplink_time # First period
                periods_uplink_start_ts_list.append((period_start-e2e_start).total_seconds())
                current_pkt_size_sum = y_resolver_arcore_uplink_size[idx]
                continue

            interval_diff = (x_resolver_uplink_time - period_start).total_seconds()
            if interval_diff > 0.5: # This packet is the start of a new period.
                interval_sum = interval_sum + interval_diff
                interval_cnt = interval_cnt + 1
                period_start = x_resolver_uplink_time
                max_interval = max(max_interval, interval_diff)
                periods_uplink_start_ts_list.append((period_start-e2e_start).total_seconds())
                periods_uplink_pkt_size_sum_list.append(current_pkt_size_sum)
                current_pkt_size_sum = y_resolver_arcore_uplink_size[idx]
            else:
                current_pkt_size_sum += y_resolver_arcore_uplink_size[idx]

            if idx == len(x_resolver_arcore_uplink_times) - 1:
                periods_uplink_pkt_size_sum_list.append(current_pkt_size_sum)

        # Downlink
        period_start = None
        periods_downlink_start_ts_list = []
        periods_downlink_pkt_size_sum_list = []
        current_pkt_size_sum = 0
        for idx, x_resolver_downlink_time in enumerate(x_resolver_arcore_downlink_times):
            # Ignore SLAM data took place before drawing lines.
            if x_resolver_downlink_time < e2e_start:
                continue

            if period_start is None:
                period_start = x_resolver_downlink_time # First period
                periods_downlink_start_ts_list.append((period_start-e2e_start).total_seconds())
                current_pkt_size_sum = y_resolver_arcore_downlink_size[idx]
                continue

            interval_diff = (x_resolver_downlink_time - period_start).total_seconds()
            if interval_diff > 0.5: # This packet is the start of a new period.
                interval_sum = interval_sum + interval_diff
                interval_cnt = interval_cnt + 1
                period_start = x_resolver_downlink_time
                max_interval = max(max_interval, interval_diff)

                periods_downlink_start_ts_list.append((period_start-e2e_start).total_seconds())
                periods_downlink_pkt_size_sum_list.append(current_pkt_size_sum)
                current_pkt_size_sum = y_resolver_arcore_downlink_size[idx] # New period.
            else:
                current_pkt_size_sum += y_resolver_arcore_downlink_size[idx]

            # Last packet
            if idx == len(x_resolver_arcore_downlink_times) - 1:
                periods_downlink_pkt_size_sum_list.append(current_pkt_size_sum)

        fig, ax1 = plt.subplots()
        # set figure size
        fig.set_size_inches(10, 6)

        ax2 = ax1.twinx()  # Create a twin Axes sharing the xaxis.

        ax1.set_xticks(np.arange(datetime.timedelta(0).total_seconds(), (e2e_end - e2e_start).total_seconds(), 1.0))
        ax1.set_xlim((e2e_start - e2e_start).total_seconds(), (e2e_end - e2e_start).total_seconds())


        # Create a dummy legend for ax2
        ax1.scatter(
            [x for x in periods_uplink_start_ts_list],
            [x/1000 for x in periods_uplink_pkt_size_sum_list], # KB
            color='red',
            # label='Packet Size: Resolver Uplink',
            marker='+'
        )
        ax1.scatter(
            [x for x in periods_downlink_start_ts_list],
            [x/1000 for x in periods_downlink_pkt_size_sum_list], # KB
            color='orange',
            label='Packet Size: Resolver Downlink',
            marker='+'
        )
        # Create a dummy legend for ax2
        ax1.scatter(
            [],
            [],
            color='magenta',
            marker='_'
        )
        ax2.scatter(
            [(x - e2e_start).total_seconds() for x in x_host_draw_time],
            [x/1000 for x in y_host_draw_e2e],
            color='green',
            # label='e2e latency (host draw)',
            marker='_'
        )
        # This will not be plotted.
        ax2.scatter(
            [(x - e2e_start).total_seconds() for x in x_resolver_draw_time],
            [x/1000 for x in y_resolver_draw_e2e],
            color='magenta',
            marker='_'
        )
        # Set the chart title and axis labels
        my_font_size = 28.5
        ax1.set_xlabel('Time (s)', fontsize=my_font_size)
        ax1.set_ylabel('Message size (KB)', fontsize=my_font_size)
        ax2.set_ylabel('E2E Latency (s)', fontsize=my_font_size)
        ax1.set_ylim(ymin=0, ymax=90)
        ax2.set_ylim(ymin=0, ymax=1.4)

        plt.gca().xaxis.set_major_locator(MaxNLocator(prune='lower'))
        plt.subplots_adjust(right=0.75)  # adjust the right margin here
        plt.scatter([], [], color='red', marker='+', label='SLAM msg. size: Resolver uplink')
        plt.scatter([], [], color='orange', marker='+', label='SLAM msg. size: Resolver downlink')
        plt.scatter([], [], color='green', marker='_', label='SLAM E2E Latency')
        ax1.tick_params(labelsize=my_font_size)
        ax2.tick_params(labelsize=my_font_size)

        filename = 'agg_SLAM_static_short_period.pdf'
        plt.savefig(os.path.join(ROOT_PATH, f'../Figures/', filename), format='pdf')
        plt.show()


        interval_avg = interval_sum / interval_cnt
        print("Internal interval is: ", interval_avg)



if __name__ == '__main__':
    main()