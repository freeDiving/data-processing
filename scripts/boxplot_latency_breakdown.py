import os
from typing import List

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

ROOT_PATH = os.path.abspath(os.path.dirname(__file__))


# plot boxplots
def set_box_color(bp, color):
    plt.setp(bp['boxes'], color=color)
    plt.setp(bp['whiskers'], color=color)
    plt.setp(bp['caps'], color=color)
    plt.setp(bp['medians'], color=color)


def get_output_path(exp_name, run_name, file_name):
    return os.path.join(ROOT_PATH, f'../output/{exp_name}/run{run_name}/{file_name}')


def adapt_to_boxplot(df):
    data = {
        'host: local action': [],
        'host: data transmission': [],
        'cloud: processing': [],
        'resolver: rendering': [],
        'e2e': []
    }
    for _, row in df.iterrows():
        data[row['state']].append(row['duration'])

    return [
        data['host: local action'],
        data['host: data transmission'],
        data['cloud: processing'],
        data['resolver: rendering'],
        data['e2e']
    ]


def generate_data(df_list):
    res = None
    for df in df_list:
        if res is None:
            res = adapt_to_boxplot(df)
        else:
            tmp = adapt_to_boxplot(df)
            res[0] = res[0] + tmp[0]
            res[1] = res[1] + tmp[1]
            res[2] = res[2] + tmp[2]
            res[3] = res[3] + tmp[3]
            res[4] = res[4] + tmp[4]
    return res


def output_boxplot(
        df_5g_static: List[pd.DataFrame],
        df_5g_block_static: List[pd.DataFrame],
        df_wifi_static: List[pd.DataFrame],
        df_lte_static: List[pd.DataFrame],
        type: str,
):
    label_list = ['5G', '5G-Blocked', 'WiFi', 'LTE']
    data_5g_static_line = generate_data(df_5g_static)
    data_5g_block_line = generate_data(df_5g_block_static)
    data_wifi_static_line = generate_data(df_wifi_static)
    data_lte_static_line = generate_data(df_lte_static)

    plt.figure(figsize=(7, 4))
    bp1 = plt.boxplot(data_5g_static_line, positions=np.array(range(len(data_5g_static_line))) * 3.0 - 0.6, sym='+',
                      widths=0.4)
    bp2 = plt.boxplot(data_5g_block_line, positions=np.array(range(len(data_5g_block_line))) * 3.0, sym='+',
                      widths=0.4)
    bp3 = plt.boxplot(data_wifi_static_line, positions=np.array(range(len(data_wifi_static_line))) * 3.0 + 0.6, sym='+',
                      widths=0.4)
    bp4 = plt.boxplot(data_lte_static_line, positions=np.array(range(len(data_lte_static_line))) * 3.0 + 0.6 * 2,
                      sym='+',
                      widths=0.4)

    set_box_color(bp1, 'black')
    set_box_color(bp2, 'royalblue')
    set_box_color(bp3, 'red')
    set_box_color(bp4, 'green')

    ticks = ('1a', '1b', 'c', '2d', 'e2e')
    plt.xticks(range(0, len(ticks) * 3, 3), ticks, fontsize=11)
    plt.yticks(fontsize=11)
    # draw temporary red and blue lines and use them to create a legend
    plt.plot([], c='black', label=label_list[0])
    plt.plot([], c='royalblue', label=label_list[1])
    plt.plot([], c='red', label=label_list[2])
    plt.plot([], c='green', label=label_list[3])

    plt.ylabel('Latency (ms)', fontsize=12)
    plt.xlabel('Latency Type', fontsize=12)
    plt.legend(fontsize=8.25, loc='upper left')
    plt.xlim(-1, len(ticks) * 2.9)
    plt.tight_layout()
    plt.savefig(os.path.join(ROOT_PATH, f'../output/latency_breakdown_{type}.png'))


def prepare_data_for_lines():
    df_5g_static_lines = []
    for num in range(1, 6):
        df_5g_static_lines.append(
            pd.read_csv(get_output_path('5g-static-line', num, 'phases.csv'))
        )

    # only 4 runs for 5G blocked
    df_5g_block_static_lines = []
    for num in range(1, 5):
        df_5g_block_static_lines.append(
            pd.read_csv(get_output_path('5g-static-point', num, 'phases.csv'))
        )

    df_wifi_static_lines = []
    for num in range(1, 6):
        df_wifi_static_lines.append(
            pd.read_csv(get_output_path('wifi-static-line', num, 'phases.csv'))
        )

    df_lte_static_lines = []
    for num in range(1, 6):
        df_lte_static_lines.append(
            pd.read_csv(get_output_path('lte-static-line', num, 'phases.csv'))
        )

    return (
        df_5g_static_lines,
        df_5g_block_static_lines,
        df_wifi_static_lines,
        df_lte_static_lines,
    )


def prepare_data_for_points():
    df_5g_static_points = []
    for num in range(1, 6):
        df_5g_static_points.append(
            pd.read_csv(get_output_path('5g-static-point', num, 'phases.csv'))
        )

    df_5g_block_static_points = []
    for num in range(1, 6):
        df_5g_block_static_points.append(
            pd.read_csv(get_output_path('5g-static-point', num, 'phases.csv'))
        )

    df_wifi_static_points = []
    for num in range(1, 6):
        df_wifi_static_points.append(
            pd.read_csv(get_output_path('wifi-static-point', num, 'phases.csv'))
        )

    df_lte_static_points = []
    for num in range(1, 6):
        df_lte_static_points.append(
            pd.read_csv(get_output_path('lte-static-point', num, 'phases.csv'))
        )

    return (
        df_5g_static_points,
        df_5g_block_static_points,
        df_wifi_static_points,
        df_lte_static_points,
    )


def main():
    data_for_lines = prepare_data_for_lines()
    output_boxplot(*data_for_lines, type='lines')

    data_for_points = prepare_data_for_points()
    output_boxplot(*data_for_points, type='points')


if __name__ == '__main__':
    main()
