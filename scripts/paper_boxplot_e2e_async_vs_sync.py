# Plot Cloud Anchor E2E (5G), and Just-a-Line E2E (5G, LTE, Wifi) with boxplots.

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
    e2e_list = []
    for _, row in df.iterrows():
        if row['state'] == 'e2e':
            e2e_list.append(row['duration']/1000)

    return e2e_list

def generate_data(df_list):
    """
    Combine results of all runs
    Args:
        df_list: list of results of each run.

    Returns:
        The list that contains all e2e results.
    """
    res = None
    for df in df_list:
        if res is None:
            res = adapt_to_boxplot(df)
        else:
            res = res + adapt_to_boxplot(df)
    return res


def output_boxplot(
        df_5g_static: List[pd.DataFrame],
        #: List[pd.DataFrame],
        df_wifi_static: List[pd.DataFrame],
        df_lte_static: List[pd.DataFrame],
        type: str,
):
    #label_list = ['5G', '5G-Blocked', 'WiFi', 'LTE']
    label_list = ['5G', 'WiFi', 'LTE']
    five_g_list = [[6459/1000, 7135/1000, 4831/1000, 3618/1000, 3849/1000]] + [generate_data(df_5g_static)]
    wifi_list = [[], generate_data(df_wifi_static)]
    lte_list = [[], generate_data(df_lte_static)]

    cloud_anchor_all_e2e = generate_data(df_5g_static) + generate_data(df_wifi_static) + generate_data(df_lte_static)
    cloud_anchor_all_e2e = np.asarray(cloud_anchor_all_e2e)
    p = np.percentile(cloud_anchor_all_e2e, 75)
    print("The max E2E of just-a-line is: ", max(cloud_anchor_all_e2e))
    print("The 75th percentile E2E of just-a-line is: ", p)
    print("The min E2E of just-a-line is: ", min(cloud_anchor_all_e2e))


    #plt.figure(figsize=(7, 4))
    plt.figure(figsize=(7.2, 5))
    step_size = 0.2
    base_loc = 1.3
    bp1 = plt.boxplot(five_g_list, positions=np.array(range(len(five_g_list))) * base_loc-step_size, sym='+',
                      widths=0.15)
    bp2 = plt.boxplot(wifi_list, positions=np.array(range(len(wifi_list))) * base_loc, sym='+',
                      widths=0.15)
    bp3 = plt.boxplot(lte_list, positions=np.array(range(len(lte_list))) * base_loc+step_size, sym='+',
                      widths=0.15)
    #ax1.set_aspect(1.5)
    set_box_color(bp1, 'black')
    set_box_color(bp2, 'royalblue')
    set_box_color(bp3, 'red')

    ticks = ('Cloud Anchor', 'Just-a-Line')
    #plt.xticks(range(0, len(ticks), 1), ticks)
    my_font_size = 25
    plt.xticks([-step_size, base_loc], ticks, fontsize=my_font_size)
    plt.yticks(fontsize=my_font_size)
    plt.ylim(ymin=0)
    plt.ylabel("Time (s)", fontsize=my_font_size)
    # draw temporary red and blue lines and use them to create a legend
    plt.plot([], [], c='black', label=label_list[0])
    plt.plot([], c='royalblue', label=label_list[1])
    plt.plot([], c='red', label=label_list[2])
    plt.legend(fontsize=my_font_size, loc='upper right')
    #ax1.tight_layout()
    plt.savefig(os.path.join(ROOT_PATH, f'../Figures/static_e2e_boxplot.pdf'), format="pdf", bbox_inches="tight")
    plt.show()


def prepare_data_for_lines():
    df_5g_static_lines = []
    for num in range(1, 6):
        df_5g_static_lines.append(
            pd.read_csv(get_output_path('5g-static-line', num, 'phases.csv'))
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

    #data_for_points = prepare_data_for_points()
    #output_boxplot(*data_for_points, type='points')


if __name__ == '__main__':
    main()
