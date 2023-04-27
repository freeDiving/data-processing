import sys
from typing import List

import matplotlib.pyplot as plt
import os
# import numpy as np
import bisect

import numpy as np
import pandas as pd
import glob

ROOT_PATH = os.path.abspath(os.path.dirname(__file__))


def get_output_path(exp_name, run_name, file_name):
    return os.path.join(ROOT_PATH, f'../output/{exp_name}/run{run_name}/{file_name}')


def extract_pkt_size(df):
    data = []
    for _, row in df.iterrows():
        data.append(row['pkt_size'])
    return data


def generate_data(df_list):
    res = None
    for df in df_list:
        if res is None:
            res = extract_pkt_size(df)
        else:
            res.extend(extract_pkt_size(df))
    return res


def output_cdf(data_list: List, title: str, type: str):
    data_list = np.sort(data_list)
    cdf = np.cumsum(data_list) / np.sum(data_list)

    plt.plot(data_list, cdf)
    plt.xlabel('Data Packet Size (bytes)')
    plt.ylabel('Cumulative Probability')
    plt.legend(loc='best')
    if title is not None:
        plt.title(title)
    plt.savefig(os.path.join(ROOT_PATH, f'../output/cdfplot_data_size_{type}.png'))
    plt.clf()


def prepare_data_for_lines():
    df_5g_static_lines = []
    for num in range(1, 6):
        df_5g_static_lines.append(
            pd.read_csv(get_output_path('5g-static-line', num, 'send_pkt_sequences.csv'))
        )

    # only 4 runs for 5G blocked
    df_5g_block_static_lines = []
    for num in range(1, 5):
        df_5g_block_static_lines.append(
            pd.read_csv(get_output_path('5g-static-line', num, 'send_pkt_sequences.csv'))
        )

    df_wifi_static_lines = []
    for num in range(1, 6):
        df_wifi_static_lines.append(
            pd.read_csv(get_output_path('wifi-static-line', num, 'send_pkt_sequences.csv'))
        )

    df_lte_static_lines = []
    for num in range(1, 6):
        df_lte_static_lines.append(
            pd.read_csv(get_output_path('lte-static-line', num, 'send_pkt_sequences.csv'))
        )
    df_list = df_5g_static_lines + df_5g_block_static_lines + df_wifi_static_lines + df_lte_static_lines
    return df_list


def prepare_data_for_points():
    df_5g_static_points = []
    for num in range(1, 6):
        df_5g_static_points.append(
            pd.read_csv(get_output_path('5g-static-point', num, 'send_pkt_sequences.csv'))
        )

    df_5g_block_static_points = []
    for num in range(1, 6):
        df_5g_block_static_points.append(
            pd.read_csv(get_output_path('5g-static-point', num, 'send_pkt_sequences.csv'))
        )

    df_wifi_static_points = []
    for num in range(1, 6):
        df_wifi_static_points.append(
            pd.read_csv(get_output_path('wifi-static-point', num, 'send_pkt_sequences.csv'))
        )

    df_lte_static_points = []
    for num in range(1, 6):
        df_lte_static_points.append(
            pd.read_csv(get_output_path('lte-static-point', num, 'send_pkt_sequences.csv'))
        )

    return df_5g_static_points + df_5g_block_static_points + df_wifi_static_points + df_lte_static_points


if __name__ == '__main__':
    df_list = prepare_data_for_lines()
    output_cdf(generate_data(df_list), title='Size of each data pkt sent from host to cloud', type='lines')

    df_list = prepare_data_for_points()
    output_cdf(generate_data(df_list), title='Size of each data pkt sent from host to cloud', type='points')
