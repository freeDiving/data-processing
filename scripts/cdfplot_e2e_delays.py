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


def extract_e2e_delays(df):
    data = []
    for _, row in df.iterrows():
        if row['state'] == 'e2e':
            data.append(row['duration'])
    return data


def generate_data(df_list):
    res = None
    for df in df_list:
        if res is None:
            res = extract_e2e_delays(df)
        else:
            res.extend(extract_e2e_delays(df))
    return res


def output_cdf(e2e_delays: List, title: str, type: str):
    e2e_delays = np.sort(e2e_delays)
    cdf = np.cumsum(e2e_delays) / np.sum(e2e_delays)

    plt.plot(e2e_delays, cdf)
    plt.xlabel('E2E Delays (ms)')
    plt.ylabel('Cumulative Probability')
    plt.legend(loc='best')
    if title is not None:
        plt.title(title)
    plt.savefig(os.path.join(ROOT_PATH, f'../output/cdfplot_e2e_delays_{type}.png'))
    plt.clf()


def prepare_e2e_delays_for_lines():
    df_5g_static_lines = []
    for num in range(1, 6):
        df_5g_static_lines.append(
            pd.read_csv(get_output_path('5g-static-line', num, 'phases.csv'))
        )

    # only 4 runs for 5G blocked
    df_5g_block_static_lines = []
    for num in range(1, 5):
        df_5g_block_static_lines.append(
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
    df_list = df_5g_static_lines + df_5g_block_static_lines + df_wifi_static_lines + df_lte_static_lines
    return df_list


def prepare_e2e_delays_for_points():
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

    return df_5g_static_points + df_5g_block_static_points + df_wifi_static_points + df_lte_static_points


if __name__ == '__main__':
    df_lines = prepare_e2e_delays_for_lines()
    output_cdf(generate_data(df_lines), title='E2E Delays for Lines', type='lines')

    df_points = prepare_e2e_delays_for_points()
    output_cdf(generate_data(df_points), title='E2E Delays for Points', type='points')
