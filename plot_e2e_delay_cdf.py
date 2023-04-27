import sys
from typing import List

import matplotlib.pyplot as plt
import os
# import numpy as np
import bisect

import numpy as np
import pandas as pd
import glob


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


def output_cdf(e2e_delays: List, title: str):
    e2e_delays = np.sort(e2e_delays)
    cdf = np.cumsum(e2e_delays) / np.sum(e2e_delays)

    plt.plot(e2e_delays, cdf)
    plt.xlabel('E2E Delays (ms)')
    plt.ylabel('Cumulative Probability')
    plt.legend(loc='best')
    if title is not None:
        plt.title(title)
    plt.show()


def prepare_e2e_delays_for_lines():
    df_5g_static_lines = []
    for num in [
        10,
        11,
        13,
        15,
        16
    ]:
        df_5g_static_lines.append(
            pd.read_csv('./datasets/5g-static-line/output/0407-run{num}_phases.csv'.format(num=num)))
    df_5g_block_static_lines = []
    for num in [
        1,
        2,
        3,
        4,
        5,
    ]:
        df_5g_block_static_lines.append(
            pd.read_csv('./datasets/5g-block-line/output/0421-5gbl-run{num}_phases.csv'.format(num=num)))
    df_wifi_static_lines = []
    for num in [
        1,
        2,
        3,
        4,
        5
    ]:
        df_wifi_static_lines.append(
            pd.read_csv('./datasets/wifi-static-line/output/0422-wifi-run{num}_phases.csv'.format(num=num)))
    df_lte_static_lines = []
    for num in [
        1,
        2,
        3,
        4,
        5
    ]:
        df_lte_static_lines.append(
            pd.read_csv('./datasets/lte-static-line/output/0421-ltel-run{num}_phases.csv'.format(num=num)))
    df_list = df_5g_static_lines + df_5g_block_static_lines + df_wifi_static_lines + df_lte_static_lines
    return df_list


def prepare_e2e_delays_for_points():
    df_5g_static_points = []
    for num in [
        1,
        2,
        3,
        4,
        6
    ]:
        df_5g_static_points.append(
            pd.read_csv('./datasets/5g-static-point/output/0407-run{num}_phases.csv'.format(num=num)))

    df_5g_block_static_points = []
    for num in [
        2,
        4,
        5,
        6,
    ]:
        df_5g_block_static_points.append(
            pd.read_csv('./datasets/5g-block-point/output/0412-5gb-run{num}_phases.csv'.format(num=num)))

    df_wifi_static_points = []
    for num in [
        1,
        2,
        3,
        4,
        5
    ]:
        df_wifi_static_points.append(
            pd.read_csv('./datasets/wifi-static-point/output/run{num}_phases.csv'.format(num=num)))

    df_lte_static_points = []
    for num in [
        2,
        4,
        5,
        8,
        9,
    ]:
        df_lte_static_points.append(
            pd.read_csv('./datasets/lte-static-point/output/0412-lte-run{num}_phases.csv'.format(num=num)))

    return df_5g_static_points + df_5g_block_static_points + df_wifi_static_points + df_lte_static_points


if __name__ == '__main__':
    # df_list = prepare_e2e_delays_for_lines()
    # output_cdf(generate_data(df_list), title='E2E Delays for Lines')

    df_list = prepare_e2e_delays_for_points()
    output_cdf(generate_data(df_list), title='E2E Delays for Points')

# plt.savefig('/home/nuwins/moinak/pam_2022_ar/pam_2022_ar/new_measurements/delay_breakdown_all.pdf')
