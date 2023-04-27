import sys
from typing import List

import matplotlib.pyplot as plt
import os
# import numpy as np
import bisect

import numpy as np
import pandas as pd
import glob


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


def output_cdf(data_list: List, title: str):
    data_list = np.sort(data_list)
    cdf = np.cumsum(data_list) / np.sum(data_list)

    plt.plot(data_list, cdf)
    plt.xlabel('Data Packet Size (bytes)')
    plt.ylabel('Cumulative Probability')
    plt.legend(loc='best')
    if title is not None:
        plt.title(title)
    plt.show()


def prepare_data_for_lines():
    df_5g_static_lines = []
    for num in [
        10,
        11,
        13,
        15,
        16
    ]:
        df_5g_static_lines.append(
            pd.read_csv('./datasets/5g-static-line/output/0407-run{num}_send_pkt_sequences.csv'.format(num=num)))
    df_5g_block_static_lines = []
    for num in [
        1,
        2,
        3,
        4,
        5,
    ]:
        df_5g_block_static_lines.append(
            pd.read_csv('./datasets/5g-block-line/output/0421-5gbl-run{num}_send_pkt_sequences.csv'.format(num=num)))
    df_wifi_static_lines = []
    for num in [
        1,
        2,
        3,
        4,
        5
    ]:
        df_wifi_static_lines.append(
            pd.read_csv('./datasets/wifi-static-line/output/0422-wifi-run{num}_send_pkt_sequences.csv'.format(num=num)))
    df_lte_static_lines = []
    for num in [
        1,
        2,
        3,
        4,
        5
    ]:
        df_lte_static_lines.append(
            pd.read_csv('./datasets/lte-static-line/output/0421-ltel-run{num}_send_pkt_sequences.csv'.format(num=num)))
    df_list = df_5g_static_lines + df_5g_block_static_lines + df_wifi_static_lines + df_lte_static_lines
    return df_list


def prepare_data_for_points():
    df_5g_static_points = []
    for num in [
        1,
        2,
        3,
        4,
        6
    ]:
        df_5g_static_points.append(
            pd.read_csv('./datasets/5g-static-point/output/0407-run{num}_send_pkt_sequences.csv'.format(num=num)))

    df_5g_block_static_points = []
    for num in [
        2,
        4,
        5,
        6,
    ]:
        df_5g_block_static_points.append(
            pd.read_csv('./datasets/5g-block-point/output/0412-5gb-run{num}_send_pkt_sequences.csv'.format(num=num)))

    df_wifi_static_points = []
    for num in [
        1,
        2,
        3,
        4,
        5
    ]:
        df_wifi_static_points.append(
            pd.read_csv('./datasets/wifi-static-point/output/run{num}_send_pkt_sequences.csv'.format(num=num)))

    df_lte_static_points = []
    for num in [
        2,
        4,
        5,
        8,
        9,
    ]:
        df_lte_static_points.append(
            pd.read_csv('./datasets/lte-static-point/output/0412-lte-run{num}_send_pkt_sequences.csv'.format(num=num)))

    return df_5g_static_points + df_5g_block_static_points + df_wifi_static_points + df_lte_static_points


if __name__ == '__main__':
    df_list = prepare_data_for_lines()
    output_cdf(generate_data(df_list), title='Size of data sent to the cloud during 1b')

    df_list = prepare_data_for_points()
    output_cdf(generate_data(df_list), title='Size of data sent to the cloud during 1b')

# plt.savefig('/home/nuwins/moinak/pam_2022_ar/pam_2022_ar/new_measurements/delay_breakdown_all.pdf')
