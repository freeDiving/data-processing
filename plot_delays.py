import sys
import matplotlib.pyplot as plt
import os
# import numpy as np
import bisect

import numpy as np
import pandas as pd
import glob

n = 9
width = 0.30
ind = np.arange(n)
fig, ax = plt.subplots(1, 2, figsize=(8, 5))
col_idx = ['black', 'royalblue', 'red']
run_type_list = ['towards', 'away', 'lte']
label_list = ['5G', '5G-Blocked', 'WiFi', 'LTE']
base_path = "/home/nuwins/moinak/pam_2022_ar/pam_2022_ar/new_measurements/"
bg_com_list = []
nbg_com_list = []
lte_list = []
count = 0


# ax[0].set_xlabel('Delay type')
# ax[0].set_ylabel('Delay (s)')
# ax[0].set_xticks(ind + width + width / 3)
# ax[0].set_ylim(ymin=0, ymax=15)
# ax[0].set_xticklabels(('1a', '1b', '1c', '2x', '2a', '2b', '2c', '2d', 'E2E'))
# # ax[0].legend((fiveg_bar, fiveg_away_bar, lte_bar), ('5G - towards', '5G - away' ,'LTE'), loc='upper left')
# #plot cdf e2e


# ax[1].set_ylabel('CDF')
# ax[1].set_xlabel('E2E delay (s)')
# ax[1].legend(loc='best', fontsize=9)
# plt.tight_layout()
# plt.savefig('/home/nuwins/moinak/pam_2022_ar/pam_2022_ar/new_measurements/delay_breakdown_new_pos.pdf')
# plt.close()
# print()

# plot boxplots
def set_box_color(bp, color):
    plt.setp(bp['boxes'], color=color)
    plt.setp(bp['whiskers'], color=color)
    plt.setp(bp['caps'], color=color)
    plt.setp(bp['medians'], color=color)


df_5g_static_line = pd.read_csv('./datasets/5g-static-line/output/0407-run10_phases.csv')
df_5g_block_static_line = pd.read_csv('./datasets/5g-block-line/output/0421-5gbl-run2_phases.csv')
df_wifi_static_line = pd.read_csv('./datasets/wifi-static-line/output/0422-wifi-run1_phases.csv')
df_lte_static_line = pd.read_csv('./datasets/lte-static-line/output/0421-ltel-run1_phases.csv')

max_val = df_5g_block_static_line['duration'].max()
min_val = df_5g_block_static_line['duration'].min()

ticks = (
    '1a', '1b', 'c', '2d', 'e2e',
)


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


plt.figure(figsize=(7, 4))

data_5g_static_line = adapt_to_boxplot(df_5g_static_line)
data_wifi_static_line = adapt_to_boxplot(df_5g_static_line)
data_lte_static_line = adapt_to_boxplot(df_lte_static_line)
data_5g_block_line = adapt_to_boxplot(df_5g_block_static_line)

bp1 = plt.boxplot(data_5g_static_line, positions=np.array(range(len(data_5g_static_line))) * 3.0 - 0.6, sym='+',
                  widths=0.4)
bp2 = plt.boxplot(data_5g_block_line, positions=np.array(range(len(data_5g_block_line))) * 3.0, sym='+',
                  widths=0.5)
bp3 = plt.boxplot(data_wifi_static_line, positions=np.array(range(len(data_wifi_static_line))) * 3.0 + 0.6, sym='+',
                  widths=0.4)
bp4 = plt.boxplot(data_lte_static_line, positions=np.array(range(len(data_lte_static_line))) * 3.0 + 0.6 * 2, sym='+',
                  widths=0.4)

set_box_color(bp1, 'black')
set_box_color(bp2, 'royalblue')
set_box_color(bp3, 'red')
set_box_color(bp4, 'green')

plt.xticks(range(0, len(ticks) * 3, 3), ticks, fontsize=11)
plt.yticks(fontsize=11)
# draw temporary red and blue lines and use them to create a legend
plt.plot([], c='black', label=label_list[0])
plt.plot([], c='royalblue', label=label_list[1])
plt.plot([], c='red', label=label_list[2])
plt.plot([], c='green', label=label_list[3])

plt.ylabel('Latency (s)', fontsize=12)
plt.xlabel('Latency Type', fontsize=12)
plt.legend(fontsize=8.25, loc='upper left')
plt.xlim(-1, len(ticks) * 2.9)
# plt.ylim(ymax=5)
plt.tight_layout()

if __name__ == '__main__':
    plt.show()
# plt.savefig('/home/nuwins/moinak/pam_2022_ar/pam_2022_ar/new_measurements/delay_breakdown_all.pdf')
