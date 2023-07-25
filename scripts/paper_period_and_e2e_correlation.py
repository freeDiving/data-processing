# Plot figure 3(b)

import os

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from matplotlib.ticker import MaxNLocator

ROOT_PATH = os.path.abspath(os.path.dirname(__file__))

def input_path(*file_path) -> str:
    res = os.path.join(ROOT_PATH, *file_path)
    return res


def get_phase_file_path(dir_name):
    return os.path.join(ROOT_PATH, f'../output/{dir_name}/phases.csv')

def extract_e2e_delays(df):
    data = []
    for _, row in df.iterrows():
        if row['state'] == 'e2e':
            data.append(row['duration'])
    return data


def main():
    short_period_host_dirs = [
        get_phase_file_path('5g-static-line/run2'),  # 0.7044605217391305
        get_phase_file_path('5g-static-line/run4'),  # 0.672940035714286
        get_phase_file_path('5g-resolver_move-line/run1'),  # 0.6796149473684211
        get_phase_file_path('5g-resolver_move-line/run2'),  # 0.7057408857142855
        get_phase_file_path('5g-resolver_move-line/run5'),  # 0.6814988421052632
    ]
    long_period_host_dirs = [
        get_phase_file_path('5g-static-line/run1'),  # 3.2096174
        get_phase_file_path('5g-static-line/run3'),  # 3.2213651249999997
        get_phase_file_path('5g-static-line/run5'),  # 3.2528272
        get_phase_file_path('5g-host_move-line/run1'),  # 3.2448035
        get_phase_file_path('5g-host_move-line/run2'),  # 3.251666
        get_phase_file_path('5g-host_move-line/run3'),  # 3.1662763333333337
        get_phase_file_path('5g-host_move-line/run4'),  # 3.206519333333333
        get_phase_file_path('5g-host_move-line/run5'),  # 3.186882833333333
        get_phase_file_path('5g-resolver_move-line/run3'),  # 3.15552375
    ]

    e2e_list_short_period = []
    for dir in short_period_host_dirs:
        df = pd.read_csv(dir)
        e2e_list_short_period += extract_e2e_delays(df)

    e2e_list_short_period = np.sort(e2e_list_short_period)
    cdf_short_period = np.cumsum(e2e_list_short_period) / np.sum(e2e_list_short_period)

    e2e_list_long_period = []
    for dir in long_period_host_dirs:
        df = pd.read_csv(dir)
        e2e_list_long_period += extract_e2e_delays(df)

    e2e_list_long_period = np.sort(e2e_list_long_period)
    cdf_long_period = np.cumsum(e2e_list_long_period) / np.sum(e2e_list_long_period)

    # Plot
    my_font_size = 20
    fig, ax = plt.subplots(figsize=(6, 3.5))
    ax.plot(e2e_list_short_period, cdf_short_period, label="Short period", linewidth=3)
    ax.plot(e2e_list_long_period, cdf_long_period, label="Long period", linewidth=3)
    plt.xlim(xmin=0)
    plt.ylim(ymin=0, ymax=1)
    plt.gca().xaxis.set_major_locator(MaxNLocator(prune='lower'))
    plt.xlabel("E2E latency (s)", fontsize=my_font_size)
    plt.ylabel("CDF", fontsize=18)
    plt.xticks(fontsize=my_font_size)
    ax.set_xticks(ax.get_xticks()[::2])
    plt.yticks(fontsize=my_font_size)
    plt.legend(loc="lower right", fontsize=my_font_size)
    plt.savefig(os.path.join(ROOT_PATH, f'../Figures/cdf_e2e_period_correlation.pdf'), format='pdf')
    plt.show()


if __name__ == '__main__':
    main()
