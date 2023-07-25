# Plot figure 2(b)

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
        if row['state'] == 'host: local action' or row['state'] == 'resolver: local action':
            data['host: local action'].append(row['duration']/1000)
        elif row['state'] == 'host: data transmission' or row['state'] == 'resolver: data transmission':
            data['host: data transmission'].append(row['duration']/1000)
        elif row['state'] == 'resolver: rendering' or row['state'] == 'host: rendering':
            data['resolver: rendering'].append(row['duration']/1000)
        else:
            data[row['state']].append(row['duration']/1000)

    return [
        data['host: local action'],
        data['host: data transmission'],
        data['cloud: processing'],
        data['resolver: rendering'],
        data['e2e']
    ]


def generate_data(df_list):
    """
    Merge multiple runs
    Args:
        df_list:

    Returns:

    """
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
        df_5g_dynamic: List[pd.DataFrame],
):
    label_list = ['5G: Static', '5G: Mobility']
    data_5g_static_line = generate_data(df_5g_static)
    df_5g_dynamic = generate_data(df_5g_dynamic)

    # Get 75% percentile
    delay_1a_all = np.array(data_5g_static_line[0] + df_5g_dynamic[0])
    delay_1b_all = np.array(data_5g_static_line[1] + df_5g_dynamic[1])
    delay_c_all = np.array(data_5g_static_line[2] + df_5g_dynamic[2])
    delay_2d_all = np.array(data_5g_static_line[3] + df_5g_dynamic[3])

    print("1a 75% percentile for static and mobile: ", np.percentile(delay_1a_all, 75))
    print("1b 75% percentile for static and mobile: ", np.percentile(delay_1b_all, 75))
    print("c 75% percentile for static and mobile: ", np.percentile(delay_c_all, 75))
    print("2d 75% percentile for static and mobile: ", np.percentile(delay_2d_all, 75))
    print("75% percentile for all phases in static and mobile scenarios: ",
          np.percentile(np.concatenate((delay_1a_all, delay_1b_all, delay_c_all, delay_2d_all)), 75))

    # tweak the "figsize" parameter

    plt.figure(figsize=(7.2, 5))
    bp1 = plt.boxplot(data_5g_static_line, positions=np.array(range(len(data_5g_static_line))) * 3.0 - 0.6, sym='+',
                      widths=0.4)
    bp2 = plt.boxplot(df_5g_dynamic, positions=np.array(range(len(df_5g_dynamic))) * 3.0, sym='+',
                      widths=0.4)

    set_box_color(bp1, 'red')
    set_box_color(bp2, 'royalblue')

    ticks = ('1a', '1b', 'c', '2d', 'E2E')
    my_font_size = 25

    plt.xticks(range(0, len(ticks) * 3, 3), ticks, fontsize=my_font_size)
    plt.yticks(fontsize=my_font_size)
    # draw temporary red and blue lines and use them to create a legend
    plt.plot([], c='red', label=label_list[0])
    plt.plot([], c='royalblue', label=label_list[1]) # royal blue = 5G Mobility

    plt.ylabel('Latency (s)', fontsize=my_font_size)
    plt.xlabel('Latency type', fontsize=my_font_size)
    plt.legend(fontsize=my_font_size, loc='upper center')
    plt.xlim(-1, len(ticks) * 2.9)
    plt.ylim(ymax=2200/1000)
    plt.tight_layout()
    plt.savefig(os.path.join(ROOT_PATH, f'../Figures/latency_breakdown.pdf'), format="pdf", bbox_inches="tight")
    plt.show()


def prepare_data_for_lines():
    df_5g_static_lines = []
    for num in range(1, 6):
        df_5g_static_lines.append(
            pd.read_csv(get_output_path('5g-static-line', num, 'phases.csv'))
        )

    df_5g_dynamic_lines = []
    for num in range(1, 6):
        df_5g_dynamic_lines.append(
            pd.read_csv(get_output_path("5g-host_move-line", num, 'phases.csv'))
        )
        df_5g_dynamic_lines.append(
            pd.read_csv(get_output_path("5g-resolver_move-line", num, 'phases.csv'))
        )


    return (
        df_5g_static_lines,
        df_5g_dynamic_lines,
    )


def main():
    data_for_lines = prepare_data_for_lines()
    output_boxplot(*data_for_lines)


if __name__ == '__main__':
    main()
