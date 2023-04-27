import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

if __name__ == '__main__':
    n = 9
    width = 0.30
    ind = np.arange(n)
    col_idx = ['black', 'royalblue', 'red']
    run_type_list = ['towards', 'away', 'lte']
    label_list = ['5G', '5G-Blocked', 'WiFi', 'LTE']
    # base_path = "/home/nuwins/moinak/pam_2022_ar/pam_2022_ar/new_measurements/"
    bg_com_list = []
    nbg_com_list = []
    lte_list = []
    count = 0

    fig, ax = plt.subplots(1, 2, figsize=(8, 6))


    # plot boxplots
    def set_box_color(bp, color):
        plt.setp(bp['boxes'], color=color)
        plt.setp(bp['whiskers'], color=color)
        plt.setp(bp['caps'], color=color)
        plt.setp(bp['medians'], color=color)


    df_5g_static_lines = []
    for num in [
        1,
        2,
        3,
        4,
        6
    ]:
        # df_5g_static_lines.append(
        #     pd.read_csv('./datasets/5g-static-line/output/0407-run{num}_phases.csv'.format(num=num)))
        df_5g_static_lines.append(
            pd.read_csv('./datasets/5g-static-point/output/0407-run{num}_phases.csv'.format(num=num)))

    df_5g_block_static_lines = []
    for num in [
        2,
        4,
        5,
        6,
    ]:
        # df_5g_block_static_lines.append(
        #     pd.read_csv('./datasets/5g-block-line/output/0421-5gbl-run{num}_phases.csv'.format(num=num)))
        df_5g_block_static_lines.append(
            pd.read_csv('./datasets/5g-block-point/output/0412-5gb-run{num}_phases.csv'.format(num=num)))

    df_wifi_static_lines = []
    for num in [
        1,
        2,
        3,
        4,
        5
    ]:
        # df_wifi_static_lines.append(
        #     pd.read_csv('./datasets/wifi-static-line/output/0422-wifi-run{num}_phases.csv'.format(num=num)))
        df_wifi_static_lines.append(
            pd.read_csv('./datasets/wifi-static-point/output/run{num}_phases.csv'.format(num=num)))

    df_lte_static_lines = []
    for num in [
        2,
        4,
        5,
        8,
        9,
    ]:
        # df_lte_static_lines.append(
        #     pd.read_csv('./datasets/lte-static-line/output/0421-ltel-run{num}_phases.csv'.format(num=num)))
        df_lte_static_lines.append(
            pd.read_csv('./datasets/lte-static-point/output/0412-lte-run{num}_phases.csv'.format(num=num)))

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


    data_5g_static_line = generate_data(df_5g_static_lines)
    data_5g_block_line = generate_data(df_5g_block_static_lines)
    data_wifi_static_line = generate_data(df_wifi_static_lines)
    data_lte_static_line = generate_data(df_lte_static_lines)

    plt.figure(figsize=(7, 4))

    bp1 = plt.boxplot(data_5g_static_line, positions=np.array(range(len(data_5g_static_line))) * 3.0 - 0.6, sym='+',
                      widths=0.4)
    bp2 = plt.boxplot(data_5g_block_line, positions=np.array(range(len(data_5g_block_line))) * 3.0, sym='+',
                      widths=0.5)
    bp3 = plt.boxplot(data_wifi_static_line, positions=np.array(range(len(data_wifi_static_line))) * 3.0 + 0.6, sym='+',
                      widths=0.4)
    bp4 = plt.boxplot(data_lte_static_line, positions=np.array(range(len(data_lte_static_line))) * 3.0 + 0.6 * 2,
                      sym='+',
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

    plt.ylabel('Latency (ms)', fontsize=12)
    plt.xlabel('Latency Type', fontsize=12)
    plt.legend(fontsize=8.25, loc='upper left')
    plt.xlim(-1, len(ticks) * 2.9)
    # plt.ylim(ymax=5)
    plt.tight_layout()
    # plt.title('Latency Breakdown (Drawing Point)', fontsize=12)

    plt.show()
# plt.savefig('/home/nuwins/moinak/pam_2022_ar/pam_2022_ar/new_measurements/delay_breakdown_all.pdf')
