# Data Processing for Just A Line Measurements

## Quick Start

Following the steps can help you kickstart the data processing with our scripts:

1. Create virtual python environment and install dependencies
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```

2. Enter src directory and run the `main` script
   The timeline and phases calculation results will be saved in `output` directory as csv files
    ```bash
    cd src
    python main.py
    ```

3. To run the plotting scripts, enter scripts directory and run the `plot` scripts

## Dataset Information

Enter `datasets` directory, you will find our available datasets

The naming convention of dir is as follows:

`<wireless_tech>-<condition>-<draw_line_or_point>`

In each dataset, there are 2 dirs: `host` and `resolver`, where includes a bunch of runs of
data collected from host and resolver respectively

Specifically, in each run, there are 2 data files:

- `capture.pcap`: the raw pcap file dumped by tcpdump
- `static_log.logcat`: the logcat file dumped by `adb logcat`

### Wireless Technologies

We've tested Just A Line under 5 different conditions:

- 5G Line of Sight
- 5G Blockage
- LTE
- WiFi

The speed tests are as follows:

| Technology | Average Downlink speed (Mbps) | Average Uplink speed (Mbps) |
|------------|-------------------------------|-----------------------------|
| 5G LOS     | 2077 ± 87                     | 314 ± 34                    |
| 5G Blocked | 1411 ± 303                    | 143.5 ± 12.5                |
| LTE        | 55.6 ± 27.8                   | 30.45 ± 14.65               |
| 802.11ac   | 295.5 ± 12.5                  | 11.9 ± 0.1                  |

### Conditions

- `static`: means the device is static during the measurement
- `move`: means the device is moving during the measurement
- `block`: means the device is blocked by a human body during the measurement

## How to use the .pcap files?

The pcap files are captured by tcpdump, which is a command line tool for capturing network packets.

You can open them with Wireshark, which is a GUI tool for analyzing network packets.

If you want to analyze the pcap files programmatically, you can use the `pyshark` library in python, just like what we
do in ours.

Since the pcap traces are logged while playing the Just A Line app,
you can filter the packets by the timestamps of app logs `static_log.logcat`.

For example, you can filter the packets within the e2e time range of drawing by finding:

- `start_time`: Search the timestamp of the first log that contains `touch screen` on the host side
- `end_time`: Search the timestamp of the last log that `onChildChanged` on the resolver side

Then you can filter packets with time range `[start_time, end_time]` in Wireshark.

For details, check our code `prepare_timeline` in `src/timeline/timeline.py`

