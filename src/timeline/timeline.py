from src.timeline.moment import parse_log_and_pcap


def get_timeline(info_map):
    timeline = []
    host_runtime_info_map = info_map.get("host")
    resolver_runtime_info_map = info_map.get("resolver")
    # Combine all moments
    timeline.extend(host_runtime_info_map.log_drawing_moments)
    timeline.extend(resolver_runtime_info_map.log_drawing_moments)
    timeline.extend(host_runtime_info_map.pcap_drawing_moments)
    timeline.extend(resolver_runtime_info_map.pcap_drawing_moments)
    # sort moments by time
    timeline.sort(key=lambda x: x.time)

    return timeline


def prepare_timeline(host_app_log, resolver_app_log, host_pcap, resolver_pcap):
    """
    Merge all moments from host app, resolver app, host pcap, resolver pcap
    into a single timeline.
    :param host_app_log:
    :param resolver_app_log:
    :param host_pcap:
    :param resolver_pcap:
    :return:
    """
    info_map = parse_log_and_pcap(host_app_log, resolver_app_log, host_pcap, resolver_pcap)
    timeline = get_timeline(info_map)

    return {
        'timeline': timeline,
        'info_map': info_map,
    }
