from src.timeline.moment import prepare_moment_data


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
    moment_map = prepare_moment_data(host_app_log, resolver_app_log, host_pcap, resolver_pcap)

    # combine all moments
    timeline = []
    timeline.extend(moment_map.get('host_app'))
    timeline.extend(moment_map.get('resolver_app'))
    timeline.extend(moment_map.get('host_pcap'))
    timeline.extend(moment_map.get('resolver_pcap'))
    # sort moments by time
    timeline.sort(key=lambda x: x.time)
    return {
        'timeline': timeline,
        'moment_map': moment_map,
    }
