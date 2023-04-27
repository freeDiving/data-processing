def diff_sec(t1, t2):
    if t1 is None or t2 is None:
        return 'NaN'
    return f'{(t2 - t1).total_seconds() * 1000: .0f}'
