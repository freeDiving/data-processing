import re
import unittest
from datetime import datetime
from typing import Union, List, Any

from constants import DATETIME_FORMAT


def extract_timestamp(line: str, year: str) -> Union[datetime, None]:
    pattern = r".*?(\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.\d{3})"
    match = re.match(pattern, line)
    if not match:
        return None
    app_log_time = match.group(1)
    return datetime.strptime(year + '-' + app_log_time, DATETIME_FORMAT)


def extract_stroke_id(line: str) -> Union[str, None]:
    pattern_1 = r".*id=([-\w]+)"
    pattern_2 = r".*id:\s([-\w]+)"
    match = re.match(pattern_1, line)
    if not match:
        match = re.match(pattern_2, line)
    if not match:
        return None
    return match.group(1)


def identify_phase(line: str, phase: str) -> bool:
    pattern = r"\[{phase}\]".format(phase=phase)
    res = re.search(pattern, line)
    return res is not None


def is_formal_log(line: str) -> bool:
    pattern = r".*time=.*"
    res = re.match(pattern, line)
    return res is not None


def has_prefix(line: str, prefix: str) -> bool:
    extracted = re.match(r".*?ar_activity:\s(.*)", line)
    if not extracted:
        return False
    extracted_line = extracted.group(1)
    pattern = r"^({prefix}).*".format(prefix=prefix)
    match = re.match(pattern, extracted_line)
    return match is not None


class Phase:
    phase: str
    desc: str
    start_time: datetime
    end_time: datetime
    start_raw_data: str
    end_raw_data: str
    metadata: dict

    def __init__(self, **kwargs):
        self.phase = kwargs.get("phase") or ""
        self.desc = kwargs.get("desc") or ""
        self.start_time = kwargs.get("start_time") or ""
        self.end_time = kwargs.get("end_time") or ""
        self.start_raw_data = kwargs.get("start_raw_data") or ""
        self.end_raw_data = kwargs.get("end_raw_data") or ""
        self.metadata = kwargs.get("metadata") or dict()

    def get_duration(self):
        return self.end_time - self.start_time


class Moment:
    name: str
    source: str
    time: datetime
    metadata: dict
    raw_data: Any

    def __init__(self, **kwargs):
        self.name = kwargs.get("name") or ""
        self.source = kwargs.get("source") or ""
        self.action_from = kwargs.get("action_from") or ""
        self.action_to = kwargs.get("action_to") or ""
        self.time = kwargs.get("time") or ""
        self.metadata = kwargs.get("metadata") or dict()
        self.raw_data = kwargs.get("raw_data") or None


def get_phase_instance(line: str, phases: List[str]) -> Union[Phase, None]:
    phase = ""
    for p in phases:
        if identify_phase(line, p):
            phase = p
            break

    if phase == "":
        return None

    timestamp = extract_timestamp(line)
    return Phase(phase=phase, time=datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S.%f'), raw_line=line)


def get_phases_from_lines(lines: List[str], type: str):
    res = []
    for line in lines:
        phase = Phase()
        if type == 'host':
            # [1a start]
            # [2a end - 2d start]
            pass
        elif type == 'resolver':
            res.append(phase)
    return res


def generate_moment(formal_log: str, year: str) -> Moment:
    moment = Moment()
    moment.time = datetime.strptime(extract_timestamp(formal_log, year=year), '%Y-%m-%d %H:%M:%S.%f')
    moment.raw_data = formal_log
    return moment


class ProcessAppLogUnitTest(unittest.TestCase):
    def test_extract_timestamp(self):
        line = '04-07 15:34:34.421 10456 10592 D ar_activity: [Update ARCore frame time=2023-04-07 15:34:34.421]'
        self.assertEqual('2023-04-07 15:34:34.421', extract_timestamp(line, year='2023'))

    def test_identify_phases(self):
        line = '04-07 15:16:47.171  6297  6297 D ar_activity: [[1a start] touch screen time=2023-04-07 15:16:47.171]'
        self.assertEqual(True, identify_phase(line, '1a start'))
        line = "04-07 15:16:47.193  6297  6444 D ar_activity: [[2d] after update lines time=2023-04-07 15:16:47.193]"
        self.assertEqual(True, identify_phase(line, '2d'))
        line = "04-07 15:16:47.193  6297  6444 D ar_activity: [[2d start] after update lines time=2023-04-07 15:16:47.193]"
        self.assertEqual(True, identify_phase(line, '2d start'))
        line = "04-07 15:16:47.193  6297  6444 D ar_activity: [[2d start] after update lines time=2023-04-07 15:16:47.193]"
        self.assertEqual(False, identify_phase(line, '2d'))

    def test_get_phase_instance(self):
        line = '04-07 15:16:47.171  6297  6297 D ar_activity: [[1a start] touch screen time=2023-04-07 15:16:47.171]'
        phase_obj = get_phase_instance(line, phases=["1a start", "2a end - 2d start", "2d"])
        self.assertEqual('1a start', phase_obj.phase)
        self.assertEqual(datetime.strptime('2023-04-07 15:16:47.171', '%Y-%m-%d %H:%M:%S.%f'), phase_obj.time)
        self.assertEqual(line, phase_obj.raw_line)

    def test_get_phases(self):
        lines = [
            "04-07 15:16:47.171  6297  6297 D ar_activity: [[1a start] touch screen time=2023-04-07 15:16:47.171]",
            "04-07 15:34:12.865 14107 14245 D ar_activity: [Update ARCore frame time=2023-04-07 15:34:12.864]",
            "04-07 15:34:12.866 14107 14107 D ar_activity: [[2a end - 2d start] onChildAdded stroke id=-NSSCZrPmSmAX1NZRwr1 time=2023-04-07 15:34:12.866]",
            "04-07 15:34:12.866 14107 14107 D ar_activity: stroke (id: -NSSCZrPmSmAX1NZRwr1) was resolved at 2023-04-07 15:34:12.866",
            "04-07 15:34:12.869 14107 14245 D ar_activity: [[2d] after update lines time=2023-04-07 15:34:12.869]",
        ]

        phases = get_phases_from_lines(lines, phases=["1a start", "2a end - 2d start", "2d"])
        self.assertEqual(3, len(phases))

    def test_match_prefix(self):
        line = '04-07 15:16:47.171  6297  6297 D ar_activity: [[1a start] touch screen time=2023-04-07 15:16:47.171]'
        self.assertEqual(True, has_prefix(line, r'\[\[1a start\] touch screen'))

        line = '04-07 15:16:47.171  6297  6297 D ar_activity: [[1b end] time=2023-04-07 15:16:47.171]'
        self.assertEqual(False, has_prefix(line, r'\[\[1a start\]'))

        line = '04-07 15:16:47.408 11056 11213 D ar_activity: [[2d] after update lines time=2023-04-07 15:16:47.407]'
        self.assertEqual(True, has_prefix(line, r'\[\[2d\]'))

        line = '04-07 15:34:36.196 10456 10592 D ar_activity: [[2d end] stroke time=2023-04-07 15:34:36.196]'
        self.assertEqual(True, has_prefix(line, r'\[\[2d end\]'))

        line = '04-07 15:35:34.304 10854 10854 D ar_activity: [[2a end - 2d start] onChildChanged stroke id=-NSSCsksd3t6Qrxa0fqY time=2023-04-07 15:35:34.303]'
        self.assertEqual(True, has_prefix(line, r'\[\[2a end - 2d start\] onChildChanged'))

        line = '04-07 15:35:34.221 10854 11002 D ar_activity: stroke (id: -NSSCsksd3t6Qrxa0fqY) was added at 2023-04-07 15:35:34.221'
        self.assertEqual(True, has_prefix(line, r'stroke \(id: .*?\) was added at'))
