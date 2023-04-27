import re
from datetime import datetime
from typing import Union

from src.constants import DATETIME_FORMAT


def has_prefix(line: str, prefix: str) -> bool:
    extracted = re.match(r".*?ar_activity:\s(.*)", line)
    if not extracted:
        return False
    extracted_line = extracted.group(1)
    pattern = r"^({prefix}).*".format(prefix=prefix)
    match = re.match(pattern, extracted_line)
    return match is not None


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
