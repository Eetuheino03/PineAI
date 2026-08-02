"""Strict, dependency-free RFC 3339 validation shared by backend boundaries."""

import datetime
import re
from typing import Any, Optional, Tuple

from .errors import BackendError


RFC3339_PATTERN = re.compile(
    r"^([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):"
    r"([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?"
    r"([Zz]|[+-][0-9]{2}:[0-9]{2})$"
)


def validate_rfc3339(
    value: Any,
    field: str,
    error_code: str,
    nullable: bool = False,
) -> Optional[str]:
    """Return a validated RFC 3339 value or raise a stable backend error."""
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not value:
        raise BackendError(
            error_code,
            "{0} must be a valid RFC 3339 date-time string".format(field),
        )
    match = RFC3339_PATTERN.match(value)
    if match is None:
        raise BackendError(
            error_code,
            "{0} must be a valid RFC 3339 date-time string".format(field),
        )

    try:
        datetime.date(
            int(match.group(1)),
            int(match.group(2)),
            int(match.group(3)),
        )
    except ValueError as failure:
        raise BackendError(
            error_code,
            "{0} contains an invalid calendar date".format(field),
        ) from failure

    hour = int(match.group(4))
    minute = int(match.group(5))
    second = int(match.group(6))
    if hour > 23 or minute > 59 or second > 59:
        raise BackendError(
            error_code,
            "{0} contains an invalid time component".format(field),
        )

    zone = match.group(8)
    if zone.upper() != "Z" and (
        int(zone[1:3]) > 23 or int(zone[4:6]) > 59
    ):
        raise BackendError(
            error_code,
            "{0} contains an invalid timezone offset".format(field),
        )
    return value


def rfc3339_order_key(value: str) -> Tuple[int, int]:
    """Return an exact UTC `(seconds, nanoseconds)` ordering key."""
    match = RFC3339_PATTERN.match(value)
    if match is None:
        raise ValueError("invalid RFC 3339 value")
    fraction = int((match.group(7) or "").ljust(9, "0"))
    zone = match.group(8)
    if zone.upper() == "Z":
        offset_seconds = 0
    else:
        sign = 1 if zone[0] == "+" else -1
        offset_seconds = sign * (
            int(zone[1:3]) * 3600 + int(zone[4:6]) * 60
        )
    day = datetime.date(
        int(match.group(1)),
        int(match.group(2)),
        int(match.group(3)),
    )
    seconds = (
        day.toordinal() * 86400
        + int(match.group(4)) * 3600
        + int(match.group(5)) * 60
        + int(match.group(6))
        - offset_seconds
    )
    return (seconds, fraction)


def normalize_rfc3339_utc(value: str) -> str:
    """Return a validated instant in canonical UTC without losing nanoseconds."""
    seconds, nanoseconds = rfc3339_order_key(value)
    ordinal, second_of_day = divmod(seconds, 86400)
    try:
        day = datetime.date.fromordinal(ordinal)
    except ValueError as failure:
        raise ValueError("RFC 3339 value is outside the supported UTC range") from failure
    hour, remainder = divmod(second_of_day, 3600)
    minute, second = divmod(remainder, 60)
    result = "{0:04d}-{1:02d}-{2:02d}T{3:02d}:{4:02d}:{5:02d}".format(
        day.year,
        day.month,
        day.day,
        hour,
        minute,
        second,
    )
    if nanoseconds:
        result += "." + "{0:09d}".format(nanoseconds).rstrip("0")
    return result + "Z"
