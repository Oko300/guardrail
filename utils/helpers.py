import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

def get_current_utc_timestamp() -> datetime:
    """
    Returns the current UTC datetime.

    Returns:
        datetime: The current UTC datetime object.
    """
    return datetime.utcnow()

def format_datetime_iso(dt: datetime) -> str:
    """
    Formats a datetime object into an ISO 8601 string.

    Args:
        dt (datetime): The datetime object to format.

    Returns:
        str: The ISO 8601 formatted string.
    """
    return dt.isoformat()

def parse_datetime_iso(dt_str: str) -> datetime:
    """
    Parses an ISO 8601 string into a datetime object.

    Args:
        dt_str (str): The ISO 8601 formatted string.

    Returns:
        datetime: The parsed datetime object.
    """
    return datetime.fromisoformat(dt_str)

def safe_float_conversion(value: Any, default: float = 0.0) -> float:
    """
    Safely converts a value to a float, returning a default on failure.

    Args:
        value (Any): The value to convert.
        default (float): The default value to return if conversion fails.

    Returns:
        float: The converted float or the default value.
    """
    try:
        return float(value)
    except (ValueError, TypeError):
        logger.warning(f"Failed to convert '{value}' to float, returning default {default}")
        return default

def safe_int_conversion(value: Any, default: int = 0) -> int:
    """
    Safely converts a value to an int, returning a default on failure.

    Args:
        value (Any): The value to convert.
        default (int): The default value to return if conversion fails.

    Returns:
        int: The converted int or the default value.
    """
    try:
        return int(value)
    except (ValueError, TypeError):
        logger.warning(f"Failed to convert '{value}' to int, returning default {default}")
        return default

def get_nested_value(data: Dict, keys: List[str], default: Any = None) -> Any:
    """
    Safely retrieves a nested value from a dictionary using a list of keys.

    Args:
        data (Dict): The dictionary to search within.
        keys (List[str]): A list of keys representing the path to the nested value.
        default (Any): The default value to return if any key in the path is not found.

    Returns:
        Any: The nested value or the default value.
    """
    current_value = data
    for key in keys:
        if isinstance(current_value, dict) and key in current_value:
            current_value = current_value[key]
        else:
            return default
    return current_value

# Self-test block
if __name__ == "__main__":
    print("Running utils/helpers.py self-test...")

    # Test 1: get_current_utc_timestamp
    print("\n--- Test 1: get_current_utc_timestamp ---")
    now_utc = get_current_utc_timestamp()
    print(f"Current UTC timestamp: {now_utc}")
    assert isinstance(now_utc, datetime)
    assert now_utc.tzinfo is None # UTC by default, no tzinfo

    # Test 2: format_datetime_iso and parse_datetime_iso
    print("\n--- Test 2: format_datetime_iso and parse_datetime_iso ---")
    test_dt = datetime(2026, 7, 13, 10, 30, 0)
    iso_str = format_datetime_iso(test_dt)
    print(f"Formatted ISO string: {iso_str}")
    assert iso_str == "2026-07-13T10:30:00"
    
    parsed_dt = parse_datetime_iso(iso_str)
    print(f"Parsed datetime: {parsed_dt}")
    assert parsed_dt == test_dt

    # Test 3: safe_float_conversion
    print("\n--- Test 3: safe_float_conversion ---")
    assert safe_float_conversion("123.45") == 123.45
    assert safe_float_conversion(100) == 100.0
    assert safe_float_conversion("abc") == 0.0
    assert safe_float_conversion(None, default=99.9) == 99.9
    print("safe_float_conversion tests passed.")

    # Test 4: safe_int_conversion
    print("\n--- Test 4: safe_int_conversion ---")
    assert safe_int_conversion("123") == 123
    assert safe_int_conversion(45.67) == 45
    assert safe_int_conversion("xyz") == 0
    assert safe_int_conversion(None, default=-1) == -1
    print("safe_int_conversion tests passed.")

    # Test 5: get_nested_value
    print("\n--- Test 5: get_nested_value ---")
    test_data = {
        "level1": {
            "level2a": "value_a",
            "level2b": {
                "level3": 123
            }
        },
        "another_key": [1, 2, 3]
    }
    assert get_nested_value(test_data, ["level1", "level2a"]) == "value_a"
    assert get_nested_value(test_data, ["level1", "level2b", "level3"]) == 123
    assert get_nested_value(test_data, ["level1", "non_existent"]) is None
    assert get_nested_value(test_data, ["level1", "non_existent"], default="default_val") == "default_val"
    assert get_nested_value(test_data, ["non_existent", "level2a"]) is None
    assert get_nested_value(test_data, ["another_key", "level3"]) is None # Not a dict at this level
    print("get_nested_value tests passed.")

    print("\nAll utils/helpers.py self-tests passed!")