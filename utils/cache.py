from cachetools import TTLCache
from typing import Any, Optional
from config import CACHE_TTL_SECONDS

# Initialize a global TTL cache
# TTLCache(maxsize, ttl) - maxsize is the maximum number of items, ttl is time-to-live in seconds
cache: TTLCache = TTLCache(maxsize=1000, ttl=CACHE_TTL_SECONDS)

def get_from_cache(key: str) -> Optional[Any]:
    """
    Retrieves a value from the cache.

    Args:
        key (str): The key associated with the value.

    Returns:
        Optional[Any]: The cached value if found and not expired, otherwise None.
    """
    return cache.get(key)

def set_in_cache(key: str, value: Any, ttl: Optional[int] = None):
    """
    Stores a value in the cache.

    Args:
        key (str): The key to associate with the value.
        value (Any): The value to store.
        ttl (Optional[int]): Time-to-live for this specific item in seconds.
                             If None, uses the default CACHE_TTL_SECONDS from config.
    """
    if ttl is not None:
        cache[key] = value
        cache.ttl[key] = ttl
    else:
        cache[key] = value

def invalidate_cache(key: str):
    """
    Removes a specific item from the cache.

    Args:
        key (str): The key of the item to remove.
    """
    if key in cache:
        del cache[key]

def clear_cache():
    """
    Clears all items from the cache.
    """
    cache.clear()

# Self-test block
if __name__ == "__main__":
    import time
    print("Running utils/cache.py self-test...")

    # Ensure CACHE_TTL_SECONDS is set for testing
    from config import CACHE_TTL_SECONDS as TEST_CACHE_TTL_SECONDS

    # Test 1: Set and get item
    print("\n--- Test 1: Set and get item ---")
    set_in_cache("test_key_1", "test_value_1")
    value = get_from_cache("test_key_1")
    print(f"Retrieved 'test_key_1': {value}")
    assert value == "test_value_1"

    # Test 2: Item expiration (requires waiting)
    print(f"\n--- Test 2: Item expiration (waiting for {TEST_CACHE_TTL_SECONDS + 1} seconds) ---")
    set_in_cache("test_key_2", "test_value_2", ttl=1) # Set a short TTL for testing
    value_before_expire = get_from_cache("test_key_2")
    print(f"Retrieved 'test_key_2' before expiration: {value_before_expire}")
    assert value_before_expire == "test_value_2"
    
    time.sleep(1.1) # Wait for more than 1 second
    value_after_expire = get_from_cache("test_key_2")
    print(f"Retrieved 'test_key_2' after expiration: {value_after_expire}")
    assert value_after_expire is None

    # Test 3: Invalidate specific item
    print("\n--- Test 3: Invalidate specific item ---")
    set_in_cache("test_key_3", "test_value_3")
    value_before_invalidate = get_from_cache("test_key_3")
    print(f"Retrieved 'test_key_3' before invalidate: {value_before_invalidate}")
    assert value_before_invalidate == "test_value_3"
    
    invalidate_cache("test_key_3")
    value_after_invalidate = get_from_cache("test_key_3")
    print(f"Retrieved 'test_key_3' after invalidate: {value_after_invalidate}")
    assert value_after_invalidate is None

    # Test 4: Clear all items
    print("\n--- Test 4: Clear all items ---")
    set_in_cache("test_key_4a", "test_value_4a")
    set_in_cache("test_key_4b", "test_value_4b")
    print(f"Cache size before clear: {len(cache)}")
    assert len(cache) > 0
    
    clear_cache()
    print(f"Cache size after clear: {len(cache)}")
    assert len(cache) == 0
    assert get_from_cache("test_key_4a") is None

    print("\nAll utils/cache.py self-tests passed!")