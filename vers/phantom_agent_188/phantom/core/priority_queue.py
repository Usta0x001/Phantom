"""
Priority Queue implementations for vulnerability and scan management.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass(order=True)
class PriorityItem:
    """Item with priority for queue ordering."""
    priority: int
    timestamp: float = field(compare=False)
    data: Any = field(compare=False)


class VulnerabilityPriorityQueue:
    """Priority queue for vulnerability processing (higher priority = more critical)."""
    
    def __init__(self) -> None:
        self._items: list[PriorityItem] = []
    
    def push(self, priority: int, data: Any) -> None:
        """Add item with priority (0=low, 10=critical)."""
        import time
        item = PriorityItem(priority=-priority, timestamp=time.time(), data=data)
        self._items.append(item)
        self._items.sort()
    
    def pop(self) -> Any | None:
        """Remove and return highest priority item."""
        if self._items:
            return self._items.pop(0).data
        return None
    
    def peek(self) -> Any | None:
        """View highest priority item without removing."""
        if self._items:
            return self._items[0].data
        return None
    
    def __len__(self) -> int:
        return len(self._items)
    
    def is_empty(self) -> bool:
        return len(self._items) == 0


class ScanPriorityQueue:
    """Priority queue for scan task ordering."""
    
    def __init__(self) -> None:
        self._items: list[PriorityItem] = []
    
    def push(self, priority: int, data: Any) -> None:
        """Add task with priority (higher = earlier execution)."""
        import time
        item = PriorityItem(priority=-priority, timestamp=time.time(), data=data)
        self._items.append(item)
        self._items.sort()
    
    def pop(self) -> Any | None:
        """Remove and return next task."""
        if self._items:
            return self._items.pop(0).data
        return None
    
    def peek(self) -> Any | None:
        """View next task without removing."""
        if self._items:
            return self._items[0].data
        return None
    
    def __len__(self) -> int:
        return len(self._items)
    
    def is_empty(self) -> bool:
        return len(self._items) == 0