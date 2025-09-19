"""
Queueing Module

Advanced queueing system for the security reasoner with support for
priority-based processing, batching, and high-throughput event handling.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Union
from queue import Queue, PriorityQueue, Empty, Full
from threading import Thread, Lock, Event, Condition
from enum import Enum
import time
import uuid
import json
import heapq
from collections import defaultdict, deque


class QueuePriority(Enum):
    """Queue priority levels"""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4
    EMERGENCY = 5


class QueueStatus(Enum):
    """Queue processing status"""
    ACTIVE = "active"
    PAUSED = "paused"
    STOPPED = "stopped"
    DRAINING = "draining"


@dataclass
class QueuedItem:
    """Item in the security processing queue"""
    item_id: str
    data: Any
    priority: QueuePriority
    timestamp: datetime
    retry_count: int = 0
    max_retries: int = 3
    timeout: Optional[float] = None
    callback: Optional[Callable] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __lt__(self, other: 'QueuedItem') -> bool:
        """Compare items for priority queue ordering (higher priority first)"""
        if self.priority.value != other.priority.value:
            return self.priority.value > other.priority.value
        return self.timestamp < other.timestamp
    
    def is_expired(self) -> bool:
        """Check if item has exceeded its timeout"""
        if self.timeout is None:
            return False
        return (datetime.now() - self.timestamp).total_seconds() > self.timeout
    
    def can_retry(self) -> bool:
        """Check if item can be retried"""
        return self.retry_count < self.max_retries
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            "item_id": self.item_id,
            "priority": self.priority.name,
            "timestamp": self.timestamp.isoformat(),
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "timeout": self.timeout,
            "metadata": self.metadata,
            "expired": self.is_expired(),
            "can_retry": self.can_retry()
        }


@dataclass
class QueueMetrics:
    """Queue performance metrics"""
    items_processed: int = 0
    items_failed: int = 0
    items_retried: int = 0
    items_expired: int = 0
    total_processing_time: float = 0.0
    max_processing_time: float = 0.0
    min_processing_time: float = float('inf')
    queue_size_samples: List[int] = field(default_factory=list)
    throughput_samples: List[float] = field(default_factory=list)
    
    @property
    def average_processing_time(self) -> float:
        """Average processing time per item"""
        if self.items_processed == 0:
            return 0.0
        return self.total_processing_time / self.items_processed
    
    @property
    def success_rate(self) -> float:
        """Success rate of processed items"""
        total = self.items_processed + self.items_failed
        if total == 0:
            return 0.0
        return self.items_processed / total
    
    @property
    def average_queue_size(self) -> float:
        """Average queue size"""
        if not self.queue_size_samples:
            return 0.0
        return sum(self.queue_size_samples) / len(self.queue_size_samples)
    
    @property
    def average_throughput(self) -> float:
        """Average throughput (items per second)"""
        if not self.throughput_samples:
            return 0.0
        return sum(self.throughput_samples) / len(self.throughput_samples)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            "items_processed": self.items_processed,
            "items_failed": self.items_failed,
            "items_retried": self.items_retried,
            "items_expired": self.items_expired,
            "average_processing_time": self.average_processing_time,
            "max_processing_time": self.max_processing_time,
            "min_processing_time": self.min_processing_time if self.min_processing_time != float('inf') else 0.0,
            "success_rate": self.success_rate,
            "average_queue_size": self.average_queue_size,
            "average_throughput": self.average_throughput
        }


class SecurityQueue:
    """
    High-performance priority queue for security event processing.
    
    Features:
    - Priority-based processing
    - Automatic retries with exponential backoff
    - Batch processing capabilities
    - Metrics and monitoring
    - Thread-safe operations
    - Dead letter queue for failed items
    """
    
    def __init__(self, 
                 max_size: int = 10000,
                 num_workers: int = 4,
                 batch_size: int = 1,
                 max_batch_wait: float = 1.0,
                 retry_delay: float = 1.0,
                 retry_multiplier: float = 2.0,
                 enable_metrics: bool = True):
        """
        Initialize security queue.
        
        Args:
            max_size: Maximum queue size
            num_workers: Number of worker threads
            batch_size: Items to process in each batch
            max_batch_wait: Maximum time to wait for batch completion
            retry_delay: Initial retry delay in seconds
            retry_multiplier: Retry delay multiplier for exponential backoff
            enable_metrics: Enable metrics collection
        """
        self.max_size = max_size
        self.num_workers = num_workers
        self.batch_size = batch_size
        self.max_batch_wait = max_batch_wait
        self.retry_delay = retry_delay
        self.retry_multiplier = retry_multiplier
        self.enable_metrics = enable_metrics
        
        # Queue implementation
        self._queue: PriorityQueue = PriorityQueue(maxsize=max_size)
        self._dead_letter_queue: Queue = Queue()
        self._retry_queue: PriorityQueue = PriorityQueue()
        
        # Worker management
        self._workers: List[Thread] = []
        self._status = QueueStatus.STOPPED
        self._stop_event = Event()
        self._pause_event = Event()
        self._drain_event = Event()
        
        # Thread synchronization
        self._lock = Lock()
        self._batch_condition = Condition()
        
        # Processing callbacks
        self._processor: Optional[Callable] = None
        self._batch_processor: Optional[Callable] = None
        self._error_handler: Optional[Callable] = None
        
        # Metrics
        self._metrics = QueueMetrics() if enable_metrics else None
        self._metrics_thread: Optional[Thread] = None
        
        # Item tracking
        self._active_items: Dict[str, QueuedItem] = {}
        self._completed_items: deque = deque(maxlen=1000)
        
        # Priority distribution tracking
        self._priority_counts: Dict[QueuePriority, int] = defaultdict(int)
        
        # Batching state
        self._current_batch: List[QueuedItem] = []
        self._last_batch_time = time.time()
    
    def set_processor(self, processor: Callable[[Any], Any]) -> None:
        """
        Set the item processor function.
        
        Args:
            processor: Function to process individual items
        """
        self._processor = processor
    
    def set_batch_processor(self, processor: Callable[[List[Any]], List[Any]]) -> None:
        """
        Set the batch processor function.
        
        Args:
            processor: Function to process batches of items
        """
        self._batch_processor = processor
    
    def set_error_handler(self, handler: Callable[[Exception, QueuedItem], None]) -> None:
        """
        Set the error handler function.
        
        Args:
            handler: Function to handle processing errors
        """
        self._error_handler = handler
    
    def start(self) -> None:
        """Start the queue processing workers"""
        if self._status != QueueStatus.STOPPED:
            return
        
        self._status = QueueStatus.ACTIVE
        self._stop_event.clear()
        self._pause_event.set()  # Start unpaused
        
        # Start worker threads
        for i in range(self.num_workers):
            worker = Thread(target=self._worker_loop, name=f"SecurityQueue-Worker-{i}")
            worker.daemon = True
            worker.start()
            self._workers.append(worker)
        
        # Start retry handler
        retry_thread = Thread(target=self._retry_loop, name="SecurityQueue-Retry")
        retry_thread.daemon = True
        retry_thread.start()
        self._workers.append(retry_thread)
        
        # Start metrics collection
        if self.enable_metrics:
            self._metrics_thread = Thread(target=self._metrics_loop, name="SecurityQueue-Metrics")
            self._metrics_thread.daemon = True
            self._metrics_thread.start()
    
    def stop(self, timeout: float = 30.0) -> None:
        """
        Stop the queue processing.
        
        Args:
            timeout: Maximum time to wait for workers to stop
        """
        if self._status == QueueStatus.STOPPED:
            return
        
        self._status = QueueStatus.STOPPED
        self._stop_event.set()
        self._pause_event.set()  # Ensure workers can exit
        
        # Wait for workers to complete
        for worker in self._workers:
            worker.join(timeout=timeout)
        
        self._workers.clear()
    
    def pause(self) -> None:
        """Pause queue processing"""
        if self._status == QueueStatus.ACTIVE:
            self._status = QueueStatus.PAUSED
            self._pause_event.clear()
    
    def resume(self) -> None:
        """Resume queue processing"""
        if self._status == QueueStatus.PAUSED:
            self._status = QueueStatus.ACTIVE
            self._pause_event.set()
    
    def drain(self, timeout: float = 60.0) -> bool:
        """
        Drain the queue, processing all pending items.
        
        Args:
            timeout: Maximum time to wait for drain completion
            
        Returns:
            True if drained successfully, False if timeout
        """
        if self._status not in [QueueStatus.ACTIVE, QueueStatus.PAUSED]:
            return False
        
        self._status = QueueStatus.DRAINING
        self._drain_event.clear()
        self._pause_event.set()  # Ensure processing continues
        
        # Wait for queue to empty
        start_time = time.time()
        while not self._queue.empty() and (time.time() - start_time) < timeout:
            time.sleep(0.1)
        
        # Wait for active items to complete
        while self._active_items and (time.time() - start_time) < timeout:
            time.sleep(0.1)
        
        success = self._queue.empty() and not self._active_items
        self._drain_event.set()
        
        return success
    
    def enqueue(self, 
                data: Any,
                priority: QueuePriority = QueuePriority.NORMAL,
                timeout: Optional[float] = None,
                max_retries: int = 3,
                callback: Optional[Callable] = None,
                metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Add an item to the queue.
        
        Args:
            data: Data to process
            priority: Processing priority
            timeout: Item timeout in seconds
            max_retries: Maximum retry attempts
            callback: Optional completion callback
            metadata: Additional metadata
            
        Returns:
            Item ID for tracking
            
        Raises:
            Full: If queue is at capacity
        """
        item_id = str(uuid.uuid4())
        
        item = QueuedItem(
            item_id=item_id,
            data=data,
            priority=priority,
            timestamp=datetime.now(),
            max_retries=max_retries,
            timeout=timeout,
            callback=callback,
            metadata=metadata or {}
        )
        
        try:
            self._queue.put(item, block=False)
            
            with self._lock:
                self._priority_counts[priority] += 1
            
            return item_id
            
        except Full:
            raise Full("Queue is at maximum capacity")
    
    def enqueue_batch(self, 
                     items: List[Dict[str, Any]],
                     default_priority: QueuePriority = QueuePriority.NORMAL) -> List[str]:
        """
        Add multiple items to the queue efficiently.
        
        Args:
            items: List of item dictionaries
            default_priority: Default priority for items without explicit priority
            
        Returns:
            List of item IDs
        """
        item_ids = []
        
        for item_data in items:
            data = item_data.get('data')
            priority = item_data.get('priority', default_priority)
            timeout = item_data.get('timeout')
            max_retries = item_data.get('max_retries', 3)
            callback = item_data.get('callback')
            metadata = item_data.get('metadata')
            
            try:
                item_id = self.enqueue(data, priority, timeout, max_retries, callback, metadata)
                item_ids.append(item_id)
            except Full:
                # Stop adding items if queue is full
                break
        
        return item_ids
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get current queue status and statistics.
        
        Returns:
            Dictionary with queue status information
        """
        with self._lock:
            priority_distribution = dict(self._priority_counts)
        
        status = {
            "status": self._status.value,
            "queue_size": self._queue.qsize(),
            "active_items": len(self._active_items),
            "dead_letter_size": self._dead_letter_queue.qsize(),
            "retry_queue_size": self._retry_queue.qsize(),
            "workers": len(self._workers),
            "priority_distribution": {p.name: count for p, count in priority_distribution.items()},
            "metrics": self._metrics.to_dict() if self._metrics else None
        }
        
        return status
    
    def get_item_status(self, item_id: str) -> Optional[Dict[str, Any]]:
        """
        Get status of a specific item.
        
        Args:
            item_id: Item ID to check
            
        Returns:
            Item status dictionary or None if not found
        """
        # Check active items
        if item_id in self._active_items:
            return {
                "status": "processing",
                "item": self._active_items[item_id].to_dict()
            }
        
        # Check completed items
        for item in self._completed_items:
            if item.item_id == item_id:
                return {
                    "status": "completed",
                    "item": item.to_dict()
                }
        
        return None
    
    def _worker_loop(self) -> None:
        """Main worker loop for processing queue items"""
        while not self._stop_event.is_set():
            # Wait for pause to be lifted
            self._pause_event.wait()
            
            if self._stop_event.is_set():
                break
            
            try:
                # Get item from queue
                item = self._queue.get(timeout=1.0)
                
                # Check if item is expired
                if item.is_expired():
                    self._handle_expired_item(item)
                    continue
                
                # Track active item
                with self._lock:
                    self._active_items[item.item_id] = item
                
                # Process item
                self._process_item(item)
                
            except Empty:
                continue
            except Exception as e:
                # Log unexpected errors
                if self._error_handler:
                    self._error_handler(e, None)
    
    def _process_item(self, item: QueuedItem) -> None:
        """Process a single item"""
        start_time = time.time()
        success = False
        
        try:
            if self.batch_size > 1 and self._batch_processor:
                self._process_item_batched(item)
            else:
                self._process_item_individual(item)
            
            success = True
            
        except Exception as e:
            success = False
            self._handle_processing_error(item, e)
        
        finally:
            processing_time = time.time() - start_time
            self._complete_item(item, success, processing_time)
    
    def _process_item_individual(self, item: QueuedItem) -> None:
        """Process item individually"""
        if self._processor:
            result = self._processor(item.data)
            
            # Execute callback if provided
            if item.callback:
                item.callback(result)
    
    def _process_item_batched(self, item: QueuedItem) -> None:
        """Process item as part of a batch"""
        with self._batch_condition:
            self._current_batch.append(item)
            
            # Process batch if conditions are met
            should_process = (
                len(self._current_batch) >= self.batch_size or
                (time.time() - self._last_batch_time) >= self.max_batch_wait
            )
            
            if should_process and self._batch_processor:
                batch = self._current_batch[:]
                self._current_batch.clear()
                self._last_batch_time = time.time()
                
                # Process the batch
                batch_data = [item.data for item in batch]
                results = self._batch_processor(batch_data)
                
                # Execute callbacks
                for item, result in zip(batch, results):
                    if item.callback:
                        item.callback(result)
    
    def _handle_processing_error(self, item: QueuedItem, error: Exception) -> None:
        """Handle processing error with retry logic"""
        item.retry_count += 1
        
        if item.can_retry():
            # Calculate retry delay with exponential backoff
            delay = self.retry_delay * (self.retry_multiplier ** (item.retry_count - 1))
            
            # Schedule for retry
            retry_time = datetime.now() + timedelta(seconds=delay)
            self._retry_queue.put((retry_time, item))
            
            if self._metrics:
                self._metrics.items_retried += 1
        else:
            # Send to dead letter queue
            self._dead_letter_queue.put((item, error))
            
            if self._metrics:
                self._metrics.items_failed += 1
        
        # Call error handler
        if self._error_handler:
            self._error_handler(error, item)
    
    def _handle_expired_item(self, item: QueuedItem) -> None:
        """Handle expired item"""
        if self._metrics:
            self._metrics.items_expired += 1
        
        # Send to dead letter queue
        self._dead_letter_queue.put((item, TimeoutError("Item expired")))
        
        if self._error_handler:
            self._error_handler(TimeoutError("Item expired"), item)
    
    def _complete_item(self, item: QueuedItem, success: bool, processing_time: float) -> None:
        """Complete item processing"""
        # Remove from active items
        with self._lock:
            if item.item_id in self._active_items:
                del self._active_items[item.item_id]
        
        # Add to completed items
        self._completed_items.append(item)
        
        # Update metrics
        if self._metrics:
            if success:
                self._metrics.items_processed += 1
                self._metrics.total_processing_time += processing_time
                self._metrics.max_processing_time = max(self._metrics.max_processing_time, processing_time)
                self._metrics.min_processing_time = min(self._metrics.min_processing_time, processing_time)
        
        # Mark queue task as done
        self._queue.task_done()
    
    def _retry_loop(self) -> None:
        """Loop for handling retry queue"""
        while not self._stop_event.is_set():
            try:
                # Get item from retry queue with timeout
                retry_time, item = self._retry_queue.get(timeout=1.0)
                
                # Wait until retry time
                now = datetime.now()
                if now < retry_time:
                    wait_time = (retry_time - now).total_seconds()
                    if self._stop_event.wait(wait_time):
                        break
                
                # Re-enqueue item if queue is not full
                try:
                    self._queue.put(item, block=False)
                except Full:
                    # If queue is full, put back in retry queue with longer delay
                    future_retry = datetime.now() + timedelta(seconds=self.retry_delay)
                    self._retry_queue.put((future_retry, item))
                
            except Empty:
                continue
    
    def _metrics_loop(self) -> None:
        """Loop for collecting queue metrics"""
        while not self._stop_event.is_set():
            if self._metrics:
                # Sample queue size
                self._metrics.queue_size_samples.append(self._queue.qsize())
                
                # Keep only recent samples
                if len(self._metrics.queue_size_samples) > 100:
                    self._metrics.queue_size_samples = self._metrics.queue_size_samples[-100:]
                
                # Calculate throughput
                if len(self._metrics.queue_size_samples) >= 2:
                    recent_processed = self._metrics.items_processed
                    # Simple throughput calculation (items per second over last interval)
                    throughput = recent_processed / max(1, len(self._metrics.queue_size_samples))
                    self._metrics.throughput_samples.append(throughput)
                    
                    if len(self._metrics.throughput_samples) > 100:
                        self._metrics.throughput_samples = self._metrics.throughput_samples[-100:]
            
            # Sleep for metrics collection interval
            if self._stop_event.wait(5.0):
                break
    
    def get_dead_letter_items(self, max_items: int = 100) -> List[Dict[str, Any]]:
        """
        Get items from dead letter queue.
        
        Args:
            max_items: Maximum number of items to retrieve
            
        Returns:
            List of failed items with error information
        """
        items = []
        count = 0
        
        try:
            while count < max_items and not self._dead_letter_queue.empty():
                item, error = self._dead_letter_queue.get_nowait()
                items.append({
                    "item": item.to_dict(),
                    "error": str(error),
                    "error_type": type(error).__name__
                })
                count += 1
        except Empty:
            pass
        
        return items
    
    def clear_dead_letter_queue(self) -> int:
        """
        Clear the dead letter queue.
        
        Returns:
            Number of items cleared
        """
        count = 0
        try:
            while not self._dead_letter_queue.empty():
                self._dead_letter_queue.get_nowait()
                count += 1
        except Empty:
            pass
        
        return count
    
    def requeue_item(self, item_id: str, new_priority: Optional[QueuePriority] = None) -> bool:
        """
        Requeue a failed item from dead letter queue.
        
        Args:
            item_id: ID of item to requeue
            new_priority: Optional new priority level
            
        Returns:
            True if item was found and requeued, False otherwise
        """
        # Look for item in dead letter queue
        temp_items = []
        found_item = None
        
        try:
            while not self._dead_letter_queue.empty():
                item, error = self._dead_letter_queue.get_nowait()
                if item.item_id == item_id:
                    found_item = item
                else:
                    temp_items.append((item, error))
        except Empty:
            pass
        
        # Put back other items
        for item, error in temp_items:
            self._dead_letter_queue.put((item, error))
        
        # Requeue found item
        if found_item:
            if new_priority:
                found_item.priority = new_priority
            
            found_item.retry_count = 0  # Reset retry count
            found_item.timestamp = datetime.now()  # Update timestamp
            
            try:
                self._queue.put(found_item, block=False)
                return True
            except Full:
                # Put back in dead letter queue if main queue is full
                self._dead_letter_queue.put((found_item, Exception("Requeue failed - queue full")))
        
        return False