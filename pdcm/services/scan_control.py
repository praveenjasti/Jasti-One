from threading import Event


class ScanCancelled(Exception):
    """Raised when a user cancels a read-only scan."""


def raise_if_cancelled(cancellation_event: Event | None) -> None:
    if cancellation_event is not None and cancellation_event.is_set():
        raise ScanCancelled()
