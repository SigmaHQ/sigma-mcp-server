"""Background loading of the MITRE data used by pySigma's tag validators.

The ``attacktag`` and ``d3_fendtag`` validators need the MITRE ATT&CK and
D3FEND data.  pySigma downloads it on first use and caches it on disk, but
it does not remember a failed download: without internet access every
validation tries again, and can wait up to 30 seconds each time.

:class:`ReferenceData` therefore loads the data in background threads.
Until a dataset is available, ``validate_rule`` skips the validators that
need it and says so, instead of blocking.  After a failed download the next
attempt starts at the earliest :data:`RETRY_AFTER` seconds later.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any

from sigma.data import mitre_attack, mitre_d3fend

log = logging.getLogger(__name__)

RETRY_AFTER = 600.0
"""Seconds to wait after a failed download before trying again."""


class DatasetStatus(str, Enum):
    """Loading state of a reference dataset."""

    NOT_STARTED = "not_started"
    LOADING = "loading"
    READY = "ready"
    FAILED = "failed"


@dataclass
class Dataset:
    """A reference dataset and the validators that need it."""

    name: str
    validators: tuple[str, ...]
    loader: Callable[[], object]
    status: DatasetStatus = DatasetStatus.NOT_STARTED
    error: str | None = None
    failed_at: float | None = None


def _load_attack() -> object:
    return mitre_attack.mitre_attack_techniques


def _load_d3fend() -> object:
    return mitre_d3fend.mitre_d3fend_techniques


def default_datasets() -> list[Dataset]:
    """The datasets pySigma's core validators depend on."""
    return [
        Dataset("MITRE ATT&CK", ("attacktag",), _load_attack),
        Dataset("MITRE D3FEND", ("d3_fendtag",), _load_d3fend),
    ]


class ReferenceData:
    """Loads reference datasets in the background and reports their state."""

    def __init__(
        self,
        datasets: list[Dataset] | None = None,
        retry_after: float = RETRY_AFTER,
    ) -> None:
        self.datasets = datasets if datasets is not None else default_datasets()
        self.retry_after = retry_after
        self._mutex = threading.Lock()
        self._threads: list[threading.Thread] = []

    def start_loading(self) -> None:
        """Start loading every dataset that is neither available nor loading.

        A dataset whose last attempt failed is retried only after
        :attr:`retry_after` seconds.  Never blocks.
        """
        now = time.monotonic()
        with self._mutex:
            for dataset in self.datasets:
                due = dataset.status is DatasetStatus.NOT_STARTED or (
                    dataset.status is DatasetStatus.FAILED
                    and dataset.failed_at is not None
                    and now - dataset.failed_at >= self.retry_after
                )
                if not due:
                    continue
                dataset.status = DatasetStatus.LOADING
                thread = threading.Thread(
                    target=self._load,
                    args=(dataset,),
                    name=f"sigma-reference-{dataset.name}",
                    daemon=True,
                )
                self._threads.append(thread)
                thread.start()

    def _load(self, dataset: Dataset) -> None:
        try:
            dataset.loader()
        except Exception as exc:  # noqa: BLE001 - reported to the client
            log.warning("Loading %s failed: %s", dataset.name, exc)
            with self._mutex:
                dataset.status = DatasetStatus.FAILED
                dataset.error = str(exc)
                dataset.failed_at = time.monotonic()
            return
        with self._mutex:
            dataset.status = DatasetStatus.READY
            dataset.error = None

    def wait(self, timeout: float | None = None) -> None:
        """Block until all loading threads have finished (for tests)."""
        for thread in list(self._threads):
            thread.join(timeout)

    def unavailable_validators(self) -> dict[str, str]:
        """Map each validator whose data is not available to the reason."""
        reasons: dict[str, str] = {}
        with self._mutex:
            for dataset in self.datasets:
                if dataset.status is DatasetStatus.READY:
                    continue
                if dataset.status is DatasetStatus.FAILED:
                    reason = (
                        f"the {dataset.name} data could not be downloaded "
                        f"({dataset.error}); it will be retried later"
                    )
                else:
                    reason = f"the {dataset.name} data is still being downloaded"
                for validator in dataset.validators:
                    reasons[validator] = reason
        return reasons

    def describe(self) -> list[dict[str, Any]]:
        """Return the state of every dataset."""
        with self._mutex:
            return [
                {
                    "name": d.name,
                    "status": d.status.value,
                    "validators": list(d.validators),
                    "error": d.error,
                }
                for d in self.datasets
            ]


reference_data = ReferenceData()
"""The process-wide reference data loader used by ``validate_rule``."""
