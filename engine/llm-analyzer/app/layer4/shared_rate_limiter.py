"""
shared_rate_limiter.py — Thread-safe, process-wide pacer for Gemini quotas.

The sequential verdict engine gives each GeminiBackend its own in-process
TPMRateLimiter. That model breaks down the moment several worker threads each
hold their own backend and fire requests concurrently: nothing coordinates
their combined token/request rate, so the account-level quota is blown and the
API starts returning 429s.

SharedRateLimiter is a single object handed to *every* worker backend. It
enforces two account-level Gemini limits at once:

  - TPM (input tokens per minute), and
  - RPM (requests per minute).

It mirrors the method surface of gemini_backend.TPMRateLimiter
(``acquire()`` / ``record(prompt_tokens)``) so it can be dropped straight into
``GeminiBackend.rate_limiter`` with no other wiring.

Pacing model
------------
Each call sequence per worker thread is: acquire() → send request → record().

``acquire()`` blocks until *both* a request slot and an estimated token budget
are available within the trailing 60-second window, then **reserves** them
(appends a request timestamp and an estimated token count). Reserving up front
is what makes concurrency safe: without it, N threads could all pass the check
simultaneously and collectively overshoot the quota.

``record()`` reconciles the reservation with the real prompt-token count once
the response comes back, using a thread-local handle to find the slot it
reserved. The window is therefore eventually exact, and never under-counts
in-flight requests.
"""

from __future__ import annotations

import threading
import time
from collections import deque


class SharedRateLimiter:
    """Process-wide TPM + RPM pacer shared across all worker backends."""

    DEFAULT_HEADROOM = 0.9
    COLD_START_ESTIMATE = 100_000
    GROWTH_FACTOR = 1.05
    WINDOW_SECONDS = 60.0

    def __init__(
        self,
        *,
        tpm_limit: int,
        rpm_limit: int,
        headroom: float = DEFAULT_HEADROOM,
        log_fn=None,
    ):
        # A limit of 0 (or less) disables that dimension.
        self.tpm_budget = int(tpm_limit * headroom) if tpm_limit > 0 else 0
        self.rpm_budget = int(rpm_limit * headroom) if rpm_limit > 0 else 0

        self._tpm_window: deque = deque()   # (timestamp, tokens)
        self._rpm_window: deque = deque()   # timestamp
        self._lock = threading.Lock()
        self._tls = threading.local()       # per-thread reservation handle
        self._last_prompt_tokens = 0
        self._warned_oversize = False

        self.log = log_fn or (lambda *a, **k: None)

    # ---------------- internal helpers ----------------

    def _evict_stale(self, now: float) -> None:
        cutoff = now - self.WINDOW_SECONDS
        while self._tpm_window and self._tpm_window[0][0] < cutoff:
            self._tpm_window.popleft()
        while self._rpm_window and self._rpm_window[0] < cutoff:
            self._rpm_window.popleft()

    def _tpm_sum(self) -> int:
        return sum(tokens for _, tokens in self._tpm_window)

    def _estimate_next(self) -> int:
        if self._last_prompt_tokens == 0:
            return self.COLD_START_ESTIMATE
        return int(self._last_prompt_tokens * self.GROWTH_FACTOR)

    # ---------------- public API (TPMRateLimiter-compatible) -----------

    def acquire(self) -> None:
        """Block until a request + token budget is free, then reserve both."""
        while True:
            with self._lock:
                now = time.monotonic()
                self._evict_stale(now)

                estimate = self._estimate_next()

                # A single request estimated larger than the whole budget
                # would never fit — admit it rather than deadlock (the
                # window self-corrects on the next request via record()).
                oversize = (
                    self.tpm_budget > 0 and estimate > self.tpm_budget
                )
                if oversize and not self._warned_oversize:
                    self.log(
                        f"  ⚠ Estimated request size ({estimate:,} tokens) "
                        f"exceeds the entire TPM budget "
                        f"({self.tpm_budget:,}). Proceeding without TPM "
                        f"pacing for oversized requests.",
                        color="yellow",
                    )
                    self._warned_oversize = True

                tpm_ok = (
                    self.tpm_budget == 0
                    or oversize
                    or self._tpm_sum() + estimate <= self.tpm_budget
                )
                rpm_ok = (
                    self.rpm_budget == 0
                    or len(self._rpm_window) + 1 <= self.rpm_budget
                )

                if tpm_ok and rpm_ok:
                    self._rpm_window.append(now)
                    self._tpm_window.append((now, estimate))
                    self._tls.slot = (now, estimate)
                    return

                # Compute how long until the earliest blocking entry ages
                # out of the 60s window.
                waits = []
                if not rpm_ok and self._rpm_window:
                    waits.append(self._rpm_window[0] + self.WINDOW_SECONDS - now)
                if not tpm_ok and self._tpm_window:
                    waits.append(
                        self._tpm_window[0][0] + self.WINDOW_SECONDS - now
                    )
                sleep_for = max(0.2, min(waits) if waits else 0.5)

                reason = []
                if not rpm_ok:
                    reason.append(
                        f"RPM {len(self._rpm_window)}/{self.rpm_budget}"
                    )
                if not tpm_ok:
                    reason.append(
                        f"TPM {self._tpm_sum():,}/{self.tpm_budget:,}"
                    )
                self.log(
                    f"  ⏸ Rate pacing ({', '.join(reason)}); "
                    f"sleeping {sleep_for:.1f}s",
                    color="dim",
                )
            # Sleep OUTSIDE the lock so other threads can make progress /
            # record their actuals while this one waits.
            time.sleep(sleep_for)

    def record(self, prompt_tokens: int) -> None:
        """Reconcile the reservation made in acquire() with the real count."""
        if prompt_tokens <= 0:
            return
        with self._lock:
            self._last_prompt_tokens = prompt_tokens
            slot = getattr(self._tls, "slot", None)
            if slot is None:
                # No matching reservation (shouldn't happen in normal
                # acquire→record flow); just add the actual.
                self._tpm_window.append((time.monotonic(), prompt_tokens))
                return
            ts, est = slot
            for i, (t, tok) in enumerate(self._tpm_window):
                if t == ts and tok == est:
                    self._tpm_window[i] = (t, prompt_tokens)
                    break
            self._tls.slot = None

    # ---------------- introspection (for logging) ----------------

    def snapshot(self) -> dict:
        with self._lock:
            now = time.monotonic()
            self._evict_stale(now)
            return {
                "rpm_in_window": len(self._rpm_window),
                "rpm_budget": self.rpm_budget,
                "tpm_in_window": self._tpm_sum(),
                "tpm_budget": self.tpm_budget,
            }
