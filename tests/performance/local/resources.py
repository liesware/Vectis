"""Sample the Vectis PID on macOS/Linux, without sampling the load generator."""

import csv
from contextlib import ExitStack
import subprocess
import threading
import time


def cpu_seconds(text):
    days, _, clock = text.strip().rpartition("-")
    parts = [float(part) for part in clock.split(":")]
    total = 0.0
    for part in parts:
        total = total * 60 + part
    return total + (int(days) * 86400 if days else 0)


def process_sample(pid):
    result = subprocess.run(["ps", "-p", str(pid), "-o", "rss=", "-o", "time="],
                            capture_output=True, text=True, check=False)
    if result.returncode or not result.stdout.strip():
        raise RuntimeError("could not sample the Vectis PID")
    rss, cpu = result.stdout.split()
    return int(rss) * 1024, cpu_seconds(cpu)


class ResourceSampler:
    def __init__(self, pid, destination=None):
        self.pid = pid
        self.destination = destination
        self.event = threading.Event()
        self.thread = None
        self.errors = []
        self.aggregates = {"samples": 0}

    def summary(self):
        """Read after stop/join; no per-sample history is retained in memory."""
        return dict(self.aggregates)

    def _record(self, rss, cpu, percent):
        state = self.aggregates
        if state["samples"] == 0:
            state.update(rss_initial_bytes=rss, rss_peak_bytes=rss, cpu_percent_peak_one_core=0)
        state.update(samples=state["samples"] + 1, rss_final_bytes=rss,
                     rss_peak_bytes=max(state["rss_peak_bytes"], rss),
                     rss_delta_bytes=rss - state["rss_initial_bytes"],
                     cpu_seconds_delta=max(0, cpu - self.initial[1]),
                     cpu_percent_peak_one_core=max(state["cpu_percent_peak_one_core"], percent))

    def start(self):
        self.started = time.monotonic()
        self.initial = process_sample(self.pid)
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        try:
            self._collect()
        except (OSError, ValueError, RuntimeError) as error:
            self.errors.append(str(error))

    def _collect(self):
        with ExitStack() as stack:
            stream = stack.enter_context(self.destination.open("w", newline="")) if self.destination else None
            writer = csv.writer(stream) if stream else None
            if writer:
                writer.writerow(["elapsed_seconds", "rss_bytes", "cpu_seconds", "cpu_percent_one_core"])
            previous_time, previous_cpu = self.started, self.initial[1]
            rss, cpu = self.initial
            self._record(rss, cpu, 0)
            if writer:
                writer.writerow([0, rss, cpu, 0])
                stream.flush()
            while True:
                stopping = self.event.wait(1)
                now = time.monotonic()
                try:
                    rss, cpu = process_sample(self.pid)
                except (OSError, ValueError, RuntimeError) as error:
                    self.errors.append(str(error))
                    return
                elapsed = now - previous_time
                percent = 100 * max(0, cpu - previous_cpu) / elapsed if elapsed > 0 else 0
                self._record(rss, cpu, percent)
                if writer:
                    writer.writerow([round(now - self.started, 6), rss, cpu, round(percent, 3)])
                    stream.flush()
                previous_time, previous_cpu = now, cpu
                if stopping:
                    return

    def stop(self):
        self.event.set()
        if self.thread is not None:
            self.thread.join()
