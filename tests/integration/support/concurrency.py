"""Shared concurrency scaffold for race tests.

Both the integration suite (StatusClient) and the security-fuzz suite
(FuzzClient) drive the same one-time-token race: release N decode jobs at the
same instant so they genuinely contend, then collect their results in order.
Keeping the barrier/executor mechanics here means a fix to the timing or
contention logic lands once instead of drifting between two copies.
"""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier


def run_simultaneously(jobs, executor=None, release_timeout=10, result_timeout=20):
    """Run `jobs` (zero-arg callables) concurrently and return their results in
    submission order.

    A barrier holds every worker until all of them — plus the calling thread —
    have arrived, so the jobs are released together and actually race. Pass an
    `executor` to reuse one pool across many calls (e.g. a fuzz loop); when it is
    None a right-sized pool is created and torn down for this single call.
    """
    jobs = list(jobs)
    barrier = Barrier(len(jobs) + 1)

    def run(job):
        barrier.wait(timeout=release_timeout)
        return job()

    def submit(pool):
        futures = [pool.submit(run, job) for job in jobs]
        barrier.wait(timeout=release_timeout)
        return [future.result(timeout=result_timeout) for future in futures]

    if executor is not None:
        return submit(executor)
    with ThreadPoolExecutor(max_workers=len(jobs)) as owned:
        return submit(owned)
