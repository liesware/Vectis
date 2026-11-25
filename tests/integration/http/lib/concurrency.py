
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier


def run_simultaneously(jobs, executor=None, release_timeout=10, result_timeout=20):
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
