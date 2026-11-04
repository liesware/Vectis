"""Request ZAP's native SARIF report before the packaged scan shuts down."""

from pathlib import Path


def zap_pre_shutdown(zap):
    zap.reports.generate(
        title="Vectis API scan",
        template="sarif-json",
        reportfilename="report.sarif.json",
        reportdir="/zap/wrk",
        display=False,
    )
    Path("/zap/wrk/report.sarif.json").replace("/zap/wrk/report.sarif")
