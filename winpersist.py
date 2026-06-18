#!/usr/bin/env python3
"""WinPersist Hunter — one-shot Windows persistence mechanism hunter.

Scans common persistence locations, scores findings with a risk model,
maps them to MITRE ATT&CK, and produces JSON + HTML reports. Each invocation
is a single, stateless scan — there is no daemon, watcher, or stored baseline.
"""
import argparse
import os
import socket
import sys
from datetime import datetime, timezone

from hunter import __version__
from hunter.scoring import score_detection
from hunter.correlate import annotate_clusters
from hunter.reporter.json_reporter import write_json
from hunter.reporter.html_reporter import write_html

from hunter.modules.run_keys import RunKeysHunter
from hunter.modules.scheduled_tasks import ScheduledTasksHunter
from hunter.modules.services import ServicesHunter
from hunter.modules.wmi_subs import WMISubscriptionHunter
from hunter.modules.startup_folders import StartupFoldersHunter
from hunter.modules.ifeo import IFEOHunter
from hunter.modules.winlogon import WinlogonHunter
from hunter.modules.appinit import AppInitLSAHunter
from hunter.modules.com_hijack import COMHijackHunter
from hunter.modules.browser_extensions import BrowserExtensionsHunter
from hunter.modules.office_persistence import OfficePersistenceHunter
from hunter.modules.active_setup import ActiveSetupHunter
from hunter.modules.screensaver import ScreensaverHunter
from hunter.modules.netsh_helper import NetshHelperHunter
from hunter.modules.bits_jobs import BITSJobsHunter
from hunter.modules.time_providers import TimeProvidersHunter
from hunter.modules.print_monitors import PrintMonitorsHunter
from hunter.modules.drivers import DriversHunter
from hunter.modules.shim_database import ShimDatabaseHunter
from hunter.modules.boot_execute import BootExecuteHunter
from hunter.modules.profile_list import ProfileListHunter
from hunter.modules.appx_packages import AppxPackagesHunter

ALL_MODULES = {
    "run_keys": RunKeysHunter,
    "scheduled_tasks": ScheduledTasksHunter,
    "services": ServicesHunter,
    "wmi_subs": WMISubscriptionHunter,
    "startup_folders": StartupFoldersHunter,
    "ifeo": IFEOHunter,
    "winlogon": WinlogonHunter,
    "appinit_lsa": AppInitLSAHunter,
    "com_hijack": COMHijackHunter,
    "browser_extensions": BrowserExtensionsHunter,
    "office_persistence": OfficePersistenceHunter,
    "active_setup": ActiveSetupHunter,
    "screensaver": ScreensaverHunter,
    "netsh_helper": NetshHelperHunter,
    "bits_jobs": BITSJobsHunter,
    "time_providers": TimeProvidersHunter,
    "print_monitors": PrintMonitorsHunter,
    "drivers": DriversHunter,
    "shim_database": ShimDatabaseHunter,
    "boot_execute": BootExecuteHunter,
    "profile_list": ProfileListHunter,
    "appx_packages": AppxPackagesHunter,
}

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def banner():
    return (
        f"\n  WinPersist Hunter v{__version__}\n"
        f"  One-shot Windows persistence hunter\n"
        f"  ---------------------------------------\n"
    )


def parse_args():
    p = argparse.ArgumentParser(description="Hunt Windows persistence mechanisms.")
    p.add_argument("-m", "--modules", default="all",
                   help=f"Comma-separated list of modules or 'all'. Available: {', '.join(ALL_MODULES)}")
    p.add_argument("-o", "--output-dir", default="output", help="Output directory.")
    p.add_argument("--min-severity", default="info",
                   choices=list(SEVERITY_ORDER), help="Minimum severity to report.")
    p.add_argument("--no-html", action="store_true", help="Skip HTML report.")
    p.add_argument("--no-json", action="store_true", help="Skip JSON report.")
    p.add_argument("--quiet", action="store_true", help="Suppress per-finding console output.")
    p.add_argument("--list-modules", action="store_true", help="List available modules and exit.")
    p.add_argument("--offline-feed", action="store_true",
                   help="Skip live download of loldrivers feed (use cached copy if present).")
    p.add_argument("--hash-drivers", action="store_true",
                   help="Hash every driver, even when BYOVD feed is unavailable.")
    return p.parse_args()


def _instantiate(name, args):
    cls = ALL_MODULES[name]
    if name == "drivers":
        return cls(offline_feed=args.offline_feed, hash_all=args.hash_drivers)
    return cls()


def run_modules(selected, args):
    detections = []
    for mname in selected:
        cls = ALL_MODULES[mname]
        print(f"[*] Running {mname} ({cls.technique_id})...")
        try:
            mod = _instantiate(mname, args)
            results = mod.run() or []
        except Exception as e:
            print(f"[!] {mname} failed: {e}")
            continue
        print(f"    -> {len(results)} raw finding(s)")
        detections.extend(results)
    return detections


def main():
    args = parse_args()
    if args.list_modules:
        for name, cls in ALL_MODULES.items():
            print(f"  {name:22s} {cls.technique_id:12s} {cls.technique_name}")
        return 0

    if os.name != "nt":
        print("[!] WinPersist Hunter is designed for Windows.", file=sys.stderr)
        return 2

    print(banner())
    if args.modules == "all":
        selected = list(ALL_MODULES.keys())
    else:
        selected = [m.strip() for m in args.modules.split(",") if m.strip()]
        for m in selected:
            if m not in ALL_MODULES:
                print(f"[!] Unknown module: {m}", file=sys.stderr)
                return 2

    raw = run_modules(selected, args)
    raw = annotate_clusters(raw)
    detections = [score_detection(d) for d in raw]

    min_rank = SEVERITY_ORDER[args.min_severity]
    detections = [d for d in detections if SEVERITY_ORDER[d.severity] >= min_rank]
    detections.sort(key=lambda d: (-d.score, d.module))

    if not args.quiet:
        print("\n=== Findings ===")
        for d in detections:
            print(f"[{d.severity.upper():8s}] {d.score:3d}  {d.technique_id:12s}  {d.module}")
            if d.artifact:
                print(f"             artifact   : {d.artifact}")
            if d.description:
                print(f"             description: {d.description}")
            print(f"             location   : {d.location}")
            print(f"             name       : {d.name}")
            if d.value:
                v = d.value if len(d.value) < 200 else d.value[:197] + "..."
                print(f"             value      : {v}")
            for r in d.reasons:
                print(f"             - {r}")
            print()

    os.makedirs(args.output_dir, exist_ok=True)
    now = datetime.now(timezone.utc)
    ts = now.strftime("%Y%m%dT%H%M%SZ")
    meta = {
        "scan_time": now.isoformat(),
        "hostname": socket.gethostname(),
        "modules": selected,
        "tool_version": __version__,
        "min_severity": args.min_severity,
    }
    if not args.no_json:
        jp = os.path.join(args.output_dir, f"report-{ts}.json")
        write_json(jp, detections, meta)
        print(f"[+] JSON report: {jp}")
    if not args.no_html:
        hp = os.path.join(args.output_dir, f"report-{ts}.html")
        write_html(hp, detections, meta)
        print(f"[+] HTML report: {hp}")

    print(f"\n[+] Total findings: {len(detections)}")
    counts = {}
    for d in detections:
        counts[d.severity] = counts.get(d.severity, 0) + 1
    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev in counts:
            print(f"    {sev:8s} : {counts[sev]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
