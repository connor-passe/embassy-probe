#!/usr/bin/env python3
"""Run the external exposure scan on a GitHub-hosted runner and sign the result.

`docs/tasks/T027-external-exposure-scanner.md`. Invoked only by
`.github/workflows/external-scan.yml`.

**Standard library only, and it imports nothing from this repository.** It runs on
a cloud runner that holds the house's WAN addresses in its environment; the less
code that executes there, the smaller the surface that can mishandle them. The
Pi-side parser, the control gate and the state machine live in
`backend/src/embassy_secdash/exposure/` and are exercised by the unit suite.

THE THREE THINGS THIS SCRIPT MUST GET RIGHT
---------------------------------------------
1. **The positive control runs every time, over the same egress.** A scan of
   `scanme.nmap.org` — sanctioned by the Nmap project for exactly this, and the
   only third-party host this task may touch. Its open-port count is what makes a
   "filtered" verdict mean anything, and it is recorded per run.
2. **No address leaves this job.** Every occurrence of every `WAN_*` secret is
   replaced with its sha256 hex before anything is written, and the result is
   then RE-CHECKED for the literal. A hit aborts the run. GitHub masks secrets in
   logs, but masking is a backstop, not a design.
3. **A failure is reported, never smoothed over.** No egress, no IPv6 route, a
   timeout, a missing secret — each produces an explicit error string in the
   control block, which the Pi turns into `ok=0` and a named reason. There is no
   code path here that converts "we could not tell" into "nothing was open".
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

#: The house's own reserved block plus every port T027's environment table says
#: must never answer from outside.
V6_PORTS = "22,53,80,443,445,514,1883,5060,8000,8123,8443,8500,8600-8619,9222,9333,9337,9338,9999"

CONTROL_HOST = "scanme.nmap.org"

#: 22 and 80 are open on the control host by design. 25847 is a high port that is
#: NOT open on it — it is the negative half of the control, and it is what catches
#: the opposite failure: a transparent proxy or captive portal that answers every
#: SYN reads as "everything is open", which would manufacture `exposure.port_open`
#: for the whole house. A control with only open ports cannot see that.
CONTROL_PORTS = "22,80,25847"
CONTROL_PORT_COUNT = 3
CONTROL_EXPECTED_OPEN = 2

#: `MAX_BODY_BYTES` in `backend/src/embassy_secdash/exposure/wire.py`, minus room
#: for the JSON wrapper. Exceeding it is a hard failure rather than a silent trim:
#: a truncated result is a result nobody can audit.
MAX_BODY_BYTES = 240 * 1024

SCAN_TIMEOUT_S = 900


def die(message: str) -> None:
    """Fail the job loudly, at the top of the log, with no partial output."""
    print(f"::error::{message}", file=sys.stderr)
    sys.exit(1)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


#: Anything shaped like an address, in ANY textual form nmap might choose. Applied
#: to diagnostic text on top of the exact-literal redaction below, because
#: `redact()` can only replace the EXACT bytes of the secret and nmap does not
#: promise to echo a target back the way it was handed one: it re-prints IPv6 in
#: its own compressed form, and it prints the resolved address of a name. A public
#: job log gets whichever form nmap chose, so the literal substitution alone is not
#: a control — it is one of two.
_ADDR_SHAPED = re.compile(
    r"(?:(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?)"  # IPv4, optionally with a prefix length
    r"|(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:/\d{1,3})?"  # IPv6, incl. `::` forms
)


def scrub(text: str, secrets_to_hash: dict[str, str]) -> str:
    """Make one line of DIAGNOSTIC text safe to print into a public job log.

    Two independent controls, in this order:

    1. `redact()` — exact secret literals become their sha256, so a reader can
       still correlate a message with the target it belongs to.
    2. `_ADDR_SHAPED` — every remaining address-shaped token becomes `<addr>`.

    Step 2 exists because step 1 is not sufficient on its own. `WAN_IPV6_TARGETS`
    is a MULTI-LINE secret, and GitHub masks multi-line secrets by whole value,
    not by line: a single GUA printed on its own is not masked. nmap also
    re-prints IPv6 in its own compressed form and prints resolved addresses of
    names, neither of which matches the literal that was handed in. Before this
    function existed, `run_nmap` returned raw `completed.stderr` and both callers
    printed it with `::warning::` — so any scan failure published the target
    address into the log. That is survivable in a private repository and is a
    disclosure in a public one, which is precisely the vantage T027 needs.
    """
    return _ADDR_SHAPED.sub("<addr>", redact(text, secrets_to_hash))


def run_nmap(args: list[str], secrets_to_hash: dict[str, str]) -> tuple[str | None, str | None]:
    """`(xml, error)`. Exactly one is not None. **Never raises.**

    An nmap that exits non-zero, times out, or writes nothing is an ERROR, not an
    empty result. The distinction is the whole task: an empty result would read
    as "nothing is open".

    The error string is scrubbed HERE, at the only place raw subprocess output is
    read, rather than at each caller. A caller that forgets is the failure mode,
    and there is no unscrubbed value in scope for one to forget about.
    """
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "scan.xml"
        try:
            completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
                [*args, "-oX", str(out)],
                capture_output=True,
                text=True,
                timeout=SCAN_TIMEOUT_S,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return None, f"nmap timed out after {SCAN_TIMEOUT_S}s"
        except OSError as exc:
            return None, scrub(f"nmap could not be executed: {exc}", secrets_to_hash)
        if not out.exists() or out.stat().st_size == 0:
            return None, scrub(
                f"nmap produced no XML (exit {completed.returncode}): {completed.stderr[:200]}",
                secrets_to_hash,
            )
        xml = out.read_text(encoding="utf-8", errors="replace")
    return xml, None


def count_open(xml: str) -> int | None:
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return None
    return sum(
        1
        for port in root.iter("port")
        for state in port.findall("state")
        if state.get("state") == "open"
    )


def redact(text: str, secrets_to_hash: dict[str, str]) -> str:
    """Substitute every secret literal for its hash, longest first.

    Longest first so that a `/64` prefix does not partially eat a full GUA and
    leave a recognisable tail behind.
    """
    out = text
    for literal in sorted(secrets_to_hash, key=len, reverse=True):
        out = out.replace(literal, secrets_to_hash[literal])
    return out


def split_targets(raw: str) -> list[str]:
    return [t.strip() for t in re.split(r"[,\s]+", raw) if t.strip()]


def control_block(
    family: int, extra_args: list[str], secrets_to_hash: dict[str, str]
) -> dict[str, object]:
    xml, error = run_nmap(
        ["nmap", *extra_args, "-Pn", "-sT", "-p", CONTROL_PORTS, CONTROL_HOST], secrets_to_hash
    )
    if error is not None:
        # THE MOST IMPORTANT BRANCH ON THE RUNNER. GitHub-hosted runners have
        # historically had no IPv6 egress; `nmap -6` fails outright and this is
        # the line that stops that becoming "IPv6 inbound: FILTERED".
        print(f"control v{family}: FAILED — {error}")
        return {"open_ports": None, "error": error, "ports_probed": CONTROL_PORT_COUNT}
    opened = count_open(xml or "")
    print(
        f"control v{family}: {opened} open of {CONTROL_PORT_COUNT} probed on {CONTROL_HOST} "
        f"(expected {CONTROL_EXPECTED_OPEN})"
    )
    return {
        "open_ports": opened,
        "error": None if opened is not None else "control XML did not parse",
        "ports_probed": CONTROL_PORT_COUNT,
        # Every probed port answering — including the one that must not — is the
        # interception case, and it fails in the ALARMING direction if ignored.
        "all_open_suspected": opened == CONTROL_PORT_COUNT,
    }


def main() -> int:
    # --- secrets, by name, checked before anything runs -------------------
    missing = [
        name
        for name in ("WAN_IPV4", "WAN_IPV6_TARGETS", "SCAN_INGEST_TOKEN")
        if not os.environ.get(name)
    ]
    if missing:
        die(
            "missing required repository secret(s): "
            + ", ".join(missing)
            + ". See docs/artifacts/T027-transport-decision.md for exactly what each one is "
            "and how to create it. This job does not run with a placeholder."
        )

    wan_v4 = os.environ["WAN_IPV4"].strip()
    v6_targets = split_targets(os.environ["WAN_IPV6_TARGETS"])
    key = os.environ["SCAN_INGEST_TOKEN"]
    if not v6_targets:
        die("WAN_IPV6_TARGETS is set but empty after parsing; nothing to scan")

    hashes = {wan_v4: sha256_hex(wan_v4)}
    for target in v6_targets:
        hashes[target] = sha256_hex(target)

    scan_ts = int(time.time())
    targets: list[dict[str, object]] = []

    # --- the positive control, FIRST, over the same egress ---------------
    control = {"4": control_block(4, [], hashes), "6": control_block(6, ["-6"], hashes)}

    # --- IPv4: SYN scan of the top 1000, open ports only -----------------
    v4_xml, v4_error = run_nmap(
        ["sudo", "nmap", "-Pn", "-sS", "--top-ports", "1000", "--open", wan_v4], hashes
    )
    if v4_error is not None:
        print(f"::warning::IPv4 scan failed: {v4_error}")
        control["4"] = {**control["4"], "error": v4_error}
    else:
        targets.append(
            {
                "target": "wan_ipv4",
                "family": 4,
                "target_value_hash": hashes[wan_v4],
                "nmap_xml": redact(v4_xml or "", hashes),
            }
        )

    # --- IPv6: connect scan of the named ports, per monitored GUA --------
    for target in v6_targets:
        xml, error = run_nmap(["nmap", "-6", "-Pn", "-sT", "-p", V6_PORTS, target], hashes)
        if error is not None:
            print(f"::warning::IPv6 scan of one target failed: {error}")
            continue
        targets.append(
            {
                "target": "wan_ipv6",
                "family": 6,
                "target_value_hash": hashes[target],
                "nmap_xml": redact(xml or "", hashes),
            }
        )

    envelope = {
        "schema_version": 1,
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "run_url": (
            f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/"
            f"{os.environ.get('GITHUB_REPOSITORY', '')}/actions/runs/"
            f"{os.environ.get('GITHUB_RUN_ID', '')}"
        ),
        # Set by the runner, not by this script. It is the claim the Pi asserts
        # against the protected default branch.
        "workflow_ref": os.environ.get("GITHUB_WORKFLOW_REF", ""),
        "scan_ts": scan_ts,
        "nonce": secrets.token_hex(16),
        "scanner": "github_actions",
        "control": control,
        "targets": targets,
    }

    body = json.dumps(envelope, sort_keys=True, separators=(",", ":"))

    # --- the redaction's own positive control ----------------------------
    for literal in hashes:
        if literal and literal in body:
            die(
                "REDACTION FAILED: a WAN address literal survived into the signed body. "
                "Nothing was published. This is a bug in redact(), not a scan result."
            )
    if len(body.encode("utf-8")) > MAX_BODY_BYTES:
        die(
            f"signed body is {len(body.encode('utf-8'))} bytes, over the {MAX_BODY_BYTES} cap. "
            "Nothing was published — a truncated result is one nobody can audit."
        )

    digest = hmac.new(key.encode("utf-8"), body.encode("utf-8"), "sha256").hexdigest()
    signature = f"sha256={digest}"
    wrapper = {
        "run_id": envelope["run_id"],
        "workflow_ref": envelope["workflow_ref"],
        "timestamp": scan_ts,
        "signature": signature,
        # The EXACT bytes that were signed, as a string. The poller forwards
        # `body.encode("utf-8")` unmodified; re-serialising would invalidate the
        # signature, which is the property that makes the transport untrusted-safe.
        "body": body,
    }

    out = Path(sys.argv[1] if len(sys.argv) > 1 else "latest.json")
    out.write_text(json.dumps(wrapper, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"published {out} — {len(targets)} target result(s), "
        f"control v4={control['4'].get('open_ports')} v6={control['6'].get('open_ports')}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
