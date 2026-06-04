#!/usr/bin/env python3
"""Pin-only entrypoint for the pure-protocol GoPay flow.

Target UX:

    python3 android_gopay_2.10.0/protocol/pure_pin_only.py --pin 736294

Everything else is intentionally defaulted:
- buy an Indonesia SMSCloud number
- poll OTP automatically
- generate a fresh protocol device tuple
- register/login
- refresh the signup token into a normal goto-auth session
- run the PIN OTP challenge and submit the new PIN
- verify the post-PIN profile state when the profile endpoint exposes it

Current status: this wrapper defaults to the recovered pure-Python enhanced
X-E1 signer and does not need adb / Frida / the app at runtime.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from full_pure_signup_pin import KEY_DEFAULT, NumberAlreadyRegistered, run  # noqa: E402
from gopay_protocol import SIGNUP_CLIENT_NAME, SIGNUP_CLIENT_SECRET  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="Pin-only pure protocol signup/login/set-PIN runner")
    ap.add_argument("--pin", required=True, help="new GoPay PIN, e.g. 736294")
    ap.add_argument("--out", help="state json path")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="only build first request")
    ap.add_argument("--skip-waf-preflight", action="store_true", help="skip historical /cvs/v1/initiate WAF probe before buying SMS")
    ap.add_argument("--attempts", type=int, default=8, help="retry with a fresh SMSCloud number if it is recycled, rate-limited, or no OTP arrives")
    ap.add_argument("--otp-timeout", type=int, default=240, help="seconds to wait per SMSCloud number")
    ap.add_argument("--sms-key", default=os.getenv("SMSCLOUD_KEY", KEY_DEFAULT))
    ap.add_argument(
        "--xe-mode",
        choices=["none", "captured", "adb-oracle", "pure", "enhanced"],
        default=os.getenv("GOPAY_XE_MODE", "enhanced"),
        help="X-E1 signer mode; default enhanced is adb-free pure Python",
    )
    ap.add_argument("--xe-resolution-key", default=os.getenv("GOPAY_XE_RESOLUTION_KEY"))
    ap.add_argument("--xe-random-hex", default=os.getenv("GOPAY_XE_RANDOM_HEX"))
    ap.add_argument(
        "--device-from-capture",
        default=None,
        help="diagnostic only; do not use for new accounts once pure signer is complete",
    )
    args = ap.parse_args()

    if not args.dry_run and not args.skip_waf_preflight:
        probe_out = HERE / "runs" / f"probe_initiate_waf_pre_pin_{time.strftime('%Y%m%d_%H%M%S')}.json"
        p = subprocess.run(
            [sys.executable, str(HERE / "probe_initiate_waf.py"), "--out", str(probe_out)],
            cwd=str(HERE.parent.parent),
            text=True,
            capture_output=True,
            timeout=90,
        )
        if p.returncode != 0:
            print(p.stdout, end="")
            print(p.stderr, end="", file=sys.stderr)
            return p.returncode
        try:
            probe = json.loads(probe_out.read_text(encoding="utf-8"))
            waf_hits = [r for r in probe.get("results", []) if r.get("is_waf_html_403")]
            if waf_hits and len(waf_hits) == len(probe.get("results", [])):
                print(f"[WAF-PREFLIGHT] /cvs/v1/initiate 仍是 Tencent WAF HTML 403，已在买号前停止: {probe_out}")
                return 7
        except Exception as e:
            print(f"[WAF-PREFLIGHT] parse failed, continue anyway: {e}")

    last_exc: Exception | None = None
    attempts = 1 if args.dry_run else max(1, args.attempts)
    for i in range(attempts):
        # Build an argparse-like object for the existing complete runner.  This
        # keeps one implementation of the protocol state machine.
        out = args.out
        if not out and attempts > 1:
            out = str(HERE / "runs" / f"pure_pin_only_attempt{i + 1}_{time.strftime('%Y%m%d_%H%M%S')}.json")
        ns = argparse.Namespace(
            phone="6281234567890" if args.dry_run else None,
            buy=False if args.dry_run else True,
            sms_key=args.sms_key,
            sms_service="ni",
            sms_country=6,
            sms_max_price="2.25",
            sms_order_id=None,
            otp=None,
            otp_timeout=args.otp_timeout,
            otp_interval=5,
            finish_sms_order=True,
            pin=args.pin,
            initiate_default_first=os.getenv("GOPAY_INITIATE_DEFAULT_FIRST", "") == "1",
            tokenized_pin=None,
            pin_tokenizer="aes-ecb",
            pin_tokenizer_cmd=None,
            signup_name="TestUser",
            signup_client_name=os.getenv("GOPAY_SIGNUP_CLIENT_NAME", SIGNUP_CLIENT_NAME),
            signup_client_secret=os.getenv("GOPAY_SIGNUP_CLIENT_SECRET", SIGNUP_CLIENT_SECRET),
            signup_basic=os.getenv("GOPAY_SIGNUP_BASIC"),
            signed_up_country=os.getenv("GOPAY_SIGNED_UP_COUNTRY", "62"),
            signup_waf_retries=int(os.getenv("GOPAY_SIGNUP_WAF_RETRIES", "3")),
            signup_waf_sleep=float(os.getenv("GOPAY_SIGNUP_WAF_SLEEP", "2.0")),
            skip_customer_signup=False,
            login_otp=None,
            login_otp_timeout=240,
            pin_otp=None,
            pin_otp_timeout=240,
            flow="signup",
            device_id=None,
            x_m1=None,
            device_from_capture=args.device_from_capture,
            xe_mode=args.xe_mode,
            capture_json=str(HERE.parent / "runtime_now" / "full_signup_pin_capture_20260529_200358.artifacts.json"),
            adb="./adb/adb",
            oracle_dex="/data/local/tmp/oracle.dex",
            libbattery="/data/local/tmp/libbatteryOpt.so",
            liboracle="/data/local/tmp/liboracle.so",
            verify_signer_against_capture=None,
            xe_resolution_key=args.xe_resolution_key,
            xe_random_hex=args.xe_random_hex,
            selftest_only=False,
            dry_run=args.dry_run,
            quiet=args.quiet,
            out=out,
        )
        try:
            return run(ns)
        except TimeoutError as e:
            last_exc = e
            print(f"[attempt {i + 1}/{attempts}] OTP timeout，换号重试: {e}")
            if args.out:
                break
        except NumberAlreadyRegistered as e:
            last_exc = e
            print(f"[attempt {i + 1}/{attempts}] 号码已注册/回收号，换号重试: {e}")
            if args.out:
                break
        except RuntimeError as e:
            msg = str(e)
            if "ratelimit" in msg.lower() or "ratelimited" in msg.lower() or "429" in msg:
                last_exc = e
                print(f"[attempt {i + 1}/{attempts}] 服务端限流，换号/设备重试: {e}")
                if args.out:
                    break
                continue
            raise
    if last_exc:
        raise last_exc
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
