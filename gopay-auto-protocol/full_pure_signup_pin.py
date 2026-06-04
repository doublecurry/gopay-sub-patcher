#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
import time
from typing import Any, Dict, Optional

from gopay_protocol import (
    AdbOracleSigner,
    CapturedSigner,
    DeviceProfile,
    EnhancedPythonXESigner,
    GoPayProtocol,
    NullSigner,
    PurePythonXESigner,
    AUTH_SECRET,
    SIGNUP_BASIC_SUFFIX,
    SIGNUP_CLIENT_NAME,
    SIGNUP_CLIENT_SECRET,
    SIGNUP_XOR_SECRET_CANDIDATE,
    extract_path,
    minjson,
    normalize_id_phone,
    pick_first,
    tokenize_pin_aes_ecb,
)
from smscloud_client import SmsCloud
# https://smscloud.sbs/sms  接码平台
KEY_DEFAULT = "改成你自己的"


class NumberAlreadyRegistered(RuntimeError):
    pass


def jdump(x: Any) -> str:
    return json.dumps(x, ensure_ascii=False, indent=2)


def save_state(path: pathlib.Path, state: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(jdump(state), encoding="utf-8")
    tmp.replace(path)


def make_signer(args: argparse.Namespace):
    if args.xe_mode == "none":
        return NullSigner()
    if args.xe_mode == "captured":
        if not args.capture_json:
            raise SystemExit("--xe-mode captured 需要 --capture-json")
        return CapturedSigner(args.capture_json)
    if args.xe_mode == "adb-oracle":
        return AdbOracleSigner(adb=args.adb, oracle_dex=args.oracle_dex, libbattery=args.libbattery, liboracle=args.liboracle)
    if args.xe_mode == "pure":
        return PurePythonXESigner(random_hex=args.xe_random_hex) if not args.xe_resolution_key else PurePythonXESigner(resolution_key=args.xe_resolution_key, random_hex=args.xe_random_hex)
    if args.xe_mode == "enhanced":
        return EnhancedPythonXESigner(random_hex=args.xe_random_hex) if not args.xe_resolution_key else EnhancedPythonXESigner(resolution_key=args.xe_resolution_key, random_hex=args.xe_random_hex)
    raise SystemExit(f"unknown xe mode {args.xe_mode}")


def maybe_tokenize_pin(args: argparse.Namespace, pin_token: str) -> str:
    if args.tokenized_pin:
        return args.tokenized_pin
    if args.pin_tokenizer_cmd:
        import subprocess

        env = os.environ.copy()
        env.update({"GOPAY_PIN": args.pin, "GOPAY_PIN_TOKEN": pin_token})
        p = subprocess.run(args.pin_tokenizer_cmd, shell=True, text=True, capture_output=True, env=env, timeout=30)
        if p.returncode != 0:
            raise RuntimeError(f"pin tokenizer failed rc={p.returncode}\nSTDOUT={p.stdout}\nSTDERR={p.stderr}")
        return p.stdout.strip().splitlines()[-1]
    if args.pin_tokenizer == "aes-ecb":
        return tokenize_pin_aes_ecb(args.pin, pin_token)
    raise RuntimeError("缺少 tokenized PIN：传 --tokenized-pin，或用 --pin-tokenizer-cmd 接一个已逆出的 tokenizePin")


def require_success(step: str, status: int, data: Any, allow: tuple[int, ...] = (200, 201, 202)) -> None:
    if status not in allow:
        raise RuntimeError(f"{step} failed: HTTP {status}\n{jdump(data)}")
    if isinstance(data, dict) and data.get("success") is False:
        raise RuntimeError(f"{step} app-error:\n{jdump(data)}")


def has_error_code(data: Any, code: str) -> bool:
    if isinstance(data, dict):
        errs = data.get("errors")
        if isinstance(errs, list):
            return any(isinstance(e, dict) and e.get("code") == code for e in errs)
        return any(has_error_code(v, code) for v in data.values())
    if isinstance(data, list):
        return any(has_error_code(v, code) for v in data)
    return False


def is_success_response(status: int, data: Any, allow: tuple[int, ...] = (200, 201, 202)) -> bool:
    if status not in allow:
        return False
    if isinstance(data, dict) and data.get("success") is False:
        return False
    return True


def is_waf_html(status: int, data: Any) -> bool:
    raw = data.get("raw", "") if isinstance(data, dict) else ""
    return status == 403 and isinstance(raw, str) and ("WAF Block Page" in raw or "Tencent Cloud WAF" in raw)


def is_phone_registered_error(data: Any) -> bool:
    text = json.dumps(data, ensure_ascii=False, default=str) if not isinstance(data, str) else data
    return "CO:CUST:phone_already_taken" in text or "Nomor HP-mu sudah terdaftar" in text


def poll_sms_code(
    sms: SmsCloud,
    order_id: str,
    *,
    timeout: int,
    interval: int,
    previous_code: str = "",
) -> tuple[str, Any]:
    """Poll SMSCloud and ignore the previous OTP when a second OTP is needed."""
    deadline = time.time() + timeout
    last_code = previous_code
    last_raw = None
    while time.time() < deadline:
        try:
            code, raw = sms.poll_code(order_id, timeout=min(interval, max(1, int(deadline - time.time()))), interval=interval)
        except TimeoutError:
            continue
        last_raw = raw
        if not previous_code or code != previous_code:
            return code, raw
        last_code = code
        time.sleep(interval)
    raise TimeoutError(f"no new sms code for {order_id}; previous={previous_code!r}; last_code={last_code!r}; last={last_raw!r}")


def extract_account_id(data: Any) -> Optional[str]:
    """Prefer numeric GoTo/GoPay account ids from accountlist-like JSON."""
    candidates = []

    def walk(x: Any, path: str = "") -> None:
        if isinstance(x, dict):
            for k, v in x.items():
                lk = k.lower()
                if lk in {"account_id", "accountid", "customer_id", "userid", "user_id", "id"}:
                    if isinstance(v, (str, int)) and re.fullmatch(r"\d{5,20}", str(v)):
                        candidates.append((0 if "account" in lk else 1, path + "/" + k, str(v)))
                walk(v, path + "/" + k)
        elif isinstance(x, list):
            for i, v in enumerate(x):
                walk(v, f"{path}[{i}]")

    walk(data)
    if not candidates:
        return None
    candidates.sort(key=lambda t: (t[0], len(t[1])))
    return candidates[0][2]


def run(args: argparse.Namespace) -> int:
    out = pathlib.Path(args.out or f"android_gopay_2.10.0/protocol/runs/pure_signup_pin_{time.strftime('%Y%m%d_%H%M%S')}.json")
    state: Dict[str, Any] = {"args": vars(args), "steps": []}

    sms: Optional[SmsCloud] = None
    order: Optional[Dict[str, Any]] = None
    if args.buy:
        sms = SmsCloud(args.sms_key)
        print("[smscloud] balance", sms.balance())
        order = sms.buy(service=args.sms_service, country=args.sms_country, max_price=args.sms_max_price)
        print("[smscloud] order", jdump(order))
        state["sms_order"] = order
        phone = str(order.get("phoneNumber") or order.get("phone") or "")
    elif getattr(args, "sms_order_id", None):
        if not args.phone:
            raise SystemExit("--sms-order-id 需要同时传 --phone")
        sms = SmsCloud(args.sms_key)
        order = {"id": str(args.sms_order_id), "phoneNumber": args.phone, "reused": True}
        print("[smscloud] reuse order", jdump(order))
        state["sms_order"] = order
        phone = args.phone
    elif args.phone:
        phone = args.phone
    else:
        raise SystemExit("--buy 或 --phone 必选")

    country_code, local = normalize_id_phone(phone)
    print(f"[phone] acquired input={phone} normalized={country_code}{local}")
    state["phone"] = {"input": phone, "country_code": country_code, "local": local}

    if args.device_from_capture:
        device = DeviceProfile.from_capture(args.device_from_capture)
    else:
        device = DeviceProfile.default(unique_id=args.device_id, x_m1=args.x_m1)
    state["device"] = device.__dict__

    signer = make_signer(args)
    gp = GoPayProtocol(device=device, signer=signer, debug=not args.quiet, dry_run=args.dry_run)
    save_state(out, state)
    try:
        # 0. Optional local signer sanity check against a captured artifact.
        if args.verify_signer_against_capture:
            rows = json.loads(pathlib.Path(args.verify_signer_against_capture).read_text(encoding="utf-8"))
            row = rows[0] if isinstance(rows, list) else (rows.get("items") or rows.get("artifacts"))[0]
            host, path = row["host_path"].split("/", 1)
            path = "/" + path
            h = gp.headers()
            h.update(
                {
                    "x-uniqueid": row["x_uniqueid"],
                    "x-m1": row["x_m1"],
                    "x-e2": row["x_e2"],
                    "x-phonemodel": row["phone_model"],
                    "x-deviceos": row["device_os"],
                    "x-appid": row["app_id"],
                    "x-appversion": row["app_version"],
                }
            )
            old_random = getattr(signer, "random_hex", None)
            if old_random is None and row.get("x_e1"):
                parts = str(row["x_e1"]).split(":")
                if len(parts) >= 4 and re.fullmatch(r"[0-9a-fA-F]{160}", parts[1]):
                    setattr(signer, "random_hex", parts[1])
            got = signer.sign(row["method"], host, path, row["body_text"], h, ts=int(row["ts"]))
            if hasattr(signer, "random_hex"):
                setattr(signer, "random_hex", old_random)
            state["signer_selftest"] = {"expected": row["x_e1"], "got": got, "match": got == row["x_e1"]}
            print("[signer-selftest]", "MATCH" if got == row["x_e1"] else "MISMATCH")
            save_state(out, state)
            if args.selftest_only:
                return 0 if got == row["x_e1"] else 3

        # 1. login/methods is the app's first probe. For a fresh signup the
        # server returns auth:error:user:not_found; the app then proceeds to
        # cvs/v1/methods with flow=signup.
        sc, data, headers = gp.login_methods(local, country_code)
        state["steps"].append({"name": "login_methods", "status": sc, "data": data, "headers": headers})
        save_state(out, state)
        if args.dry_run:
            print("[DRY-RUN] 首包已生成，未继续依赖服务端响应")
            return 0
        if args.flow == "signup" and has_error_code(data, "auth:error:user:not_found"):
            print("[+] fresh signup: login_methods returned user:not_found; switching to cvs_methods signup")
            sc, data, headers = gp.cvs_methods(local, flow=args.flow, country_code=country_code)
            state["steps"].append({"name": "cvs_methods", "status": sc, "data": data, "headers": headers})
            save_state(out, state)
        elif args.flow == "signup" and sc in (200, 201, 202):
            raise NumberAlreadyRegistered(f"NUMBER_ALREADY_REGISTERED: login_methods returned HTTP {sc} for +62{local}; data={jdump(data)[:500]}")
        else:
            require_success("login_methods", sc, data)
        require_success("cvs_methods/login_methods", sc, data)
        verification_id = pick_first(data, ["verification_id", "challenge_id"])
        default_method = str(pick_first(data, ["default_method"]) or "otp_sms")
        method = default_method
        methods = pick_first(data, ["methods"])
        if isinstance(methods, list) and "otp_sms" in methods:
            method = "otp_sms"
        if not verification_id:
            raise RuntimeError("login_methods 没拿到 verification_id/challenge_id")
        print("[+] verification_id", verification_id, "method", method)

        # 2. CVS initiate actually sends OTP for signup/login verification.
        # Runtime capture shows the app follows the server default method
        # (often otp_wa) first, then switches to otp_sms when the user chooses
        # SMS.  Keep that sequence: it avoids subtle server-side state where
        # the SMS request returns 200/otp_token but the downstream SMS route
        # never delivers to the rental number.
        if args.flow == "signup" and args.initiate_default_first and default_method != "otp_sms" and method == "otp_sms":
            print(f"[+] default method is {default_method}; initiating default first, then otp_sms")
            sc, data0, headers0 = gp.cvs_initiate(local, str(verification_id), method=str(default_method), flow=args.flow, country_code=country_code)
            state["steps"].append({"name": "cvs_initiate_default", "status": sc, "data": data0, "headers": headers0})
            save_state(out, state)
            require_success("cvs_initiate_default", sc, data0, allow=(200, 201, 202, 204))
        sc, data, headers = gp.cvs_initiate(local, str(verification_id), method=str(method), flow=args.flow, country_code=country_code)
        state["steps"].append({"name": "cvs_initiate", "status": sc, "data": data, "headers": headers})
        save_state(out, state)
        require_success("cvs_initiate", sc, data, allow=(200, 201, 202, 204))
        otp_token = pick_first(data, ["otp_token", "otpToken"])
        retry_timers = pick_first(data, ["retry_timer_in_seconds", "retryTimerInSeconds"])

        # 3. Obtain OTP.
        otp = args.otp
        if not otp:
            if not sms or not order:
                raise RuntimeError("需要 --otp，或使用 --buy 自动从 SMSCloud 轮询")
            # Poll in short windows and proactively hit `/cvs/v1/retry` using
            # the initiate otp_token.  Static AOT confirms retry is
            # {client_id, client_secret, flow, verification_method,
            #  data:{otp_token}}; it cannot replace initiate, but is useful
            # for SMSCloud routes that miss the first delivery.
            retry_after = retry_timers if isinstance(retry_timers, list) else [30, 60, 90]
            deadline = time.time() + args.otp_timeout
            raw_sms = None
            for attempt in range(len(retry_after) + 1):
                remaining = max(1, int(deadline - time.time()))
                if attempt < len(retry_after):
                    window = min(remaining, int(retry_after[attempt]) + 15)
                else:
                    window = remaining
                try:
                    otp, raw_sms = sms.poll_code(str(order["id"]), timeout=window, interval=args.otp_interval)
                    break
                except TimeoutError as e:
                    state.setdefault("otp_poll_timeouts", []).append({"attempt": attempt, "error": str(e)})
                    save_state(out, state)
                    if not otp_token or attempt >= len(retry_after) or time.time() >= deadline:
                        raise
                    print(f"[smscloud] no OTP yet; calling cvs_retry attempt={attempt + 1}")
                    sc, data_r, headers_r = gp.cvs_retry(str(otp_token), method=str(method), flow=args.flow)
                    state["steps"].append({"name": f"cvs_retry_{attempt + 1}", "status": sc, "data": data_r, "headers": headers_r})
                    save_state(out, state)
                    require_success(f"cvs_retry_{attempt + 1}", sc, data_r, allow=(200, 201, 202, 204))
            state["otp"] = {"code": otp, "raw": raw_sms}
            print("[smscloud] OTP", otp, raw_sms)
            save_state(out, state)

        # 4. Verify OTP. Prefer CVS verify; if server returns schema error the
        # captured state file preserves enough detail to mutate body safely.
        sc, data, headers = gp.cvs_verify(local, str(verification_id), str(otp), method=str(method), flow=args.flow, country_code=country_code, otp_token=str(otp_token) if otp_token else None)
        state["steps"].append({"name": "cvs_verify", "status": sc, "data": data, "headers": headers})
        save_state(out, state)
        require_success("cvs_verify", sc, data)

        verification_token = pick_first(data, ["verification_token", "verificationToken", "device_verification_token", "device_verification_token_id"])
        auth_code = pick_first(data, ["authorization_code", "auth_code", "code"])
        access_token = pick_first(data, ["access_token", "accessToken"])
        refresh_token = pick_first(data, ["refresh_token", "refreshToken"])
        print("[+] verify tokens", {"verification_token": bool(verification_token), "auth_code": bool(auth_code), "access_token": bool(access_token)})

        # 5. Runtime/AOT shows a post-CVS account resolver before token exchange:
        # /goto-auth/accountlist with Verification-Token: Bearer <1fa>.  The
        # token endpoint rejects phone-local account_id as invalid_1fa_token;
        # accountlist resolves the numeric account_id that /goto-auth/token
        # expects for existing/recycled accounts.
        account_id = None
        if verification_token and not access_token and args.flow != "signup":
            sc, data_acct, headers = gp.accountlist(str(verification_token))
            state["steps"].append({"name": "goto_auth_accountlist", "status": sc, "data": data_acct, "headers": headers})
            save_state(out, state)
            if sc in (200, 201, 202):
                account_id = extract_account_id(data_acct)
                print("[+] accountlist account_id", account_id)
                access_token = access_token or pick_first(data_acct, ["access_token", "accessToken"])
                refresh_token = refresh_token or pick_first(data_acct, ["refresh_token", "refreshToken"])
                auth_code = auth_code or pick_first(data_acct, ["authorization_code", "auth_code", "code"])
            else:
                print("[!] accountlist did not resolve account_id; will try signup/token fallback")
        elif verification_token and not access_token and args.flow == "signup":
            print("[+] signup flow: skip pre-signup accountlist; use verification_token directly for customer_signup")

        # 6. Some pure-signup branches require customer profile creation/name submit.
        signup_created_without_token = False
        if args.signup_name and verification_token and not access_token and not account_id and not args.skip_customer_signup:
            variants = [
                {
                    "label": "auth_id_authsecret_cc62_escaped",
                    "client_name": "gopay:consumer:app",
                    "client_secret": AUTH_SECRET,
                    "basic": SIGNUP_BASIC_SUFFIX,
                    "signed_up_country": "62",
                    "escape_client_name_colon": True,
                },
                {
                    "label": "args",
                    "client_name": args.signup_client_name,
                    "client_secret": args.signup_client_secret,
                    "basic": args.signup_basic or SIGNUP_BASIC_SUFFIX,
                    "signed_up_country": args.signed_up_country,
                    "escape_client_name_colon": False,
                },
                {
                    "label": "gopay_consumer_authsecret_cc62",
                    "client_name": SIGNUP_CLIENT_NAME,
                    "client_secret": AUTH_SECRET,
                    "basic": SIGNUP_BASIC_SUFFIX,
                    "signed_up_country": "62",
                    "escape_client_name_colon": False,
                },
                {
                    "label": "gopay_consumer_xorsecret_cc62",
                    "client_name": SIGNUP_CLIENT_NAME,
                    "client_secret": SIGNUP_XOR_SECRET_CANDIDATE,
                    "basic": SIGNUP_BASIC_SUFFIX,
                    "signed_up_country": "62",
                    "escape_client_name_colon": False,
                },
                {
                    "label": "gopay_consumer_authsecret_ID",
                    "client_name": SIGNUP_CLIENT_NAME,
                    "client_secret": AUTH_SECRET,
                    "basic": SIGNUP_BASIC_SUFFIX,
                    "signed_up_country": "ID",
                    "escape_client_name_colon": False,
                },
            ]
            seen = set()
            last_signup_error = None
            for idx, v in enumerate(variants, 1):
                key = (v["client_name"], v["client_secret"], v["basic"], v["signed_up_country"], bool(v.get("escape_client_name_colon")))
                if key in seen:
                    continue
                seen.add(key)
                print("[+] customer_signup variant", v["label"])
                for waf_try in range(args.signup_waf_retries + 1):
                    sc, data2, headers = gp.customer_signup(
                        local,
                        args.signup_name,
                        country_code=country_code,
                        verification_token=str(verification_token),
                        signup_client_name=v["client_name"],
                        signup_client_secret=v["client_secret"],
                        signup_basic=v["basic"],
                        signed_up_country=v["signed_up_country"],
                        escape_client_name_colon=bool(v.get("escape_client_name_colon")),
                    )
                    if not is_waf_html(sc, data2) or waf_try >= args.signup_waf_retries:
                        break
                    state["steps"].append({"name": f"customer_signup_{idx}_{v['label']}_waf_retry_{waf_try + 1}", "status": sc, "data": data2, "headers": headers, "variant": v})
                    save_state(out, state)
                    print(f"[!] customer_signup WAF 403; retrying after {args.signup_waf_sleep}s ({waf_try + 1}/{args.signup_waf_retries})")
                    time.sleep(args.signup_waf_sleep)
                state["steps"].append({"name": f"customer_signup_{idx}_{v['label']}", "status": sc, "data": data2, "headers": headers, "variant": v})
                save_state(out, state)
                last_signup_error = {"status": sc, "data": data2, "variant": v}
                if is_phone_registered_error(data2):
                    raise NumberAlreadyRegistered(f"NUMBER_ALREADY_REGISTERED: customer_signup phone already taken for +62{local}")
                account_id = account_id or extract_account_id(data2)
                access_token = access_token or pick_first(data2, ["access_token", "accessToken"])
                refresh_token = refresh_token or pick_first(data2, ["refresh_token", "refreshToken"])
                auth_code = auth_code or pick_first(data2, ["authorization_code", "auth_code", "code"])
                if access_token or is_success_response(sc, data2, allow=(200, 201, 202, 206)):
                    print("[+] customer_signup accepted", v["label"], "access_token", bool(access_token))
                    if not access_token:
                        signup_created_without_token = True
                    break
            if not access_token and not signup_created_without_token and last_signup_error is not None:
                raise RuntimeError(f"customer_signup failed before token exchange: HTTP {last_signup_error['status']} {jdump(last_signup_error['data'])[:1000]}")

        # 6b. Some signup responses are HTTP 206 with a created customer object
        # but empty tokens. In that case the phone is now registered; immediately
        # run the normal OTP login_1fa flow on the same SMSCloud rental number to
        # obtain the accountlist 1fa_token and exchange it for access_token.
        if signup_created_without_token and not access_token:
            print("[+] signup created customer without token; starting post-signup OTP login")
            sc, data_lm, headers = gp.login_methods(local, country_code)
            state["steps"].append({"name": "post_signup_login_methods", "status": sc, "data": data_lm, "headers": headers})
            save_state(out, state)
            require_success("post_signup_login_methods", sc, data_lm)
            login_verification_id = pick_first(data_lm, ["verification_id", "challenge_id"])
            login_method = str(pick_first(data_lm, ["default_method"]) or "otp_sms")
            login_methods = pick_first(data_lm, ["methods"])
            if isinstance(login_methods, list) and "otp_sms" in login_methods:
                login_method = "otp_sms"
            if not login_verification_id:
                raise RuntimeError("post_signup_login_methods 未返回 verification_id")

            sc, data_li, headers = gp.cvs_initiate(
                local,
                str(login_verification_id),
                method=login_method,
                flow="login_1fa",
                country_code=country_code,
            )
            state["steps"].append({"name": "post_signup_login_cvs_initiate", "status": sc, "data": data_li, "headers": headers})
            save_state(out, state)
            require_success("post_signup_login_cvs_initiate", sc, data_li, allow=(200, 201, 202, 204))
            login_otp_token = pick_first(data_li, ["otp_token", "otpToken"])
            if not login_otp_token:
                raise RuntimeError("post_signup_login_cvs_initiate 未返回 otp_token")

            login_otp = args.login_otp
            if not login_otp:
                if not sms or not order:
                    raise RuntimeError("post-signup 登录需要 --login-otp，或使用 --buy 自动从 SMSCloud 轮询")
                login_otp, raw_login_sms = poll_sms_code(
                    sms,
                    str(order["id"]),
                    timeout=args.login_otp_timeout,
                    interval=args.otp_interval,
                    previous_code=str(otp or ""),
                )
                state["login_otp"] = {"code": login_otp, "raw": raw_login_sms}
                print("[smscloud] LOGIN OTP", login_otp, raw_login_sms)
                save_state(out, state)

            sc, data_lv, headers = gp.cvs_verify(
                local,
                str(login_verification_id),
                str(login_otp),
                method=login_method,
                flow="login_1fa",
                country_code=country_code,
                otp_token=str(login_otp_token),
            )
            state["steps"].append({"name": "post_signup_login_cvs_verify", "status": sc, "data": data_lv, "headers": headers})
            save_state(out, state)
            require_success("post_signup_login_cvs_verify", sc, data_lv)
            login_verification_token = pick_first(data_lv, ["verification_token", "verificationToken"])
            if not login_verification_token:
                raise RuntimeError("post_signup_login_cvs_verify 未返回 verification_token")

            sc, data_acct, headers = gp.accountlist(str(login_verification_token))
            state["steps"].append({"name": "post_signup_login_accountlist", "status": sc, "data": data_acct, "headers": headers})
            save_state(out, state)
            require_success("post_signup_login_accountlist", sc, data_acct)
            account_id = extract_account_id(data_acct)
            one_fa_token = pick_first(data_acct, ["1fa_token", "one_fa_token", "token"])
            if not account_id or not one_fa_token:
                raise RuntimeError("post_signup_login_accountlist 未返回 account_id/1fa_token")
            sc, data_tok, headers = gp.token(verification_token=str(one_fa_token), account_id=str(account_id))
            state["steps"].append({"name": "post_signup_login_token", "status": sc, "data": data_tok, "headers": headers})
            save_state(out, state)
            require_success("post_signup_login_token", sc, data_tok, allow=(200, 201, 202))
            access_token = pick_first(data_tok, ["access_token", "accessToken"])
            refresh_token = pick_first(data_tok, ["refresh_token", "refreshToken"])

        # 7. Exchange token if not directly returned.
        if not access_token:
            if verification_token:
                sc, data, headers = gp.token(verification_token=str(verification_token), account_id=str(account_id or local))
            elif auth_code:
                sc, data, headers = gp.token(authorization_code=str(auth_code), account_id=str(account_id or local))
            else:
                raise RuntimeError("OTP verify 后没有 access_token / verification_token / auth_code")
            state["steps"].append({"name": "goto_auth_token", "status": sc, "data": data, "headers": headers})
            save_state(out, state)
            require_success("goto_auth_token", sc, data)
            access_token = pick_first(data, ["access_token", "accessToken"])
            refresh_token = pick_first(data, ["refresh_token", "refreshToken"])
        if not access_token:
            raise RuntimeError("未拿到 access_token")

        # `/v7/customers/signup` can return a short-lived RS256 access token
        # that is accepted by auth but rejected by customer APIs as
        # "Session is revoked".  The Android app immediately persists the
        # refresh token and obtains the normal encrypted goto-auth session
        # token before calling downstream customer endpoints.  Do the same
        # whenever a refresh token is available (idempotent for already-good
        # sessions, decisive for direct signup tokens).
        if refresh_token:
            sc, data_rt, headers = gp.token(refresh_token=str(refresh_token), account_id="")
            state["steps"].append({"name": "refresh_after_signup_token", "status": sc, "data": data_rt, "headers": headers})
            save_state(out, state)
            if is_success_response(sc, data_rt, allow=(200, 201, 202)):
                access_token = pick_first(data_rt, ["access_token", "accessToken"]) or access_token
                refresh_token = pick_first(data_rt, ["refresh_token", "refreshToken"]) or refresh_token
                print("[+] refreshed signup token for customer APIs")

        state["tokens"] = {"access_token": access_token, "refresh_token": refresh_token}
        save_state(out, state)
        print("[+] access_token acquired")

        # 8. Signup 后设置 PIN 是独立的 goto_pin_wa_sms CVS 二次验证：
        # allowed -> pin CVS methods/initiate -> poll second OTP -> verify ->
        # setup/tokens。不要用 signup OTP token 直接打 setup/tokens。
        sc, data, headers = gp.pin_allowed(str(access_token), args.pin)
        state["steps"].append({"name": "pin_allowed", "status": sc, "data": data, "headers": headers})
        save_state(out, state)
        require_success("pin_allowed", sc, data)

        sc, data, headers = gp.cvs_methods_pin(str(access_token))
        state["steps"].append({"name": "pin_cvs_methods", "status": sc, "data": data, "headers": headers})
        save_state(out, state)
        require_success("pin_cvs_methods", sc, data)
        pin_verification_id = pick_first(data, ["verification_id", "challenge_id"])
        pin_default_method = str(pick_first(data, ["default_method"]) or "otp_sms")
        pin_method = pin_default_method
        pin_methods = pick_first(data, ["methods"])
        if isinstance(pin_methods, list) and "otp_sms" in pin_methods:
            pin_method = "otp_sms"
        if not pin_verification_id:
            raise RuntimeError("pin_cvs_methods 未返回 verification_id")

        sc, data, headers = gp.cvs_initiate_pin(str(access_token), str(pin_verification_id), method=str(pin_method))
        state["steps"].append({"name": "pin_cvs_initiate", "status": sc, "data": data, "headers": headers})
        save_state(out, state)
        require_success("pin_cvs_initiate", sc, data, allow=(200, 201, 202, 204))
        pin_otp_token = pick_first(data, ["otp_token", "otpToken"])
        if not pin_otp_token:
            raise RuntimeError("pin_cvs_initiate 未返回 otp_token")

        pin_otp = args.pin_otp
        if not pin_otp:
            if not sms or not order:
                raise RuntimeError("PIN 二次验证需要 --pin-otp，或使用 --buy 自动从同一 SMSCloud 订单轮询")
            try:
                pin_otp, raw_pin_sms = poll_sms_code(
                    sms,
                    str(order["id"]),
                    timeout=args.pin_otp_timeout,
                    interval=args.otp_interval,
                    previous_code=str(otp or ""),
                )
            except TimeoutError:
                print("[smscloud] no PIN OTP yet; calling pin cvs_retry once")
                sc, data_r, headers_r = gp.cvs_retry_pin(str(access_token), str(pin_otp_token), method=str(pin_method))
                state["steps"].append({"name": "pin_cvs_retry_1", "status": sc, "data": data_r, "headers": headers_r})
                save_state(out, state)
                require_success("pin_cvs_retry_1", sc, data_r, allow=(200, 201, 202, 204))
                pin_otp_token = str(pick_first(data_r, ["otp_token", "otpToken"]) or pin_otp_token)
                pin_otp, raw_pin_sms = poll_sms_code(
                    sms,
                    str(order["id"]),
                    timeout=args.pin_otp_timeout,
                    interval=args.otp_interval,
                    previous_code=str(otp or ""),
                )
            state["pin_otp"] = {"code": pin_otp, "raw": raw_pin_sms}
            print("[smscloud] PIN OTP", pin_otp, raw_pin_sms)
            save_state(out, state)

        sc, data, headers = gp.cvs_verify_pin(str(access_token), str(pin_verification_id), str(pin_otp), str(pin_otp_token), method=str(pin_method))
        state["steps"].append({"name": "pin_cvs_verify", "status": sc, "data": data, "headers": headers})
        save_state(out, state)
        require_success("pin_cvs_verify", sc, data)
        pin_verification_token = pick_first(data, ["verification_token", "verificationToken"])
        if not pin_verification_token:
            raise RuntimeError("pin_cvs_verify 未返回 verification_token")

        sc, data, headers = gp.pin_setup_token_after_otp(str(access_token), args.pin, str(pin_verification_token))
        state["steps"].append({"name": "pin_setup_token_after_otp", "status": sc, "data": data, "headers": headers})
        save_state(out, state)
        require_success("pin_setup_token_after_otp", sc, data)

        # Non-mutating completion check.  The reference app treats
        # `/v1/users/profile.is_pin_setup == true` as the post-signup ready
        # condition.  Some edge variants omit the field; in that case keep the
        # endpoint success as the decisive mutation, but fail loudly if the
        # server explicitly says the PIN is still not set.
        sc, data_prof, headers = gp.user_profile(str(access_token))
        state["steps"].append({"name": "profile_after_pin_setup", "status": sc, "data": data_prof, "headers": headers})
        save_state(out, state)
        is_pin_setup = pick_first(data_prof, ["is_pin_setup", "isPinSetup"])
        if is_pin_setup is False:
            raise RuntimeError(f"profile_after_pin_setup says PIN is not set:\n{jdump(data_prof)[:1000]}")

        state["pin"] = {
            "pin_body_mode": "signup_pin_otp_setup_tokens",
            "pin_method": pin_method,
            "pin_setup_complete": True,
            "profile_is_pin_setup": is_pin_setup,
        }
        save_state(out, state)
        print("[DONE] 注册/登录/设置 PIN 纯协议流程完成")
        return 0
    finally:
        gp.close()
        if sms and order and args.finish_sms_order:
            try:
                state["sms_finish"] = sms.finish(str(order["id"]))
                save_state(out, state)
            except Exception as e:
                print("[smscloud] finish failed:", e)
                try:
                    state["sms_cancel_after_finish_failed"] = sms.cancel(str(order["id"]))
                    save_state(out, state)
                    print("[smscloud] cancel OK")
                except Exception as e2:
                    print("[smscloud] cancel failed:", e2)
        print("[STATE]", out)


def main() -> int:
    ap = argparse.ArgumentParser(description="GoPay Android 2.10.0 pure-protocol signup/login/PIN runner")
    ap.add_argument("--phone", help="+62/62/local Indonesian number")
    ap.add_argument("--buy", action="store_true", help="buy SMSCloud Indonesia number")
    ap.add_argument("--sms-key", default=os.getenv("SMSCLOUD_KEY", KEY_DEFAULT))
    ap.add_argument("--sms-service", default="ni")
    ap.add_argument("--sms-country", type=int, default=6)
    ap.add_argument("--sms-max-price", default="2.25")
    ap.add_argument("--sms-order-id", help="reuse an already bought SMSCloud order; requires --phone")
    ap.add_argument("--otp")
    ap.add_argument("--otp-timeout", type=int, default=1200)
    ap.add_argument("--otp-interval", type=int, default=5)
    ap.add_argument("--finish-sms-order", action="store_true")
    ap.add_argument("--pin", default="736294")
    ap.add_argument("--initiate-default-first", action="store_true", default=os.getenv("GOPAY_INITIATE_DEFAULT_FIRST", "") == "1")
    ap.add_argument("--tokenized-pin", help="already tokenized/encrypted PIN output")
    ap.add_argument("--pin-tokenizer", choices=["aes-ecb", "external-only"], default="aes-ecb", help="default pure-Python tokenizePin candidate")
    ap.add_argument("--pin-tokenizer-cmd", help="command prints tokenized PIN; env GOPAY_PIN/GOPAY_PIN_TOKEN are set")
    ap.add_argument("--signup-name", default="TestUser")
    ap.add_argument("--signup-client-name", default=os.getenv("GOPAY_SIGNUP_CLIENT_NAME", SIGNUP_CLIENT_NAME))
    ap.add_argument("--signup-client-secret", default=os.getenv("GOPAY_SIGNUP_CLIENT_SECRET", SIGNUP_CLIENT_SECRET))
    ap.add_argument("--signup-basic", default=os.getenv("GOPAY_SIGNUP_BASIC"), help="Authorization Basic 后面的 suffix；不传则使用 base64(signup UUID)")
    ap.add_argument("--signed-up-country", default=os.getenv("GOPAY_SIGNED_UP_COUNTRY", "62"))
    ap.add_argument("--signup-waf-retries", type=int, default=int(os.getenv("GOPAY_SIGNUP_WAF_RETRIES", "3")))
    ap.add_argument("--signup-waf-sleep", type=float, default=float(os.getenv("GOPAY_SIGNUP_WAF_SLEEP", "2.0")))
    ap.add_argument("--skip-customer-signup", action="store_true")
    ap.add_argument("--login-otp", help="signup 206 后 post-signup 登录 OTP；不传则继续从同一 SMSCloud 订单轮询")
    ap.add_argument("--login-otp-timeout", type=int, default=240)
    ap.add_argument("--pin-otp", help="PIN 二次验证 OTP；不传则继续从同一 SMSCloud 订单轮询")
    ap.add_argument("--pin-otp-timeout", type=int, default=240)
    ap.add_argument("--flow", default="signup")
    ap.add_argument("--device-id")
    ap.add_argument("--x-m1")
    ap.add_argument("--device-from-capture")
    ap.add_argument("--xe-mode", choices=["none", "captured", "adb-oracle", "pure", "enhanced"], default="enhanced")
    ap.add_argument("--capture-json", default="android_gopay_2.10.0/runtime_now/full_signup_pin_capture_20260529_200358.artifacts.json")
    ap.add_argument("--xe-resolution-key", default=None, help="X-E1 HMAC key/resolution; omitted means mode default")
    ap.add_argument("--xe-random-hex", help="diagnostic deterministic 80-byte random hex for signer selftests")
    ap.add_argument("--adb", default="./adb/adb")
    ap.add_argument("--oracle-dex", default="/data/local/tmp/oracle.dex")
    ap.add_argument("--libbattery", default="/data/local/tmp/libbatteryOpt.so")
    ap.add_argument("--liboracle", default="/data/local/tmp/liboracle.so")
    ap.add_argument("--verify-signer-against-capture")
    ap.add_argument("--selftest-only", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--out")
    return run(ap.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
