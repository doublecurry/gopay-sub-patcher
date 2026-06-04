#!/usr/bin/env python3
import time, re, requests

class SmsCloud:
    def __init__(self, api_key, base='https://smscloud.sbs/api/system'):
        self.base = base.rstrip('/')
        self.s = requests.Session()
        self.s.headers['apiKey'] = api_key

    def _get(self, path, **params):
        r = self.s.get(self.base + path, params=params or None, timeout=30)
        r.raise_for_status()
        j = r.json()
        if j.get('code') != 0:
            raise RuntimeError(f'smscloud error {j}')
        return j.get('data')

    def balance(self):
        return self._get('/public/sms/balance')

    def inventory(self, service='ni', country=6):
        return self._get('/public/sms/getInventory', serviceCode=service, country=country)

    def buy(self, service='ni', country=6, max_price='2.25'):
        """Buy a number, tolerating SMSCloud's fast-moving price buckets.

        The flexible endpoint rejects stale `maxPrice` values with
        "价格参数无效，请从库存接口重新获取".  The UI docs say callers should
        read `getInventory` first; do that automatically and pick the highest
        currently available bucket that does not exceed `max_price` (or the
        cheapest bucket if none fit).
        """
        price = str(max_price)
        try:
            inv = self.inventory(service=service, country=country)
            row = next((x for x in inv or [] if str(x.get('country')) == str(country)), None)
            if row and isinstance(row.get('freePriceMap'), dict) and row['freePriceMap']:
                prices = sorted(float(p) for p in row['freePriceMap'].keys())
                ceiling = float(max_price)
                eligible = [p for p in prices if p <= ceiling]
                chosen = eligible[-1] if eligible else prices[0]
                price = f'{chosen:g}'
        except Exception:
            pass
        tried = []
        candidates = [price]
        try:
            if row and isinstance(row.get('freePriceMap'), dict):
                all_prices = [f'{float(p):g}' for p in sorted(row['freePriceMap'].keys(), key=lambda x: float(x))]
                # If all buckets <= maxPrice are temporarily exhausted, try the
                # next higher buckets as a controlled fallback instead of
                # failing the whole run before protocol testing starts.
                for p in all_prices:
                    if p not in candidates:
                        candidates.append(p)
        except Exception:
            pass
        last_error = None
        for p in candidates:
            try:
                return self._get('/public/sms/flexible', countryCode=country, serviceCode=service, maxPrice=p)
            except Exception as e:
                tried.append(p)
                last_error = e
        raise RuntimeError(f'smscloud buy failed; tried prices={tried}; last={last_error}')

    def sync(self, order_id):
        return self._get(f'/public/sms/orders/sync/{order_id}')

    def cancel(self, order_id):
        return self._get(f'/public/sms/orders/cancel/{order_id}')

    def finish(self, order_id):
        return self._get(f'/public/sms/orders/finish/{order_id}')

    def resend(self, order_id):
        return self._get(f'/public/sms/orders/resend/{order_id}')

    def replace(self, order_id):
        return self._get(f'/public/sms/orders/replace/{order_id}')

    def poll_code(self, order_id, timeout=1200, interval=5):
        end = time.time() + timeout
        last = None
        while time.time() < end:
            data = self.sync(order_id)
            last = data
            text = '' if data is None else str(data)
            m = re.search(r'(?<!\d)(\d{4,8})(?!\d)', text)
            if m:
                return m.group(1), data
            time.sleep(interval)
        raise TimeoutError(f'no sms code for {order_id}; last={last!r}')
