# gopay-sub-patcher

A small utility for assisting in recording subscription and billing redirect information. It reads the necessary state from the currently logged-in session and attempts to generate a billing page address that can be opened in the browser, facilitating continued operation even when page redirection is unstable, the environment changes, or the process is interrupted.

> Suitable for users with some experience using browser developer tools. Please use only within your own account and device environment.

## Project Content

- `checkout-link-only.js`: outputs key session information and the billing link.

- `gopay-long-link.js`: A version with process prompts for easy observation of requests and return results.

- `gopay_pure_signer.py`: Related auxiliary scripts; refer to them as needed.

## How to Use

### Method 1: Browser Console

1. Log in to the target account and go to the subscription/billing related page.

2. Press `F12` on the page to open the developer tools.

3. Switch to the **Console** tab. 4. Copy the contents of `checkout-link-only.js` and execute it.

4. Based on the console output, copy the generated page address and open it in a suitable browser environment.

### Method Two: Refer to Script Logic

If you need to integrate your own debugging or automation process, you can read the request construction, response parsing, and output logic in `gopay-long-link.js` and adapt it according to your actual scenario.

## Precautions

- The generated link is related to the current account session and settlement process; please do not share it publicly.

- Please protect your account, payment information, and browser environment during operation.

- Page structure, API returns, or risk control strategies may change; the script's long-term stability is not guaranteed.

- This project is only for process observation and technical exchange purposes; users must determine the applicable scope and risks themselves.
