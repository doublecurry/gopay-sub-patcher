(async function checkoutLinkOnly() {
  try {
    const session = await fetch('/api/auth/session').then((r) => r.json());
    const accessToken = session?.accessToken;
    if (!accessToken) {
      console.log('accessToken: null');
      return;
    }

    const payload = {
      plan_name: 'chatgptplusplan',
      billing_details: {
        country: 'ID',
        currency: 'IDR',
      },
      cancel_url: 'https://chatgpt.com/#pricing',
      promo_campaign: {
        promo_campaign_id: 'plus-1-month-free',
        is_coupon_from_query_param: false,
      },
      checkout_ui_mode: 'hosted',
    };

    const response = await fetch('https://chatgpt.com/backend-api/payments/checkout', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    const data = await response.json();
    const hostedUrl = data?.url || data?.stripe_hosted_url || data?.checkout_url || null;

    console.log('accessToken:', accessToken);
    console.log('paymentLink:', hostedUrl);
  } catch (e) {
    console.log('accessToken: null');
    console.log('paymentLink: null');
  }
})();
