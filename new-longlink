(async () => {
  "use strict";

  const PATH = "/checkout/openai_llc/";

  const PAYLOAD = {
    plan_name: "chatgptplusplan",
    billing_details: {
      country: "ID",
      currency: "IDR",
    },
    cancel_url: "https://chatgpt.com/#pricing",
    promo_campaign: {
      promo_campaign_id: "plus-1-month-free",
      is_coupon_from_query_param: false,
    },
    checkout_ui_mode: "hosted",
  };

  function log(message, data) {
    console.log(`[GoPay Checkout] ${message}`, data || "");
  }

  async function fetchJson(url, options = {}) {
    const response = await fetch(url, options);
    const data = await response.json().catch(() => null);

    if (!response.ok) {
      console.error("[GoPay Checkout] 请求失败：", data);
      throw new Error(`HTTP ${response.status}`);
    }

    return data;
  }

  try {
    if (!location.pathname.startsWith(PATH)) {
      alert(`当前不是 checkout 页面。\n\n请先进入 ${PATH} 开头的页面再执行。`);
      console.warn("[GoPay Checkout] 当前路径：", location.pathname);
      return;
    }

    log("正在获取登录 Token...");

    const session = await fetchJson("/api/auth/session", {
      credentials: "include",
    });

    const token = session?.accessToken;

    if (!token) {
      alert("获取登录 Token 失败，请确认你已经登录 ChatGPT。");
      throw new Error("没有获取到 accessToken");
    }

    log("Token 获取成功，正在生成 Stripe 付款链接...");

    const data = await fetchJson("https://chatgpt.com/backend-api/payments/checkout", {
      method: "POST",
      credentials: "include",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(PAYLOAD),
    });

    const checkoutUrl = data?.url || data?.stripe_hosted_url || data?.checkout_url;

    if (!checkoutUrl) {
      console.error("[GoPay Checkout] 原始响应：", data);
      alert("没有在响应里找到付款链接，请看控制台原始响应。");
      return;
    }

    console.log("[GoPay Checkout] Stripe 付款链接：", checkoutUrl);
    console.log("[GoPay Checkout] 原始响应：", data);

    location.href = checkoutUrl;
  } catch (error) {
    console.error("[GoPay Checkout] 执行失败：", error);
    alert(`执行失败：${error.message || error}`);
  }
})();
