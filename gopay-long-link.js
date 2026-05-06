(async function generatePlusHostedLinkIDR() {
  console.log("⏳ [plus-link] 正在获取 Session Token...");

  // ── 1. 获取当前登录的 Access Token ──────────────────────────────────────
  let accessToken;
  try {
    const session = await fetch("/api/auth/session").then((r) => r.json());
    accessToken = session?.accessToken;
    if (!accessToken) throw new Error("accessToken 为空");
  } catch (e) {
    console.error("❌ [plus-link] 获取 Token 失败，请确保已登录 ChatGPT：", e.message);
    return;
  }
  console.log("✅ [plus-link] Token 获取成功");

  // ── 2. 构造请求 Payload (切入印尼区 ID/IDR) ──────────────────────────────
  const payload = {
    plan_name: "chatgptplusplan",
    billing_details: {
      country: "ID",    // 国家代码改为：印度尼西亚 (Indonesia)
      currency: "IDR",  // 币种改为：印尼卢比 (Indonesian Rupiah)
    },
    cancel_url: "https://chatgpt.com/#pricing",
    promo_campaign: {
      promo_campaign_id: "plus-1-month-free",
      is_coupon_from_query_param: false,
    },
    checkout_ui_mode: "hosted", // 维持 hosted 模式以获取原生 Stripe 链接
  };

  // ── 3. 发送请求 ──────────────────────────────────────────────────────────
  console.log("⏳ [plus-link] 正在请求 Stripe 印尼区长链接...");
  let data;
  try {
    const response = await fetch(
      "https://chatgpt.com/backend-api/payments/checkout",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      }
    );
    data = await response.json();

    if (!response.ok) {
      console.error("❌ [plus-link] 请求失败，HTTP", response.status, data);
      return;
    }
  } catch (e) {
    console.error("❌ [plus-link] 网络请求异常：", e.message);
    return;
  }

  // ── 4. 输出结果 ──────────────────────────────────────────────────────────
  const hostedUrl = data?.url || data?.stripe_hosted_url || data?.checkout_url;

  if (!hostedUrl) {
    console.warn("⚠️ [plus-link] 未找到长链接，原始响应如下：");
    console.log(data);
    return;
  }

  console.log("─".repeat(60));
  console.log("✅ [plus-link] 印尼区链接生成成功！");
  console.log("");
  console.log("📋 Checkout Session ID :", data.checkout_session_id);
  console.log("🏢 Processor Entity    :", data.processor_entity);
  console.log("💰 Plan                : ChatGPT Plus（首月 Rp 0 / 免费试用）");
  console.log("");
  console.log("🔗 Stripe 长链接（请复制到浏览器打开）：");
  console.log(hostedUrl);
  console.log("─".repeat(60));
})();