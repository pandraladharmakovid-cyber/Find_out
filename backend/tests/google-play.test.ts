import { describe, expect, it } from "vitest";
import {
  parsePlayStoreSearchHtml,
  parsePlayStoreDetailHtml,
} from "../src/integrations/google-play.client";

/**
 * Fixtures mirror the two card layouts the Play Store currently renders:
 * the featured card (vWM94c/LbQbAe) and the standard list card (DdYX5/wMUdtb).
 */
const SEARCH_FIXTURE = `
<div class="ipRz4"><a href="/store/apps/details?id=com.paypal.android.p2pmobile" aria-label="PayPal" class="Qfxief"></a>
  <div class="DxDVjd"><img src="https://play-lh.googleusercontent.com/paypal-icon=s64-rw" class="T75of bzqKMd" />
  <div><div class="vWM94c">PayPal - Pay, Send, Save</div><div class="LbQbAe">PayPal Mobile</div></div></div>
  <div class="TT9eCd" role="img" aria-label="Rated 4.2 stars out of five stars"></div>
</div>
<div><a href="/store/apps/details?id=com.paypal.merchant.client" class="Qfxief"></a>
  <div><div class="DdYX5">PayPal Business</div><div class="wMUdtb">PayPal Mobile</div></div>
  <span aria-hidden="true">3.8</span>
</div>
<div><a href="/store/apps/details?id=com.example.fake.wallet" class="Qfxief"></a>
  <div><div class="DdYX5">PayPal Secure Login &amp; Support</div><div class="wMUdtb">Totally Unrelated Dev</div></div>
</div>
`;

const DETAIL_FIXTURE = `
<html><head>
<meta property="og:image" content="https://play-lh.googleusercontent.com/abc123=s0-br30" />
<meta property="og:description" content="Send and receive money securely with the official app." />
<title>PayPal - Pay, Send, Save - Apps on Google Play</title>
</head><body>
<div class="Vbfug auoIOc"><a href="/store/apps/dev?id=1"><span>PayPal Mobile</span></a></div>
</body></html>
`;

describe("Google Play parser", () => {
  it("extracts package id, title, publisher and rating from search cards", () => {
    const cards = parsePlayStoreSearchHtml(SEARCH_FIXTURE, 25);

    expect(cards).toHaveLength(3);
    expect(cards[0]).toMatchObject({
      packageId: "com.paypal.android.p2pmobile",
      title: "PayPal - Pay, Send, Save",
      developer: "PayPal Mobile",
      rating: 4.2,
    });
    expect(cards[0]?.iconUrl).toContain("play-lh.googleusercontent.com");
    expect(cards[1]).toMatchObject({
      packageId: "com.paypal.merchant.client",
      title: "PayPal Business",
      developer: "PayPal Mobile",
      rating: 3.8,
    });
    // HTML entities must be decoded, otherwise the imposter name is mangled.
    expect(cards[2]?.title).toBe("PayPal Secure Login & Support");
    expect(cards[2]?.developer).toBe("Totally Unrelated Dev");
  });

  it("honours the requested limit", () => {
    expect(parsePlayStoreSearchHtml(SEARCH_FIXTURE, 2)).toHaveLength(2);
  });

  it("returns an empty array instead of throwing on unknown markup", () => {
    expect(parsePlayStoreSearchHtml("<html><body>redesigned store</body></html>", 10)).toEqual([]);
  });

  it("parses a detail page into title, developer, description and icon", () => {
    const detail = parsePlayStoreDetailHtml(DETAIL_FIXTURE);

    expect(detail.title).toBe("PayPal - Pay, Send, Save");
    expect(detail.developer).toBe("PayPal Mobile");
    expect(detail.description).toContain("Send and receive money");
    expect(detail.iconUrl).toBe("https://play-lh.googleusercontent.com/abc123");
  });
});
