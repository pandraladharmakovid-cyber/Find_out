import { describe, expect, it } from "vitest";
import { createTranslator } from "../../frontend/src/i18n";
import en from "../../frontend/src/locales/en.json";
import hi from "../../frontend/src/locales/hi.json";
import te from "../../frontend/src/locales/te.json";

describe("Frontend translation contract", () => {
  it("returns real Hindi and Telugu navigation translations through the function API", () => {
    expect(createTranslator("en")("nav.dashboard")).toBe(en.nav.dashboard);
    expect(createTranslator("hi")("nav.dashboard")).toBe(hi.nav.dashboard);
    expect(createTranslator("te")("nav.dashboard")).toBe(te.nav.dashboard);
    expect(hi.nav.dashboard).not.toBe(en.nav.dashboard);
    expect(te.nav.dashboard).not.toBe(en.nav.dashboard);
  });

  it("exposes a function API and returns the key for an unknown path", () => {
    const hindi = createTranslator("hi") as ((key: string) => string) & Record<string, unknown>;
    expect(hindi.nav).toBeUndefined();
    expect(createTranslator("hi")("path.that.does.not.exist")).toBe("path.that.does.not.exist");
  });
});
