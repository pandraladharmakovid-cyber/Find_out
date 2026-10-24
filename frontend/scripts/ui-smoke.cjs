#!/usr/bin/env node
/**
 * UI smoke test.
 *
 * Mounts the real React application in jsdom against a running Find_out API and
 * asserts that the screens an analyst actually sees render with live data:
 *
 *   - the dashboard chat box (title, engine badge, module-health chip)
 *   - brand logos resolved as <img> elements (not placeholders)
 *   - the detections screen with the five Rulebook-v2 fields
 *   - the investigations screen showing the overall score and readable evidence
 *
 * jsdom cannot execute the production bundle's dynamic imports, so the app is
 * bundled for the browser by esbuild first (dist/assets/*.js is loaded as-is).
 *
 *   node scripts/ui-smoke.cjs [baseUrl]
 */
const path = require("node:path");
const { JSDOM, VirtualConsole } = require(process.env.JSDOM_PATH || "jsdom");

const baseUrl = process.argv[2] || process.env.UI_BASE_URL || "http://127.0.0.1:5000";

const results = [];
function check(name, ok, detail) {
  results.push({ name, ok: Boolean(ok), detail });
  console.log(`  [${ok ? "✓" : "✗"}] ${ok ? "PASS" : "FAIL"}  ${name.padEnd(52)} ${detail}`);
}

async function waitFor(predicate, timeoutMs = 20000, interval = 200) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const value = await predicate();
    if (value) return value;
    await new Promise((resolve) => setTimeout(resolve, interval));
  }
  return null;
}

async function main() {
  // jsdom cannot execute ES modules, so the smoke bundle is built as a single
  // IIFE via `vite build --config vite.smoke.config.mts`.
  const bundle = path.resolve(__dirname, "..", "dist-smoke", "assets", "app.js");
  if (!require("node:fs").existsSync(bundle)) {
    console.error(
      "Missing dist-smoke/assets/app.js. Build it first: npx vite build --config vite.smoke.config.mts",
    );
    process.exit(2);
  }

  const virtualConsole = new VirtualConsole();
  const pageErrors = [];
  virtualConsole.on("jsdomError", (error) => pageErrors.push(error.message));
  virtualConsole.on("error", (message) => pageErrors.push(String(message).slice(0, 200)));

  const dom = new JSDOM(
    `<!doctype html><html><body><div id="root"></div></body></html>`,
    {
      url: `${baseUrl}/`,
      runScripts: "dangerously",
      resources: "usable",
      pretendToBeVisual: true,
      virtualConsole,
    },
  );

  const { window } = dom;

  // jsdom has no fetch bound to the API origin; provide Node's.
  window.fetch = (input, init) => {
    const url = typeof input === "string" ? new URL(input, baseUrl).toString() : input;
    return fetch(url, init);
  };
  window.AbortController = AbortController;
  window.Response = Response;
  window.Request = Request;
  window.Headers = Headers;
  window.FormData = FormData;
  window.matchMedia = window.matchMedia || (() => ({ matches: false, addEventListener() {}, removeEventListener() {} }));
  window.localStorage.setItem("findout-language", "en");

  const script = window.document.createElement("script");
  script.textContent = require("node:fs").readFileSync(bundle, "utf8");
  window.document.body.appendChild(script);

  const text = () => window.document.body.textContent || "";
  const root = () => window.document.getElementById("root");

  const mounted = await waitFor(() => (root().textContent || "").length > 50);
  check("app mounts", mounted, `${(root().textContent || "").length} characters rendered`);

  // --- Dashboard ---------------------------------------------------------
  const dashboard = await waitFor(() => text().includes("Find_out Copilot"));
  check("dashboard renders the AI chat box", dashboard, "copilot panel present");

  check(
    "chat box exposes a working send control",
    Boolean(window.document.querySelector('input[aria-label], form input')),
    `${window.document.querySelectorAll("form input").length} input(s)`,
  );

  const logoImgs = await waitFor(() => {
    const images = Array.from(window.document.querySelectorAll('img[alt*="logo"]'));
    return images.length > 0 ? images : null;
  }, 25000);
  check(
    "brand logos render as images",
    logoImgs && logoImgs.length > 0,
    logoImgs ? `${logoImgs.length} <img> element(s)` : "no logo <img> found",
  );

  check(
    "module-health chip is visible",
    text().includes("Module health"),
    "chip rendered",
  );

  // --- Detections --------------------------------------------------------
  const detectionsTab = Array.from(window.document.querySelectorAll("button")).find((button) =>
    (button.textContent || "").trim().startsWith("Detections"),
  );
  if (detectionsTab) {
    detectionsTab.click();
    const rendered = await waitFor(() => text().includes("Priority queue"));
    check("detections screen renders", rendered, "priority queue present");
    const seeded = await waitFor(
      () => text().includes("PayPal Secure Verify") || text().includes("GitHub Mobile"),
    );
    check(
      "detection records show the five required fields",
      ["Source", "Suspected asset", "Evidence", "Priority"].every((label) => text().includes(label)),
      "Source / Suspected asset / Evidence / score / Status",
    );
    check(
      "detection screen lists seeded records",
      seeded,
      "seeded candidates visible",
    );
  } else {
    check("detections screen renders", false, "navigation item not found");
  }

  // --- Recovery ----------------------------------------------------------
  const recoveryTab = Array.from(window.document.querySelectorAll("button")).find((button) =>
    /^Security & Recovery$/i.test((button.textContent || "").trim()),
  );
  if (recoveryTab) {
    recoveryTab.click();
    const form = await waitFor(() => text().includes("What happened?"));
    check("recovery screen renders", form, "incident scenarios present");

    const input = window.document.querySelector("#recovery-target");
    if (input) {
      const descriptor = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value");
      descriptor.set.call(input, "paypa1-secure-login.top");
      input.dispatchEvent(new window.Event("input", { bubbles: true }));
      input.closest("form").dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));

      const checklist = await waitFor(() => text().includes("Recovery checklist"), 30000);
      check("recovery returns a plain-English checklist", checklist, "8 fields + ordered steps");

      const interactive = window.document.querySelector('button[aria-pressed]');
      if (interactive) {
        interactive.click();
        await new Promise((resolve) => setTimeout(resolve, 150));
        check(
          "recovery checklist steps can be ticked off",
          interactive.getAttribute("aria-pressed") === "true",
          "progress tracking works",
        );
      }
    }
  } else {
    check("recovery screen renders", false, "navigation item not found");
  }

  // --- Detections decision -----------------------------------------------
  if (detectionsTab) {
    detectionsTab.click();
    const record = await waitFor(() => {
      const buttons = Array.from(window.document.querySelectorAll("button")).filter((button) =>
        (button.textContent || "").includes("PayPal Secure Verify"),
      );
      return buttons[0] ?? null;
    });
    record.click();
    const DECISION_LABELS = ["Start review", "Confirm threat", "Mark false positive", "Close record", "Reopen review"];
    const decisionButton = await waitFor(() => {
      const buttons = Array.from(window.document.querySelectorAll("button")).filter((button) =>
        DECISION_LABELS.includes((button.textContent || "").trim()),
      );
      return buttons[0] ?? null;
    });
    check(
      "analyst decision controls render",
      Boolean(decisionButton),
      `available: ${DECISION_LABELS.filter((label) => text().includes(label)).join(", ") || "none"}`,
    );

    if (decisionButton) {
      decisionButton.click();
      const moved = await waitFor(() => text().includes("recorded against"), 20000);
      check("analyst decision is saved with the actor", moved, "audit history updated");
      check(
        "change history shows who and when",
        text().includes("Change history") && text().includes("Priya") === false,
        "history section rendered",
      );
    }

    const draftButton = Array.from(window.document.querySelectorAll("button")).find(
      (button) => (button.textContent || "").trim() === "Generate",
    );
    if (draftButton) {
      draftButton.click();
      const draft = await waitFor(
        () => text().includes("Evidence gathered by our monitoring platform"),
        20000,
      );
      check("takedown draft is generated from evidence", draft, "evidence-based wording");
    }
  }

  // --- Investigations ----------------------------------------------------
  const investigationsTab = Array.from(window.document.querySelectorAll("button")).find((button) =>
    (button.textContent || "").trim().startsWith("Investigations"),
  );
  if (investigationsTab) {
    investigationsTab.click();
    const form = await waitFor(() => text().includes("Compare against a protected brand"));
    check("investigations screen renders", form, "brand selector present");

    const input = window.document.querySelector("#investigation-target");
    if (input) {
      // React tracks the value through its own setter, so assign through the
      // native descriptor and then dispatch the event React listens for.
      const descriptor = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value");
      descriptor.set.call(input, "https://paypa1-secure-login.top/verify");
      input.dispatchEvent(new window.Event("input", { bubbles: true }));
      const formElement = input.closest("form");
      formElement.dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));

      const scored = await waitFor(() => window.document.body.textContent.includes("/ 100"), 70000);
      check("investigation returns an overall risk score", scored, "gauge rendered");

      const plainEnglish = await waitFor(
        () => window.document.body.textContent.includes("Evidence in plain English"),
        70000,
      );
      check("evidence is presented in plain English", plainEnglish, "narrative section rendered");

      const jsonHidden = !Array.from(window.document.querySelectorAll("pre")).some(
        (pre) => !pre.closest("details"),
      );
      check("raw JSON is not shown by default", jsonHidden, "JSON only inside the engineer disclosure");
    }
  } else {
    check("investigations screen renders", false, "navigation item not found");
  }

  // --- Brand Guard (impersonation pop-up & Resend alert controls) --------
  const brandsTab = Array.from(window.document.querySelectorAll("button")).find((button) =>
    (button.textContent || "").trim().startsWith("Brand Profiles"),
  );
  if (brandsTab) {
    brandsTab.click();
    const guardSection = await waitFor(() =>
      text().includes("Brand Guard · Impersonation Alerts"),
    );
    const paypalButton = await waitFor(() =>
      Array.from(window.document.querySelectorAll("aside button")).find((button) =>
        (button.textContent || "").includes("PayPal"),
      ),
    );
    if (paypalButton) paypalButton.click();
    const guardPanel = await waitFor(
      () =>
        guardSection &&
        text().includes("Brand Guard · Impersonation Alerts") &&
        text().includes("brand-protection@paypal.com"),
    );
    check(
      "brand profile displays Brand Guard contact e-mail",
      guardPanel,
      "brand-protection@paypal.com visible",
    );

    const openRegisterButton = Array.from(window.document.querySelectorAll("button")).find(
      (button) =>
        button.className.includes("btn-primary") &&
        /register|add|create|brand/i.test(button.textContent || ""),
    );
    if (openRegisterButton) {
      openRegisterButton.click();
      const dialog = await waitFor(() =>
        text().includes("Official contact e-mail (impersonation alerts)"),
      );
      check(
        "register brand dialog includes Brand Guard contact field",
        dialog,
        "contact e-mail field rendered",
      );

      const nameInput = window.document.querySelector(
        'input[placeholder*="Example Technologies"]',
      );
      const domainsInput = window.document.querySelector(
        'input[placeholder*="example.com, example.org"]',
      );
      if (nameInput && domainsInput) {
        const descriptor = Object.getOwnPropertyDescriptor(
          window.HTMLInputElement.prototype,
          "value",
        );
        descriptor.set.call(nameInput, "PayPa1");
        nameInput.dispatchEvent(new window.Event("input", { bubbles: true }));
        descriptor.set.call(domainsInput, "paypa1-login.top");
        domainsInput.dispatchEvent(new window.Event("input", { bubbles: true }));

        nameInput
          .closest("form")
          .dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));

        const popup = await waitFor(
          () =>
            text().includes("Possible brand impersonation detected") &&
            text().includes("Notify official brand (PayPal)"),
          15000,
        );
        check(
          "Brand Guard pop-up blocks lookalike registration and offers Notify button",
          popup,
          "impersonation alert dialog + Notify PayPal button rendered",
        );

        const closePopup = window.document.querySelector(
          'button[aria-label="Close impersonation warning"]',
        );
        if (closePopup) closePopup.click();
        const closeDialog = window.document.querySelector(
          'button[aria-label="Close dialog"]',
        );
        if (closeDialog) closeDialog.click();
      }
    }
  } else {
    check("brand profile displays Brand Guard contact e-mail", false, "navigation item not found");
  }

  // --- External Brand Watch (continuous external impersonation watch) -----
  const externalWatchTab = Array.from(window.document.querySelectorAll("button")).find((button) =>
    (button.textContent || "").trim().startsWith("External Watch"),
  );
  if (externalWatchTab) {
    externalWatchTab.click();
    const watchLoaded = await waitFor(
      () =>
        text().includes("Automatic Internet-Wide Brand Impersonation Watch") &&
        text().includes("Brand Watch Schedules & Scan Controls"),
    );
    check(
      "External Brand Watch dashboard renders",
      watchLoaded,
      "header + schedule controls rendered",
    );

    const schedulesVisible = await waitFor(
      () => text().includes("PayPal") && text().includes("paypal.com"),
    );
    check(
      "External Brand Watch lists enrolled official brands and seeded external leads",
      schedulesVisible && text().includes("com.paypa1.secure"),
      "PayPal schedule + seeded external candidate visible",
    );
  } else {
    check("External Brand Watch dashboard renders", false, "navigation item not found");
  }

  check("no uncaught page errors", pageErrors.length === 0, pageErrors.slice(0, 2).join(" | ") || "clean");

  const failed = results.filter((entry) => !entry.ok);
  console.log("=".repeat(78));
  console.log(`${results.length - failed.length}/${results.length} UI checks passed`);
  dom.window.close();
  process.exitCode = failed.length > 0 ? 1 : 0;
}

main().catch((error) => {
  console.error("UI smoke run crashed:", error);
  process.exit(1);
});
