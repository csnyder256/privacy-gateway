import { expect, test } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await page.evaluate(() => localStorage.clear());
  await page.reload();
});

test("custom policy, trust mode, preview, download, snippets, and persistence stay aligned", async ({ page }) => {
  await page.locator("#next").click();
  const email = page.locator('[data-entity="EMAIL_ADDRESS"]');
  await email.locator("select.action").selectOption("redact");
  await email.locator("input.confidence-value").fill("100");
  await email.locator("input.confidence-value").press("Tab");
  await page.locator("#allow-terms").fill("allowed@example.com");
  await page.locator("#deny-terms").fill("Project Nightfall:ORGANIZATION");

  await page.locator("#next").click();
  await page.locator('[data-mode="selfhosted"]').click();
  await page.locator("#retention").fill("2");
  await page.locator("#audit-retention").fill("7");
  await page.locator("#next").click();
  await page.locator("#sample-input").fill("Email maya@example.com and allowed@example.com about Project Nightfall.");
  await expect(page.locator("#sample-output")).toHaveValue(/maya@example\.com/u);
  await expect(page.locator("#sample-output")).toHaveValue(/allowed@example\.com/u);
  await expect(page.locator("#sample-output")).not.toHaveValue(/Project Nightfall/u);

  await page.locator("#next").click();
  await expect(page.locator("#mode-summary")).toContainText("Self-hosted network vault");
  await expect(page.locator("#install-snippet")).toContainText("create_session(policy=policy)");
  const downloadPromise = page.waitForEvent("download");
  await page.locator("#download-policy").click();
  const download = await downloadPromise;
  const stream = await download.createReadStream();
  if (!stream) throw new Error("download stream unavailable");
  let body = "";
  for await (const chunk of stream) body += chunk.toString();
  const policy = JSON.parse(body);
  expect(policy.rules.find((rule: { entity: string }) => rule.entity === "EMAIL_ADDRESS").minimum_confidence_ppm).toBe(1_000_000);
  expect(policy.mapping_retention_seconds).toBe(172_800);
  expect(policy.audit_retention_seconds).toBe(604_800);
  expect(policy.deny_terms).toEqual({ "Project Nightfall": "ORGANIZATION" });
  expect(await page.evaluate(() => localStorage.getItem("privacy-gateway-policy-draft-v1"))).not.toContain("Project Nightfall.");

  await page.reload();
  await page.locator("#next").click();
  await expect(page.locator('[data-entity="EMAIL_ADDRESS"] select.action')).toHaveValue("redact");
  await expect(page.locator('[data-entity="EMAIL_ADDRESS"] input.confidence-value')).toHaveValue("100");
});

test("one-way mode remains irreversible and mobile keeps granular controls visible", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.locator("#next").click();
  const email = page.locator('[data-entity="EMAIL_ADDRESS"]');
  await expect(email.locator(".reversible")).toBeVisible();
  await expect(email.locator(".confidence")).toBeVisible();
  await page.locator("#next").click();
  await page.locator('[data-mode="oneway"]').click();
  await page.locator("#back").click();
  await expect(email.locator("select.action")).toHaveValue("redact");
  await expect(email.locator('select.action option:has-text("tokenize")')).toHaveAttribute("disabled", "");
  await expect(email.locator("input.reverse")).toBeDisabled();
  await page.locator("#next").click();
  await page.locator("#next").click();
  await page.locator("#next").click();
  await expect(page.locator("#mode-summary")).toContainText("One-way");
  await page.locator('[data-snippet="typescript"]').click();
  await expect(page.locator("#install-snippet")).toContainText("policyFromServer");
  await page.locator('[data-snippet="docker"]').click();
  await expect(page.locator("#install-snippet")).toContainText("No gateway container is required");
});
