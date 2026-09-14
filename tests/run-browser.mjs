import { mkdir } from 'node:fs/promises';
import checkBrowser from './browser-check.js';

const { chromium } = await import(process.env.PLAYWRIGHT_MODULE ?? 'playwright');
const browser = await chromium.launch({ channel: 'chromium' });
try {
  const page = await browser.newPage({ viewport: { width: 1100, height: 1000 } });
  await page.goto(process.env.DKIM_TEST_URL ?? 'http://localhost:8000');
  await mkdir('output/playwright', { recursive: true });
  console.log(await checkBrowser(page));
  await page.setViewportSize({ width: 1100, height: 1000 });
  await page.screenshot({ path: 'output/playwright/desktop.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: 'output/playwright/mobile.png', fullPage: true });
} finally {
  await browser.close();
}
