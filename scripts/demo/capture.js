// Screenshots for the README demo GIF (run by capture.py inside the demo VM).
// Logs in, then attacks the host from the lab's attacker namespace and
// captures the dashboard as each alert arrives live.
const { chromium } = require('playwright');
const { execSync } = require('child_process');

const { FRAMES, USERNAME, PASSWORD, ATTACKER_NS, TARGET } = process.env;
const BASE = 'http://127.0.0.1:4173';
const WAIT = 180000; // an emulated VM is slow
let n = 0;

function attack(cmd) {
  console.log('attack:', cmd);
  execSync(`ip netns exec ${ATTACKER_NS} ${cmd}`, { stdio: 'ignore', timeout: WAIT });
}

(async () => {
  const browser = await chromium.launch(process.env.CHROME ? { executablePath: process.env.CHROME } : {});
  const page = await browser.newPage({ viewport: { width: 1280, height: 800 }, deviceScaleFactor: 1 });
  const shot = async (name) => {
    await page.screenshot({ path: `${FRAMES}/${String(++n).padStart(2, '0')}-${name}.png` });
    console.log('frame', n, name);
  };

  await page.goto(`${BASE}/login`);
  await page.fill('#username', USERNAME);
  await page.fill('#password', PASSWORD);
  await shot('login');
  await page.click('button:has-text("Sign in")');
  await page.waitForSelector('text=Live updates on', { timeout: WAIT });
  await page.waitForTimeout(3000);
  await shot('dashboard');

  attack(`nmap -sS -Pn -n -p 1-200 --max-retries 0 ${TARGET}`);
  await page.waitForSelector('text=/SYN Scan Detected/', { timeout: WAIT });
  await page.waitForTimeout(2000);
  await shot('syn-scan');

  attack(`nmap -sX -Pn -n -p 1-200 --max-retries 0 ${TARGET}`);
  await page.waitForSelector('text=/Xmas Scan Detected/', { timeout: WAIT });
  await page.waitForTimeout(2000);
  await shot('xmas-scan');

  attack(`timeout 4 hping3 -S --flood --rand-source -p 8080 ${TARGET}`);
  await page.waitForSelector('text=/SYN Flood/', { timeout: WAIT });
  await page.waitForTimeout(2000);
  await shot('syn-flood');

  await page.click('a[href="/alerts"]');
  await page.waitForSelector('text=/SYN Scan Detected/', { timeout: WAIT });
  await page.waitForTimeout(2000);
  await shot('alerts');

  await page.click('text=/SYN Scan Detected/');
  await page.waitForURL(/\/alerts\/\d+/, { timeout: WAIT });
  await page.waitForTimeout(3000);
  await shot('alert-detail');

  await page.click('a[href="/hosts"]');
  await page.waitForTimeout(5000);
  await shot('hosts');

  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
