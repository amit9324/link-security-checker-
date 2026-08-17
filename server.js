const express = require("express");
const path = require("path");
const dns = require("dns").promises;

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "10kb" }));
app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

function analyzeUrl(input) {
  let url;
  try { url = new URL(input); }
  catch { return { error: "Invalid URL. Enter a complete URL such as https://example.com" }; }

  if (!["http:", "https:"].includes(url.protocol)) {
    return { error: "Only HTTP and HTTPS URLs are supported." };
  }

  const hostname = url.hostname.toLowerCase();
  let score = 0;
  const findings = [];
  const warnings = [];
  const addGood = text => findings.push({ level: "good", text });
  const addWarning = (text, points = 0) => { score += points; findings.push({ level: "warning", text }); warnings.push(text); };

  if (url.protocol === "https:") addGood("HTTPS is enabled.");
  else addWarning("The URL does not use HTTPS.", 20);

  const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4.test(hostname) || hostname.includes(":")) addWarning("The host is an IP address instead of a normal domain name.", 20);
  else addGood("The host uses a domain name.");

  if (input.length > 150) addWarning("The URL is unusually long.", 10);
  else addGood("URL length is within a normal range.");

  if (input.includes("@")) addWarning("The URL contains an @ symbol, which can be used to disguise the real host.", 15);
  if (hostname.includes("xn--")) addWarning("The domain contains Punycode and may represent look-alike characters.", 15);

  const labels = hostname.split(".").filter(Boolean);
  if (labels.length >= 5) addWarning("The domain has an unusually large number of subdomains.", 10);

  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount >= 3) addWarning("The hostname contains many hyphens.", 5);

  const keywords = ["login","signin","verify","verification","password","account","secure","security","update","confirm","wallet","payment","free","bonus","gift","claim","recover","unlock"];
  const lower = input.toLowerCase();
  const foundKeywords = keywords.filter(k => lower.includes(k));
  if (foundKeywords.length) addWarning(`Suspicious keyword(s) detected: ${foundKeywords.join(", ")}.`, Math.min(foundKeywords.length * 4, 16));

  if (/%[0-9a-f]{2}/i.test(input)) addWarning("The URL contains percent-encoded characters.", 5);
  if (url.username || url.password) addWarning("The URL contains embedded user information before the hostname.", 15);

  const suspiciousTlds = new Set([".zip", ".mov", ".click", ".top", ".work", ".country"]);
  const tld = "." + (hostname.split(".").pop() || "");
  if (suspiciousTlds.has(tld)) addWarning(`The domain uses ${tld}, a TLD that can deserve extra caution.`, 5);

  score = Math.min(score, 100);
  let risk, level;
  if (score <= 20) { risk = "LOW RISK"; level = "low"; }
  else if (score <= 50) { risk = "SUSPICIOUS"; level = "medium"; }
  else { risk = "HIGH RISK"; level = "high"; }

  return {
    valid: true, url: url.href, hostname,
    protocol: url.protocol.replace(":", "").toUpperCase(),
    port: url.port || (url.protocol === "https:" ? "443" : "80"),
    score, risk, level, findings, warnings,
    phishingIndicators: foundKeywords,
    path: url.pathname || "/", queryPresent: Boolean(url.search)
  };
}

app.post("/api/check", async (req, res) => {
  const input = String(req.body?.url || "").trim();
  if (!input) return res.status(400).json({ error: "Please enter a URL." });

  const result = analyzeUrl(input);
  if (result.error) return res.status(400).json(result);

  let addresses = [], dnsError = null;
  try { addresses = await dns.lookup(result.hostname, { all: true }); }
  catch { dnsError = "DNS lookup could not be completed."; }

  res.json({
    ...result,
    domain: {
      hostname: result.hostname, protocol: result.protocol, port: result.port,
      path: result.path, dns: addresses.map(a => a.address), dnsError
    },
    note: "This is a heuristic security and phishing-risk assessment. It does not guarantee that a URL is safe or malicious."
  });
});

app.get("/api/health", (req, res) => res.json({ status: "ok" }));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Link Security Checker running on port ${PORT}`);
});
