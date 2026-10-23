
"use strict";

// ==========================================
// RISKGUARD AI - SHARED UTILITIES
// ==========================================

const $ = id => document.getElementById(id);

let linksChecked = 0;
let messagesChecked = 0;
let highRiskCount = 0;
let latestURLScore = null;
let latestMessageScore = null;
let transcript = [];

const CASE_STORAGE_KEY = "riskguard_cases_v1";

function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>"']/g, character => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[character]);
}

function getRiskLevel(score) {
  if (score >= 60) return "high";
  if (score >= 30) return "medium";
  return "low";
}

function riskLabel(level) {
  return `<span class="risk-label ${level}">${level.toUpperCase()} RISK</span>`;
}

function updateDashboard() {
  $("linksChecked").textContent = linksChecked;
  $("messagesChecked").textContent = messagesChecked;
  $("highRiskCount").textContent = highRiskCount;
  $("complaintsCount").textContent = getCases().length;
}

function showError(elementId, message) {
  const element = $(elementId);
  element.className = "result-box risk-medium";
  element.innerHTML =
    `<h3>Unable to continue</h3><p>${escapeHTML(message)}</p>`;
  element.classList.remove("hidden");
}

function renderResult(elementId, title, score, details, recommendation) {
  const element = $(elementId);
  const level = getRiskLevel(score);

  element.className = `result-box risk-${level}`;
  element.innerHTML = `
    ${riskLabel(level)}
    <h3>${escapeHTML(title)}</h3>
    <div class="result-score">${score}/100 risk score</div>
    <ul>
      ${details.map(item => `<li>${escapeHTML(item)}</li>`).join("")}
    </ul>
    <p class="result-recommendation">
      <strong>Recommended action:</strong>
      ${escapeHTML(recommendation)}
    </p>
  `;
  element.classList.remove("hidden");

  if (level === "high") highRiskCount++;

  updateDashboard();
}

function recordCombinedScore(type, score) {
  if (type === "url") latestURLScore = score;
  if (type === "message") latestMessageScore = score;
  updateCombinedAssessment();
}

function updateCombinedAssessment() {
  $("combinedUrlScore").textContent =
    latestURLScore === null ? "—" : `${latestURLScore}/100`;

  $("combinedMessageScore").textContent =
    latestMessageScore === null ? "—" : `${latestMessageScore}/100`;

  const scores = [latestURLScore, latestMessageScore]
    .filter(score => score !== null);

  if (!scores.length) {
    $("combinedRisk").textContent = "Not assessed";
    $("combinedExplanation").textContent =
      "Analyze a link or message to generate a combined assessment.";
    return;
  }

  // Use the highest available score to avoid averaging away a severe risk.
  const overallScore = Math.max(...scores);
  const level = getRiskLevel(overallScore);

  $("combinedRisk").textContent =
    level.charAt(0).toUpperCase() + level.slice(1);

  $("combinedExplanation").textContent =
    `Overall estimated risk: ${overallScore}/100. ` +
    `The highest available URL/message score determines the overall level. ` +
    `This is a heuristic assessment, not a verified fraud determination.`;

  $("combinedRisk").style.color =
    level === "high" ? "#d93445" :
    level === "medium" ? "#d98216" : "#16845b";
}


// ==========================================
// MODULE 1: URL / PHISHING DETECTION
// ==========================================

function analyzeURL(rawURL) {
  const input = rawURL.trim();

  if (!input) {
    return { error: "Please enter a website or order link." };
  }

  // Do not silently treat arbitrary schemes as HTTPS.
  const schemeMatch = input.match(/^([a-zA-Z][a-zA-Z\d+.-]*):/);
  if (schemeMatch && !["http", "https"].includes(schemeMatch[1].toLowerCase())) {
    return { error: "Only HTTP or HTTPS website links can be checked." };
  }

  let parsedURL;

  try {
    parsedURL = new URL(
      schemeMatch ? input : `https://${input}`
    );
  } catch {
    return { error: "Invalid URL. Check the address and try again." };
  }

  if (!["http:", "https:"].includes(parsedURL.protocol)) {
    return { error: "Only HTTP or HTTPS website links can be checked." };
  }

  const hostname = parsedURL.hostname.toLowerCase();

  if (!hostname || !hostname.includes(".") || /\s/.test(hostname)) {
    return { error: "Enter a complete website domain, such as example.com." };
  }

  let score = 0;
  const indicators = [];
  const fullURL = input.toLowerCase();

  if (parsedURL.protocol !== "https:") {
    score += 15;
    indicators.push("The link does not use HTTPS encryption.");
  } else {
    indicators.push("HTTPS is present, but it does not prove the website is genuine.");
  }

  if (hostname.startsWith("xn--") || hostname.includes(".xn--")) {
    score += 25;
    indicators.push("The domain contains an internationalized/punycode label.");
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    score += 25;
    indicators.push("The host is an IP address rather than a typical domain.");
  }

  if (hostname.length > 35) {
    score += 10;
    indicators.push("The hostname is unusually long.");
  }

  const suspiciousWords = [
    "verify-account", "account-verify", "login-secure",
    "free-gift", "claim-prize", "urgent-payment",
    "payment-update", "refund-now", "bank-login",
    "wallet-connect", "password-reset", "kyc-update"
  ];

  const matched = suspiciousWords.filter(word => fullURL.includes(word));

  if (matched.length) {
    score += Math.min(30, matched.length * 10);
    indicators.push("Suspicious keywords: " + matched.join(", ") + ".");
  }

  if (hostname.split(".").length >= 5) {
    score += 10;
    indicators.push("The domain has several subdomain levels.");
  }

  if (parsedURL.port && !["80", "443"].includes(parsedURL.port)) {
    score += 10;
    indicators.push("The URL uses a non-standard port.");
  }

  if (input.length > 150) {
    score += 10;
    indicators.push("The URL is unusually long.");
  }

  // Flag a brand name embedded in a domain, without treating official
  // subdomains as automatically suspicious.
  const brands = [
    "amazon", "flipkart", "paypal", "google",
    "microsoft", "apple", "fedex", "dhl"
  ];

  const labels = hostname.split(".");
  const suspiciousBrand = brands.find(brand =>
    labels.some(label =>
      label.includes(brand) && label !== brand
    )
  );

  if (suspiciousBrand) {
    score += 15;
    indicators.push(
      `The domain contains a brand-like label (${suspiciousBrand}) that should be verified.`
    );
  }

  // URL credentials can be used to disguise the real destination.
  if (parsedURL.username || parsedURL.password) {
    score += 25;
    indicators.push("The URL contains embedded username/password information.");
  }

  score = Math.min(100, score);

  if (indicators.length === 0) {
    indicators.push("No obvious URL warning patterns were detected.");
  }

  let recommendation;

  if (score >= 60) {
    recommendation =
      "Avoid opening the link or entering information. Visit the retailer through its official app or manually typed address.";
  } else if (score >= 30) {
    recommendation =
      "Proceed cautiously. Independently verify the domain and order before paying or signing in.";
  } else {
    recommendation =
      "No major URL warning patterns were detected. Verify the seller and payment details independently.";
  }

  return {
    score,
    indicators,
    domain: hostname,
    protocol: parsedURL.protocol,
    recommendation
  };
}

$("checkLinkBtn").addEventListener("click", () => {
  const analysis = analyzeURL($("websiteLink").value);

  if (analysis.error) {
    showError("linkResult", analysis.error);
    return;
  }

  linksChecked++;
  recordCombinedScore("url", analysis.score);

  renderResult(
    "linkResult",
    "Website Link Assessment",
    analysis.score,
    [
      "Source: " + $("linkSource").value,
      "Domain: " + analysis.domain,
      "Protocol: " + analysis.protocol,
      ...analysis.indicators
    ],
    analysis.recommendation
  );
});

$("demoLinkBtn").addEventListener("click", () => {
  $("websiteLink").value =
    "http://secure-account-verify-free-gift.example.invalid/claim-prize";
  $("linkSource").value = "WhatsApp";
  $("checkLinkBtn").click();
});


// ==========================================
// MODULE 2: MESSAGE ANALYSIS
// ==========================================

function analyzeMessage(message) {
  if (!message.trim()) {
    return { error: "Please enter or extract a message first." };
  }

  let score = 0;
  const indicators = [];
  const text = message.toLowerCase();

  const rules = [
    {
      regex: /\b(otp|one.time.password|verification code)\b/i,
      points: 15,
      reason: "The message refers to an OTP or verification code."
    },
    {
      regex: /\b(password|banking pin|card pin|bank pin)\b/i,
      points: 20,
      reason: "The message mentions confidential credentials."
    },
    {
      regex: /\b(click here|tap here|open this link|verify now)\b/i,
      points: 10,
      reason: "The message urges the recipient to click or verify."
    },
    {
      regex: /\b(urgent|immediately|within \d+ minutes|expires today|act now)\b/i,
      points: 15,
      reason: "The message uses urgency or time pressure."
    },
    {
      regex: /\b(prize|winner|won a|free gift|lottery|lucky draw)\b/i,
      points: 20,
      reason: "The message promises an unexpected reward."
    },
    {
      regex: /\b(refund|delivery|courier|parcel|shipment|order)\b/i,
      points: 5,
      reason: "The message concerns an order or delivery; verify it independently."
    },
    {
      regex: /\b(pay now|processing fee|release fee|customs fee|pay to receive)\b/i,
      points: 20,
      reason: "The message requests a fee or payment."
    },
    {
      regex: /\b(account suspended|account blocked|account locked)\b/i,
      points: 15,
      reason: "The message threatens to suspend or block an account."
    },
    {
      regex: /\b(upi|bank account|credit card|debit card)\b/i,
      points: 10,
      reason: "The message mentions banking or payment details."
    },
    {
      regex: /\b(install this app|download apk|remote access)\b/i,
      points: 25,
      reason: "The message asks for an app installation or device access."
    },
    {
      regex: /\b(bit\.ly|tinyurl\.com|t\.co|is\.gd)\b/i,
      points: 10,
      reason: "The message contains a shortened link."
    },
    {
      regex: /\b(guaranteed income|double your money|easy money|earn \d+ daily)\b/i,
      points: 20,
      reason: "The message promises unusually easy or guaranteed earnings."
    }
  ];

  rules.forEach(rule => {
    if (rule.regex.test(text)) {
      score += rule.points;
      indicators.push(rule.reason);
    }
  });

  const links = message.match(/https?:\/\/[^\s<>"']+|www\.[^\s<>"']+/gi) || [];

  if (links.length) {
    indicators.push(
      `${links.length} web link(s) detected. Check each destination independently.`
    );
  }

  score = Math.min(100, score);

  if (!indicators.length) {
    indicators.push("No listed suspicious-message patterns were detected.");
  }

  let recommendation;

  if (score >= 60) {
    recommendation =
      "Treat the message as highly suspicious. Do not click, pay, install apps, or share OTPs. Verify through the official service.";
  } else if (score >= 30) {
    recommendation =
      "Use caution. Contact the company through verified contact details, not those in the message.";
  } else {
    recommendation =
      "The rule-based score is low, but that does not prove the message is genuine. Verify the sender and order independently.";
  }

  return { score, indicators, recommendation, links };
}

function analyzeAndRenderMessage(message, resultElementId) {
  const analysis = analyzeMessage(message);

  if (analysis.error) {
    showError(resultElementId, analysis.error);
    return null;
  }

  messagesChecked++;
  recordCombinedScore("message", analysis.score);

  renderResult(
    resultElementId,
    "Suspicious Message Assessment",
    analysis.score,
    analysis.indicators,
    analysis.recommendation
  );

  return analysis;
}


// ==========================================
// MODULE 2: SCREENSHOT UPLOAD AND OCR
// ==========================================

let selectedScreenshot = null;
let previewObjectURL = null;

$("screenshotInput").addEventListener("change", () => {
  const file = $("screenshotInput").files[0];

  selectedScreenshot = file || null;

  if (previewObjectURL) {
    URL.revokeObjectURL(previewObjectURL);
    previewObjectURL = null;
  }

  if (!file) {
    $("imagePreviewWrap").classList.add("hidden");
    return;
  }

  if (!file.type.startsWith("image/")) {
    selectedScreenshot = null;
    $("screenshotInput").value = "";
    showError("screenshotResult", "Please select a valid image file.");
    return;
  }

  // Limit browser memory use.
  if (file.size > 8 * 1024 * 1024) {
    selectedScreenshot = null;
    $("screenshotInput").value = "";
    showError("screenshotResult", "Please choose an image smaller than 8 MB.");
    return;
  }

  previewObjectURL = URL.createObjectURL(file);
  $("imagePreview").src = previewObjectURL;
  $("imagePreviewWrap").classList.remove("hidden");
});

$("extractTextBtn").addEventListener("click", async () => {
  if (!selectedScreenshot) {
    showError("screenshotResult", "Upload a screenshot before running OCR.");
    return;
  }

  if (!window.Tesseract) {
    showError(
      "screenshotResult",
      "The OCR library did not load. Check your internet connection and reload the page."
    );
    return;
  }

  const button = $("extractTextBtn");
  button.disabled = true;
  $("ocrProgress").classList.remove("hidden");
  $("ocrProgress").textContent = "Loading OCR engine...";

  try {
    const result = await Tesseract.recognize(
      selectedScreenshot,
      "eng",
      {
        logger: event => {
          if (event.status) {
            const percentage = typeof event.progress === "number"
              ? ` (${Math.round(event.progress * 100)}%)`
              : "";
            $("ocrProgress").textContent = event.status + percentage;
          }
        }
      }
    );

    $("extractedText").value = result.data.text.trim();

    $("ocrProgress").textContent =
      $("extractedText").value
        ? "Text extraction complete. Review the text before analyzing it."
        : "No readable text found. Try a clearer screenshot or paste the message manually.";

  } catch (error) {
    $("ocrProgress").textContent =
      "OCR failed. Try another image or paste the message manually.";
    console.error("OCR error:", error);
  } finally {
    button.disabled = false;
  }
});

$("demoScreenshotBtn").addEventListener("click", () => {
  $("extractedText").value =
    "URGENT! Your parcel is on hold. Verify your account immediately using this link: https://secure-account-verify.example.invalid/claim. Pay a processing fee to release your delivery.";

  $("ocrProgress").classList.remove("hidden");
  $("ocrProgress").textContent =
    "Demo text loaded. This example simulates OCR output; no screenshot was processed.";
});

$("analyzeScreenshotBtn").addEventListener("click", () => {
  const text = $("extractedText").value.trim();

  const analysis = analyzeAndRenderMessage(text, "screenshotResult");
  if (!analysis) return;

  const linksBox = $("extractedLinks");
  const foundLinks = text.match(/https?:\/\/[^\s<>"']+|www\.[^\s<>"']+/gi) || [];

  linksBox.classList.remove("hidden");

  if (!foundLinks.length) {
    linksBox.className = "result-box";
    linksBox.innerHTML =
      "<h3>Extracted URLs</h3><p>No URLs were found in this text.</p>";
    return;
  }

  linksBox.className = "result-box";
  linksBox.innerHTML = `
    <h3>Extracted URLs</h3>
    <p>Review these addresses before visiting them.</p>
    <ul>
      ${foundLinks.map(link =>
        `<li><code>${escapeHTML(link)}</code></li>`
      ).join("")}
    </ul>
    <button id="checkExtractedLinksBtn" class="btn btn-secondary" type="button">
      Check All Extracted Links
    </button>
  `;

  $("checkExtractedLinksBtn").addEventListener("click", () => {
    const results = [];

    foundLinks.forEach(link => {
      const urlAnalysis = analyzeURL(link.replace(/[),.;!?]+$/, ""));

      if (urlAnalysis.error) {
        results.push(`${link}: Unable to parse URL`);
        return;
      }

      linksChecked++;
      recordCombinedScore("url", urlAnalysis.score);
      results.push(
        `${urlAnalysis.domain}: ${urlAnalysis.score}/100 (${getRiskLevel(urlAnalysis.score)} risk)`
      );
    });

    $("linkResult").className = "result-box";
    $("linkResult").innerHTML = `
      <h3>Extracted URL Assessments</h3>
      <ul>${results.map(item => `<li>${escapeHTML(item)}</li>`).join("")}</ul>
      <p>These results use the same URL heuristic rules as Module 1.</p>
    `;
    $("linkResult").classList.remove("hidden");
    updateDashboard();

    $("linkResult").scrollIntoView({ behavior: "smooth", block: "nearest" });
  });
});


// ==========================================
// MODULE 3: COMPLAINT MANAGEMENT
// ==========================================

function getCases() {
  try {
    const saved = JSON.parse(localStorage.getItem(CASE_STORAGE_KEY) || "[]");
    return Array.isArray(saved) ? saved : [];
  } catch {
    return [];
  }
}

function saveCases(cases) {
  try {
    localStorage.setItem(CASE_STORAGE_KEY, JSON.stringify(cases));
    return true;
  } catch {
    showError(
      "complaintFeedback",
      "The browser could not save the case. Local storage may be full or disabled."
    );
    return false;
  }
}

function makeCaseId() {
  const date = new Date();
  const stamp = [
    date.getFullYear(),
    String(date.getMonth() + 1).padStart(2, "0"),
    String(date.getDate()).padStart(2, "0")
  ].join("");

  return `RG-${stamp}-${Math.random().toString(36).slice(2, 7).toUpperCase()}`;
}

function getCaseAdvice(category, description) {
  const text = `${category} ${description}`.toLowerCase();

  if (/fraud|scam|suspicious|otp|phishing/.test(text)) {
    return "Avoid suspicious links and payments. Preserve screenshots, verify through the official platform, and contact your bank promptly if money or credentials were compromised.";
  }

  if (/damaged|defective|broken/.test(text)) {
    return "Photograph the product and packaging, retain the invoice, and submit a return, replacement, or refund request through the official order page.";
  }

  if (/wrong product|incorrect/.test(text)) {
    return "Photograph the delivered item and label, compare it with the order confirmation, and report the mismatch through the official order page.";
  }

  if (/missing/.test(text)) {
    return "Check the package and split shipments, document what arrived, and report the missing item through official support.";
  }

  if (/delivery|delayed/.test(text)) {
    return "Check the official tracking page, confirm the estimated delivery date, and retain your complaint reference if you contact support.";
  }

  if (/refund|replacement|payment/.test(text)) {
    return "Check the order's refund or replacement options in the official app. Do not pay an unexpected fee to release a refund.";
  }

  return "Keep order records and relevant evidence. Contact the retailer through its official support channel and save the complaint reference.";
}

$("complaintForm").addEventListener("submit", event => {
  event.preventDefault();

  const name = $("complaintName").value.trim();
  const category = $("complaintCategory").value;
  const description = $("complaintDescription").value.trim();
  const files = Array.from($("complaintEvidence").files || []);

  if (!name || !description) {
    showError("complaintFeedback", "Enter your name and describe the complaint.");
    return;
  }

  const cases = getCases();

  const newCase = {
    id: makeCaseId(),
    name,
    orderId: $("complaintOrder").value.trim(),
    category,
    priority: $("complaintPriority").value,
    description,
    evidence: files.map(file => file.name),
    advice: getCaseAdvice(category, description),
    status: "Open",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };

  cases.unshift(newCase);

  if (!saveCases(cases)) return;

  $("complaintFeedback").className = "result-box risk-low";
  $("complaintFeedback").innerHTML = `
    <span class="risk-label low">CASE CREATED</span>
    <h3>Complaint submitted successfully</h3>
    <p><strong>Case ID:</strong> ${escapeHTML(newCase.id)}</p>
    <p><strong>Category:</strong> ${escapeHTML(category)}</p>
    <p><strong>Suggested next step:</strong> ${escapeHTML(newCase.advice)}</p>
    <p>Save your case ID for reference. This local demo does not send the complaint to a retailer.</p>
  `;
  $("complaintFeedback").classList.remove("hidden");

  $("complaintForm").reset();
  renderCases();
  updateDashboard();
});

function renderCases() {
  const cases = getCases();
  const container = $("caseList");

  if (!cases.length) {
    container.innerHTML =
      '<p class="empty-state">No cases registered yet. Submit a complaint to create your first case.</p>';
    updateDashboard();
    return;
  }

  container.innerHTML = cases.map(item => {
    const statusClass = item.status.toLowerCase().replace(/\s+/g, "-");

    return `
      <article class="case-card">
        <div class="case-top">
          <div>
            <div class="case-id">${escapeHTML(item.id)}</div>
            <h4>${escapeHTML(item.category)}</h4>
            <p class="case-meta">
              Submitted: ${escapeHTML(new Date(item.createdAt).toLocaleString())}
              · Priority: ${escapeHTML(item.priority)}
            </p>
          </div>
          <span class="status-badge ${escapeHTML(statusClass)}">
            ${escapeHTML(item.status)}
          </span>
        </div>

        <p class="case-meta">
          Customer: ${escapeHTML(item.name)}
          ${item.orderId ? " · Order: " + escapeHTML(item.orderId) : ""}
        </p>

        <p class="case-description">${escapeHTML(item.description)}</p>

        ${item.evidence && item.evidence.length ? `
          <p class="case-files">
            Evidence filenames: ${item.evidence.map(escapeHTML).join(", ")}
          </p>
        ` : ""}

        <p class="result-recommendation">
          <strong>Suggested next step:</strong> ${escapeHTML(item.advice)}
        </p>

        <div class="case-actions">
          <label for="status-${escapeHTML(item.id)}">Update status</label>
          <select id="status-${escapeHTML(item.id)}" data-case-status="${escapeHTML(item.id)}">
            <option value="Open" ${item.status === "Open" ? "selected" : ""}>Open</option>
            <option value="In Progress" ${item.status === "In Progress" ? "selected" : ""}>In Progress</option>
            <option value="Resolved" ${item.status === "Resolved" ? "selected" : ""}>Resolved</option>
          </select>
          <button class="delete-case" type="button" data-delete-case="${escapeHTML(item.id)}">
            Delete case
          </button>
        </div>
      </article>
    `;
  }).join("");

  updateDashboard();
}

$("caseList").addEventListener("change", event => {
  const select = event.target.closest("[data-case-status]");
  if (!select) return;

  const cases = getCases();
  const item = cases.find(entry => entry.id === select.dataset.caseStatus);

  if (!item) return;

  item.status = select.value;
  item.updatedAt = new Date().toISOString();

  if (saveCases(cases)) renderCases();
});

$("caseList").addEventListener("click", event => {
  const button = event.target.closest("[data-delete-case]");
  if (!button) return;

  const id = button.dataset.deleteCase;

  if (!window.confirm(`Delete case ${id}? This cannot be undone.`)) return;

  const cases = getCases().filter(item => item.id !== id);

  if (saveCases(cases)) {
    renderCases();
    $("complaintFeedback").className = "result-box";
    $("complaintFeedback").textContent = `Case ${id} was deleted from this browser.`;
    $("complaintFeedback").classList.remove("hidden");
  }
});

$("exportCasesBtn").addEventListener("click", () => {
  const cases = getCases();

  if (!cases.length) {
    showError("complaintFeedback", "There are no cases to export yet.");
    return;
  }

  downloadText(
    "RiskGuard_AI_Cases.json",
    JSON.stringify(cases, null, 2),
    "application/json;charset=utf-8"
  );
});


// ==========================================
// CUSTOMER SUPPORT CHATBOT
// ==========================================

const chatMessages = $("chatMessages");

function addChatMessage(message, sender) {
  const row = document.createElement("div");
  row.className = `chat-row ${sender}`;

  const avatar = document.createElement("div");
  avatar.className = "chat-avatar";
  avatar.textContent = sender === "bot" ? "🛡️" : "👤";

  const bubble = document.createElement("div");
  bubble.className = "chat-bubble";
  bubble.textContent = message;

  row.append(avatar, bubble);
  chatMessages.appendChild(row);
  chatMessages.scrollTop = chatMessages.scrollHeight;

  transcript.push({
    sender: sender === "bot" ? "RiskGuard Assistant" : "You",
    message
  });
}

function getChatbotReply(userMessage) {
  const text = userMessage.toLowerCase();

  const has = (...words) => words.some(word => text.includes(word));

  if (has("otp", "password", "scam", "fraud", "phishing", "suspicious")) {
    return "If you suspect fraud, do not click unknown links or share credentials.\n\n" +
      "1. Verify the message through the official retailer app or website.\n" +
      "2. Never share your OTP, password, or banking PIN.\n" +
      "3. If you entered credentials on a suspicious site, change the affected password using the official site.\n" +
      "4. If money was lost, contact your bank or payment provider promptly.";
  }

  if (has("extra payment", "asked to pay", "payment link", "pay a fee", "additional fee", "refund fee")) {
    return "Be careful. Do not pay an unexpected fee through a link or personal account to obtain a refund or release a parcel.\n\n" +
      "1. Open the retailer's official app or website yourself.\n" +
      "2. Check your order and refund status.\n" +
      "3. Contact verified customer support.\n" +
      "4. Never share an OTP, password, or banking PIN.";
  }

  if (has("damaged", "broken", "cracked", "defective", "not working", "faulty")) {
    return "I'm sorry your product arrived in that condition.\n\n" +
      "1. Photograph the damage or defect.\n" +
      "2. Keep the packaging and invoice.\n" +
      "3. Open the order in the official retailer app.\n" +
      "4. Request a return, replacement, or refund if available.\n" +
      "5. Save the complaint reference.";
  }

  if (has("wrong product", "wrong item", "different product", "incorrect item")) {
    return "For an incorrect product:\n\n" +
      "1. Photograph the product and shipping label.\n" +
      "2. Compare it with your order confirmation.\n" +
      "3. Report the issue through the official order page.\n" +
      "4. Request a return, replacement, or refund according to the retailer's policy.";
  }

  if (has("missing", "not included", "accessory", "incomplete order")) {
    return "For a missing item:\n\n" +
      "1. Check all package compartments.\n" +
      "2. Check whether the order has multiple shipments.\n" +
      "3. Photograph the contents received.\n" +
      "4. Report the missing item through official support.";
  }

  if (has("seller not responding", "seller isn't replying", "seller is not responding", "seller not replying", "seller ignoring", "no response from seller")) {
    return "If the seller is not responding:\n\n" +
      "1. Send a clear written complaint.\n" +
      "2. Keep screenshots of your messages.\n" +
      "3. Escalate through the platform's official support or grievance process.\n" +
      "4. Save the complaint reference and deadlines.\n\n" +
      "In India, you can explore the National Consumer Helpline at consumerhelpline.gov.in. Check the official website for current contact details.";
  }

  if (has("refund", "replacement", "return my money", "money back", "exchange")) {
    return "To request a refund or replacement:\n\n" +
      "1. Open the official shopping app.\n" +
      "2. Select the relevant order.\n" +
      "3. Choose Return, Refund, Replacement, or Report a Problem if available.\n" +
      "4. Attach evidence when requested.\n" +
      "5. Save the request number.\n\n" +
      "Eligibility depends on the retailer's policy and applicable law. A refund is not guaranteed.";
  }

  if (has("not arrived", "not delivered", "late delivery", "delayed", "delivery problem", "where is my order", "not received")) {
    return "For a delivery issue:\n\n" +
      "1. Check the official order tracking page.\n" +
      "2. Confirm the estimated delivery date.\n" +
      "3. Contact official support if tracking is incorrect or delayed.\n" +
      "4. Save the tracking and complaint reference.\n\n" +
      "Avoid unexpected delivery-fee links from unknown senders.";
  }

  return "I can help with:\n\n" +
    "• Damaged or defective products\n" +
    "• Wrong or missing items\n" +
    "• Refunds and replacements\n" +
    "• Delivery delays\n" +
    "• Sellers who do not respond\n" +
    "• Suspicious links and messages\n\n" +
    "Please describe the issue in a little more detail. Do not share passwords, OTPs, or banking details.";
}

function sendChatMessage(message) {
  const text = message.trim();
  if (!text) return;

  addChatMessage(text, "user");

  const reply = getChatbotReply(text);

  window.setTimeout(() => addChatMessage(reply, "bot"), 200);
}

$("chatForm").addEventListener("submit", event => {
  event.preventDefault();
  const message = $("chatInput").value.trim();
  if (!message) return;

  $("chatInput").value = "";
  sendChatMessage(message);
});

document.querySelectorAll("[data-prompt]").forEach(button => {
  button.addEventListener("click", () => {
    sendChatMessage(button.dataset.prompt || "");
  });
});

$("resetChatBtn").addEventListener("click", () => {
  chatMessages.replaceChildren();
  transcript = [];

  addChatMessage(
    "Hi! Tell me what happened with your order, and I'll suggest practical next steps.",
    "bot"
  );
});

function downloadText(filename, content, mimeType = "text/plain;charset=utf-8") {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");

  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();

  // Delay revocation to allow the browser to begin the download.
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

$("downloadChatBtn").addEventListener("click", () => {
  const content = transcript.map(item =>
    `${item.sender}:\n${item.message}`
  ).join("\n\n------------------------------\n\n");

  downloadText(
    "RiskGuard_AI_Chat_Transcript.txt",
    content || "No chat messages.",
  );
});


// ==========================================
// INITIALIZE
// ==========================================

renderCases();
updateDashboard();
updateCombinedAssessment();
