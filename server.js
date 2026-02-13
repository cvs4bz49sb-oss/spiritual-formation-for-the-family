const express = require("express");
const path = require("path");
const crypto = require("crypto");
const puppeteer = require("puppeteer");

const app = express();
const PORT = process.env.PORT || 3000;

// HubSpot config
const HUBSPOT_TOKEN = process.env.HUBSPOT_TOKEN;
const HUBSPOT_LIST_ID = process.env.HUBSPOT_LIST_ID || "7195";

// Session secret for signing cookies
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --- Cookie helpers ---
function signValue(val) {
  return val + "." + crypto.createHmac("sha256", SESSION_SECRET).update(val).digest("base64url");
}

function verifySignedValue(signed) {
  if (!signed) return null;
  const idx = signed.lastIndexOf(".");
  if (idx < 0) return null;
  const val = signed.substring(0, idx);
  const expected = signValue(val);
  if (signed === expected) return val;
  return null;
}

function parseCookies(req) {
  const cookies = {};
  const header = req.headers.cookie || "";
  header.split(";").forEach((c) => {
    const [key, ...v] = c.trim().split("=");
    if (key) cookies[key.trim()] = decodeURIComponent(v.join("="));
  });
  return cookies;
}

function isAuthenticated(req) {
  const cookies = parseCookies(req);
  const email = verifySignedValue(cookies.sf_access);
  return !!email;
}

// --- HubSpot API helpers ---
async function findContactByEmail(email) {
  const res = await fetch("https://api.hubapi.com/crm/v3/objects/contacts/search", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${HUBSPOT_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      filterGroups: [{
        filters: [{
          propertyName: "email",
          operator: "EQ",
          value: email.toLowerCase().trim(),
        }],
      }],
      properties: ["email", "firstname", "lastname"],
      limit: 1,
    }),
  });
  const data = await res.json();
  if (data.total > 0) return data.results[0];
  return null;
}

async function isContactInList(contactId) {
  // Use HubSpot Lists v3 API to check membership
  const res = await fetch(
    `https://api.hubapi.com/crm/v3/lists/${HUBSPOT_LIST_ID}/memberships?limit=100`,
    {
      headers: {
        "Authorization": `Bearer ${HUBSPOT_TOKEN}`,
      },
    }
  );

  if (!res.ok) {
    // Fallback: try the legacy v1 API
    return await isContactInListLegacy(contactId);
  }

  const data = await res.json();

  // Check if contact is in results
  const contactIdStr = String(contactId);
  let memberships = data.results || [];
  if (memberships.some((m) => String(m.recordId || m) === contactIdStr)) return true;

  // Paginate if needed
  let next = data.paging?.next?.after;
  while (next) {
    const pageRes = await fetch(
      `https://api.hubapi.com/crm/v3/lists/${HUBSPOT_LIST_ID}/memberships?limit=100&after=${next}`,
      { headers: { "Authorization": `Bearer ${HUBSPOT_TOKEN}` } }
    );
    const pageData = await pageRes.json();
    memberships = pageData.results || [];
    if (memberships.some((m) => String(m.recordId || m) === contactIdStr)) return true;
    next = pageData.paging?.next?.after;
  }

  return false;
}

async function isContactInListLegacy(contactId) {
  // Legacy v1 API: check contact membership
  const res = await fetch(
    `https://api.hubapi.com/contacts/v1/lists/${HUBSPOT_LIST_ID}/contacts/all?count=100&property=email`,
    {
      headers: {
        "Authorization": `Bearer ${HUBSPOT_TOKEN}`,
      },
    }
  );

  if (!res.ok) return false;

  const data = await res.json();
  const contactIdStr = String(contactId);

  let contacts = data.contacts || [];
  if (contacts.some((c) => String(c.vid) === contactIdStr)) return true;

  let hasMore = data["has-more"];
  let offset = data["vid-offset"];

  while (hasMore) {
    const pageRes = await fetch(
      `https://api.hubapi.com/contacts/v1/lists/${HUBSPOT_LIST_ID}/contacts/all?count=100&vidOffset=${offset}&property=email`,
      { headers: { "Authorization": `Bearer ${HUBSPOT_TOKEN}` } }
    );
    const pageData = await pageRes.json();
    contacts = pageData.contacts || [];
    if (contacts.some((c) => String(c.vid) === contactIdStr)) return true;
    hasMore = pageData["has-more"];
    offset = pageData["vid-offset"];
  }

  return false;
}

// --- Verification endpoint ---
app.post("/api/verify", async (req, res) => {
  const email = (req.body.email || "").toLowerCase().trim();

  if (!email) {
    return res.status(400).json({ success: false, message: "Please enter your email address." });
  }

  if (!HUBSPOT_TOKEN) {
    console.error("HUBSPOT_TOKEN not set");
    return res.status(500).json({ success: false, message: "Access verification is not configured." });
  }

  try {
    // Step 1: Find contact in HubSpot
    const contact = await findContactByEmail(email);
    if (!contact) {
      return res.json({
        success: false,
        message: "We couldn\u2019t find that email. Please use the email you signed up with, or subscribe first.",
      });
    }

    // Step 2: Check if contact is in the access list
    const inList = await isContactInList(contact.id);
    if (!inList) {
      return res.json({
        success: false,
        message: "That email doesn\u2019t have access yet. Please subscribe first to get access.",
      });
    }

    // Step 3: Set signed cookie and grant access
    const signed = signValue(email);
    res.setHeader("Set-Cookie", `sf_access=${encodeURIComponent(signed)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60 * 60 * 24 * 90}`);
    return res.json({ success: true });
  } catch (err) {
    console.error("HubSpot verification error:", err);
    return res.status(500).json({ success: false, message: "Something went wrong. Please try again." });
  }
});

// --- Logout endpoint ---
app.get("/api/logout", (req, res) => {
  res.setHeader("Set-Cookie", "sf_access=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
  res.redirect("/");
});

// --- Static files ---
// Serve static files but block direct access to index.html (access control is handled by the catch-all route)
app.use((req, res, next) => {
  if (req.path === "/index.html") {
    return next(); // Let the catch-all route handle it with auth check
  }
  next();
}, express.static(path.join(__dirname, "public"), {
  index: false, // Prevent auto-serving index.html at /
}));

// --- PDF endpoint (requires auth, or internal print request) ---
app.get("/api/pdf", async (req, res) => {
  // Allow internal Puppeteer requests (from localhost)
  const isInternal = req.hostname === "localhost" || req.hostname === "127.0.0.1";
  if (!isInternal && !isAuthenticated(req)) {
    return res.status(401).send("Access denied. Please verify your email first.");
  }

  let browser;
  try {
    browser = await puppeteer.launch({
      headless: true,
      args: ["--no-sandbox", "--disable-setuid-sandbox"],
    });
    const page = await browser.newPage();

    await page.goto(`http://localhost:${PORT}/?print=true`, {
      waitUntil: "networkidle0",
      timeout: 30000,
    });

    // Wait for fonts to load
    await page.evaluateHandle("document.fonts.ready");

    const pdfData = await page.pdf({
      format: "Letter",
      margin: { top: "0.75in", bottom: "0.75in", left: "0.75in", right: "0.75in" },
      printBackground: true,
      displayHeaderFooter: false,
    });

    const pdfBuffer = Buffer.from(pdfData);
    res.set({
      "Content-Type": "application/pdf",
      "Content-Disposition": 'attachment; filename="spiritual-formation-for-the-family.pdf"',
      "Content-Length": pdfBuffer.length,
    });
    res.end(pdfBuffer);
  } catch (err) {
    console.error("PDF generation error:", err);
    res.status(500).send("Failed to generate PDF");
  } finally {
    if (browser) await browser.close();
  }
});

// --- Main page ---
app.get("*", (req, res) => {
  const isPrint = req.query.print === "true";
  const isLocal = req.hostname === "localhost" || req.hostname === "127.0.0.1";

  // Always serve full page for print mode (Puppeteer) from localhost
  if (isPrint && isLocal) {
    return res.sendFile(path.join(__dirname, "public", "index.html"));
  }

  // Check authentication
  if (isAuthenticated(req)) {
    return res.sendFile(path.join(__dirname, "public", "index.html"));
  }

  // Not authenticated — serve the gate page
  return res.sendFile(path.join(__dirname, "public", "gate.html"));
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
