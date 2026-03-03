const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const puppeteer = require("puppeteer");
const cheerio = require("cheerio");
const epub = require("epub-gen-memory").default;

const app = express();
const PORT = process.env.PORT || 3000;

// HubSpot config
const HUBSPOT_TOKEN = process.env.HUBSPOT_TOKEN;
const HUBSPOT_LIST_ID = process.env.HUBSPOT_LIST_ID || "7195";

// Bypass token for direct access links (set in Railway env vars)
const BYPASS_TOKEN = process.env.BYPASS_TOKEN;

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

  if (!res.ok) {
    console.error(`[HubSpot] Contact search failed: ${res.status}`);
    return null;
  }

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
    console.error(`[HubSpot] List v3 API failed: ${res.status}, falling back to legacy`);
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

  if (!res.ok) {
    console.error(`[HubSpot] Legacy API also failed: ${res.status}`);
    return false;
  }

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

// --- ePub content extraction ---
const EPUB_CSS = `
body {
  font-family: Georgia, 'Times New Roman', serif;
  font-size: 1em;
  line-height: 1.75;
  color: #2d2927;
}
h2, h3 {
  font-family: Georgia, serif;
  margin-top: 1.5em;
  margin-bottom: 0.5em;
}
h3 { font-size: 1.2em; margin-top: 1.2em; }
p { margin-bottom: 0.8em; text-indent: 0; }
blockquote {
  margin: 1.2em 1.5em;
  padding-left: 1em;
  border-left: 3px solid #d89f5b;
  font-style: italic;
}
ul, ol { margin: 1em 0; padding-left: 2em; }
li { margin-bottom: 0.4em; }
a { color: #c1593c; text-decoration: underline; }
em { font-style: italic; }
strong { font-weight: bold; }
`;

let cachedChapters = null;

// No sub-sections to merge in this ebook — each section maps 1:1 to a TOC entry
const MERGE_INTO = {};

function getChapters() {
  if (cachedChapters) return cachedChapters;

  const html = fs.readFileSync(
    path.join(__dirname, "public", "index.html"),
    "utf-8"
  );
  const $ = cheerio.load(html);
  const chapterMap = new Map();
  const chapterOrder = [];

  $("section.content-section").each((i, section) => {
    const $section = $(section);
    const rawTitle = $section.find("h2.section-title").first().text();
    const $content = $section.clone();
    $content.find("h2.section-title").first().remove();
    $content.find("p.essay-author").remove();

    const parentTitle = MERGE_INTO[rawTitle] || rawTitle;

    if (chapterMap.has(parentTitle)) {
      chapterMap.get(parentTitle).content +=
        `<h2>${rawTitle}</h2>` + $content.html();
    } else {
      chapterMap.set(parentTitle, {
        title: parentTitle,
        content: $content.html(),
      });
      chapterOrder.push(parentTitle);
    }
  });

  // Title page as first chapter
  const titlePage = {
    title: "",
    excludeFromToc: true,
    beforeToc: true,
    content: `
      <div style="text-align: center; margin-top: 40%; font-family: Georgia, serif;">
        <p style="font-size: 0.85em; letter-spacing: 0.15em; text-transform: uppercase; color: #666; margin-bottom: 2em;">Mere Orthodoxy</p>
        <h1 style="font-size: 2em; line-height: 1.3; margin-bottom: 0.5em;">Spiritual Formation for the Family</h1>
        <p style="font-size: 1em; font-style: italic; color: #555; margin-bottom: 2em;">A Mere Orthodoxy Collection</p>
      </div>
    `,
  };

  cachedChapters = [titlePage, ...chapterOrder.map((t) => chapterMap.get(t))];
  return cachedChapters;
}

// --- ePub endpoint (requires auth, or internal request) ---
app.get("/api/epub", async (req, res) => {
  const isInternal = req.hostname === "localhost" || req.hostname === "127.0.0.1";
  if (!isInternal && !isAuthenticated(req)) {
    return res.status(401).send("Access denied. Please verify your email first.");
  }

  try {
    const chapters = getChapters();

    const epubBuffer = await epub(
      {
        title: "Spiritual Formation for the Family",
        author: "Mere Orthodoxy",
        publisher: "Mere Orthodoxy",
        description: "A Mere Orthodoxy Collection",
        lang: "en",
        css: EPUB_CSS,
        tocTitle: "Contents",
        version: 3,
      },
      chapters
    );

    res.set({
      "Content-Type": "application/epub+zip",
      "Content-Disposition":
        'attachment; filename="spiritual-formation-for-the-family.epub"',
      "Content-Length": epubBuffer.length,
    });
    res.end(epubBuffer);
  } catch (err) {
    console.error("EPUB generation error:", err);
    res.status(500).send("Failed to generate EPUB");
  }
});

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
      args: [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-dev-shm-usage",
        "--disable-gpu",
        "--single-process",
      ],
    });
    const page = await browser.newPage();

    await page.goto(`http://localhost:${PORT}/?print=true`, {
      waitUntil: "networkidle0",
      timeout: 60000,
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

  // Bypass token: e.g. /my-secret-token grants access and sets cookie
  if (BYPASS_TOKEN && req.path === `/${BYPASS_TOKEN}`) {
    const signed = signValue("bypass");
    res.setHeader("Set-Cookie", `sf_access=${encodeURIComponent(signed)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60 * 60 * 24 * 90}`);
    return res.redirect("/");
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
