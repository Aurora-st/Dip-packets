import express from "express";
import cors from "cors";
import { promises as fs } from "fs";
import path from "path";

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// ROOT ENDPOINT
app.get('/', (req, res) => {
  res.json({ 
    status: 'DPI Backend Running',
    message: 'API is live',
    endpoints: ['/api/stats', '/api/rules']
  });
});

// Absolute paths to stats.json and rules.json in the engine directory
const STATS_FILE = "D:\\dpi-engine\\engine\\stats.json";
const RULES_FILE = "D:\\dpi-engine\\engine\\rules.json";

// Helper to read JSON file safely with a fallback
async function readJsonFile(filePath, fallbackValue) {
  try {
    const data = await fs.readFile(filePath, "utf-8");
    return JSON.parse(data);
  } catch (error) {
    // If file doesn't exist yet, return the fallback
    return fallbackValue;
  }
}

// Helper to write JSON file safely (using temp file + rename)
async function writeJsonFile(filePath, data) {
  const tmpPath = `${filePath}.tmp`;
  await fs.writeFile(tmpPath, JSON.stringify(data, null, 2), "utf-8");
  await fs.rename(tmpPath, filePath);
}

// 1. GET /api/stats: Read and serve stats.json
app.get("/api/stats", async (req, res) => {
  const defaultStats = {
    timestamp: Date.now() / 1000,
    packets_per_sec: 0,
    blocked_per_sec: 0,
    total_packets: 0,
    total_blocked: 0,
    top_apps: [],
    active_flows_count: 0,
    recent_flows: []
  };
  const stats = await readJsonFile(STATS_FILE, defaultStats);
  res.json(stats);
});

// 2. GET /api/rules: Read and serve rules.json
app.get("/api/rules", async (req, res) => {
  const defaultRules = {
    blocked_ips: [],
    blocked_domains: [],
    blocked_apps: []
  };
  const rules = await readJsonFile(RULES_FILE, defaultRules);
  res.json(rules);
});

// 3. POST /api/rules: Add or delete rules in rules.json
app.post("/api/rules", async (req, res) => {
  const { action, type, value } = req.body;

  if (!type || !value) {
    return res.status(400).json({ error: "Missing type or value" });
  }

  const defaultRules = {
    blocked_ips: [],
    blocked_domains: [],
    blocked_apps: []
  };
  const rules = await readJsonFile(RULES_FILE, defaultRules);

  // Map the input type (ip, domain, app) to the key in rules.json
  let targetKey;
  if (type === "ip") targetKey = "blocked_ips";
  else if (type === "domain") targetKey = "blocked_domains";
  else if (type === "app") targetKey = "blocked_apps";
  else {
    return res.status(400).json({ error: `Invalid rule type: ${type}` });
  }

  const array = rules[targetKey] || [];

  if (action === "delete") {
    // Remove the rule
    rules[targetKey] = array.filter((item) => item !== value);
    console.log(`[*] Removing rule: Block ${type} = ${value}`);
  } else {
    // Add the rule if it doesn't already exist
    if (!array.includes(value)) {
      array.push(value);
      rules[targetKey] = array;
      console.log(`[*] Adding rule: Block ${type} = ${value}`);
    }
  }

  try {
    await writeJsonFile(RULES_FILE, rules);
    res.json({ success: true, rules });
  } catch (error) {
    console.error("[!] Error writing rules file:", error);
    res.status(500).json({ error: "Failed to write rules to disk" });
  }
});

app.listen(PORT, () => {
  console.log(`[+] Node Express server running on http://localhost:${PORT}`);
});
