# 🛡️ Antigravity DPI — Deep Packet Inspection & Monitor Dashboard

A premium, full-stack Deep Packet Inspection (DPI) engine and real-time visualization dashboard. It sniffs network traffic locally (using Scapy or a high-performance mock packet generator) and streams live telemetry to a cloud dashboard.

### 🌐 Live Deployments
* **Frontend UI (Netlify)**: [https://dpi-packet.netlify.app](https://dpi-packet.netlify.app)
* **Backend API (Render)**: [https://dpi-backend-vmaf.onrender.com](https://dpi-backend-vmaf.onrender.com)

---

## 🚀 Key Features

* **🤖 Animated Robot Mascot (V10)**:
  * Embedded high-definition robot video mascot that automatically plays/moves while active data is being pulled, and pauses gracefully at rest.
  * Runs at a constant, smooth `1.0x` playback rate to prevent buffering or frame lag.
* **〰️ Single Wavy Neon Connector**:
  * A mathematically precise, CSS-animated cyan neon wavy line that oscillates smoothly inside the gap between the mascot card and stats cards.
  * Completely responsive: automatically hides on screens below `900px` to maintain a clean layout.
* **💚 Live Network Health Badge**:
  * Calculates the blocked packet ratio: `Health = blocked_packets / total_packets`.
  * Displays color-coded network threat statuses: `HEALTHY` (green), `SUSPICIOUS` (yellow), or `CRITICAL THREAT` (red).
* **⚠️ Adjustable Safety Threshold Banner**:
  * Real-time range slider to adjust safety alert thresholds (from `50` to `2500` blocked packets).
  * Exceeding the threshold instantly triggers a shaking, neon-red threat warning banner at the top of the screen.
* **📊 CSV Data Log Exporter**:
  * One-click download button to export the entire recent traffic log (IPs, Ports, classification, byte sizes, and block statuses) as a timestamped `.csv` file.
* **🔄 End-to-End Cloud Synchronization**:
  * The local Python engine pushes stats to the Render cloud backend, and pulls block rules down to apply packet blocks instantly at the network card level.

---

## 📁 Repository Layout

```
D:\dpi-engine\
├── engine\
│   ├── dpi_engine.py      # Python DPI engine (sniffs card / decodes TLS SNI / blocks flows)
│   ├── rules.json         # Local rules list (IPs, Domains, and Apps to block)
│   └── stats.json         # Real-time aggregated stats exported locally
├── backend\
│   ├── server.js          # Node.js Express server (stores in-memory stats & manages rules)
│   └── package.json       # Backend dependencies (cors, express)
└── frontend\
    ├── src\
    │   ├── App.jsx        # Premium dashboard with charts, table, and rules configuration
    │   ├── RobotMascot.jsx# HD Video Mascot Controller
    │   └── index.css      # Custom neon styling, glassmorphism card templates, and animations
    └── package.json       # React dependencies (vite, recharts, framer-motion, lucide-react)
```

---

## 🛠️ How to Run the Project (Operational Guide)

You can run the project in **Cloud Mode** (recommended for production) or **Local Mode** (for offline development).

### 1️⃣ Cloud Mode (Render + Netlify + Local Sniffer) — *Recommended*
Use this mode to run the live production website. Since the frontend (Netlify) and backend (Render) are hosted in the cloud, you **only** need to run the Python sniffer locally on your computer to push data up.

1. Open a **PowerShell terminal** in VS Code.
2. Bind the backend environment variable to the Render URL and run the Python engine:
   ```powershell
   $env:DPI_BACKEND_URL="https://dpi-backend-vmaf.onrender.com"
   python D:\dpi-engine\engine\dpi_engine.py --step 8 --mock
   ```
   *(To capture real physical network traffic instead of simulated mock data, run VS Code as Administrator and remove the `--mock` flag).*
3. Open the live dashboard in your browser: [https://dpi-packet.netlify.app](https://dpi-packet.netlify.app)
4. Update rules on the site, and watch the local sniffer apply blocks instantly!

---

### 2️⃣ Local Mode (All components running offline on your computer)
Use this mode for offline testing and local code development.

* **Terminal 1: Python DPI Engine**:
  ```powershell
  python D:\dpi-engine\engine\dpi_engine.py --step 8 --mock
  ```
* **Terminal 2: Node.js Express API**:
  ```powershell
  cd backend
  npm install
  npm start
  ```
  Runs on: `http://localhost:5000`
* **Terminal 3: React Vite Client**:
  ```powershell
  cd frontend
  npm install
  npm run dev
  ```
  Runs on: `http://localhost:5173`

---

## ⚡ API Specifications

### 1. Stats Endpoint
* **GET `/api/stats`**: Serves the cached or disk stats.json payload.
* **POST `/api/stats`**: Pushes stats from the local engine to the backend cache.

### 2. Rules Endpoint
* **GET `/api/rules`**: Returns current IP, domain, and application block lists.
* **POST `/api/rules`**: Adds or deletes rule configurations.
  ```json
  // Body to ADD a rule:
  {
    "action": "add",
    "type": "ip | domain | app",
    "value": "facebook.com"
  }
  // Body to DELETE a rule:
  {
    "action": "delete",
    "type": "domain",
    "value": "facebook.com"
  }
  ```
