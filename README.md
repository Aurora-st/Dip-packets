# DPI Engine Dashboard (Python + Node + React)

A small demo project that simulates a DPI (Deep Packet Inspection) engine, exports real-time stats to disk, and exposes them via a Node/Express API to a React dashboard.

## Repository layout

- `engine/` — Python DPI engine (packet tracking + stats/rules files)
  - `dpi_engine.py` — main engine
  - `rules.json` — block lists (IP/domain/app)
  - `stats.json` — continuously updated stats for the UI
- `backend/` — Node/Express API
  - `server.js` — REST endpoints for `stats.json` and `rules.json`
- `frontend/` — React (Vite) dashboard
  - `src/` — UI components
  - visualizes stats and lets you update blocking rules

## Prerequisites

- **Python** 3.x
- **Node.js** 18+ (recommended)
- **npm**
- For live packet capture with `scapy`: network privileges (admin/root) and a working Scapy install.

## How it works

1. The **Python engine** tracks flows and applies the current rules from `engine/rules.json`.
2. Every ~1s, it writes aggregated results to `engine/stats.json`.
3. The **Node backend** serves:
   - `GET /api/stats` → reads `engine/stats.json`
   - `GET /api/rules` → reads `engine/rules.json`
   - `POST /api/rules` → updates `engine/rules.json`
4. The **React frontend** polls the API and renders charts/tables.

## Running the project

### 1) Start the backend API

```bash
cd backend
npm install
npm start
```

- Runs on: `http://localhost:5000`

### 2) Start the Python DPI engine

From repository root:

```bash
cd engine
```

#### Mock mode (recommended for quick testing)

```bash
python dpi_engine.py --mock --step 8
```

This runs the end-to-end engine indefinitely using the built-in mock packet generator.

#### Step-by-step testing

You can run individual stages using `--step` (1..8). Example:

```bash
python dpi_engine.py --mock --step 7
```

#### Live capture mode

```bash
python dpi_engine.py --step 8
```

> Note: live sniffing requires Scapy and sufficient permissions.

### 3) Start the frontend

```bash
cd frontend
npm install
npm run dev
```

Then open the URL printed by Vite (typically `http://localhost:5173`).

## Rules API

The backend reads/writes `engine/rules.json`.

### Get current rules

```bash
curl http://localhost:5000/api/rules
```

### Add or delete a rule

`POST /api/rules` with JSON body:

```json
{
  "action": "add" ,
  "type": "ip|domain|app",
  "value": "8.8.8.8"
}
```

To delete:

```json
{
  "action": "delete",
  "type": "domain",
  "value": "youtube.com"
}
```

## Files used by the engine

- `engine/rules.json`
  - `blocked_ips`: list of strings
  - `blocked_domains`: list of strings
  - `blocked_apps`: list of strings

- `engine/stats.json`
  - updated continuously with counters, top apps, and recent flows

## Notes / limitations

- Domain matching is done as substring checks on extracted SNI.
- App classification is heuristic-based on SNI and ports.
- Live packet capture may fail without the right environment/privileges; mock mode is provided for testing.

## License

Add your license information here.

