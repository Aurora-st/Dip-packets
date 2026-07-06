import React, { useState, useEffect } from "react";
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell
} from "recharts";
import {
  Shield,
  Activity,
  Zap,
  Globe,
  Database,
  Trash2,
  Plus,
  AlertTriangle,
  Server,
  Lock,
  ArrowRight
} from "lucide-react";
import RobotMascot from "./RobotMascot";

const API_BASE = import.meta.env.VITE_BACKEND_URL 
  ? `${import.meta.env.VITE_BACKEND_URL}/api`
  : "http://localhost:5000/api";

const generateWavePath = (wavelength, amplitude, height, totalWidth = 2200) => {
  let d = `M 0 ${height}`;
  const cycles = Math.ceil(totalWidth / wavelength);
  for (let i = 0; i < cycles; i++) {
    const x1 = i * wavelength + wavelength / 4;
    const y1 = height - amplitude;
    const x2 = i * wavelength + wavelength / 2;
    const y2 = height;
    d += ` Q ${x1} ${y1} ${x2} ${y2}`;
    
    const x3 = i * wavelength + wavelength;
    const y3 = height;
    d += ` T ${x3} ${y3}`;
  }
  return d;
};

function App() {
  const [stats, setStats] = useState({
    timestamp: Date.now() / 1000,
    packets_per_sec: 0,
    blocked_per_sec: 0,
    total_packets: 0,
    total_blocked: 0,
    top_apps: [],
    active_flows_count: 0,
    recent_flows: []
  });

  const [rules, setRules] = useState({
    blocked_ips: [],
    blocked_domains: [],
    blocked_apps: []
  });

  const [ruleType, setRuleType] = useState("domain");
  const [ruleValue, setRuleValue] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  // Mascot Animation State: "idle" | "loading" | "complete"
  const [mascotState, setMascotState] = useState("idle");

  // Advanced feature state: Safety Threshold configuration
  const [blockedThreshold, setBlockedThreshold] = useState(500);

  // Advanced feature function: Export live log logs to CSV
  const exportStatsToCSV = () => {
    if (stats.recent_flows.length === 0) {
      alert("No traffic logs available to export.");
      return;
    }
    const headers = ["Protocol", "Source IP", "Source Port", "Destination IP", "Destination Port", "Classification", "SNI Host", "Packets", "Bytes", "Status"];
    const rows = stats.recent_flows.map(f => [
      f.protocol,
      f.src_ip,
      f.src_port || "-",
      f.dst_ip,
      f.dst_port || "-",
      f.app,
      f.sni || "-",
      f.packet_count,
      f.byte_count,
      f.blocked ? "BLOCKED" : "ALLOWED"
    ]);

    const csvContent = "data:text/csv;charset=utf-8," 
      + [headers.join(","), ...rows.map(e => e.join(","))].join("\n");
    
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `dpi_traffic_log_${Math.floor(Date.now() / 1000)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Fetch stats and rules
  const fetchData = async () => {
    const startTime = Date.now();
    setMascotState("loading");
    console.log("Fetching from:", API_BASE);
    try {
      const statsRes = await fetch(`${API_BASE}/stats`);
      if (!statsRes.ok) throw new Error(`Stats endpoint failed with status ${statsRes.status}`);
      const statsData = await statsRes.json();
      setStats(statsData);

      const rulesRes = await fetch(`${API_BASE}/rules`);
      if (!rulesRes.ok) throw new Error(`Rules endpoint failed with status ${rulesRes.status}`);
      const rulesData = await rulesRes.json();
      setRules(rulesData);

      setError(null);
      
      // Calculate elapsed time to ensure loading state lasts exactly 600ms
      const elapsed = Date.now() - startTime;
      const loadingDelay = Math.max(0, 600 - elapsed);
      
      setTimeout(() => {
        setMascotState("complete");
        // Hold complete state for 400ms before returning to idle
        setTimeout(() => {
          setMascotState((current) => current === "complete" ? "idle" : current);
        }, 400);
      }, loadingDelay);
      
    } catch (err) {
      console.error("API Error:", err);
      setError(`Backend server disconnected. Fetch failed from ${API_BASE}`);
      setMascotState("idle");
    } finally {
      setLoading(false);
    }
  };

  // Poll API every 1 second
  useEffect(() => {
    fetchData(); // Initial load
    const interval = setInterval(fetchData, 1000);
    return () => clearInterval(interval);
  }, []);

  // Add rule handler
  const handleAddRule = async (e) => {
    e.preventDefault();
    if (!ruleValue.trim()) return;

    try {
      const res = await fetch(`${API_BASE}/rules`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          type: ruleType,
          value: ruleValue.trim()
        })
      });

      if (!res.ok) throw new Error("Failed to add rule");
      const data = await res.json();
      setRules(data.rules);
      setRuleValue("");
    } catch (err) {
      alert("Error adding rule. Check backend status.");
    }
  };

  // Delete rule handler
  const handleDeleteRule = async (type, value) => {
    try {
      const res = await fetch(`${API_BASE}/rules`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action: "delete",
          type,
          value
        })
      });

      if (!res.ok) throw new Error("Failed to delete rule");
      const data = await res.json();
      setRules(data.rules);
    } catch (err) {
      alert("Error deleting rule. Check backend status.");
    }
  };

  const isBlockingActive = stats.total_blocked > 0;

  // Calculate Network Health
  const totalPackets = stats.total_packets || 0;
  const totalBlocked = stats.total_blocked || 0;
  const blockRatio = totalPackets > 0 ? (totalBlocked / totalPackets) * 100 : 0;
  let healthStatus = { label: "HEALTHY", color: "#10b981", class: "indicator-pulse-green", bg: "rgba(16, 185, 129, 0.1)" };
  if (totalBlocked > 0) {
    if (blockRatio > 15) {
      healthStatus = { label: "CRITICAL THREAT", color: "#ef4444", class: "indicator-pulse-red", bg: "rgba(239, 68, 68, 0.1)" };
    } else if (blockRatio > 5) {
      healthStatus = { label: "SUSPICIOUS", color: "#f59e0b", class: "indicator-pulse-yellow", bg: "rgba(245, 158, 11, 0.1)" };
    }
  }

  // Custom tooltips for chart
  const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
      return (
        <div style={{
          backgroundColor: "#161c2d",
          border: "1px solid rgba(255,255,255,0.1)",
          padding: "10px",
          borderRadius: "8px"
        }}>
          <p style={{ margin: 0, fontWeight: 600, color: "#f8fafc" }}>{payload[0].name}</p>
          <p style={{ margin: 0, color: "#6366f1" }}>Packets: {payload[0].value}</p>
        </div>
      );
    }
    return null;
  };

  // Setup data for charting
  const chartData = stats.top_apps.length > 0 
    ? stats.top_apps.map(item => ({ name: item.app, packets: item.packets }))
    : [
        { name: "YouTube", packets: 0 },
        { name: "Facebook", packets: 0 },
        { name: "Google", packets: 0 },
        { name: "Amazon", packets: 0 },
        { name: "Netflix", packets: 0 }
      ];

  return (
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column" }}>
      {/* Navbar Header */}
      <header className="glass-card" style={{
        margin: "20px",
        padding: "15px 30px",
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        borderRadius: "16px"
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: "15px" }}>
          <div style={{
            background: "linear-gradient(135deg, #6366f1, #06b6d4)",
            padding: "10px",
            borderRadius: "12px",
            boxShadow: "0 0 15px rgba(99, 102, 241, 0.4)"
          }}>
            <Shield size={24} style={{ color: "#fff" }} />
          </div>
          <div>
            <h1 style={{ margin: 0, fontSize: "1.5rem", fontWeight: 700, background: "linear-gradient(to right, #ffffff, #94a3b8)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" }}>
              DPI Packet Sentinel
            </h1>
            <p style={{ margin: 0, fontSize: "0.75rem", color: "#64748b" }}>
              Deep Packet Inspection Engine & Real-Time Monitor
            </p>
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "15px" }}>
          {error ? (
            <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "#ef4444", fontSize: "0.85rem", background: "rgba(239, 68, 68, 0.1)", padding: "6px 12px", borderRadius: "20px", border: "1px solid rgba(239, 68, 68, 0.2)" }}>
              <AlertTriangle size={14} />
              Backend Down
            </div>
          ) : (
            <>
              {/* Network Health Indicator */}
              <div style={{ 
                display: "flex", 
                alignItems: "center", 
                gap: "8px", 
                color: healthStatus.color, 
                fontSize: "0.85rem", 
                background: healthStatus.bg, 
                padding: "6px 12px", 
                borderRadius: "20px", 
                border: `1px solid ${healthStatus.color}40`,
                fontWeight: 600
              }}>
                <span className={healthStatus.class}></span>
                Health: {healthStatus.label} ({blockRatio.toFixed(1)}%)
              </div>

              <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "#10b981", fontSize: "0.85rem", background: "rgba(16, 185, 129, 0.1)", padding: "6px 12px", borderRadius: "20px", border: "1px solid rgba(16, 185, 129, 0.2)" }}>
                <span className="indicator-pulse-green"></span>
                Live Capturing
              </div>
            </>
          )}
          <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "0.85rem", color: "#94a3b8" }}>
            <Server size={14} />
            Express :5000
          </div>
        </div>
      </header>

      {/* Main Body */}
      <main style={{ flex: 1, padding: "0 20px 40px 20px", display: "flex", flexDirection: "column", gap: "25px" }}>
        
        {/* Error Alert Box */}
        {error && (
          <div style={{
            background: "rgba(239, 68, 68, 0.15)",
            border: "1px solid rgba(239, 68, 68, 0.3)",
            borderRadius: "12px",
            padding: "15px 20px",
            color: "#fca5a5",
            display: "flex",
            alignItems: "center",
            gap: "12px"
          }}>
            <AlertTriangle size={20} />
            <span>{error}</span>
          </div>
        )}

        {/* Threat Alert Banner */}
        {stats.total_blocked > blockedThreshold && (
          <div className="glass-card glow-blocked animate-urgent-shake" style={{
            background: "rgba(239, 68, 68, 0.15)",
            border: "1px solid rgba(239, 68, 68, 0.4)",
            borderRadius: "12px",
            padding: "15px 20px",
            color: "#fca5a5",
            fontWeight: 800,
            fontSize: "1rem",
            display: "flex",
            alignItems: "center",
            gap: "12px",
            boxShadow: "0 0 20px rgba(239, 68, 68, 0.25)"
          }}>
            <AlertTriangle size={20} style={{ color: "#ef4444" }} />
            <span>THREAT WARNING: Blocked packet count ({stats.total_blocked.toLocaleString()}) has exceeded the safety threshold of {blockedThreshold.toLocaleString()}!</span>
          </div>
        )}

        {/* Mascot & KPIs Top Layout */}
        <section style={{ 
          display: "flex", 
          gap: "20px", 
          alignItems: "center",
          width: "100%",
          position: "relative"
        }}>
          
          {/* Left Column: Robot Mascot Character */}
          <div style={{ flexShrink: 0 }}>
            <RobotMascot state={mascotState} />
          </div>

          {/* Middle Column: Single Wavy Neon Line in Gap Only */}
          <div className="connector-gap" style={{ 
            flex: 1, 
            height: "80px", 
            position: "relative", 
            overflow: "hidden", 
            display: "flex", 
            alignItems: "center" 
          }}>
            {mascotState === "loading" && (
              <svg style={{ width: "100%", height: "100%", overflow: "hidden", pointerEvents: "none" }}>
                <path 
                  d={generateWavePath(80, 15, 40)} 
                  stroke="#00d9ff" 
                  strokeWidth="3" 
                  fill="none" 
                  className="wave-line-animate"
                  style={{ filter: "drop-shadow(0 0 6px rgba(0, 217, 255, 0.8))" }}
                />
              </svg>
            )}
          </div>

          {/* Right Column: Hero KPIs Grid */}
          <div style={{ 
            display: "grid", 
            gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", 
            gap: "20px",
            flex: 3
          }}>
            {/* Card 1: Live Rate */}
            <div className="glass-card" style={{ padding: "20px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <p style={{ margin: 0, fontSize: "0.85rem", color: "#94a3b8", fontWeight: 500 }}>Live Rate</p>
                <h3 style={{ margin: "5px 0", fontSize: "2rem", fontWeight: 700 }}>{stats.packets_per_sec} <span style={{ fontSize: "1rem", color: "#64748b" }}>pps</span></h3>
              </div>
              <div style={{ background: "rgba(99, 102, 241, 0.15)", padding: "12px", borderRadius: "12px", color: "#6366f1" }}>
                <Activity size={24} />
              </div>
            </div>

            {/* Card 2: Total Packets */}
            <div className="glass-card" style={{ padding: "20px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <p style={{ margin: 0, fontSize: "0.85rem", color: "#94a3b8", fontWeight: 500 }}>Total Captured</p>
                <h3 style={{ margin: "5px 0", fontSize: "2rem", fontWeight: 700 }}>{stats.total_packets.toLocaleString()}</h3>
              </div>
              <div style={{ background: "rgba(6, 182, 212, 0.15)", padding: "12px", borderRadius: "12px", color: "#06b6d4" }}>
                <Database size={24} />
              </div>
            </div>

            {/* Card 3: Blocked Packets */}
            <div className={`glass-card ${isBlockingActive ? "glow-blocked" : ""}`} style={{ padding: "20px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <p style={{ margin: 0, fontSize: "0.85rem", color: isBlockingActive ? "#fca5a5" : "#94a3b8", fontWeight: 500 }}>Total Blocked</p>
                <h3 style={{ margin: "5px 0", fontSize: "2rem", fontWeight: 700, color: isBlockingActive ? "#ef4444" : "#f8fafc" }}>
                  {stats.total_blocked.toLocaleString()}
                </h3>
              </div>
              <div style={{
                background: isBlockingActive ? "rgba(239, 68, 68, 0.15)" : "rgba(100, 116, 139, 0.15)",
                padding: "12px",
                borderRadius: "12px",
                color: isBlockingActive ? "#ef4444" : "#64748b"
              }}>
                <Lock size={24} />
              </div>
            </div>

            {/* Card 4: Active Flows */}
            <div className="glass-card" style={{ padding: "20px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <p style={{ margin: 0, fontSize: "0.85rem", color: "#94a3b8", fontWeight: 500 }}>Active Flows</p>
                <h3 style={{ margin: "5px 0", fontSize: "2rem", fontWeight: 700 }}>{stats.active_flows_count}</h3>
              </div>
              <div style={{ background: "rgba(139, 92, 246, 0.15)", padding: "12px", borderRadius: "12px", color: "#8b5cf6" }}>
                <Zap size={24} />
              </div>
            </div>
          </div>
        </section>

        {/* Charts & Rules Grid */}
        <section style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(400px, 1fr))", gap: "25px" }}>
          
          {/* Chart Panel */}
          <div className="glass-card" style={{ padding: "25px", display: "flex", flexDirection: "column" }}>
            <h3 style={{ margin: "0 0 20px 0", fontSize: "1.15rem", display: "flex", alignItems: "center", gap: "10px" }}>
              <Activity size={18} style={{ color: "#6366f1" }} />
              Top Applications By Traffic (Packets)
            </h3>
            
            <div style={{ flex: 1, width: "100%", minHeight: "260px" }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 5 }}>
                  <defs>
                    <linearGradient id="barGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#6366f1" stopOpacity={0.85} />
                      <stop offset="100%" stopColor="#06b6d4" stopOpacity={0.3} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="name" stroke="#64748b" tickLine={false} style={{ fontSize: "0.75rem" }} />
                  <YAxis stroke="#64748b" tickLine={false} style={{ fontSize: "0.75rem" }} />
                  <Tooltip content={<CustomTooltip />} cursor={{ fill: "rgba(255,255,255,0.02)" }} />
                  <Bar dataKey="packets" fill="url(#barGrad)" radius={[6, 6, 0, 0]}>
                    {chartData.map((entry, index) => (
                      <Cell
                        key={`cell-${index}`}
                        fill={
                          entry.name === "Facebook" && isBlockingActive 
                            ? "url(#barGrad)" 
                            : "url(#barGrad)"
                        }
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Rules Configuration Panel */}
          <div className="glass-card" style={{ padding: "25px", display: "flex", flexDirection: "column", gap: "20px" }}>
            <h3 style={{ margin: 0, fontSize: "1.15rem", display: "flex", alignItems: "center", gap: "10px" }}>
              <Lock size={18} style={{ color: "#ef4444" }} />
              Traffic Control & Blocking Rules
            </h3>

            {/* Add Rule Form */}
            <form onSubmit={handleAddRule} style={{ display: "flex", gap: "10px" }}>
              <select
                value={ruleType}
                onChange={(e) => setRuleType(e.target.value)}
                style={{
                  padding: "10px 14px",
                  borderRadius: "10px",
                  fontSize: "0.85rem",
                  cursor: "pointer"
                }}
              >
                <option value="domain">Domain Name</option>
                <option value="ip">IP Address</option>
                <option value="app">Application</option>
              </select>

              <input
                type="text"
                value={ruleValue}
                onChange={(e) => setRuleValue(e.target.value)}
                placeholder={
                  ruleType === "domain"
                    ? "e.g. facebook.com"
                    : ruleType === "ip"
                    ? "e.g. 8.8.8.8"
                    : "e.g. YouTube"
                }
                style={{
                  flex: 1,
                  padding: "10px 16px",
                  borderRadius: "10px",
                  fontSize: "0.85rem"
                }}
              />

              <button
                type="submit"
                style={{
                  background: "linear-gradient(135deg, #ef4444, #b91c1c)",
                  color: "#ffffff",
                  border: "none",
                  padding: "0 18px",
                  borderRadius: "10px",
                  fontSize: "0.85rem",
                  fontWeight: 600,
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  gap: "6px",
                  boxShadow: "0 4px 12px rgba(239, 68, 68, 0.25)",
                  transition: "all 0.2s"
                }}
              >
                <Plus size={16} />
                Block
              </button>
            </form>
            {/* Alert Threshold Setting inside Rules Card */}
            <div style={{
              background: "rgba(255, 255, 255, 0.02)",
              padding: "15px",
              borderRadius: "12px",
              border: "1px solid rgba(255, 255, 255, 0.05)",
              display: "flex",
              flexDirection: "column",
              gap: "8px",
              marginTop: "5px",
              marginBottom: "5px"
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.8rem", color: "#94a3b8", fontWeight: 600 }}>
                <span>ALERT THRESHOLD</span>
                <span style={{ color: "#ef4444" }}>{blockedThreshold} BLOCKED PKTS</span>
              </div>
              <input
                type="range"
                min="50"
                max="2500"
                step="50"
                value={blockedThreshold}
                onChange={(e) => setBlockedThreshold(Number(e.target.value))}
                style={{
                  width: "100%",
                  accentColor: "#ef4444",
                  cursor: "pointer"
                }}
              />
              <span style={{ fontSize: "0.75rem", color: "#64748b" }}>
                Triggers visual warning banner if total blocked packets exceed this limit.
              </span>
            </div>

            {/* Active Rules List */}
            <div style={{ flex: 1, overflowY: "auto", maxHeight: "200px", display: "flex", flexDirection: "column", gap: "12px" }}>
              <p style={{ margin: "0 0 5px 0", fontSize: "0.8rem", color: "#64748b", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.05em" }}>
                Active Block List
              </p>

              {/* Domains list */}
              {rules.blocked_domains.map((domain) => (
                <div key={domain} className="glass-card" style={{ padding: "8px 15px", display: "flex", justifyContent: "space-between", alignItems: "center", background: "rgba(239, 68, 68, 0.04)", borderRadius: "10px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                    <span style={{ fontSize: "0.7rem", fontWeight: 700, padding: "2px 6px", borderRadius: "6px", background: "rgba(239, 68, 68, 0.15)", color: "#fca5a5" }}>DOMAIN</span>
                    <span style={{ fontSize: "0.85rem", color: "#f8fafc" }}>{domain}</span>
                  </div>
                  <button onClick={() => handleDeleteRule("domain", domain)} style={{ background: "none", border: "none", color: "#64748b", cursor: "pointer", display: "flex", padding: "4px" }} title="Remove block">
                    <Trash2 size={15} className="trash-icon" style={{ transition: "color 0.2s" }} onMouseEnter={(e) => e.target.style.color = "#ef4444"} onMouseLeave={(e) => e.target.style.color = "#64748b"} />
                  </button>
                </div>
              ))}

              {/* IPs list */}
              {rules.blocked_ips.map((ip) => (
                <div key={ip} className="glass-card" style={{ padding: "8px 15px", display: "flex", justifyContent: "space-between", alignItems: "center", background: "rgba(239, 68, 68, 0.04)", borderRadius: "10px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                    <span style={{ fontSize: "0.7rem", fontWeight: 700, padding: "2px 6px", borderRadius: "6px", background: "rgba(239, 68, 68, 0.15)", color: "#fca5a5" }}>IP</span>
                    <span style={{ fontSize: "0.85rem", color: "#f8fafc" }}>{ip}</span>
                  </div>
                  <button onClick={() => handleDeleteRule("ip", ip)} style={{ background: "none", border: "none", color: "#64748b", cursor: "pointer", display: "flex", padding: "4px" }}>
                    <Trash2 size={15} style={{ transition: "color 0.2s" }} onMouseEnter={(e) => e.target.style.color = "#ef4444"} onMouseLeave={(e) => e.target.style.color = "#64748b"} />
                  </button>
                </div>
              ))}

              {/* Apps list */}
              {rules.blocked_apps.map((app) => (
                <div key={app} className="glass-card" style={{ padding: "8px 15px", display: "flex", justifyContent: "space-between", alignItems: "center", background: "rgba(239, 68, 68, 0.04)", borderRadius: "10px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                    <span style={{ fontSize: "0.7rem", fontWeight: 700, padding: "2px 6px", borderRadius: "6px", background: "rgba(239, 68, 68, 0.15)", color: "#fca5a5" }}>APP</span>
                    <span style={{ fontSize: "0.85rem", color: "#f8fafc" }}>{app}</span>
                  </div>
                  <button onClick={() => handleDeleteRule("app", app)} style={{ background: "none", border: "none", color: "#64748b", cursor: "pointer", display: "flex", padding: "4px" }}>
                    <Trash2 size={15} style={{ transition: "color 0.2s" }} onMouseEnter={(e) => e.target.style.color = "#ef4444"} onMouseLeave={(e) => e.target.style.color = "#64748b"} />
                  </button>
                </div>
              ))}

              {rules.blocked_domains.length === 0 && rules.blocked_ips.length === 0 && rules.blocked_apps.length === 0 && (
                <div style={{ padding: "30px", textAlign: "center", color: "#64748b", fontSize: "0.85rem" }}>
                  No active rules. All traffic allowed.
                </div>
              )}
            </div>
          </div>

        </section>

        {/* Live Active Flows Table */}
        <section className="glass-card" style={{ padding: "25px", display: "flex", flexDirection: "column" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "20px" }}>
            <h3 style={{ margin: 0, fontSize: "1.15rem", display: "flex", alignItems: "center", gap: "10px" }}>
              <Zap size={18} style={{ color: "#8b5cf6" }} />
              Live Flow Monitor (DPI Log)
            </h3>
            
            <div style={{ display: "flex", alignItems: "center", gap: "15px" }}>
              <button 
                onClick={exportStatsToCSV}
                style={{
                  background: "rgba(99, 102, 241, 0.15)",
                  border: "1px solid rgba(99, 102, 241, 0.3)",
                  color: "#a5b4fc",
                  padding: "6px 12px",
                  borderRadius: "8px",
                  fontSize: "0.8rem",
                  fontWeight: 600,
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  gap: "6px",
                  transition: "all 0.2s"
                }}
                onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(99, 102, 241, 0.3)"; e.currentTarget.style.borderColor = "#6366f1"; }}
                onMouseLeave={(e) => { e.currentTarget.style.background = "rgba(99, 102, 241, 0.15)"; e.currentTarget.style.borderColor = "rgba(99, 102, 241, 0.3)"; }}
              >
                <Database size={12} />
                Export CSV
              </button>
              
              <span style={{ fontSize: "0.75rem", color: "#64748b" }}>
                Showing up to 15 most recent connections
              </span>
            </div>
          </div>

          <div style={{ overflowX: "auto", width: "100%" }}>
            <table style={{ width: "100%", minWidth: "800px", textAlign: "left" }}>
              <thead>
                <tr>
                  <th style={{ padding: "12px 16px", borderRadius: "10px 0 0 10px", fontSize: "0.8rem", color: "#94a3b8" }}>PROTOCOL</th>
                  <th style={{ padding: "12px 16px", fontSize: "0.8rem", color: "#94a3b8" }}>SOURCE</th>
                  <th style={{ padding: "12px 16px", fontSize: "0.8rem", color: "#94a3b8" }}></th>
                  <th style={{ padding: "12px 16px", fontSize: "0.8rem", color: "#94a3b8" }}>DESTINATION</th>
                  <th style={{ padding: "12px 16px", fontSize: "0.8rem", color: "#94a3b8" }}>CLASSIFICATION</th>
                  <th style={{ padding: "12px 16px", fontSize: "0.8rem", color: "#94a3b8" }}>SNI HOST</th>
                  <th style={{ padding: "12px 16px", fontSize: "0.8rem", color: "#94a3b8" }}>PACKETS</th>
                  <th style={{ padding: "12px 16px", fontSize: "0.8rem", color: "#94a3b8" }}>BYTES</th>
                  <th style={{ padding: "12px 16px", borderRadius: "0 10px 10px 0", fontSize: "0.8rem", color: "#94a3b8" }}>STATUS</th>
                </tr>
              </thead>
              <tbody>
                {stats.recent_flows.map((flow, index) => {
                  const flowId = `${flow.src_ip}:${flow.src_port}-${flow.dst_ip}:${flow.dst_port}`;
                  return (
                    <tr key={flowId + index} style={{ transition: "background 0.2s" }} onMouseEnter={(e) => e.currentTarget.style.background = "rgba(255,255,255,0.01)"} onMouseLeave={(e) => e.currentTarget.style.background = "none"}>
                      <td style={{ padding: "14px 16px" }}>
                        <span style={{
                          fontSize: "0.75rem",
                          fontWeight: 700,
                          padding: "3px 8px",
                          borderRadius: "6px",
                          background: flow.protocol === "TCP" ? "rgba(99, 102, 241, 0.15)" : "rgba(139, 92, 246, 0.15)",
                          color: flow.protocol === "TCP" ? "#a5b4fc" : "#c084fc"
                        }}>
                          {flow.protocol}
                        </span>
                      </td>
                      <td style={{ padding: "14px 16px", fontSize: "0.85rem", color: "#f1f5f9" }}>
                        {flow.src_ip}<span style={{ color: "#64748b" }}>:{flow.src_port || "-"}</span>
                      </td>
                      <td style={{ padding: "14px 16px", color: "#64748b" }}>
                        <ArrowRight size={14} />
                      </td>
                      <td style={{ padding: "14px 16px", fontSize: "0.85rem", color: "#f1f5f9" }}>
                        {flow.dst_ip}<span style={{ color: "#64748b" }}>:{flow.dst_port || "-"}</span>
                      </td>
                      <td style={{ padding: "14px 16px", fontSize: "0.85rem", color: "#38bdf8", fontWeight: 500 }}>
                        {flow.app}
                      </td>
                      <td style={{ padding: "14px 16px", fontSize: "0.85rem", color: "#94a3b8", fontFamily: "monospace" }}>
                        {flow.sni || "-"}
                      </td>
                      <td style={{ padding: "14px 16px", fontSize: "0.85rem", color: "#f1f5f9" }}>
                        {flow.packet_count}
                      </td>
                      <td style={{ padding: "14px 16px", fontSize: "0.85rem", color: "#f1f5f9" }}>
                        {flow.byte_count.toLocaleString()}
                      </td>
                      <td style={{ padding: "14px 16px" }}>
                        {flow.blocked ? (
                          <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                            <span className="indicator-pulse-red"></span>
                            <span style={{ fontSize: "0.75rem", fontWeight: 700, color: "#ef4444" }} title={flow.block_reason}>
                              BLOCKED
                            </span>
                          </div>
                        ) : (
                          <span style={{ fontSize: "0.75rem", fontWeight: 700, color: "#10b981" }}>
                            ALLOWED
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })}

                {stats.recent_flows.length === 0 && (
                  <tr>
                    <td colSpan="9" style={{ padding: "40px", textAlign: "center", color: "#64748b", fontSize: "0.85rem" }}>
                      No active network flows detected. Start the Python DPI Engine.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

      </main>
    </div>
  );
}

export default App;
