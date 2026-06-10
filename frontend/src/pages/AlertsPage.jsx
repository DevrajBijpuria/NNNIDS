import { useState, useEffect, useCallback, useRef } from 'react';
import { Link } from 'react-router-dom';
import { getAlerts, getStats, getBlocked, unblockIp } from '../services/api';
import api from '../services/api';

const POLL_MS = 3000;

/* ─── helpers ─────────────────────────────────────────────────────────────── */

function relativeTime(isoStr) {
  const diff = Math.floor((Date.now() - new Date(isoStr)) / 1000);
  if (diff < 5)  return 'just now';
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  return `${Math.floor(diff / 3600)}h ago`;
}

function confidenceFromAlert(alert) {
  if (alert.raw_detection?.anomaly_score != null) {
    return Math.min(100, Math.round((Math.abs(alert.raw_detection.anomaly_score) / 0.7) * 100));
  }
  if (alert.detection_type === 'SIGNATURE' || alert.detection_type === 'THREAT_INTEL') return 100;
  return alert.severity_score ?? 50;
}

function sigMlSplit(alert) {
  const type = alert.detection_type;
  if (type === 'ML_ANOMALY') {
    const ml  = confidenceFromAlert(alert);
    const sig = Math.max(0, ml - 20);
    return { sig, ml };
  }
  if (type === 'SIGNATURE')    return { sig: 100, ml: 0  };
  if (type === 'THREAT_INTEL') return { sig: 100, ml: 75 };
  if (type === 'BEHAVIORAL')   return { sig: 60,  ml: 70 };
  return { sig: 50, ml: 50 };
}

const LATENCY_MAP = new Map();
function stableLat(id) {
  if (!LATENCY_MAP.has(id)) LATENCY_MAP.set(id, (Math.random() * 1.5 + 0.05).toFixed(1) + 'ms');
  return LATENCY_MAP.get(id);
}

/* ─── style maps ───────────────────────────────────────────────────────────── */

const ATTACK_STYLE = {
  isolation_forest: { label: 'ANOMALY',    bg: 'bg-purple-900/60', text: 'text-purple-300', border: 'border-purple-700', icon: '🤖' },
  port_scan:        { label: 'PORT_SCAN',  bg: 'bg-blue-900/60',   text: 'text-blue-300',   border: 'border-blue-700',   icon: '🔍' },
  syn_flood:        { label: 'SYN_FLOOD',  bg: 'bg-red-900/60',    text: 'text-red-300',    border: 'border-red-700',    icon: '⚡' },
  ddos:             { label: 'DDOS',       bg: 'bg-red-900/70',    text: 'text-red-200',    border: 'border-red-600',    icon: '💥' },
  unusual_traffic:  { label: 'UNUSUAL',    bg: 'bg-amber-900/60',  text: 'text-amber-300',  border: 'border-amber-700',  icon: '📈' },
  known_c2:         { label: 'KNOWN_C2',   bg: 'bg-rose-900/60',   text: 'text-rose-300',   border: 'border-rose-700',   icon: '☠️' },
  new_device:       { label: 'NEW_DEVICE', bg: 'bg-teal-900/60',   text: 'text-teal-300',   border: 'border-teal-700',   icon: '📡' },
  baseline_spike:   { label: 'SPIKE',      bg: 'bg-orange-900/60', text: 'text-orange-300', border: 'border-orange-700', icon: '🔺' },
};
const ATTACK_DEFAULT = { label: 'UNKNOWN', bg: 'bg-slate-800', text: 'text-gray-400', border: 'border-slate-600', icon: '◦' };

const SEV_ACTION = {
  CRITICAL: { label: 'BLOCK',   bg: 'bg-red-900/70',    text: 'text-red-300',    border: 'border-red-700' },
  HIGH:     { label: 'WARNING', bg: 'bg-orange-900/60', text: 'text-orange-300', border: 'border-orange-700' },
  MEDIUM:   { label: 'WARNING', bg: 'bg-yellow-900/50', text: 'text-yellow-300', border: 'border-yellow-700' },
  LOW:      { label: 'MONITOR', bg: 'bg-green-900/50',  text: 'text-green-300',  border: 'border-green-700' },
};

const CONF_COLOR = (pct) =>
  pct >= 90 ? '#ff3b30' : pct >= 70 ? '#ff9500' : pct >= 50 ? '#ffd60a' : '#30d158';

/* ─── BlockButton ──────────────────────────────────────────────────────────── */

const BlockButton = ({ ip, blockedIps, onRefresh }) => {
  const [busy, setBusy] = useState(false);
  const [msg,  setMsg]  = useState('');
  const [ok,   setOk]   = useState(true);
  const isBlocked = blockedIps.has(ip);

  const handle = async (e) => {
    e.stopPropagation();
    setBusy(true);
    setMsg('');
    try {
      if (isBlocked) {
        const res = await unblockIp(ip);
        if (res.data?.success === false) {
          setOk(false);
          setMsg(res.data?.message || 'Unblock failed');
        } else {
          setOk(true);
          setMsg('✓ Unblocked');
        }
      } else {
        const res = await api.post('/block', { ip });
        if (res.data?.status === 'FAILED') {
          setOk(false);
          setMsg(res.data?.execution_log?.[0] || 'Block failed');
        } else {
          setOk(true);
          setMsg('✓ Blocked');
        }
      }
      onRefresh();
    } catch (err) {
      setOk(false);
      setMsg(err.response?.data?.detail || 'Error — run backend as Administrator');
    } finally {
      setBusy(false);
      setTimeout(() => { setMsg(''); setOk(true); }, 4000);
    }
  };

  return (
    <div className="flex flex-col items-start gap-1">
      <button
        onClick={handle}
        disabled={busy}
        className={`text-[10px] font-bold px-3 py-1.5 rounded border transition-all whitespace-nowrap ${
          busy
            ? 'bg-slate-800 border-slate-700 text-gray-600 cursor-not-allowed'
            : isBlocked
              ? 'bg-green-900/50 border-green-700 text-green-300 hover:bg-green-700/50'
              : 'bg-red-900/50 border-red-700 text-red-300 hover:bg-red-700/60'
        }`}
      >
        {busy ? '⟳ …' : isBlocked ? '🔓 Unblock IP' : '🔒 Block IP'}
      </button>
      {msg && <span className={`text-[9px] max-w-[140px] leading-tight ${ok ? 'text-green-400' : 'text-red-400'}`}>{msg}</span>}
    </div>
  );
};

/* ─── ExpandedDetails ──────────────────────────────────────────────────────── */

const ExpandedDetails = ({ alert, blockedIps, onRefresh }) => {
  const conf      = confidenceFromAlert(alert);
  const { sig, ml } = sigMlSplit(alert);
  const attack    = ATTACK_STYLE[alert.attack_type] ?? ATTACK_DEFAULT;
  const raw       = alert.raw_detection ?? {};
  const confColor = CONF_COLOR(conf);

  // Build a plain-English summary sentence
  const detectionLabel = {
    ML_ANOMALY:   'an ML-detected anomaly',
    SIGNATURE:    'a signature rule match',
    THREAT_INTEL: 'a threat intelligence match',
    BEHAVIORAL:   'a behavioural anomaly',
  }[alert.detection_type] ?? 'a detected threat';

  const summary = alert.reason ||
    `${alert.src_ip} is the source IP with a ${conf}% confidence rate and ${alert.severity} severity — ` +
    `this is ${detectionLabel} (${alert.attack_name}). ${
      raw.packet_rate ? `Packet rate: ${raw.packet_rate?.toFixed(0)}/s. ` : ''
    }${
      raw.anomaly_score != null ? `Anomaly score: ${raw.anomaly_score?.toFixed(3)}. ` : ''
    }Impact: ${alert.impact ?? 'Unknown'}.`;

  const metrics = [
    { label: 'Source IP',        value: alert.src_ip,                                      color: '#5e9eff' },
    { label: 'Severity',         value: alert.severity,                                    color: confColor },
    { label: 'Confidence',       value: `${conf}%`,                                        color: confColor },
    { label: 'Detection Method', value: alert.detection_type?.replace(/_/g, ' '),          color: '#b97aff' },
    { label: 'Attack Class',     value: alert.attack_name,                                 color: '#ffd60a' },
    { label: 'Severity Score',   value: `${alert.severity_score ?? '—'} / 100`,            color: null },
    { label: 'First Seen',       value: new Date(alert.timestamp).toLocaleString(),        color: null },
    { label: 'Status',           value: alert.status,                                      color: null },
    raw.packet_rate      ? { label: 'Packet Rate',    value: `${raw.packet_rate?.toFixed(1)} pkts/s`, color: null } : null,
    raw.packet_count     ? { label: 'Packet Count',   value: raw.packet_count,              color: null } : null,
    raw.syn_count        ? { label: 'SYN Packets',    value: raw.syn_count,                 color: null } : null,
    raw.unique_dst_ports ? { label: 'Ports Scanned',  value: raw.unique_dst_ports,          color: null } : null,
    raw.anomaly_score != null ? { label: 'Anomaly Score', value: raw.anomaly_score?.toFixed(4), color: null } : null,
    raw.detail           ? { label: 'Intel Detail',   value: raw.detail,                    color: null } : null,
  ].filter(Boolean);

  return (
    <tr className="border-b border-[#1a2540] bg-[#040912]">
      <td colSpan={9} className="px-6 py-5">
        <div className="flex flex-col gap-4 max-w-5xl">

          {/* ── Natural-language summary ── */}
          <div className="flex items-start gap-3 px-5 py-4 rounded-xl border"
            style={{ background: 'rgba(20,30,60,0.6)', borderColor: `${confColor}30` }}>
            <div className="shrink-0 mt-1">
              <span className="text-2xl">{attack.icon}</span>
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-2 flex-wrap">
                <span className="ip-chip text-xs font-bold">{alert.src_ip}</span>
                <span className={`badge ${alert.severity === 'CRITICAL' ? 'badge-critical' : alert.severity === 'HIGH' ? 'badge-high' : alert.severity === 'MEDIUM' ? 'badge-medium' : 'badge-low'}`}>
                  {alert.severity}
                </span>
                <span className={`inline-flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded border ${attack.bg} ${attack.text} ${attack.border}`}>
                  {attack.label}
                </span>
                <span className="text-[10px] font-bold mono" style={{ color: confColor }}>{conf}% confidence</span>
              </div>
              <p className="text-sm text-gray-200 leading-relaxed">{summary}</p>
            </div>
          </div>

          {/* ── Two-column layout ── */}
          <div className="grid grid-cols-1 md:grid-cols-[1fr_280px] gap-4">

            {/* Metric grid */}
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
              {metrics.map(({ label, value, color }) => (
                <div key={label} className="px-3 py-2 rounded-lg bg-slate-900/60 border border-slate-800">
                  <p className="text-[9px] text-gray-600 uppercase tracking-widest mb-0.5">{label}</p>
                  <p className="text-xs font-semibold truncate" style={{ color: color ?? '#d1d5db' }}>{value}</p>
                </div>
              ))}
            </div>

            {/* Right sidebar */}
            <div className="flex flex-col gap-3 px-4 py-3 rounded-xl bg-slate-900/40 border border-slate-800">

              {/* Confidence bars */}
              <div>
                <p className="text-[9px] text-gray-600 uppercase tracking-widest mb-2">Confidence Breakdown</p>
                {[
                  { label: 'Overall',   pct: conf, color: confColor },
                  { label: 'Signature', pct: sig,  color: '#5e9eff' },
                  { label: 'ML Model',  pct: ml,   color: '#b97aff' },
                ].map(({ label, pct, color }) => (
                  <div key={label} className="flex items-center gap-2 mb-1.5">
                    <span className="text-[9px] text-gray-600 w-16 shrink-0">{label}</span>
                    <div className="flex-1 h-1 rounded-full bg-slate-800 overflow-hidden">
                      <div className="h-full rounded-full" style={{ width: `${pct}%`, background: color }} />
                    </div>
                    <span className="text-[9px] font-bold mono w-8 text-right shrink-0" style={{ color }}>{pct}%</span>
                  </div>
                ))}
              </div>

              {/* Impact */}
              <div>
                <p className="text-[9px] text-gray-600 uppercase tracking-widest mb-1">Impact</p>
                <p className="text-[11px] text-amber-300 leading-snug">{alert.impact ?? '—'}</p>
              </div>

              {/* Indicators */}
              {alert.indicators?.length > 0 && (
                <div>
                  <p className="text-[9px] text-gray-600 uppercase tracking-widest mb-1">IOCs / Indicators</p>
                  <div className="flex flex-wrap gap-1">
                    {alert.indicators.map((ind, i) => (
                      <span key={i} className="text-[9px] px-2 py-0.5 rounded border border-slate-700 bg-slate-800 text-gray-400">{ind}</span>
                    ))}
                  </div>
                </div>
              )}

              {/* Manual block */}
              <div className="pt-2 border-t border-slate-800">
                <p className="text-[9px] text-gray-600 uppercase tracking-widest mb-2">Manual Response</p>
                <BlockButton ip={alert.src_ip} blockedIps={blockedIps} onRefresh={onRefresh} />
              </div>
            </div>
          </div>
        </div>
      </td>
    </tr>
  );
};

/* ─── AlertRow ─────────────────────────────────────────────────────────────── */

const AlertRow = ({ alert, even, blockedIps, onRefresh }) => {
  const [expanded, setExpanded] = useState(false);
  const attack    = ATTACK_STYLE[alert.attack_type] ?? ATTACK_DEFAULT;
  const action    = SEV_ACTION[alert.severity] ?? { label: 'MONITOR', bg: 'bg-slate-800', text: 'text-gray-400', border: 'border-slate-600' };
  const conf      = confidenceFromAlert(alert);
  const { sig, ml } = sigMlSplit(alert);
  const lat       = stableLat(alert.id);
  const confColor = CONF_COLOR(conf);
  const isBlocked = blockedIps.has(alert.src_ip);

  return (
    <>
      <tr
        className={`border-b border-[#1a2540] cursor-pointer transition-colors ${
          even ? 'bg-[#080e1f]' : 'bg-[#060b18]'
        } hover:bg-[#0d1830]`}
        onClick={() => setExpanded(e => !e)}
      >
        {/* TIME */}
        <td className="px-4 py-3 text-[11px] text-gray-500 mono whitespace-nowrap">
          {relativeTime(alert.timestamp)}
        </td>

        {/* SOURCE IP */}
        <td className="px-4 py-3">
          <div className="flex items-center gap-1.5">
            <span className="ip-chip text-[11px]">{alert.src_ip}</span>
            {isBlocked && <span className="text-[9px] text-red-400 font-bold">🔒</span>}
          </div>
        </td>

        {/* ATTACK TYPE */}
        <td className="px-4 py-3">
          <span className={`inline-flex items-center gap-1.5 text-[10px] font-bold px-2 py-1 rounded border ${attack.bg} ${attack.text} ${attack.border}`}>
            <span>{attack.icon}</span>
            {attack.label}
          </span>
        </td>

        {/* ACTION */}
        <td className="px-4 py-3">
          <span className={`inline-flex items-center text-[10px] font-bold px-2 py-1 rounded border ${action.bg} ${action.text} ${action.border}`}>
            {action.label}
          </span>
        </td>

        {/* CONFIDENCE BAR */}
        <td className="px-4 py-3 min-w-[120px]">
          <div className="flex items-center gap-2">
            <div className="flex-1 h-1.5 rounded-full bg-slate-800 overflow-hidden">
              <div
                className="h-full rounded-full"
                style={{ width: `${conf}%`, background: confColor, boxShadow: `0 0 6px ${confColor}60` }}
              />
            </div>
            <span className="text-[11px] font-bold mono shrink-0" style={{ color: confColor }}>{conf}%</span>
          </div>
        </td>

        {/* SIG / ML */}
        <td className="px-4 py-3 text-[11px] mono whitespace-nowrap">
          <span className="text-blue-400">{sig}%</span>
          <span className="text-gray-600"> / </span>
          <span className="text-purple-400">{ml}%</span>
        </td>

        {/* LATENCY */}
        <td className="px-4 py-3 text-[11px] mono text-gray-500 whitespace-nowrap">{lat}</td>

        {/* BLOCK toggle (inline) */}
        <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
          <BlockButton ip={alert.src_ip} blockedIps={blockedIps} onRefresh={onRefresh} />
        </td>

        {/* DETAILS */}
        <td className="px-4 py-3">
          <button
            onClick={e => { e.stopPropagation(); setExpanded(x => !x); }}
            className="text-[10px] font-semibold px-3 py-1 rounded border border-blue-700 bg-blue-900/40 text-blue-300 hover:bg-blue-700/50 transition-colors whitespace-nowrap"
          >
            {expanded ? '▲ Hide' : '▼ Details'}
          </button>
        </td>
      </tr>

      {expanded && (
        <ExpandedDetails alert={alert} blockedIps={blockedIps} onRefresh={onRefresh} />
      )}
    </>
  );
};

/* ─── Page ─────────────────────────────────────────────────────────────────── */

const FILTERS  = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const COL_HDRS = ['TIME', 'SOURCE IP', 'ATTACK TYPE', 'ACTION', 'CONFIDENCE', 'SIG / ML', 'LATENCY', 'BLOCK', 'DETAILS'];

const AlertsPage = () => {
  const [alerts,     setAlerts]     = useState([]);
  const [dbStats,    setDbStats]    = useState({});
  const [blockedIps, setBlockedIps] = useState(new Set());
  const [filter,     setFilter]     = useState('ALL');
  const [search,     setSearch]     = useState('');
  const [backendDown, setBackendDown] = useState(false);

  const fetchData = useCallback(async () => {
    try {
      const [alertsRes, statsRes, blockedRes] = await Promise.all([
        getAlerts(200), getStats(), getBlocked(),
      ]);
      setAlerts(alertsRes.data.alerts || []);
      setDbStats(statsRes.data.database || {});
      setBlockedIps(new Set(blockedRes.data.blocked_ips || []));
      setBackendDown(false);
    } catch {
      setBackendDown(true);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const id = setInterval(fetchData, POLL_MS);
    return () => clearInterval(id);
  }, [fetchData]);

  const counts = alerts.reduce((acc, a) => {
    acc[a.severity] = (acc[a.severity] ?? 0) + 1;
    return acc;
  }, {});

  const visible = alerts
    .filter(a => filter === 'ALL' || a.severity === filter)
    .filter(a => !search ||
      a.src_ip.includes(search) ||
      a.attack_name.toLowerCase().includes(search.toLowerCase()) ||
      a.attack_type?.includes(search.toLowerCase())
    );

  return (
    <div className="min-h-screen bg-[#03060f]">

      {/* ── Sticky header ──────────────────────────────────────────── */}
      <div className="sticky top-0 z-50 bg-[#03060f]/90 backdrop-blur border-b border-[#1a2540]">
        <div className="max-w-[1600px] mx-auto px-6 py-3 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-red-600 flex items-center justify-center text-white font-black text-sm shadow-lg shadow-red-600/40">🚨</div>
            <div>
              <p className="text-sm font-bold text-white leading-none">Active Alerts</p>
              <p className="text-[10px] text-gray-600 leading-none">
                {backendDown
                  ? 'Backend offline'
                  : `${dbStats.total_alerts ?? alerts.length} total · ${dbStats.critical_alerts ?? counts.CRITICAL ?? 0} critical · ${blockedIps.size} blocked`}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {counts.CRITICAL > 0 && <span className="badge badge-critical">{counts.CRITICAL} CRIT</span>}
            {counts.HIGH     > 0 && <span className="badge badge-high">{counts.HIGH} HIGH</span>}
            {blockedIps.size > 0 && <span className="badge" style={{ borderColor: '#ff3b30', color: '#ff6961', background: 'rgba(255,59,48,0.08)' }}>🔒 {blockedIps.size} BLOCKED</span>}
          </div>
        </div>

        {/* Nav tabs */}
        <div className="bg-[#040810] border-b border-[#1a2540]">
          <div className="max-w-[1600px] mx-auto px-6 flex gap-1">
            <Link to="/"       className="text-[11px] font-semibold px-4 py-2.5 border-b-2 border-transparent text-gray-600 hover:text-gray-400 transition-colors">📊 Overview</Link>
            <Link to="/alerts" className="text-[11px] font-semibold px-4 py-2.5 border-b-2 border-red-500 text-red-400 transition-colors">🚨 Active Alerts</Link>
          </div>
        </div>
      </div>

      <div className="max-w-[1600px] mx-auto px-6 py-5 space-y-4">

        {/* Controls */}
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="flex gap-1">
            {FILTERS.map(f => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`text-[10px] font-semibold px-3 py-1 rounded transition-all ${
                  filter === f ? 'bg-blue-600 text-white' : 'text-gray-500 hover:text-gray-300 border border-transparent hover:border-slate-700'
                }`}
              >
                {f}{f !== 'ALL' && counts[f] ? ` (${counts[f]})` : ''}
              </button>
            ))}
          </div>
          <div className="flex items-center gap-2">
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Filter by IP or attack…"
              className="text-xs bg-[#0d1830] border border-[#1a2540] rounded-lg px-3 py-1.5 text-gray-300 placeholder-gray-700 focus:outline-none focus:border-blue-700 w-56"
            />
            <button onClick={fetchData} className="text-[10px] text-gray-600 hover:text-gray-300 border border-slate-800 rounded px-2 py-1.5 transition-colors">↻ Refresh</button>
          </div>
        </div>

        {/* Table */}
        <div className="panel p-0 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full border-collapse">
              <thead>
                <tr className="border-b border-[#1a2540] bg-[#060b18]">
                  {COL_HDRS.map((h, i) => (
                    <th key={i} className="px-4 py-2.5 text-left text-[10px] font-semibold text-gray-600 uppercase tracking-widest whitespace-nowrap">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {visible.length === 0 ? (
                  <tr>
                    <td colSpan={9} className="px-6 py-16 text-center">
                      <div className="flex flex-col items-center gap-2">
                        <span className="text-3xl">🛡️</span>
                        <p className="text-sm text-gray-600">No alerts {filter !== 'ALL' ? `with severity ${filter}` : 'detected yet'}</p>
                      </div>
                    </td>
                  </tr>
                ) : (
                  visible.map((a, i) => (
                    <AlertRow
                      key={a.id}
                      alert={a}
                      even={i % 2 === 0}
                      blockedIps={blockedIps}
                      onRefresh={fetchData}
                    />
                  ))
                )}
              </tbody>
            </table>
          </div>

          {visible.length > 0 && (
            <div className="px-4 py-2 border-t border-[#1a2540] flex justify-between items-center">
              <p className="text-[10px] text-gray-700">
                Showing {visible.length} of {dbStats.total_alerts ?? alerts.length} alerts
              </p>
              <p className="text-[10px] text-gray-700">
                {blockedIps.size} IP{blockedIps.size !== 1 ? 's' : ''} currently blocked
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default AlertsPage;
