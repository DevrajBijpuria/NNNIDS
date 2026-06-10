import { useState, useEffect, useRef, useCallback } from 'react';
import { Link } from 'react-router-dom';
import RiskScoreCard from '../components/RiskScoreCard';
import TrafficGraph from '../components/TrafficGraph';
import ActionPanel from '../components/ActionPanel';
import LiveAlertFeed from '../components/LiveAlertFeed';
import {
  getStatus, getAlerts, getActions, getVerifications, getRisk, getTraffic,
  getStats, startMonitor, stopMonitor,
} from '../services/api';

const WS_URL = 'ws://localhost:8000/ws';
const POLL_MS = 3000;

function requestNotif() {
  if ('Notification' in window && Notification.permission === 'default')
    Notification.requestPermission();
}

function pushNotif(title, body, severity) {
  if (!('Notification' in window) || Notification.permission !== 'granted') return;
  const pfx = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🟢' }[severity] ?? '🔵';
  new Notification(`${pfx} NNNIDS — ${title}`, { body });
}

const SEV_TOAST = {
  CRITICAL: 'border-[#ff3b30] bg-[rgba(255,59,48,0.08)] text-[#ff6961]',
  HIGH:     'border-[#ff9500] bg-[rgba(255,149,0,0.08)]  text-[#ffb340]',
  MEDIUM:   'border-[#ffd60a] bg-[rgba(255,214,10,0.06)] text-[#ffd60a]',
  LOW:      'border-[#30d158] bg-[rgba(48,209,88,0.06)]  text-[#4cd964]',
};

const StatCard = ({ label, value, color, sub }) => (
  <div className="panel flex flex-col gap-1">
    <p className="text-[10px] text-gray-600 uppercase tracking-widest">{label}</p>
    <p className="text-3xl font-bold mono count-up" style={{ color }}>{value}</p>
    {sub && <p className="text-[10px] text-gray-600">{sub}</p>}
  </div>
);

const Dashboard = () => {
  const [status, setStatus]               = useState({ running: false, monitoring: false, capture_mode: '…', interface: '' });
  const [riskData, setRiskData]           = useState({ current_risk: 0, risk_level: 'LOW', trend: 'STABLE', history: [] });
  const [alerts, setAlerts]               = useState([]);
  const [actions, setActions]             = useState([]);
  const [verifications, setVerifications] = useState([]);
  const [features, setFeatures]           = useState([]);
  const [toasts, setToasts]               = useState([]);
  const [blockedIps, setBlockedIps]       = useState([]);
  const [dbStats, setDbStats]             = useState({ total_alerts: 0, total_actions: 0, critical_alerts: 0, executed_actions: 0, mitigated_threats: 0 });
  const [error, setError]                 = useState(null);
  const [backendDown, setBackendDown]     = useState(false);
  const [toggling, setToggling]           = useState(false);
  const seen = useRef(new Set());

  const fetchData = useCallback(async () => {
    try {
      const [statusRes, riskRes, alertsRes, actionsRes, verifRes, trafficRes, statsRes] = await Promise.all([
        getStatus(), getRisk(), getAlerts(), getActions(), getVerifications(), getTraffic(), getStats(),
      ]);
      setStatus(statusRes.data);
      setRiskData(riskRes.data);
      setActions(actionsRes.data.actions || []);
      setVerifications(verifRes.data.verifications || []);
      setFeatures(trafficRes.data.features || []);
      setDbStats(statsRes.data.database || {});
      setBlockedIps(statsRes.data.blocked_ips || []);
      setBackendDown(false);

      const incoming = alertsRes.data.alerts || [];
      const fresh = incoming.filter(a => !seen.current.has(a.id));
      fresh.forEach(a => {
        seen.current.add(a.id);
        pushNotif(a.attack_name, `${a.src_ip} — ${a.severity}`, a.severity);
      });
      if (fresh.length) {
        setToasts(fresh.slice(0, 3));
        setTimeout(() => setToasts([]), 5000);
      }
      setAlerts(incoming);
    } catch {
      setBackendDown(true);
    }
  }, []);

  // ── WebSocket — real-time push from backend ──────────────────────────────
  useEffect(() => {
    let ws;
    let retryTimer;

    const connect = () => {
      ws = new WebSocket(WS_URL);

      ws.onmessage = ({ data }) => {
        try {
          const msg = JSON.parse(data);

          if (msg.type === 'blocked_ips' && Array.isArray(msg.blocked_ips)) {
            setBlockedIps(msg.blocked_ips);
          }

          if (msg.type === 'alerts' && Array.isArray(msg.alerts)) {
            setAlerts(prev => {
              const existingIds = new Set(prev.map(a => a.id));
              const fresh = msg.alerts.filter(a => !existingIds.has(a.id));
              fresh.forEach(a => {
                if (!seen.current.has(a.id)) {
                  seen.current.add(a.id);
                  pushNotif(a.attack_name, `${a.src_ip} — ${a.severity}`, a.severity);
                }
              });
              if (fresh.length) {
                setToasts(fresh.slice(0, 3));
                setTimeout(() => setToasts([]), 5000);
              }
              return fresh.length ? [...fresh, ...prev] : prev;
            });
          }

          if (msg.type === 'action') {
            setActions(prev => [msg.action, ...prev].slice(0, 50));
          }

          if (msg.type === 'verifications' && Array.isArray(msg.verifications)) {
            setVerifications(prev => [...msg.verifications, ...prev].slice(0, 50));
          }

          if (msg.type === 'risk') {
            setRiskData(prev => ({
              ...prev,
              current_risk: msg.current_risk ?? prev.current_risk,
              risk_level:   msg.risk_level   ?? prev.risk_level,
              trend:        msg.trend         ?? prev.trend,
            }));
          }

          if (msg.type === 'monitor_tick' || msg.type === 'pipeline') {
            // Lightweight status refresh on every pipeline tick
            getStatus().then(r => setStatus(r.data)).catch(() => {});
          }

          if (msg.type === 'error') {
            setBackendDown(false); // backend is up, just an internal error
          }
        } catch {
          // ignore malformed frames
        }
      };

      ws.onerror = () => {};
      ws.onclose = () => {
        // Auto-reconnect after 3 s
        retryTimer = setTimeout(connect, 3000);
      };
    };

    connect();
    return () => {
      clearTimeout(retryTimer);
      if (ws) ws.close();
    };
  }, []);

  // ── HTTP polling (slower fallback / stats sync) ───────────────────────────
  useEffect(() => {
    requestNotif();
    fetchData();
    const id = setInterval(fetchData, POLL_MS);
    return () => clearInterval(id);
  }, [fetchData]);

  const toggleMonitor = async () => {
    if (toggling) return;
    setError(null);
    setToggling(true);
    try {
      status.monitoring ? await stopMonitor() : await startMonitor(10, 2);
      await fetchData();
    } catch (e) {
      setError(e.response?.data?.detail || e.message);
    } finally {
      setToggling(false);
    }
  };

  const isLive     = status.capture_mode === 'live';
  const monitoring = status.monitoring;
  const scanning   = status.running;
  const critCount  = dbStats.critical_alerts ?? alerts.filter(a => a.severity === 'CRITICAL').length;
  const mitigated  = dbStats.mitigated_threats ?? verifications.filter(v => v.status === 'MITIGATED').length;
  const riskColor  = riskData.current_risk >= 75 ? '#ff3b30' : riskData.current_risk >= 50 ? '#ff9500' : riskData.current_risk >= 25 ? '#ffd60a' : '#30d158';

  return (
    <div className="min-h-screen bg-[#03060f] bg-grid">
      <div className="sticky top-0 z-50 bg-[#03060f]/80 backdrop-blur border-b border-[#1a2540]">
        <div className="max-w-[1600px] mx-auto px-6 py-3 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-blue-600 flex items-center justify-center text-white font-black text-sm shadow-lg shadow-blue-600/40">N³</div>
            <div>
              <p className="text-sm font-bold text-white leading-none">NNNIDS</p>
              <p className="text-[10px] text-gray-600 leading-none">Self-Healing AI IDS</p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {backendDown ? (
              <a
                href="https://github.com/NihalGeek/NNNIDS/tree/main/backend"
                target="_blank"
                rel="noopener noreferrer"
                className="badge badge-critical animate-pulse cursor-pointer hover:bg-red-900/60 transition-colors"
                title="Backend is offline — click to view setup instructions on GitHub"
              >
                ⚠ BACKEND OFFLINE — Click to set up
              </a>
            ) : (
              <>
                <span className={`badge ${isLive ? 'badge-ok' : 'badge-medium'}`}>
                  {isLive ? '◉ LIVE' : '◌ SYNTHETIC'}
                </span>
                <span
                  className={`badge ${monitoring ? 'badge-ok' : 'badge-critical'}`}
                  style={monitoring ? { animation: 'ping 2s ease-in-out infinite', borderColor: '#30d158' } : undefined}
                >
                  {monitoring ? (scanning ? '⟳ SCANNING' : '⟳ MONITORING') : '◌ IDLE'}
                </span>
                {critCount > 0 && (
                  <span className="badge badge-critical animate-pulse">{critCount} CRITICAL</span>
                )}
              </>
            )}
          </div>

          {status.interface && (
            <p className="hidden lg:block text-[10px] text-gray-700 mono truncate max-w-xs" title={status.interface}>
              iface {status.interface.replace(/\\Device\\NPF_/, '').slice(0, 38)}
            </p>
          )}

          <button
            id="btn-toggle-monitor"
            onClick={toggleMonitor}
            disabled={toggling || backendDown}
            className={`px-5 py-2 rounded-lg text-sm font-semibold transition-all shrink-0 ${
              toggling || backendDown ? 'bg-slate-800 text-gray-600 cursor-not-allowed'
              : monitoring ? 'bg-red-600/80 hover:bg-red-500 text-white shadow-lg shadow-red-600/20'
              : 'bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-600/30'
            }`}
          >
            {toggling ? '…' : monitoring ? '⏹ Stop' : '▶ Start Monitoring'}
          </button>
        </div>
      </div>

      <div className="bg-[#040810] border-b border-[#1a2540]">
        <div className="max-w-[1600px] mx-auto px-6 flex gap-1">
          <Link
            to="/"
            className="text-[11px] font-semibold px-4 py-2.5 border-b-2 border-blue-500 text-blue-400 transition-colors"
          >
            📊 Overview
          </Link>
          <Link
            to="/alerts"
            className="text-[11px] font-semibold px-4 py-2.5 border-b-2 border-transparent text-gray-600 hover:text-gray-400 transition-colors"
          >
            🚨 Active Alerts {critCount > 0 && <span className="ml-1 text-[9px] bg-red-700 text-white px-1.5 py-0.5 rounded-full">{critCount}</span>}
          </Link>
        </div>
      </div>

      <div className="max-w-[1600px] mx-auto px-6 py-6 space-y-5">
        {error && (
          <div className="p-3 rounded-lg border border-orange-700 bg-orange-900/20 text-orange-400 text-sm flex justify-between items-center">
            <span>⚠ {error}</span>
            <button onClick={() => setError(null)} className="text-orange-600 hover:text-white ml-4">✕</button>
          </div>
        )}

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard label="Current Risk"  value={`${Math.round(riskData.current_risk)}%`} color={riskColor} sub={riskData.risk_level} />
          <StatCard label="Total Alerts"  value={dbStats.total_alerts ?? alerts.length}   color="#ff6961" sub={critCount > 0 ? `${critCount} critical` : 'none critical'} />
          <StatCard label="Actions Taken" value={dbStats.total_actions ?? actions.length} color="#ffb340" sub={dbStats.executed_actions != null ? `${dbStats.executed_actions} executed` : undefined} />
          <StatCard label="Mitigated"     value={mitigated}     color="#30d158" sub={dbStats.mitigated_threats != null ? `of ${dbStats.total_actions ?? 0} actions` : undefined} />
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-[280px_1fr_260px] gap-5">
          <RiskScoreCard riskData={riskData} />
          <TrafficGraph riskHistory={riskData.history || []} features={features} />
          <LiveAlertFeed alerts={alerts} />
        </div>

        <ActionPanel actions={actions} blockedIps={blockedIps} />
      </div>
    </div>
  );
};

export default Dashboard;