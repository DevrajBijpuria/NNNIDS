/* ExpertPanel.jsx — Expert-level threat intelligence & diagnostics panel */

const SEV_COLOR  = { CRITICAL: '#ff3b30', HIGH: '#ff9500', MEDIUM: '#ffd60a', LOW: '#30d158' };
const TYPE_COLOR = { SIGNATURE: '#5e9eff', ML_ANOMALY: '#b97aff', THREAT_INTEL: '#ff6b6b', BEHAVIORAL: '#ffa554' };
const TYPE_ICON  = { SIGNATURE: '✦', ML_ANOMALY: '⬡', THREAT_INTEL: '⬥', BEHAVIORAL: '◈' };

const ATTACK_LABELS = {
  isolation_forest: 'ML Anomaly',
  port_scan:        'Port Scan',
  syn_flood:        'SYN Flood',
  ddos:             'DDoS',
  unusual_traffic:  'Unusual Traffic',
  known_c2:         'Known C2',
  new_device:       'New Device',
  baseline_spike:   'Baseline Spike',
};

/* ─── Mini bar ─────────────────────────────────────────────────────────────── */
const MiniBar = ({ value, max, color }) => (
  <div className="flex-1 h-1 rounded-full bg-slate-800 overflow-hidden">
    <div
      className="h-full rounded-full transition-all duration-700"
      style={{ width: `${max > 0 ? Math.round((value / max) * 100) : 0}%`, background: color }}
    />
  </div>
);

/* ─── Section heading ───────────────────────────────────────────────────────── */
const SectionHead = ({ label }) => (
  <p className="text-[9px] font-semibold text-gray-600 uppercase tracking-widest mb-2">{label}</p>
);

/* ─── Stat micro-card ───────────────────────────────────────────────────────── */
const Micro = ({ label, value, color }) => (
  <div className="px-3 py-2.5 rounded-lg bg-slate-900/60 border border-slate-800 flex flex-col gap-0.5">
    <p className="text-[9px] text-gray-600 uppercase tracking-widest">{label}</p>
    <p className="text-sm font-bold mono" style={{ color: color ?? '#d1d5db' }}>{value}</p>
  </div>
);

/* ─── Top Threat Actors ──────────────────────────────────────────────────────── */
const TopThreats = ({ alerts }) => {
  // Aggregate per IP
  const ipMap = {};
  for (const a of alerts) {
    if (!ipMap[a.src_ip]) ipMap[a.src_ip] = { ip: a.src_ip, count: 0, maxSev: 'LOW', types: new Set(), score: 0 };
    const e = ipMap[a.src_ip];
    e.count++;
    e.types.add(a.attack_type);
    e.score = Math.max(e.score, a.severity_score ?? 0);
    const rank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    if ((rank[a.severity] ?? 0) > (rank[e.maxSev] ?? 0)) e.maxSev = a.severity;
  }

  const sorted = Object.values(ipMap)
    .sort((a, b) => b.count - a.count)
    .slice(0, 6);

  const maxCount = sorted[0]?.count ?? 1;

  if (sorted.length === 0) {
    return <p className="text-xs text-gray-700 italic">No threat actors detected yet</p>;
  }

  return (
    <div className="space-y-2">
      {sorted.map(({ ip, count, maxSev, types, score }) => (
        <div key={ip} className="flex items-center gap-2">
          <span className="ip-chip text-[10px] w-[112px] shrink-0 truncate">{ip}</span>
          <MiniBar value={count} max={maxCount} color={SEV_COLOR[maxSev]} />
          <span className="text-[10px] mono font-bold shrink-0 w-8 text-right" style={{ color: SEV_COLOR[maxSev] }}>
            {count}
          </span>
          <span className="text-[9px] text-gray-600 shrink-0">{maxSev[0]}</span>
        </div>
      ))}
    </div>
  );
};

/* ─── Detection breakdown ───────────────────────────────────────────────────── */
const DetectionBreakdown = ({ alerts }) => {
  const counts = {};
  for (const a of alerts) counts[a.detection_type] = (counts[a.detection_type] ?? 0) + 1;
  const total = alerts.length || 1;
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]);

  if (entries.length === 0) return <p className="text-xs text-gray-700 italic">No detections yet</p>;

  return (
    <div className="space-y-2">
      {entries.map(([type, cnt]) => (
        <div key={type} className="flex items-center gap-2">
          <span className="text-[10px] w-5 shrink-0" style={{ color: TYPE_COLOR[type] ?? '#888' }}>
            {TYPE_ICON[type] ?? '◦'}
          </span>
          <span className="text-[10px] text-gray-400 w-[88px] shrink-0">{type?.replace('_', ' ')}</span>
          <MiniBar value={cnt} max={total} color={TYPE_COLOR[type] ?? '#888'} />
          <span className="text-[10px] mono text-gray-500 shrink-0 w-12 text-right">
            {cnt} ({Math.round((cnt / total) * 100)}%)
          </span>
        </div>
      ))}
    </div>
  );
};

/* ─── Attack taxonomy ───────────────────────────────────────────────────────── */
const AttackBreakdown = ({ alerts }) => {
  const counts = {};
  for (const a of alerts) counts[a.attack_type] = (counts[a.attack_type] ?? 0) + 1;
  const total = alerts.length || 1;
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 5);

  if (entries.length === 0) return <p className="text-xs text-gray-700 italic">No attack data yet</p>;

  return (
    <div className="space-y-2">
      {entries.map(([type, cnt]) => (
        <div key={type} className="flex items-center gap-2">
          <span className="text-[10px] text-gray-400 w-[110px] shrink-0 truncate">
            {ATTACK_LABELS[type] ?? type}
          </span>
          <MiniBar value={cnt} max={total} color="#5e9eff" />
          <span className="text-[10px] mono text-gray-500 shrink-0 w-8 text-right">{cnt}</span>
        </div>
      ))}
    </div>
  );
};

/* ─── Response summary ──────────────────────────────────────────────────────── */
const ResponseSummary = ({ actions }) => {
  const counts = { EXECUTED: 0, FAILED: 0, MONITORING: 0, PENDING: 0 };
  const byType = {};
  for (const a of actions) {
    counts[a.status] = (counts[a.status] ?? 0) + 1;
    byType[a.action_type] = (byType[a.action_type] ?? 0) + 1;
  }
  const total = actions.length || 1;

  return (
    <div className="space-y-2">
      {[
        { label: 'Executed',   key: 'EXECUTED',   color: '#30d158' },
        { label: 'Failed',     key: 'FAILED',     color: '#ff3b30' },
        { label: 'Monitoring', key: 'MONITORING', color: '#5e9eff' },
      ].map(({ label, key, color }) => (
        <div key={key} className="flex items-center gap-2">
          <span className="text-[10px] text-gray-400 w-16 shrink-0">{label}</span>
          <MiniBar value={counts[key]} max={total} color={color} />
          <span className="text-[10px] mono shrink-0 w-8 text-right" style={{ color }}>
            {counts[key]}
          </span>
        </div>
      ))}
    </div>
  );
};

/* ─── Live traffic features ─────────────────────────────────────────────────── */
const TrafficFeatures = ({ features }) => {
  if (!features?.length) {
    return <p className="text-xs text-gray-700 italic">Start monitoring to capture traffic features</p>;
  }

  const topIps = [...features]
    .sort((a, b) => (b.packet_rate ?? 0) - (a.packet_rate ?? 0))
    .slice(0, 5);

  const maxRate = topIps[0]?.packet_rate ?? 1;

  return (
    <div className="space-y-2">
      {topIps.map((f, i) => (
        <div key={i} className="flex items-center gap-2">
          <span className="ip-chip text-[10px] w-[112px] shrink-0 truncate">{f.src_ip}</span>
          <MiniBar value={f.packet_rate ?? 0} max={maxRate} color="#ffd60a" />
          <div className="text-[9px] mono text-gray-500 shrink-0 text-right">
            <span className="text-yellow-500 font-bold">{(f.packet_rate ?? 0).toFixed(0)}</span>
            <span className="text-gray-700">/s</span>
          </div>
        </div>
      ))}
    </div>
  );
};

/* ─── Severity heatmap ──────────────────────────────────────────────────────── */
const SeverityDistribution = ({ alerts, dbStats }) => {
  const sevs  = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const total = alerts.length || 1;
  const counts = sevs.reduce((acc, s) => {
    acc[s] = alerts.filter(a => a.severity === s).length;
    return acc;
  }, {});

  return (
    <div className="flex gap-2 h-16 items-end">
      {sevs.map(s => {
        const h = Math.max(8, Math.round((counts[s] / total) * 60));
        return (
          <div key={s} className="flex flex-col items-center gap-1 flex-1">
            <span className="text-[9px] mono" style={{ color: SEV_COLOR[s] }}>{counts[s]}</span>
            <div
              className="w-full rounded-t-sm transition-all duration-700"
              style={{ height: `${h}px`, background: SEV_COLOR[s], opacity: 0.8 }}
            />
            <span className="text-[8px] text-gray-700">{s[0]}</span>
          </div>
        );
      })}
    </div>
  );
};

/* ─── Main Panel ────────────────────────────────────────────────────────────── */
const ExpertPanel = ({ alerts = [], actions = [], features = [], dbStats = {} }) => {
  const execRate = actions.length > 0
    ? Math.round((actions.filter(a => a.status === 'EXECUTED').length / actions.length) * 100)
    : 0;
  const failRate = actions.length > 0
    ? Math.round((actions.filter(a => a.status === 'FAILED').length / actions.length) * 100)
    : 0;
  const critPct = alerts.length > 0
    ? Math.round((alerts.filter(a => a.severity === 'CRITICAL').length / alerts.length) * 100)
    : 0;

  const uniqueIps   = new Set(alerts.map(a => a.src_ip)).size;
  const uniqueTypes = new Set(alerts.map(a => a.attack_type)).size;

  return (
    <div className="panel">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <span className="text-blue-400 text-base">🔬</span>
          <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-widest">
            Threat Intelligence Diagnostics
          </h2>
        </div>
        <span className="text-[9px] text-gray-700 mono">expert view</span>
      </div>

      {/* KPI row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-5">
        <Micro label="Unique IPs"    value={uniqueIps}         color="#5e9eff" />
        <Micro label="Attack Types"  value={uniqueTypes}       color="#b97aff" />
        <Micro label="Exec Rate"     value={`${execRate}%`}    color="#30d158" />
        <Micro label="Critical %"    value={`${critPct}%`}     color="#ff3b30" />
      </div>

      {/* Main grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-5">

        {/* Top Threat Actors */}
        <div className="space-y-2">
          <SectionHead label="Top Threat Actors (by alert count)" />
          <TopThreats alerts={alerts} />
        </div>

        {/* Detection Method Breakdown */}
        <div className="space-y-2">
          <SectionHead label="Detection Method Breakdown" />
          <DetectionBreakdown alerts={alerts} />

          <div className="pt-3">
            <SectionHead label="Attack Taxonomy (top 5)" />
            <AttackBreakdown alerts={alerts} />
          </div>
        </div>

        {/* Right column */}
        <div className="space-y-4">

          {/* Severity distribution */}
          <div>
            <SectionHead label="Severity Distribution" />
            <SeverityDistribution alerts={alerts} dbStats={dbStats} />
          </div>

          {/* Response summary */}
          <div>
            <SectionHead label="Response Engine Status" />
            <ResponseSummary actions={actions} />
            {failRate > 30 && (
              <div className="mt-2 flex items-start gap-2 px-2 py-1.5 rounded bg-red-950/40 border border-red-900/50">
                <span className="text-red-400 shrink-0">⚠</span>
                <p className="text-[9px] text-red-400 leading-snug">
                  {failRate}% of actions failed — restart backend as Administrator to enable live firewall blocking
                </p>
              </div>
            )}
          </div>

          {/* Live traffic hotspots */}
          <div>
            <SectionHead label="Live Traffic Hotspots (pkt/s)" />
            <TrafficFeatures features={features} />
          </div>
        </div>
      </div>
    </div>
  );
};

export default ExpertPanel;
