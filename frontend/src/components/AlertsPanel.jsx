import { useState } from 'react';

const SEV_META = {
  CRITICAL: { dot: '#ff3b30', bar: 'border-l-[#ff3b30]', badge: 'badge-critical', glow: 'rgba(255,59,48,0.08)' },
  HIGH:     { dot: '#ff9500', bar: 'border-l-[#ff9500]', badge: 'badge-high',     glow: 'rgba(255,149,0,0.08)' },
  MEDIUM:   { dot: '#ffd60a', bar: 'border-l-[#ffd60a]', badge: 'badge-medium',   glow: 'rgba(255,214,10,0.06)' },
  LOW:      { dot: '#30d158', bar: 'border-l-[#30d158]', badge: 'badge-low',      glow: 'rgba(48,209,88,0.06)' },
};

const TYPE_ICON = {
  SIGNATURE:    '✦',
  ML_ANOMALY:   '⬡',
  BEHAVIORAL:   '◈',
  THREAT_INTEL: '⬥',
};

const AlertRow = ({ alert }) => {
  const [expanded, setExpanded] = useState(false);
  const meta = SEV_META[alert.severity] ?? SEV_META.LOW;
  const dateStr = new Date(alert.timestamp).toLocaleTimeString('en', { hour: '2-digit', minute: '2-digit', second: '2-digit' });

  return (
    <div
      className={`alert-item border-l-[3px] ${meta.bar} rounded-r-lg p-3 cursor-pointer transition-colors`}
      style={{ background: expanded ? meta.glow : 'transparent', borderBottom: '1px solid #1a2540' }}
      onClick={() => setExpanded(e => !e)}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-start gap-2 min-w-0">
          <span className="text-gray-500 text-sm mt-0.5 shrink-0" title={alert.detection_type}>
            {TYPE_ICON[alert.detection_type] ?? '◦'}
          </span>
          <div className="min-w-0">
            <p className="text-sm font-semibold text-gray-100 leading-tight">{alert.attack_name}</p>
            <div className="flex items-center gap-2 mt-0.5 flex-wrap">
              <span className="ip-chip">{alert.src_ip}</span>
              <span className="text-[10px] text-gray-600 mono">{dateStr}</span>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <span className={`badge ${meta.badge}`}>{alert.severity}</span>
          <span className="text-gray-600 text-xs">{expanded ? '▲' : '▼'}</span>
        </div>
      </div>

      {expanded && (
        <div className="mt-3 pl-5 space-y-2.5">
          {/* Human-readable reason — most prominent */}
          {alert.reason && (
            <div className="flex items-start gap-2 px-3 py-2 rounded-lg bg-slate-800/60 border border-slate-700">
              <span className="text-blue-400 shrink-0 mt-0.5">💬</span>
              <p className="text-xs text-blue-200 leading-relaxed font-medium">{alert.reason}</p>
            </div>
          )}
          {/* Technical description */}
          <p className="text-xs text-gray-500 leading-relaxed">{alert.description}</p>
          {/* Indicators */}
          {alert.indicators?.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {alert.indicators.map((ind, i) => (
                <span key={i} className="text-[10px] px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-gray-400">
                  {ind}
                </span>
              ))}
            </div>
          )}
          <p className="text-xs text-gray-600">Impact: <span className="text-gray-400">{alert.impact}</span></p>
        </div>
      )}
    </div>
  );
};

const FILTERS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

const AlertsPanel = ({ alerts = [] }) => {
  const [filter, setFilter] = useState('ALL');

  const counts = alerts.reduce((acc, a) => {
    acc[a.severity] = (acc[a.severity] ?? 0) + 1;
    return acc;
  }, {});

  const visible = filter === 'ALL' ? alerts : alerts.filter(a => a.severity === filter);

  return (
    <div className="panel flex flex-col gap-3 h-full">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-widest">Active Alerts</h2>
        <div className="flex items-center gap-1.5">
          {counts.CRITICAL > 0 && <span className="badge badge-critical">{counts.CRITICAL} CRIT</span>}
          {counts.HIGH > 0     && <span className="badge badge-high">{counts.HIGH} HIGH</span>}
        </div>
      </div>

      {/* Filter tabs */}
      <div className="flex gap-1">
        {FILTERS.map(f => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`text-[10px] font-semibold px-2 py-0.5 rounded transition-all ${
              filter === f
                ? 'bg-blue-600 text-white'
                : 'text-gray-500 hover:text-gray-300'
            }`}
          >
            {f}{f !== 'ALL' && counts[f] ? ` (${counts[f]})` : ''}
          </button>
        ))}
      </div>

      {/* List */}
      <div className="flex-1 overflow-y-auto space-y-0 min-h-[200px] max-h-[420px]">
        {visible.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-32 gap-2">
            <span className="text-2xl">🛡️</span>
            <p className="text-xs text-gray-600">No {filter === 'ALL' ? '' : filter.toLowerCase() + ' '}alerts detected</p>
          </div>
        ) : (
          visible.map(a => <AlertRow key={a.id} alert={a} />)
        )}
      </div>

      {visible.length > 0 && (
        <p className="text-[10px] text-gray-600 text-right mono">{visible.length} alert{visible.length !== 1 ? 's' : ''}</p>
      )}
    </div>
  );
};

export default AlertsPanel;