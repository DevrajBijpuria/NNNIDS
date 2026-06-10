const ACTION_META = {
  BLOCK_IP:   { icon: '🚫', color: '#ff3b30', label: 'Blocked' },
  THROTTLE:   { icon: '⇩',  color: '#ff9500', label: 'Throttled' },
  QUARANTINE: { icon: '⬡',  color: '#ffd60a', label: 'Quarantined' },
  MONITOR:    { icon: '◉',  color: '#64acff', label: 'Monitored' },
};

const STATUS_META = {
  EXECUTED:   { color: '#30d158', label: 'EXECUTED' },
  MONITORING: { color: '#64acff', label: 'MONITORING' },
  FAILED:     { color: '#ff3b30', label: 'FAILED' },
  PENDING:    { color: '#ffd60a', label: 'PENDING' },
};

const parseLog = (log) => {
  if (Array.isArray(log)) return log;
  if (typeof log === 'string') {
    try { return JSON.parse(log); } catch { return [log]; }
  }
  return [];
};

const ActionRow = ({ action }) => {
  const meta   = ACTION_META[action.action_type]  ?? { icon: '?', color: '#64acff', label: action.action_type };
  const status = STATUS_META[action.status]       ?? { color: '#64acff', label: action.status };
  const log    = parseLog(action.execution_log);
  const dateStr = new Date(action.timestamp).toLocaleTimeString('en', { hour: '2-digit', minute: '2-digit', second: '2-digit' });

  return (
    <div className="flex items-start gap-3 py-3" style={{ borderBottom: '1px solid #1a2540' }}>
      <div
        className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0 text-base mt-0.5"
        style={{ background: `${meta.color}18`, border: `1px solid ${meta.color}35` }}
      >
        {meta.icon}
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold" style={{ color: meta.color }}>{meta.label}</span>
            <span className="ip-chip">{action.src_ip}</span>
          </div>
          <span className="text-[10px] font-bold mono" style={{ color: status.color }}>
            {status.label}
          </span>
        </div>
        {log.length > 0 && (
          <p className="text-[10px] text-gray-600 mono mt-1 truncate" title={log.join(' | ')}>
            {log[0]}
          </p>
        )}
        <p className="text-[10px] text-gray-700 mt-0.5 mono">{dateStr}</p>
      </div>
    </div>
  );
};

const ActionPanel = ({ actions = [], blockedIps = [] }) => {
  const summary = actions.reduce((acc, a) => {
    acc[a.action_type] = (acc[a.action_type] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <div className="panel flex flex-col gap-3 h-full">
      <div className="flex items-center justify-between">
        <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-widest">Response Actions</h2>
        <span className="text-xs text-gray-600 mono">{actions.length} total</span>
      </div>

      {/* Live Firewall Blocked IPs */}
      {blockedIps.length > 0 && (
        <div className="rounded-lg border border-red-900/50 bg-red-950/20 p-3 flex flex-col gap-2">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse shrink-0" />
            <span className="text-[10px] font-bold text-red-400 uppercase tracking-widest">
              Firewall — {blockedIps.length} Blocked IP{blockedIps.length > 1 ? 's' : ''}
            </span>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {blockedIps.map(ip => (
              <span
                key={ip}
                className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-900/50 border border-red-800/60 text-red-300"
              >
                🚫 {ip}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Summary pills */}
      {Object.keys(summary).length > 0 && (
        <div className="flex flex-wrap gap-2">
          {Object.entries(summary).map(([type, count]) => {
            const m = ACTION_META[type] ?? { icon: '?', color: '#64acff', label: type };
            return (
              <div key={type} className="flex items-center gap-1.5 px-2 py-1 rounded-lg text-xs"
                style={{ background: `${m.color}12`, border: `1px solid ${m.color}30`, color: m.color }}>
                <span>{m.icon}</span>
                <span className="font-semibold">{count}× {m.label}</span>
              </div>
            );
          })}
        </div>
      )}

      <div className="flex-1 overflow-y-auto min-h-[200px] max-h-[400px]">
        {actions.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-32 gap-2">
            <span className="text-2xl">⚡</span>
            <p className="text-xs text-gray-600">No response actions yet</p>
          </div>
        ) : (
          actions.map(a => <ActionRow key={a.id} action={a} />)
        )}
      </div>
    </div>
  );
};

export default ActionPanel;