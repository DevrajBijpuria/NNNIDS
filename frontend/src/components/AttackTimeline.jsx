const STATUS_META = {
  MITIGATED:           { color: '#30d158', icon: '✓', barW: '100%' },
  PARTIALLY_MITIGATED: { color: '#ffd60a', icon: '~', barW: '60%'  },
  STILL_ACTIVE:        { color: '#ff3b30', icon: '✗', barW: '15%'  },
  INSUFFICIENT_DATA:   { color: '#4a6080', icon: '?', barW: '5%'   },
};

const VerifRow = ({ v }) => {
  const meta = STATUS_META[v.status] ?? STATUS_META.INSUFFICIENT_DATA;
  const pct  = Math.round((v.mitigation_effectiveness ?? 0) * 100);
  const dateStr = new Date(v.timestamp).toLocaleTimeString('en', { hour: '2-digit', minute: '2-digit', second: '2-digit' });

  return (
    <div className="py-3" style={{ borderBottom: '1px solid #1a2540' }}>
      <div className="flex items-center justify-between mb-1.5">
        <div className="flex items-center gap-2">
          <span className="text-base font-bold" style={{ color: meta.color }}>{meta.icon}</span>
          <span className="ip-chip">{v.src_ip}</span>
          <span className="text-xs text-gray-500">{v.action_taken}</span>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <span className="font-bold mono" style={{ color: meta.color }}>{pct}%</span>
          <span className="text-gray-600 mono">{dateStr}</span>
        </div>
      </div>
      <div className="h-1.5 rounded-full bg-slate-800 overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-700"
          style={{ width: `${pct}%`, background: meta.color, boxShadow: `0 0 6px ${meta.color}80` }}
        />
      </div>
      <div className="text-[10px] mono mt-1" style={{ color: meta.color }}>{v.status?.replace(/_/g, ' ')}</div>
    </div>
  );
};

const AttackTimeline = ({ verifications = [] }) => {
  const mitigated = verifications.filter(v => v.status === 'MITIGATED').length;
  const total     = verifications.length;
  const rate      = total > 0 ? Math.round((mitigated / total) * 100) : 0;

  return (
    <div className="panel flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-widest">Verification Timeline</h2>
        {total > 0 && (
          <div className="flex items-center gap-3 text-xs">
            <span className="mono" style={{ color: '#30d158' }}>{mitigated}/{total} mitigated</span>
            <span className="font-bold mono px-2 py-0.5 rounded"
              style={{ background: `rgba(48,209,88,0.1)`, color: '#30d158', border: '1px solid rgba(48,209,88,0.25)' }}>
              {rate}% effective
            </span>
          </div>
        )}
      </div>

      <div className="overflow-y-auto max-h-64">
        {verifications.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-24 gap-2">
            <span className="text-2xl">📊</span>
            <p className="text-xs text-gray-600">No verifications yet — run a scan first</p>
          </div>
        ) : (
          verifications.map(v => <VerifRow key={v.id} v={v} />)
        )}
      </div>
    </div>
  );
};

export default AttackTimeline;