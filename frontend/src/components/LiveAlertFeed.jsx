import { useState, useEffect, useRef } from 'react';

const SEV_STYLES = {
  CRITICAL: { dot: '#ff3b30', bg: 'bg-red-950/50',    border: 'border-red-900/60',    text: 'text-red-300',    badge: 'bg-red-900/70 text-red-200'    },
  HIGH:     { dot: '#ff9500', bg: 'bg-orange-950/40', border: 'border-orange-900/50', text: 'text-orange-300', badge: 'bg-orange-900/60 text-orange-200' },
  MEDIUM:   { dot: '#ffd60a', bg: 'bg-yellow-950/30', border: 'border-yellow-900/40', text: 'text-yellow-300', badge: 'bg-yellow-900/50 text-yellow-200' },
  LOW:      { dot: '#30d158', bg: 'bg-green-950/30',  border: 'border-green-900/40',  text: 'text-green-300',  badge: 'bg-green-900/50 text-green-200'  },
};

const ATTACK_SHORT = {
  isolation_forest: 'ML Anomaly',
  port_scan:        'Port Scan',
  syn_flood:        'SYN Flood',
  ddos:             'DDoS',
  unusual_traffic:  'Unusual',
  known_c2:         'Known C2',
  new_device:       'New Device',
  baseline_spike:   'Spike',
};

const EventCard = ({ event }) => {
  const s = SEV_STYLES[event.severity] ?? SEV_STYLES.LOW;
  return (
    <div
      className={`rounded-lg border px-3 py-2.5 ${s.bg} ${s.border} animate-slide-in`}
      style={{ borderLeft: `3px solid ${s.dot}` }}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5 mb-1">
            <span className="w-1.5 h-1.5 rounded-full shrink-0 animate-pulse" style={{ background: s.dot }} />
            <span className="text-[10px] font-bold text-gray-200 truncate">
              {ATTACK_SHORT[event.attack_type] ?? event.attack_name}
            </span>
          </div>
          <span className="ip-chip text-[9px]">{event.src_ip}</span>
        </div>
        <div className="flex flex-col items-end gap-1 shrink-0">
          <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${s.badge}`}>
            {event.severity[0]}
          </span>
          <span className="text-[8px] text-gray-700 mono">{event.time}</span>
        </div>
      </div>
    </div>
  );
};

const LiveAlertFeed = ({ alerts = [] }) => {
  const [feed, setFeed]   = useState([]);
  const [pulse, setPulse] = useState(false);
  const seenRef           = useRef(new Set());
  const feedRef           = useRef(null);

  useEffect(() => {
    const fresh = alerts.filter(a => !seenRef.current.has(a.id));
    if (fresh.length === 0) return;

    fresh.forEach(a => seenRef.current.add(a.id));
    const events = fresh.map(a => ({
      ...a,
      time: new Date(a.timestamp).toLocaleTimeString('en', { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
      _key: `${a.id}-${Date.now()}`,
    }));

    setFeed(prev => [...events, ...prev].slice(0, 40));
    setPulse(true);
    setTimeout(() => setPulse(false), 600);

    if (feedRef.current) feedRef.current.scrollTop = 0;
  }, [alerts]);

  const critCount = feed.filter(e => e.severity === 'CRITICAL').length;

  return (
    <div className="panel flex flex-col gap-3 h-full" style={{ minHeight: '380px' }}>
      <div className="flex items-center justify-between shrink-0">
        <div className="flex items-center gap-2">
          <span
            className="w-2 h-2 rounded-full transition-all duration-300"
            style={{ background: pulse ? '#ff3b30' : '#30d158', boxShadow: pulse ? '0 0 8px #ff3b30' : '0 0 6px #30d158' }}
          />
          <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-widest">Live Feed</h2>
        </div>
        <div className="flex items-center gap-1.5">
          {critCount > 0 && (
            <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-red-900/70 text-red-300 border border-red-800 animate-pulse">
              {critCount} CRIT
            </span>
          )}
          <span className="text-[9px] text-gray-700 mono">{feed.length} events</span>
        </div>
      </div>

      <div
        ref={feedRef}
        className="flex-1 overflow-y-auto space-y-1.5 pr-0.5"
        style={{ maxHeight: '340px' }}
      >
        {feed.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-32 gap-3 text-center">
            <div className="w-8 h-8 rounded-full border-2 border-dashed border-slate-700 flex items-center justify-center">
              <span className="text-gray-700 text-sm">📡</span>
            </div>
            <p className="text-[10px] text-gray-700 leading-snug">
              Waiting for threats…<br />
              <span className="text-gray-800">Start monitoring to see live events</span>
            </p>
          </div>
        ) : (
          feed.map(event => <EventCard key={event._key} event={event} />)
        )}
      </div>

      {feed.length > 0 && (
        <div className="shrink-0 pt-1 border-t border-[#1a2540] flex items-center justify-between">
          <span className="text-[8px] text-gray-700 mono">
            last: {feed[0]?.time}
          </span>
          <div className="flex gap-1">
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => {
              const n = feed.filter(e => e.severity === s).length;
              if (!n) return null;
              return (
                <span key={s} className="text-[8px] mono font-bold" style={{ color: SEV_STYLES[s].dot }}>
                  {s[0]}{n}
                </span>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};

export default LiveAlertFeed;
