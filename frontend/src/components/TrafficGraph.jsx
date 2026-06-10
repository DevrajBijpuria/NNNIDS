import { useMemo } from 'react';
import {
  AreaChart, Area, LineChart, Line, XAxis, YAxis,
  Tooltip, ResponsiveContainer, Legend, ReferenceLine,
} from 'recharts';

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background: '#080d1a', border: '1px solid #1a2540', borderRadius: 8, padding: '8px 14px' }}>
      <p className="text-xs text-gray-500 mono mb-1">{label}</p>
      {payload.map(p => (
        <p key={p.dataKey} className="text-sm font-semibold" style={{ color: p.color }}>
          {p.name}: <span className="font-bold">{p.value?.toFixed?.(1) ?? p.value}</span>
        </p>
      ))}
    </div>
  );
};

const TrafficGraph = ({ riskHistory = [], features = [] }) => {
  const riskData = useMemo(() =>
    [...riskHistory].reverse().slice(-30).map((r, i) => ({
      t: new Date(r.timestamp).toLocaleTimeString('en', { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
      risk: parseFloat((r.risk_score ?? 0).toFixed(1)),
    })), [riskHistory]
  );

  const trafficData = useMemo(() =>
    (features || []).slice(0, 12).map(f => ({
      ip: f.src_ip ? f.src_ip.split('.').slice(-2).join('.') : '?',
      rate: parseFloat((f.packet_rate ?? 0).toFixed(1)),
      ports: f.unique_dst_ports ?? 0,
      syn: parseFloat(((f.syn_ratio ?? 0) * 100).toFixed(0)),
    })), [features]
  );

  return (
    <div className="panel h-full flex flex-col gap-5">
      <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-widest">Live Traffic Analysis</h2>

      {/* Risk over time */}
      <div>
        <p className="text-[11px] text-gray-600 mb-2 mono">RISK SCORE OVER TIME</p>
        {riskData.length > 1 ? (
          <ResponsiveContainer width="100%" height={140}>
            <AreaChart data={riskData} margin={{ top: 4, right: 8, bottom: 0, left: -20 }}>
              <defs>
                <linearGradient id="rGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#1d6ef5" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#1d6ef5" stopOpacity={0}   />
                </linearGradient>
              </defs>
              <XAxis dataKey="t" tick={{ fill: '#4a6080', fontSize: 9, fontFamily: 'JetBrains Mono' }} interval="preserveStartEnd" />
              <YAxis domain={[0, 100]} tick={{ fill: '#4a6080', fontSize: 9 }} />
              <Tooltip content={<CustomTooltip />} />
              <ReferenceLine y={75} stroke="#ff3b30" strokeDasharray="3 3" strokeOpacity={0.5} />
              <ReferenceLine y={50} stroke="#ff9500" strokeDasharray="3 3" strokeOpacity={0.4} />
              <Area type="monotone" dataKey="risk" stroke="#1d6ef5" strokeWidth={2} fill="url(#rGrad)" name="Risk" dot={false} isAnimationActive={false} />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <div className="flex items-center justify-center h-[140px] text-gray-600 text-xs">No risk history yet — monitoring will populate this</div>
        )}
      </div>

      {/* Per-IP traffic bars */}
      {trafficData.length > 0 && (
        <div>
          <p className="text-[11px] text-gray-600 mb-2 mono">PACKET RATE BY SOURCE IP (pkts/s)</p>
          <ResponsiveContainer width="100%" height={110}>
            <LineChart data={trafficData} margin={{ top: 4, right: 8, bottom: 16, left: -20 }}>
              <XAxis dataKey="ip" tick={{ fill: '#4a6080', fontSize: 9, fontFamily: 'JetBrains Mono' }} angle={-20} textAnchor="end" />
              <YAxis tick={{ fill: '#4a6080', fontSize: 9 }} />
              <Tooltip content={<CustomTooltip />} />
              <Line type="monotone" dataKey="rate" stroke="#30d158" strokeWidth={2} dot={{ fill: '#30d158', r: 3 }} name="pkt/s" isAnimationActive={false} />
              <Line type="monotone" dataKey="syn"  stroke="#ff3b30" strokeWidth={1.5} dot={false} name="SYN%" strokeDasharray="4 2" isAnimationActive={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
};

export default TrafficGraph;