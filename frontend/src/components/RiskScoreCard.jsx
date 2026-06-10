import { useMemo } from 'react';
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  BarChart, Bar, Cell,
} from 'recharts';

const RISK_GRADIENT_ID = 'riskGradient';

const RiskTick = ({ value }) => {
  if (value >= 75) return '#ff3b30';
  if (value >= 50) return '#ff9500';
  if (value >= 25) return '#ffd60a';
  return '#30d158';
};

const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null;
  const val = payload[0].value;
  return (
    <div style={{ background: '#080d1a', border: '1px solid #1a2540', borderRadius: 8, padding: '8px 12px' }}>
      <p className="text-xs text-gray-500 mono">{payload[0].payload.label}</p>
      <p className="text-lg font-bold" style={{ color: RiskTick({ value: val }) }}>{val?.toFixed(1)}</p>
    </div>
  );
};

const RiskGauge = ({ score }) => {
  const angle = -135 + (score / 100) * 270;
  const color = RiskTick({ value: score });
  const r = 54;
  const cx = 70, cy = 70;
  const toRad = deg => (deg * Math.PI) / 180;
  const arcPoint = deg => ({
    x: cx + r * Math.cos(toRad(deg - 90)),
    y: cy + r * Math.sin(toRad(deg - 90)),
  });
  const start = arcPoint(-135);
  const end = arcPoint(135);
  const needle = arcPoint(angle);

  return (
    <svg viewBox="0 0 140 100" width="140" height="100">
      <defs>
        <linearGradient id="arcGrad" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%"   stopColor="#30d158" />
          <stop offset="50%"  stopColor="#ffd60a" />
          <stop offset="100%" stopColor="#ff3b30" />
        </linearGradient>
      </defs>
      <path
        d={`M${start.x},${start.y} A${r},${r} 0 1 1 ${end.x},${end.y}`}
        fill="none" stroke="#1a2540" strokeWidth="8" strokeLinecap="round"
      />
      <path
        d={`M${start.x},${start.y} A${r},${r} 0 1 1 ${end.x},${end.y}`}
        fill="none" stroke="url(#arcGrad)" strokeWidth="8" strokeLinecap="round"
        strokeDasharray={`${(score / 100) * 263} 263`}
      />
      <line
        x1={cx} y1={cy}
        x2={needle.x} y2={needle.y}
        stroke={color} strokeWidth="2.5" strokeLinecap="round"
        style={{ transition: 'all 0.6s ease' }}
      />
      <circle cx={cx} cy={cy} r="5" fill={color} />
      <circle cx={cx} cy={cy} r="3" fill="#080d1a" />
    </svg>
  );
};

const RiskScoreCard = ({ riskData = {} }) => {
  const score = riskData.current_risk ?? 0;
  const level = riskData.risk_level ?? 'LOW';
  const trend = riskData.trend ?? 'STABLE';
  const history = riskData.history ?? [];

  const chartData = useMemo(() =>
    [...history].reverse().slice(-20).map((r, i) => ({
      i,
      val: parseFloat(r.risk_score?.toFixed(1) ?? 0),
      label: new Date(r.timestamp).toLocaleTimeString(),
    })), [history]
  );

  const color = RiskTick({ value: score });
  const trendMeta = {
    INCREASING: { icon: '↑', color: '#ff3b30', label: 'Rising' },
    DECREASING: { icon: '↓', color: '#30d158', label: 'Dropping' },
    STABLE:     { icon: '→', color: '#64acff', label: 'Stable' },
  }[trend] ?? { icon: '→', color: '#64acff', label: 'Stable' };

  return (
    <div className="panel panel-glow h-full flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-widest">Risk Score</h2>
        <span className="text-xs font-mono px-2 py-0.5 rounded" style={{ background: `${color}18`, color, border: `1px solid ${color}40` }}>
          {level}
        </span>
      </div>

      <div className="flex items-center gap-4">
        <RiskGauge score={score} />
        <div>
          <div className="text-5xl font-bold count-up" style={{ color, fontVariantNumeric: 'tabular-nums' }}>
            {Math.round(score)}
          </div>
          <div className="text-xs text-gray-500 mt-1">out of 100</div>
          <div className="flex items-center gap-1 mt-2 text-xs font-medium" style={{ color: trendMeta.color }}>
            <span className="text-base">{trendMeta.icon}</span>
            {trendMeta.label}
          </div>
        </div>
      </div>

      {chartData.length > 1 && (
        <ResponsiveContainer width="100%" height={80}>
          <AreaChart data={chartData} margin={{ top: 4, right: 0, bottom: 0, left: 0 }}>
            <defs>
              <linearGradient id={RISK_GRADIENT_ID} x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%"  stopColor={color} stopOpacity={0.3} />
                <stop offset="95%" stopColor={color} stopOpacity={0}   />
              </linearGradient>
            </defs>
            <XAxis dataKey="i" hide />
            <YAxis domain={[0, 100]} hide />
            <Tooltip content={<CustomTooltip />} />
            <Area
              type="monotone" dataKey="val"
              stroke={color} strokeWidth={2}
              fill={`url(#${RISK_GRADIENT_ID})`}
              isAnimationActive={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      )}
    </div>
  );
};

export default RiskScoreCard;