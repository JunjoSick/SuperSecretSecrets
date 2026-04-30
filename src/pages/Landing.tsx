import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';

function mulberry32(seed: number) {
  let t = seed >>> 0;
  return function rand() {
    t += 0x6d2b79f5;
    let r = t;
    r = Math.imul(r ^ (r >>> 15), r | 1);
    r ^= r + Math.imul(r ^ (r >>> 7), r | 61);
    return ((r ^ (r >>> 14)) >>> 0) / 4294967296;
  };
}

export default function Landing() {
  const [tick, setTick] = useState(0);

  useEffect(() => {
    const id = window.setInterval(() => setTick((t) => t + 1), 180);
    return () => window.clearInterval(id);
  }, []);

  const hexRows = useMemo(() => {
    const rand = mulberry32(tick + 7);
    return Array.from({ length: 28 }, () =>
      Array.from({ length: 8 }, () => Math.floor(rand() * 256).toString(16).padStart(2, '0')).join(' '),
    );
  }, [tick]);

  return (
    <div className="mx-auto grid min-h-[calc(100vh-92px)] max-w-7xl lg:grid-cols-[1.18fr_0.82fr]">
      <section className="grid gap-10 px-6 py-12 sm:px-10 lg:px-14 lg:py-16">
        <div className="flex items-center justify-between text-[10px] uppercase tracking-[0.14em] text-ink-500">
          <span>Project · /sss /v0.1.0-rc</span>
          <span>FIPS 203 · browser runtime</span>
        </div>

        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="self-center"
        >
          <div className="mb-8 flex items-center gap-4">
            <LogoGlyph />
            <span className="mono-upper">// encrypted · split · recoverable</span>
          </div>

          <h1 className="text-balance text-[clamp(3.2rem,9vw,6.8rem)] font-medium leading-[0.9] tracking-[-0.06em] text-ink-50">
            super<span className="text-ink-500">Secret</span>
            <br />
            Secrets<span className="text-accent-300">.</span>
            <span className="ml-1 inline-block text-accent-300 [animation:blink_1.1s_steps(1)_infinite]">▍</span>
          </h1>

          <p className="mt-8 max-w-2xl text-sm leading-7 text-ink-300">
            A zero-trust cryptographic instrument. Encrypt a secret with post-quantum
            key encapsulation, then split the decryption key into{' '}
            <span className="text-accent-200">N physical QR shares</span>. Any{' '}
            <span className="text-accent-200">T shares</span> reconstructs the plaintext.
            Anything less reveals <em className="text-ink-100"> mathematically nothing</em>.
            Optional v3 layers bind the policy, prove share openings, disclose one vault
            entry at a time, and add per-share VDF delay.
          </p>

          <div className="mt-8 grid gap-4 border-t border-white/10 pt-6 sm:grid-cols-2 lg:grid-cols-3">
            <Proof label="ML-KEM-768" value="NIST PQ · level 3" />
            <Proof label="AES-256-GCM" value="AEAD · 128-bit tag" />
            <Proof label="Shamir T-of-N" value="GF(2^8) · thresholded" />
            <Proof label="Argon2id" value="optional pass layer" />
            <Proof label="v3 ZK layer" value="commit · prove · disclose" />
            <Proof label="v3 VDF lock" value="sequential share delay" />
          </div>

          <div className="mt-10 grid gap-4 sm:grid-cols-3">
            <RouteCard
              to="/encode"
              step="01"
              verb="Encode"
              desc="Seal plaintext → emit QR shares"
              accent
            />
            <RouteCard
              to="/recover"
              step="02"
              verb="Recover"
              desc="Ingest T shares → unseal plaintext"
            />
            <RouteCard
              to="/verify"
              step="03"
              verb="Verify"
              desc="Check one-entry vault proof"
            />
          </div>
        </motion.div>

        <div className="flex flex-wrap items-center justify-between gap-3 text-[10px] uppercase tracking-[0.14em] text-ink-500">
          <span>runtime: browser · offline-first</span>
          <Link to="/about" className="text-ink-300 hover:text-accent-200">
            threat model →
          </Link>
        </div>
      </section>

      <aside className="relative hidden overflow-hidden border-l border-white/10 bg-gradient-to-b from-transparent to-white/[0.03] lg:block">
        <div className="absolute left-6 right-6 top-6 z-10 flex justify-between text-[10px] uppercase tracking-[0.14em] text-ink-500">
          <span>fig.01 · entropy stream / live</span>
          <span className="text-accent-300">● sampling</span>
        </div>

        <CryptoDiagram />

        <div className="absolute bottom-16 right-6 top-16 w-56 border-l border-dashed border-white/10 pl-4 text-[10px] leading-5 text-ink-500 [mask-image:linear-gradient(180deg,transparent,black_18%,black_82%,transparent)]">
          {hexRows.map((row, i) => (
            <div key={`${i}-${row}`} className={i === 8 ? 'text-accent-300' : 'opacity-60'}>
              {row}
            </div>
          ))}
        </div>

        <div className="absolute bottom-6 left-6 right-72 flex justify-between text-[10px] uppercase tracking-[0.14em] text-ink-500">
          <span>ml-kem lattice · v3 overlays</span>
          <span>zk commit · vdf lock · vault proof</span>
        </div>
      </aside>
    </div>
  );
}

function RouteCard({
  to,
  step,
  verb,
  desc,
  accent,
}: {
  to: string;
  step: string;
  verb: string;
  desc: string;
  accent?: boolean;
}) {
  return (
    <Link
      to={to}
      className={[
        'group card-hover grid gap-3 p-5 text-left',
        accent ? 'border-accent-300/40 bg-accent-500/[0.04]' : '',
      ].join(' ')}
    >
      <div className="flex items-center justify-between">
        <span className="mono-upper">{step}</span>
        <span className="text-sm text-accent-300 transition-transform group-hover:translate-x-1">→</span>
      </div>
      <div className={['text-2xl font-medium tracking-tight', accent ? 'text-accent-200' : 'text-ink-50'].join(' ')}>
        {verb}
      </div>
      <div className="text-xs text-ink-400">{desc}</div>
    </Link>
  );
}

function Proof({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-xs font-medium text-ink-100">{label}</div>
      <div className="mt-1 text-[10px] uppercase tracking-[0.14em] text-ink-500">{value}</div>
    </div>
  );
}

function LogoGlyph() {
  return (
    <svg width="36" height="36" viewBox="0 0 32 32" className="text-accent-200" aria-hidden="true">
      <g fill="none" stroke="currentColor" strokeWidth="1.4">
        <rect x="3.5" y="3.5" width="25" height="25" />
        <rect x="8.5" y="8.5" width="15" height="15" />
        <path d="M3.5 16h5M23.5 16h5M16 3.5v5M16 23.5v5" />
      </g>
      <rect x="14" y="14" width="4" height="4" fill="currentColor" />
    </svg>
  );
}

function CryptoDiagram() {
  const nodes = Array.from({ length: 5 }, (_, i) => {
    const a = (i / 5) * Math.PI * 2 - Math.PI / 2;
    return {
      x: 280 + Math.cos(a) * 210,
      y: 280 + Math.sin(a) * 210,
      active: i < 3,
      label: `S${i + 1}`,
    };
  });

  return (
    <div className="absolute inset-0 grid place-items-center">
      <svg viewBox="0 0 560 560" className="w-[88%] max-w-[560px]" aria-hidden="true">
        <defs>
          <radialGradient id="landingGlow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="rgb(35 201 241)" stopOpacity="0.22" />
            <stop offset="60%" stopColor="rgb(35 201 241)" stopOpacity="0.03" />
            <stop offset="100%" stopColor="rgb(35 201 241)" stopOpacity="0" />
          </radialGradient>
        </defs>
        <circle cx="280" cy="280" r="260" fill="url(#landingGlow)" />
        {[260, 210, 160, 112, 70].map((r, i) => (
          <circle
            key={r}
            cx="280"
            cy="280"
            r={r}
            fill="none"
            stroke="rgb(255 255 255 / 0.12)"
            strokeDasharray={i === 1 ? '3 4' : i === 3 ? '1 5' : '0'}
          />
        ))}
        {Array.from({ length: 72 }).map((_, i) => {
          const a = (i / 72) * Math.PI * 2;
          const long = i % 6 === 0;
          const r1 = 260;
          const r2 = long ? 246 : 254;
          return (
            <line
              key={i}
              x1={280 + Math.cos(a) * r1}
              y1={280 + Math.sin(a) * r1}
              x2={280 + Math.cos(a) * r2}
              y2={280 + Math.sin(a) * r2}
              stroke="rgb(216 224 228 / 0.55)"
              strokeWidth={long ? 1 : 0.5}
            />
          );
        })}
        {nodes.map((node) => (
          <g key={node.label}>
            <line
              x1="280"
              y1="280"
              x2={node.x}
              y2={node.y}
              stroke={node.active ? 'rgb(93 220 255)' : 'rgb(255 255 255 / 0.12)'}
              strokeDasharray={node.active ? '0' : '2 3'}
            />
            <rect
              x={node.x - 14}
              y={node.y - 14}
              width="28"
              height="28"
              fill={node.active ? 'rgb(35 201 241 / 0.14)' : 'rgb(255 255 255 / 0.04)'}
              stroke={node.active ? 'rgb(93 220 255)' : 'rgb(255 255 255 / 0.12)'}
            />
            <text
              x={node.x}
              y={node.y + 3}
              fontSize="8"
              textAnchor="middle"
              fill={node.active ? 'rgb(150 235 255)' : 'rgb(101 119 128)'}
            >
              {node.label}
            </text>
          </g>
        ))}
        <rect x="260" y="260" width="40" height="40" fill="rgb(8 11 14)" stroke="rgb(93 220 255)" />
        <rect x="270" y="270" width="20" height="20" fill="rgb(93 220 255)" />
        <g fontSize="9" textAnchor="middle" fill="rgb(150 235 255)">
          <text x="280" y="143">ZK COMMIT</text>
          <text x="407" y="325">VDF LOCK</text>
          <text x="153" y="325">DISCLOSE</text>
        </g>
      </svg>
    </div>
  );
}
