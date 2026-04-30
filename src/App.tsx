import { Outlet, NavLink, Link } from 'react-router-dom';

export default function App() {
  return (
    <div className="flex min-h-screen flex-col">
      <header className="no-print sticky top-0 z-20 border-b border-white/10 bg-ink-950/80 backdrop-blur-md">
        <div className="mx-auto grid max-w-7xl gap-3 px-4 py-3 sm:px-6 lg:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] lg:items-center lg:gap-6">
          <Link to="/" className="flex min-w-0 items-center justify-center gap-3 font-semibold tracking-tight lg:justify-start">
            <LogoMark />
            <span className="min-w-0 break-words text-ink-50">superSecretSecrets</span>
            <span className="hidden text-[10px] uppercase tracking-[0.14em] text-ink-500 sm:inline">
              v0.1 · client-side only
            </span>
          </Link>
          <nav className="flex flex-wrap items-center justify-center gap-2 text-xs uppercase tracking-[0.14em]">
            <NavItem to="/encode">Encode</NavItem>
            <NavItem to="/recover">Recover</NavItem>
            <NavItem to="/verify">Verify</NavItem>
            <NavItem to="/about">About</NavItem>
          </nav>
          <div className="hidden justify-end lg:flex">
            <StatusPill />
          </div>
        </div>
      </header>
      <main className="flex-1">
        <Outlet />
      </main>
      <footer className="no-print border-t border-white/10 px-6 py-2 text-[10px] uppercase tracking-[0.14em] text-ink-500">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3">
          <span>ml-kem-768 · aes-256-gcm · shamir gf(2^8)</span>
          <span className="flex gap-5">
            <span>no network</span>
            <span>no server</span>
            <span>no telemetry</span>
          </span>
        <a
          className="text-ink-400 underline decoration-dotted hover:text-accent-200"
          href="https://github.com/junjosick/supersecretsecrets"
          target="_blank"
          rel="noreferrer noopener"
        >
          Source
        </a>
        </div>
      </footer>
    </div>
  );
}

function NavItem({ to, children }: { to: string; children: React.ReactNode }) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        [
          'border px-3 py-1.5 transition-colors',
          isActive
            ? 'border-accent-300/50 bg-accent-500/10 text-accent-200'
            : 'border-transparent text-ink-400 hover:border-white/10 hover:bg-white/[0.03] hover:text-ink-100',
        ].join(' ')
      }
    >
      {children}
    </NavLink>
  );
}

function LogoMark() {
  return (
    <svg viewBox="0 0 32 32" className="h-6 w-6 text-accent-200" aria-hidden="true">
      <g fill="none" stroke="currentColor" strokeWidth="1.4">
        <rect x="3.5" y="3.5" width="25" height="25" />
        <rect x="8.5" y="8.5" width="15" height="15" />
        <path d="M3.5 16h5M23.5 16h5M16 3.5v5M16 23.5v5" />
      </g>
      <rect x="14" y="14" width="4" height="4" fill="currentColor" />
    </svg>
  );
}

function StatusPill() {
  return (
    <div className="inline-flex items-center gap-2 rounded-full border border-white/10 px-3 py-1 text-[10px] uppercase tracking-[0.14em] text-ink-400">
      <span className="h-1.5 w-1.5 rounded-full bg-accent-300 shadow-glow" />
      offline · secure
    </div>
  );
}
