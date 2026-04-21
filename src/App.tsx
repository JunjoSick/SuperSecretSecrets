import { Outlet, NavLink, Link } from 'react-router-dom';

export default function App() {
  return (
    <div className="flex min-h-screen flex-col">
      <header className="no-print sticky top-0 z-20 border-b border-white/10 bg-ink-950/70 backdrop-blur-md">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <Link to="/" className="flex items-center gap-2 font-semibold tracking-tight">
            <LogoMark />
            <span className="text-ink-50">SuperSecretSecrets</span>
            <span className="chip">PQ + Shamir</span>
          </Link>
          <nav className="flex items-center gap-1 text-sm">
            <NavItem to="/encode">Encode</NavItem>
            <NavItem to="/recover">Recover</NavItem>
            <NavItem to="/about">About</NavItem>
          </nav>
        </div>
      </header>
      <main className="flex-1">
        <Outlet />
      </main>
      <footer className="no-print border-t border-white/5 py-6 text-center text-xs text-ink-400">
        Everything runs in your browser. No server, no logs, no telemetry.{' '}
        <a
          className="underline decoration-dotted hover:text-ink-200"
          href="https://github.com/junjosick/supersecretsecrets"
          target="_blank"
          rel="noreferrer noopener"
        >
          Source
        </a>
        .
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
          'rounded-lg px-3 py-1.5 transition-colors',
          isActive ? 'bg-white/10 text-ink-50' : 'text-ink-300 hover:bg-white/5 hover:text-ink-100',
        ].join(' ')
      }
    >
      {children}
    </NavLink>
  );
}

function LogoMark() {
  return (
    <svg viewBox="0 0 32 32" className="h-7 w-7" aria-hidden="true">
      <rect width="32" height="32" rx="7" className="fill-ink-800" />
      <g className="fill-accent-300">
        <rect x="5" y="5" width="7" height="7" rx="1" />
        <rect x="7" y="7" width="3" height="3" className="fill-accent-500" />
        <rect x="20" y="5" width="7" height="7" rx="1" />
        <rect x="22" y="7" width="3" height="3" className="fill-accent-500" />
        <rect x="5" y="20" width="7" height="7" rx="1" />
        <rect x="7" y="22" width="3" height="3" className="fill-accent-500" />
        <rect x="15" y="15" width="3" height="3" />
        <rect x="20" y="17" width="3" height="3" />
        <rect x="23" y="22" width="3" height="3" />
        <rect x="17" y="23" width="3" height="3" />
      </g>
    </svg>
  );
}
