import { Link, NavLink, Outlet } from "react-router-dom";
import ApiSettings from "./ApiSettings.jsx";
import AuthGate from "./AuthGate.jsx";

const NAV_ITEMS = [
  { to: "/", label: "Scan", end: true },
  { to: "/history", label: "History" },
  { to: "/stats", label: "Stats" },
  { to: "/feeds", label: "Feeds" },
];

export default function Layout() {
  return (
    <div className="app">
      <header className="app-header">
        <Link to="/" className="brand" aria-label="PhishNet Dashboard home">
          <svg className="brand-mark" viewBox="0 0 64 64" aria-hidden="true">
            <g fill="none" stroke="currentColor" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round">
              <rect x="8" y="12" width="48" height="32" rx="5" />
              <path d="M8 17 L32 34 L56 17" />
              <path d="M32 44 L32 52 C32 59 43 59 43 52" />
            </g>
          </svg>
          <span>
            Phish<span className="brand-accent">Net</span> <span className="brand-suffix">Dashboard</span>
          </span>
        </Link>
        <nav className="app-nav" aria-label="Main">
          {NAV_ITEMS.map((item) => (
            <NavLink key={item.to} to={item.to} end={item.end}>
              {item.label}
            </NavLink>
          ))}
        </nav>
      </header>
      <main className="app-main">
        <AuthGate>
          <Outlet />
        </AuthGate>
      </main>
      <footer className="app-footer">
        <ApiSettings />
      </footer>
    </div>
  );
}
