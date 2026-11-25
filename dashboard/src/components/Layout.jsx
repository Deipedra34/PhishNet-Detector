import { Link, NavLink, Outlet } from "react-router-dom";
import { useI18n } from "../i18n/index.js";
import ApiSettings from "./ApiSettings.jsx";
import AuthGate from "./AuthGate.jsx";
import LanguageSwitcher from "./LanguageSwitcher.jsx";

const NAV_ITEMS = [
  { to: "/", label: "nav.scan", end: true },
  { to: "/history", label: "nav.history" },
  { to: "/stats", label: "nav.stats" },
  { to: "/feeds", label: "nav.feeds" },
];

export default function Layout() {
  const { t } = useI18n();
  return (
    <div className="app">
      <header className="app-header">
        <Link to="/" className="brand" aria-label={t("app.home")}>
          <svg className="brand-mark" viewBox="0 0 64 64" aria-hidden="true">
            <g fill="none" stroke="currentColor" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round">
              <rect x="8" y="12" width="48" height="32" rx="5" />
              <path d="M8 17 L32 34 L56 17" />
              <path d="M32 44 L32 52 C32 59 43 59 43 52" />
            </g>
          </svg>
          <span>
            Phish<span className="brand-accent">Net</span> <span className="brand-suffix">{t("app.brandSuffix")}</span>
          </span>
        </Link>
        <nav className="app-nav" aria-label={t("app.mainNav")}>
          {NAV_ITEMS.map((item) => (
            <NavLink key={item.to} to={item.to} end={item.end}>
              {t(item.label)}
            </NavLink>
          ))}
        </nav>
        <LanguageSwitcher />
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
