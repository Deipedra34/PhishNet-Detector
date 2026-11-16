import { NavLink, Outlet } from "react-router-dom";
import ApiSettings from "./ApiSettings.jsx";

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
        <span className="brand">
          Phish<span className="brand-accent">Net</span> Dashboard
        </span>
        <nav className="app-nav" aria-label="Main">
          {NAV_ITEMS.map((item) => (
            <NavLink key={item.to} to={item.to} end={item.end}>
              {item.label}
            </NavLink>
          ))}
        </nav>
      </header>
      <main className="app-main">
        <Outlet />
      </main>
      <footer className="app-footer">
        <ApiSettings />
      </footer>
    </div>
  );
}
