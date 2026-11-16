import { BrowserRouter, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout.jsx";
import ScanPage from "./pages/ScanPage.jsx";
import HistoryPage from "./pages/HistoryPage.jsx";
import StatsPage from "./pages/StatsPage.jsx";
import FeedsPage from "./pages/FeedsPage.jsx";
import NotFoundPage from "./pages/NotFoundPage.jsx";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<ScanPage />} />
          <Route path="history" element={<HistoryPage />} />
          <Route path="stats" element={<StatsPage />} />
          <Route path="feeds" element={<FeedsPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
