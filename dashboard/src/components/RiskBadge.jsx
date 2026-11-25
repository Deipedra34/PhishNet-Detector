import { useI18n } from "../i18n/index.js";

/** A compact, colored risk level label for tables and lists. */
export default function RiskBadge({ level }) {
  const { t } = useI18n();
  const known = ["LOW", "MEDIUM", "HIGH"].includes(level);
  return (
    <span className={`risk-pill ${known ? `risk-${level.toLowerCase()}` : "risk-unknown"}`}>
      {known ? t(`risk.${level}`) : (level ?? "?")}
    </span>
  );
}
