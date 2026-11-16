/** A compact, colored risk level label for tables and lists. */
export default function RiskBadge({ level }) {
  const known = ["LOW", "MEDIUM", "HIGH"].includes(level);
  return <span className={`risk-pill ${known ? `risk-${level.toLowerCase()}` : "risk-unknown"}`}>{level ?? "?"}</span>;
}
