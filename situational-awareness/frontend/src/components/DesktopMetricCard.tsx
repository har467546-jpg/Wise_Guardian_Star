export default function DesktopMetricCard({
  label,
  value,
  detail,
  tone = "neutral",
}: {
  label: string;
  value: string | number;
  detail: string;
  tone?: "neutral" | "accent" | "success" | "warning" | "danger";
}) {
  return (
    <div className={`desktop-metric-card desktop-metric-card-${tone}`}>
      <div className="desktop-metric-card-head">
        <span className="desktop-metric-card-label">{label}</span>
        <strong className="desktop-metric-card-value">{value}</strong>
      </div>
      <span className="desktop-metric-card-detail">{detail}</span>
    </div>
  );
}
