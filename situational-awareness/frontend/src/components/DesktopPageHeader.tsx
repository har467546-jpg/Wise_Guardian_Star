import type { ReactNode } from "react";

type HeaderMetaTone = "neutral" | "accent" | "success" | "warning" | "danger";

type HeaderMetaItem = {
  label: string;
  value: ReactNode;
  tone?: HeaderMetaTone;
};

function toneClassName(tone: HeaderMetaTone | undefined) {
  return tone ? ` desktop-page-header-chip-${tone}` : "";
}

export default function DesktopPageHeader({
  eyebrow,
  title,
  description,
  meta = [],
  actions,
}: {
  eyebrow: string;
  title: string;
  description: string;
  meta?: HeaderMetaItem[];
  actions?: ReactNode;
}) {
  return (
    <section className="desktop-page-header">
      <div className="desktop-page-header-main">
        <span className="desktop-page-header-eyebrow">{eyebrow}</span>
        <div className="desktop-page-header-row">
          <div className="desktop-page-header-copy">
            <h2 className="desktop-page-header-title">{title}</h2>
            <p className="desktop-page-header-description">{description}</p>
          </div>
          {actions ? <div className="desktop-page-header-actions">{actions}</div> : null}
        </div>
      </div>
      {meta.length ? (
        <div className="desktop-page-header-meta">
          {meta.map((item) => (
            <div key={`${item.label}-${String(item.value)}`} className={`desktop-page-header-chip${toneClassName(item.tone)}`}>
              <span className="desktop-page-header-chip-label">{item.label}</span>
              <strong className="desktop-page-header-chip-value">{item.value}</strong>
            </div>
          ))}
        </div>
      ) : null}
    </section>
  );
}
