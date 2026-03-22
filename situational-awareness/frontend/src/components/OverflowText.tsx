"use client";

import type { CSSProperties, ReactNode } from "react";
import { Tooltip } from "antd";

type OverflowTextProps = {
  value: ReactNode;
  tooltip?: ReactNode | false;
  lines?: 1 | 2;
  block?: boolean;
  strong?: boolean;
  secondary?: boolean;
  mono?: boolean;
  className?: string;
  style?: CSSProperties;
};

function joinClassNames(...values: Array<string | false | null | undefined>) {
  return values.filter(Boolean).join(" ");
}

export default function OverflowText({
  value,
  tooltip,
  lines = 1,
  block = false,
  strong = false,
  secondary = false,
  mono = false,
  className,
  style,
}: OverflowTextProps) {
  const content = value ?? "-";
  const tooltipTitle = tooltip === false ? null : tooltip ?? content;
  const textNode = (
    <span
      className={joinClassNames(
        "ui-overflow-text",
        block ? "ui-overflow-text-block" : "ui-overflow-text-inline",
        lines === 2 ? "ui-overflow-text-two-line" : "ui-overflow-text-one-line",
        strong ? "ui-overflow-text-strong" : "",
        secondary ? "ui-overflow-text-secondary" : "",
        mono ? "mono-text" : "",
        className,
      )}
      style={style}
    >
      {content}
    </span>
  );

  if (tooltipTitle === null) {
    return textNode;
  }

  return <Tooltip title={tooltipTitle}>{textNode}</Tooltip>;
}
