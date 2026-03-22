"use client";

import { Collapse, Typography } from "antd";

type CollapsibleJsonBlockProps = {
  title: string;
  value: unknown;
  emptyText?: string;
};

function hasContent(value: unknown): boolean {
  if (value == null) {
    return false;
  }
  if (Array.isArray(value)) {
    return value.length > 0;
  }
  if (typeof value === "object") {
    return Object.keys(value as Record<string, unknown>).length > 0;
  }
  if (typeof value === "string") {
    return value.trim().length > 0;
  }
  return true;
}

function formatJsonValue(value: unknown, emptyText: string): string {
  if (!hasContent(value)) {
    return emptyText;
  }
  if (typeof value === "string") {
    return value;
  }
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

export default function CollapsibleJsonBlock({
  title,
  value,
  emptyText = "无可展示数据",
}: CollapsibleJsonBlockProps) {
  const content = formatJsonValue(value, emptyText);

  return (
    <Collapse
      ghost
      size="small"
      style={{ width: "100%" }}
      items={[
        {
          key: "json",
          label: <Typography.Text type="secondary">{title}</Typography.Text>,
          children: <div className="code-block">{content}</div>,
        },
      ]}
    />
  );
}
