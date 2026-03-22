import "@/styles/globals.css";
import "antd/dist/reset.css";

import type { Metadata } from "next";
import type { ReactNode } from "react";
import AppShell from "@/components/AppShell";

export const metadata: Metadata = {
  title: "内网资产态势感知",
  description: "内网资产发现与风险验证",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="zh-CN">
      <body><AppShell>{children}</AppShell></body>
    </html>
  );
}
