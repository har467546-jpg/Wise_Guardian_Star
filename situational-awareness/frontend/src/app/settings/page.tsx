"use client";

import { useState } from "react";
import { Button, Card, Space, Typography } from "antd";
import { SettingOutlined } from "@ant-design/icons";

import GlobalSettingsModal from "@/components/GlobalSettingsModal";
import { getStoredUserRole } from "@/lib/auth";

export default function SettingsPage() {
  const [open, setOpen] = useState(true);
  const userRole = getStoredUserRole();

  return (
    <div className="settings-page">
      <Card className="panel-card settings-page-card">
        <Space direction="vertical" size={18} className="settings-page-stack">
          <div className="settings-page-heading">
            <div>
              <Typography.Title level={3}>系统设置中心</Typography.Title>
              <Typography.Text type="secondary">
                统一管理扫描策略、Runner 心跳、修复安全策略、平台访问控制与 AI 接入参数。
              </Typography.Text>
            </div>
            <Button type="primary" icon={<SettingOutlined />} onClick={() => setOpen(true)}>
              打开设置
            </Button>
          </div>
        </Space>
      </Card>
      <GlobalSettingsModal open={open} onClose={() => setOpen(false)} userRole={userRole} />
    </div>
  );
}
