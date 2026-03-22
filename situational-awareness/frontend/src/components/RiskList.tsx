"use client";

import { useEffect, useState } from "react";
import { Alert, Card, List, Typography } from "antd";

import { apiFetch } from "@/services/api";
import { RiskFinding, RiskFindingListResponse } from "@/types/risk";
import StatusTag from "@/components/StatusTag";

export default function RiskList({ assetId }: { assetId: string }) {
  const [items, setItems] = useState<RiskFinding[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiFetch<RiskFindingListResponse>(`/risks/assets/${assetId}`)
      .then((res) => setItems(res.items))
      .catch((err) => setError((err as Error).message));
  }, [assetId]);

  return (
    <Card title={`资产 ${assetId} 风险列表`}>
      {error ? <Alert type="error" showIcon message={error} style={{ marginBottom: 16 }} /> : null}
      <List
        dataSource={items}
        renderItem={(item) => (
          <List.Item>
            <List.Item.Meta
              title={
                <>
                  <StatusTag value={item.severity} />
                  {item.title}
                </>
              }
              description={
                <Typography.Paragraph style={{ margin: 0 }}>{item.description}</Typography.Paragraph>
              }
            />
          </List.Item>
        )}
      />
    </Card>
  );
}
