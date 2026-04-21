"use client";

import { Descriptions, Input, Space, Typography } from "antd";

import { getRollbackArtifactDiffs, getRollbackArtifactSummary } from "@/lib/remediation";

type RollbackArtifactPanelProps = {
  rollbackHint?: string | null;
  rollbackCommand?: string | null;
  rollbackArtifact?: unknown;
  commandLabel?: string;
};

export default function RollbackArtifactPanel({
  rollbackHint,
  rollbackCommand,
  rollbackArtifact,
  commandLabel = "回滚命令",
}: RollbackArtifactPanelProps) {
  const summary = getRollbackArtifactSummary(rollbackArtifact);
  const diffs = getRollbackArtifactDiffs(rollbackArtifact);
  const hasContent = Boolean(rollbackHint || rollbackCommand || summary || diffs.length);

  if (!hasContent) {
    return null;
  }

  return (
    <Space direction="vertical" size={6} style={{ width: "100%" }}>
      {rollbackHint ? (
        <Typography.Text type="secondary" className="ui-detail-wrap">
          回滚提示: {rollbackHint}
        </Typography.Text>
      ) : null}

      {summary ? (
        <Descriptions column={1} size="small" bordered>
          {summary.packageName ? <Descriptions.Item label="回滚对象">{summary.packageName}</Descriptions.Item> : null}
          {summary.manager ? <Descriptions.Item label="包管理器">{summary.manager}</Descriptions.Item> : null}
          {summary.rollbackVersion ? <Descriptions.Item label="回滚版本">{summary.rollbackVersion}</Descriptions.Item> : null}
          {summary.transactionId ? <Descriptions.Item label="事务号">{summary.transactionId}</Descriptions.Item> : null}
        </Descriptions>
      ) : null}

      {diffs.length ? (
        <Space direction="vertical" size={2} style={{ width: "100%" }}>
          <Typography.Text type="secondary">前后包上下文差异</Typography.Text>
          {diffs.map((item) => (
            <Typography.Text key={item.label} type="secondary" className="ui-detail-wrap">
              {item.label}: {item.before} -&gt; {item.after}
            </Typography.Text>
          ))}
        </Space>
      ) : null}

      {rollbackCommand ? (
        <Space direction="vertical" size={4} style={{ width: "100%" }}>
          <Typography.Text type="secondary">{commandLabel}</Typography.Text>
          <Input.TextArea rows={3} value={rollbackCommand} readOnly />
        </Space>
      ) : null}
    </Space>
  );
}
