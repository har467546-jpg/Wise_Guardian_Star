"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Alert, Button, Card, Divider, Form, Input, Skeleton, Space, Typography } from "antd";
import { UserOutlined, LockOutlined, MailOutlined, SafetyCertificateOutlined, ReloadOutlined } from "@ant-design/icons";

import DesktopMetricCard from "@/components/DesktopMetricCard";
import { bootstrapAdmin, getBootstrapStatus, login } from "@/services/api";
import { setStoredAuthTokens } from "@/lib/auth";
import type { BootstrapStatusResponse } from "@/types/auth";

export default function LoginPage() {
  const router = useRouter();
  const [bootstrapStatus, setBootstrapStatus] = useState<BootstrapStatusResponse | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [statusLoading, setStatusLoading] = useState(true);
  const [loginLoading, setLoginLoading] = useState(false);
  const [bootstrapLoading, setBootstrapLoading] = useState(false);

  const refreshBootstrapStatus = async () => {
    try {
      setStatusLoading(true);
      const result = await getBootstrapStatus();
      setBootstrapStatus(result);
      setStatusError(null);
    } catch (err) {
      setBootstrapStatus(null);
      setStatusError((err as Error).message);
    } finally {
      setStatusLoading(false);
    }
  };

  useEffect(() => {
    void refreshBootstrapStatus();
  }, []);

  const onLoginFinish = async (values: any) => {
    try {
      setLoginLoading(true);
      const response = await login(values);
      setStoredAuthTokens(response);
      router.replace("/");
    } catch (err) {
      setActionError((err as Error).message);
    } finally {
      setLoginLoading(false);
    }
  };

  const onBootstrapFinish = async (values: any) => {
    try {
      setBootstrapLoading(true);
      const response = await bootstrapAdmin({
        username: values.username,
        email: values.email,
        password: values.password,
      });
      setStoredAuthTokens(response);
      router.replace("/");
    } catch (err) {
      setActionError((err as Error).message);
      void refreshBootstrapStatus();
    } finally {
      setBootstrapLoading(false);
    }
  };

  const showBootstrap = bootstrapStatus ? !bootstrapStatus.bootstrapped : false;
  const formTitle = showBootstrap ? "系统初始化" : "欢迎回来";
  const formDescription = showBootstrap ? "请创建首个超级管理员账号，系统会在完成后自动登录。" : "输入当前账号凭据，进入统一安全工作台。";

  return (
    <div className="login-shell">
      <div className="login-backdrop" />
      <div className="login-grid">
        <Card className="login-side-panel" bordered={false}>
          <div className="login-side-top">
            <div className="login-badge-row">
              <span className="brand-kicker">Unified Security Workspace</span>
              <span className="login-status-chip">{showBootstrap ? "待初始化" : "访问已启用"}</span>
            </div>

            <Typography.Title level={1} className="login-side-title">
              资产态势感知平台
            </Typography.Title>
            <Typography.Paragraph className="login-side-description">
              用统一的白色科技工作流管理资产发现、风险验证、漏洞规则和修复执行，让复杂安全操作回到一个清晰一致的桌面界面。
            </Typography.Paragraph>

            <div className="desktop-metric-grid login-metric-grid">
              <DesktopMetricCard
                label="模式"
                value="LIGHT"
                detail="统一浅色工作台"
                tone="accent"
              />
              <DesktopMetricCard
                label="引擎状态"
                value={showBootstrap ? "WAIT" : "READY"}
                detail={showBootstrap ? "等待初始化" : "访问就绪"}
                tone={showBootstrap ? "warning" : "success"}
              />
            </div>

            <div className="login-feature-grid">
              <div className="login-feature-card">
                <strong>资产与风险统一视图</strong>
                <span>在同一套工作台里查看发现结果、验证状态和风险处置入口。</span>
              </div>
              <div className="login-feature-card">
                <strong>修复流程可追踪</strong>
                <span>围绕授权、Runner、计划执行和结果输出建立一致的操作节奏。</span>
              </div>
            </div>
          </div>

          <div className="login-side-notes">
            <div className="console-stage-item">
              <span>01</span>
              <div>
                <Typography.Text strong>身份验证</Typography.Text>
                <p>使用管理员凭据进入统一工作台，初始化阶段会自动创建首个管理员。</p>
              </div>
            </div>
            <div className="console-stage-item">
              <span>02</span>
              <div>
                <Typography.Text strong>统一操作</Typography.Text>
                <p>扫描、资产、漏洞库、任务日志和修复流程共享同一套界面语言与导航结构。</p>
              </div>
            </div>
            <div className="console-stage-item">
              <span>03</span>
              <div>
                <Typography.Text strong>结果闭环</Typography.Text>
                <p>从发现到验证再到修复执行，都在浅色高可读布局中保持连贯。</p>
              </div>
            </div>
          </div>
        </Card>

        <Card className="login-form-panel" bordered={false}>
          <Space direction="vertical" size={24} className="login-form-stack">
            <header className="login-form-header">
              <Typography.Text type="secondary" className="brand-kicker login-form-kicker">
                Access Control
              </Typography.Text>
              <Typography.Title level={2} className="login-form-title">
                {formTitle}
              </Typography.Title>
              <Typography.Text type="secondary" className="login-form-description">
                {formDescription}
              </Typography.Text>
            </header>

            {statusError ? <Alert showIcon type="warning" message={statusError} /> : null}
            {actionError ? <Alert showIcon type="error" message={actionError} closable onClose={() => setActionError(null)} /> : null}

            {statusLoading ? (
              <Skeleton active paragraph={{ rows: 8 }} />
            ) : showBootstrap ? (
              <Form layout="vertical" onFinish={onBootstrapFinish} size="large" className="login-form">
                <Form.Item name="username" rules={[{ required: true, message: "请输入用户名" }]}>
                  <Input prefix={<UserOutlined className="login-input-icon" />} placeholder="管理员用户名" />
                </Form.Item>
                <Form.Item name="email" rules={[{ required: true, type: "email", message: "请输入有效邮箱" }]}>
                  <Input prefix={<MailOutlined className="login-input-icon" />} placeholder="管理员邮箱" />
                </Form.Item>
                <Form.Item name="password" rules={[{ required: true, min: 8, message: "密码至少8位" }]}>
                  <Input.Password prefix={<LockOutlined className="login-input-icon" />} placeholder="管理员密码" />
                </Form.Item>
                <Form.Item
                  name="confirmPassword"
                  dependencies={["password"]}
                  rules={[
                    { required: true, message: "请确认密码" },
                    ({ getFieldValue }) => ({
                      validator(_, value) {
                        if (!value || getFieldValue("password") === value) {
                          return Promise.resolve();
                        }
                        return Promise.reject(new Error("两次密码不一致"));
                      },
                    }),
                  ]}
                >
                  <Input.Password prefix={<SafetyCertificateOutlined className="login-input-icon" />} placeholder="确认密码" />
                </Form.Item>
                <Button type="primary" htmlType="submit" loading={bootstrapLoading} block size="large" className="login-submit-button">
                  初始化并登录
                </Button>
              </Form>
            ) : (
              <Form layout="vertical" onFinish={onLoginFinish} size="large" className="login-form">
                <Form.Item name="username" rules={[{ required: true, message: "请输入用户名" }]}>
                  <Input prefix={<UserOutlined className="login-input-icon" />} placeholder="用户名 / 邮箱" />
                </Form.Item>
                <Form.Item name="password" rules={[{ required: true, message: "请输入密码" }]}>
                  <Input.Password prefix={<LockOutlined className="login-input-icon" />} placeholder="密码" />
                </Form.Item>
                <Button type="primary" htmlType="submit" loading={loginLoading} block size="large" className="login-submit-button">
                  立即登录
                </Button>
                <Divider plain className="login-divider">OR</Divider>
                <Button
                  icon={<ReloadOutlined />}
                  onClick={() => void refreshBootstrapStatus()}
                  block
                  className="login-secondary-button"
                >
                  同步系统状态
                </Button>
              </Form>
            )}

            <footer className="login-form-footer">
              <Typography.Text type="secondary">© 2026 资产态势感知平台 · 统一安全工作台</Typography.Text>
            </footer>
          </Space>
        </Card>
      </div>
    </div>
  );
}
