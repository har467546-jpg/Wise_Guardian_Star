"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Button, Space, Tag, Typography } from "antd";
import { DisconnectOutlined, ReloadOutlined, ThunderboltOutlined } from "@ant-design/icons";
import type { FitAddon as XTermFitAddon } from "@xterm/addon-fit";
import type { Terminal as XTermTerminal } from "@xterm/xterm";
import type { IDisposable } from "@xterm/xterm";

import { issueTerminalTicket } from "@/services/api";

type TerminalStatus = "idle" | "connecting" | "connected" | "closed" | "error";

type RemoteSshTerminalProps = {
  assetId: string;
  assetLabel: string;
  enabled: boolean;
  blockedReasons: string[];
};

function buildTerminalWebSocketUrl(assetId: string, ticket: string, cols: number, rows: number): string {
  const streamPath = `/remediation/assets/${assetId}/terminal`;
  const apiBase = (process.env.NEXT_PUBLIC_API_BASE || "/api/v1").replace(/\/$/, "");
  const query = `ticket=${encodeURIComponent(ticket)}&cols=${cols}&rows=${rows}`;
  if (apiBase.startsWith("http://") || apiBase.startsWith("https://")) {
    const parsed = new URL(apiBase);
    const protocol = parsed.protocol === "https:" ? "wss:" : "ws:";
    return `${protocol}//${parsed.host}${parsed.pathname}${streamPath}?${query}`;
  }
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  return `${protocol}://${window.location.host}${apiBase}${streamPath}?${query}`;
}

function terminalStatusColor(status: TerminalStatus): string {
  switch (status) {
    case "connected":
      return "green";
    case "connecting":
      return "processing";
    case "error":
      return "red";
    case "closed":
      return "orange";
    default:
      return "default";
  }
}

function terminalStatusLabel(status: TerminalStatus): string {
  switch (status) {
    case "connected":
      return "已连接";
    case "connecting":
      return "连接中";
    case "closed":
      return "已断开";
    case "error":
      return "连接异常";
    default:
      return "未连接";
  }
}

export default function RemoteSshTerminal({ assetId, assetLabel, enabled, blockedReasons }: RemoteSshTerminalProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const terminalRef = useRef<XTermTerminal | null>(null);
  const fitAddonRef = useRef<XTermFitAddon | null>(null);
  const socketRef = useRef<WebSocket | null>(null);
  const dataSubscriptionRef = useRef<IDisposable | null>(null);
  const resizeObserverRef = useRef<ResizeObserver | null>(null);
  const connectAttemptRef = useRef(0);
  const [status, setStatus] = useState<TerminalStatus>("idle");
  const [peerLabel, setPeerLabel] = useState(assetLabel);
  const [terminalSize, setTerminalSize] = useState({ cols: 100, rows: 28 });
  const [lastError, setLastError] = useState<string | null>(null);

  const sendResize = useCallback(() => {
    const terminal = terminalRef.current;
    const socket = socketRef.current;
    if (!terminal) {
      return;
    }
    fitAddonRef.current?.fit();
    const nextSize = { cols: terminal.cols, rows: terminal.rows };
    setTerminalSize(nextSize);
    if (socket?.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ type: "resize", cols: nextSize.cols, rows: nextSize.rows }));
    }
  }, []);

  const disconnect = useCallback(() => {
    connectAttemptRef.current += 1;
    window.removeEventListener("resize", sendResize);
    resizeObserverRef.current?.disconnect();
    resizeObserverRef.current = null;
    const socket = socketRef.current;
    socketRef.current = null;
    if (socket && socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ type: "close" }));
    }
    socket?.close();
    setStatus((current) => current === "idle" ? current : "closed");
  }, [sendResize]);

  const connect = useCallback(async () => {
    if (!enabled || status === "connecting" || status === "connected") {
      return;
    }
    const container = containerRef.current;
    if (!container) {
      return;
    }
    const attemptId = connectAttemptRef.current + 1;
    connectAttemptRef.current = attemptId;
    setStatus("connecting");
    setLastError(null);

    terminalRef.current?.dispose();
    dataSubscriptionRef.current?.dispose();
    dataSubscriptionRef.current = null;
    socketRef.current?.close();
    resizeObserverRef.current?.disconnect();
    container.innerHTML = "";

    const [{ Terminal }, { FitAddon }] = await Promise.all([
      import("@xterm/xterm"),
      import("@xterm/addon-fit"),
    ]);
    if (connectAttemptRef.current !== attemptId) {
      return;
    }

    const terminal = new Terminal({
      cursorBlink: true,
      convertEol: true,
      fontFamily: "var(--font-code), Menlo, Consolas, monospace",
      fontSize: 13,
      lineHeight: 1.18,
      scrollback: 3000,
      theme: {
        background: "#07111d",
        foreground: "#d8e8f7",
        cursor: "#f7d774",
        selectionBackground: "#294863",
        black: "#07111d",
        red: "#ff6b6b",
        green: "#4ade80",
        yellow: "#facc15",
        blue: "#60a5fa",
        magenta: "#c084fc",
        cyan: "#2dd4bf",
        white: "#e5edf5",
        brightBlack: "#5d7085",
        brightRed: "#ff8787",
        brightGreen: "#86efac",
        brightYellow: "#fde047",
        brightBlue: "#93c5fd",
        brightMagenta: "#d8b4fe",
        brightCyan: "#67e8f9",
        brightWhite: "#ffffff",
      },
    });
    const fitAddon = new FitAddon();
    terminal.loadAddon(fitAddon);
    terminal.open(container);
    fitAddon.fit();
    terminal.focus();
    terminal.writeln(`\x1b[36mRequesting one-time terminal ticket...\x1b[0m`);

    terminalRef.current = terminal;
    fitAddonRef.current = fitAddon;
    const initialSize = { cols: terminal.cols, rows: terminal.rows };
    setTerminalSize(initialSize);

    let ticket = "";
    try {
      const ticketResponse = await issueTerminalTicket(assetId);
      ticket = ticketResponse.ticket;
      terminal.writeln(`\x1b[36mConnecting to ${assetLabel}...\x1b[0m`);
    } catch (error) {
      const message = error instanceof Error ? error.message : "终端票据申请失败";
      setLastError(message);
      setStatus("error");
      terminal.writeln(`\r\n\x1b[31m${message}\x1b[0m`);
      return;
    }
    if (connectAttemptRef.current !== attemptId) {
      return;
    }

    const socket = new WebSocket(buildTerminalWebSocketUrl(assetId, ticket, initialSize.cols, initialSize.rows));
    socketRef.current = socket;
    dataSubscriptionRef.current = terminal.onData((data) => {
      const activeSocket = socketRef.current;
      if (activeSocket === socket && activeSocket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ type: "input", data }));
      }
    });

    socket.onopen = () => {
      setStatus("connected");
      sendResize();
    };
    socket.onmessage = (event) => {
      try {
        const payload = JSON.parse(String(event.data)) as Record<string, unknown>;
        if (payload.type === "ready") {
          const username = String(payload.username || "");
          const ip = String(payload.ip || "");
          setPeerLabel(`${username}@${ip}` || assetLabel);
          terminal.writeln(`\r\n\x1b[32mConnected: ${username}@${ip}\x1b[0m\r\n`);
          return;
        }
        if (payload.type === "output" && typeof payload.data === "string") {
          terminal.write(payload.data);
          return;
        }
        if (payload.type === "error") {
          const message = String(payload.message || "SSH 终端连接失败");
          setLastError(message);
          setStatus("error");
          terminal.writeln(`\r\n\x1b[31m${message}\x1b[0m`);
          return;
        }
        if (payload.type === "security_violation") {
          const message = String(payload.message || "检测到高危终端命令，SSH 会话已被阻断");
          const commandPreview = String(payload.command_preview || "");
          setLastError(message);
          setStatus("error");
          terminal.writeln(`\r\n\x1b[31m${message}\x1b[0m`);
          if (commandPreview) {
            terminal.writeln(`\x1b[33mBlocked: ${commandPreview}\x1b[0m`);
          }
          return;
        }
        if (payload.type === "exit") {
          setStatus("closed");
          terminal.writeln("\r\n\x1b[33mRemote shell exited.\x1b[0m");
        }
      } catch {
        terminal.write(String(event.data));
      }
    };
    socket.onerror = () => {
      setLastError("终端 WebSocket 连接异常");
      setStatus("error");
    };
    socket.onclose = (event) => {
      if (connectAttemptRef.current !== attemptId) {
        return;
      }
      if (event.code === 1008) {
        setLastError(event.reason || "终端连接未通过授权校验");
        setStatus("error");
        terminal.writeln(`\r\n\x1b[31m${event.reason || "Unauthorized terminal session."}\x1b[0m`);
        return;
      }
      setStatus((current) => current === "error" ? current : "closed");
    };

    const observer = new ResizeObserver(() => {
      window.requestAnimationFrame(sendResize);
    });
    observer.observe(container);
    resizeObserverRef.current = observer;
    window.removeEventListener("resize", sendResize);
    window.addEventListener("resize", sendResize);
  }, [assetId, assetLabel, enabled, sendResize, status]);

  useEffect(() => {
    return () => {
      window.removeEventListener("resize", sendResize);
      disconnect();
      terminalRef.current?.dispose();
      terminalRef.current = null;
      dataSubscriptionRef.current?.dispose();
      dataSubscriptionRef.current = null;
      fitAddonRef.current = null;
    };
  }, [disconnect, sendResize]);

  useEffect(() => {
    if (!enabled) {
      disconnect();
    }
  }, [disconnect, enabled]);

  return (
    <div className="remote-ssh-terminal-shell">
      <div className="remote-ssh-terminal-toolbar">
        <Space wrap>
          <Tag color={enabled ? terminalStatusColor(status) : "default"}>
            {enabled ? terminalStatusLabel(status) : "不可连接"}
          </Tag>
          <Tag>{peerLabel}</Tag>
          <Tag>{`${terminalSize.cols}x${terminalSize.rows}`}</Tag>
        </Space>
        <Space wrap>
          <Button
            size="small"
            type="primary"
            icon={status === "closed" || status === "error" ? <ReloadOutlined /> : <ThunderboltOutlined />}
            onClick={() => void connect()}
            disabled={!enabled || status === "connecting" || status === "connected"}
            loading={status === "connecting"}
          >
            {status === "closed" || status === "error" ? "重连" : "连接"}
          </Button>
          <Button
            size="small"
            icon={<DisconnectOutlined />}
            onClick={disconnect}
            disabled={status !== "connecting" && status !== "connected"}
          >
            断开
          </Button>
        </Space>
      </div>
      {!enabled || lastError ? (
        <div className={enabled ? "remote-ssh-terminal-notice" : "remote-ssh-terminal-disabled"}>
          <Typography.Text type={lastError ? "danger" : "secondary"}>
            {lastError || blockedReasons.join("；") || "当前资产暂不可连接"}
          </Typography.Text>
        </div>
      ) : null}
      <div ref={containerRef} className="remote-ssh-terminal-surface" />
    </div>
  );
}
