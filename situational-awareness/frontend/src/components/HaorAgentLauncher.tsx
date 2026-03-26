"use client";

import { useEffect, useState } from "react";
import dynamic from "next/dynamic";
import { Badge } from "antd";

import { getStoredToken, type StoredUserRole } from "@/lib/auth";
import { getHaorSessionSummary } from "@/services/api";
import type { AgentSessionSummary } from "@/types/agent";

type HaorAgentLauncherProps = {
  userRole: StoredUserRole;
};

const HAOR_SUMMARY_POLL_INTERVAL_MS = 15_000;
const EMPTY_HAOR_SUMMARY: AgentSessionSummary = {
  has_attention: false,
  attention_kind: "none",
  session_status: null,
  runtime_phase: "idle",
  input_state: "enabled",
  input_block_reason: "none",
  current_goal_id: null,
  current_goal_title: null,
  active_skill_title: null,
  last_task_id: null,
  updated_at: null,
};

const HaorAgentDrawer = dynamic(() => import("@/components/HaorAgentDrawer"), {
  ssr: false,
});

export default function HaorAgentLauncher({ userRole }: HaorAgentLauncherProps) {
  const [activated, setActivated] = useState(false);
  const [summary, setSummary] = useState<AgentSessionSummary>(EMPTY_HAOR_SUMMARY);

  useEffect(() => {
    if (activated) {
      return undefined;
    }
    const token = getStoredToken();
    if (!token) {
      setSummary(EMPTY_HAOR_SUMMARY);
      return undefined;
    }

    let disposed = false;

    const refreshSummary = async () => {
      try {
        const result = await getHaorSessionSummary();
        if (!disposed) {
          setSummary(result);
        }
      } catch {
        return;
      }
    };

    const handleVisibilityRefresh = () => {
      if (!document.hidden) {
        void refreshSummary();
      }
    };

    void refreshSummary();
    const intervalId = window.setInterval(() => {
      void refreshSummary();
    }, HAOR_SUMMARY_POLL_INTERVAL_MS);
    document.addEventListener("visibilitychange", handleVisibilityRefresh);
    window.addEventListener("focus", handleVisibilityRefresh);

    return () => {
      disposed = true;
      window.clearInterval(intervalId);
      document.removeEventListener("visibilitychange", handleVisibilityRefresh);
      window.removeEventListener("focus", handleVisibilityRefresh);
    };
  }, [activated]);

  if (activated) {
    return <HaorAgentDrawer userRole={userRole} initialOpen />;
  }

  return (
    <div className={`haor-fab-shell ${summary.has_attention ? "haor-fab-shell-attention" : ""}`}>
      <Badge dot={summary.has_attention} color="#dc2626" offset={[-8, 8]}>
        <button type="button" className="haor-fab-button" onClick={() => setActivated(true)} aria-label="打开 haor 智能体">
          <span className="haor-fab-ball">
            <span className="haor-fab-core" />
          </span>
          <span className="haor-fab-label">haor</span>
        </button>
      </Badge>
    </div>
  );
}
