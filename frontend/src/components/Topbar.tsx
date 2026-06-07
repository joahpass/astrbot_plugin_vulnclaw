import { StatusDot } from "./StatusDot";
import { formatTaskStatus } from "../utils/taskLabels";

interface TopbarProps {
  eyebrow: string;
  title: string;
  copy: string;
  selectedTarget: string | null;
  activeTaskStatus?: string;
}

function statusTone(status?: string): "idle" | "ok" | "warn" | "danger" | "running" {
  if (status === "running" || status === "pending") return "running";
  if (status === "completed") return "ok";
  if (status === "failed") return "danger";
  if (status === "stopped") return "warn";
  return "idle";
}

export function Topbar({ eyebrow, title, copy, selectedTarget, activeTaskStatus }: TopbarProps) {
  const targetLabel = selectedTarget ? `Target: ${selectedTarget}` : "No target selected";

  return (
    <header className="topbar">
      <div>
        <div className="topbar-eyebrow">{eyebrow}</div>
        <h2>{title}</h2>
        <p>{copy}</p>
      </div>
      <div className="topbar-status">
        <StatusDot tone={statusTone(activeTaskStatus)} label={activeTaskStatus ? formatTaskStatus(activeTaskStatus) : "Idle"} />
        <StatusDot tone={selectedTarget ? "ok" : "idle"} label={targetLabel} />
      </div>
    </header>
  );
}
