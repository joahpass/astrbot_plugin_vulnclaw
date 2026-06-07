import type { TaskCommand } from "../types/api";

const COMMAND_LABELS: Record<TaskCommand, string> = {
  recon: "Quick Recon",
  run: "Standard Scan",
  scan: "Deep Scan",
  exploit: "Verification",
  persistent: "Continuous Scan",
};

const ACTION_LABELS: Record<string, string> = {
  recon: "Recon",
  run: "Standard Scan",
  scan: "Scan",
  exploit: "Verify",
  persistent: "Continuous Scan",
  post_exploitation: "Post-exploitation",
};

const PHASE_LABELS: Record<string, string> = {
  scope: "Scope",
  recon: "Recon",
  scan: "Scan",
  verify: "Verify",
  exploit: "Exploit",
  report: "Report",
};

const STATUS_LABELS: Record<string, string> = {
  pending: "Queued",
  running: "Running",
  completed: "Completed",
  failed: "Failed",
  stopped: "Stopped",
};

const FINDING_STATUS_LABELS: Record<string, string> = {
  verified: "Verified",
  pending: "Pending",
  candidate: "Candidate",
  manual_review: "Manual review",
  dismissed: "Dismissed",
  false_positive: "False positive",
};

const EVENT_LABELS: Record<string, string> = {
  task_started: "Task started",
  task_progress: "Task progress",
  task_message: "Task message",
  task_completed: "Task completed",
  task_failed: "Task failed",
  task_stopped: "Task stopped",
};

const SEVERITY_LABELS: Record<string, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  warn: "Warn",
  warning: "Warn",
  low: "Low",
  info: "Info",
};

const MCP_HEALTH_LABELS: Record<string, string> = {
  healthy: "Healthy",
  degraded: "Degraded",
  unavailable: "Offline",
  unknown: "Unknown",
};

const MCP_MODE_LABELS: Record<string, string> = {
  local: "Local",
  placeholder: "Placeholder",
  sdk: "SDK",
  sse: "SSE",
};

export function formatTaskCommand(command: string | null | undefined): string {
  if (!command) return "Scan";
  return COMMAND_LABELS[command as TaskCommand] ?? "Custom Scan";
}

export function formatTaskTitle(command: string | null | undefined, target: string): string {
  return `${formatTaskCommand(command)} - ${target}`;
}

export function formatActionLabel(action: string): string {
  return ACTION_LABELS[action] ?? action;
}

export function formatActionList(actions: string[] | undefined, fallback = "Default scope"): string {
  if (!actions?.length) return fallback;
  return actions.map(formatActionLabel).join(", ");
}

export function formatPhaseLabel(phase: string | null | undefined): string {
  if (!phase) return "No phase";
  const normalized = phase.toLowerCase();
  const matchedKey = Object.keys(PHASE_LABELS).find((key) => normalized.includes(key));
  return PHASE_LABELS[normalized] ?? (matchedKey ? PHASE_LABELS[matchedKey] : phase);
}

export function formatTaskStatus(status: string | null | undefined): string {
  if (!status) return "Idle";
  return STATUS_LABELS[status] ?? status;
}

export function formatFindingStatus(status: string | null | undefined): string {
  if (!status) return "Pending";
  const normalized = status.toLowerCase();
  const matchedKey = Object.keys(FINDING_STATUS_LABELS).find((key) => normalized.includes(key));
  return FINDING_STATUS_LABELS[normalized] ?? (matchedKey ? FINDING_STATUS_LABELS[matchedKey] : status);
}

export function formatEventLabel(event: string | null | undefined): string {
  if (!event) return "Task event";
  return EVENT_LABELS[event] ?? event;
}

export function formatSeverityLabel(severity: string | null | undefined): string {
  if (!severity) return "Info";
  const normalized = severity.toLowerCase();
  const matchedKey = Object.keys(SEVERITY_LABELS).find((key) => normalized.includes(key));
  return SEVERITY_LABELS[normalized] ?? (matchedKey ? SEVERITY_LABELS[matchedKey] : severity);
}

export function formatMcpHealth(status: string | null | undefined): string {
  if (!status) return "Unknown";
  return MCP_HEALTH_LABELS[status] ?? status;
}

export function formatMcpExecutionMode(mode: string | null | undefined): string {
  if (!mode) return "Unknown";
  return MCP_MODE_LABELS[mode] ?? mode;
}

export function formatResumeStrategy(strategy: string | null | undefined): string {
  if (!strategy) return "No resume guidance";
  const normalized = strategy.toLowerCase();
  if (normalized.includes("stop") || normalized.includes("complete")) return "Can end current scan";
  if (normalized.includes("verify")) return "Review verified findings first";
  if (normalized.includes("exploit")) return "Verify authorization before validation";
  if (normalized.includes("scan")) return "Continue risk discovery";
  if (normalized.includes("recon")) return "Add more recon";
  if (normalized.includes("continue") || normalized.includes("resume")) return "Resume from current state";
  return strategy;
}

export function formatConstraintSummary(constraints: Record<string, unknown> | undefined): string {
  if (!constraints || !Object.keys(constraints).length) return "No extra boundary";
  const labels: string[] = [];
  const onlyHost = constraints.allowed_hosts ?? constraints.only_host;
  const onlyPath = constraints.allowed_paths ?? constraints.only_path;
  const onlyPort = constraints.allowed_ports ?? constraints.only_port;
  const blockedHost = constraints.blocked_hosts ?? constraints.blocked_host;
  const blockedPath = constraints.blocked_paths ?? constraints.blocked_path;
  const allowActions = constraints.allowed_actions ?? constraints.allow_actions;
  const blockActions = constraints.blocked_actions ?? constraints.block_actions;
  if (onlyHost) labels.push(`host ${formatConstraintValue(onlyHost)}`);
  if (onlyPath) labels.push(`path ${formatConstraintValue(onlyPath)}`);
  if (onlyPort) labels.push(`port ${formatConstraintValue(onlyPort)}`);
  if (blockedHost) labels.push(`block host ${formatConstraintValue(blockedHost)}`);
  if (blockedPath) labels.push(`block path ${formatConstraintValue(blockedPath)}`);
  if (Array.isArray(allowActions)) labels.push(`allow ${formatActionList(allowActions.map(String))}`);
  if (Array.isArray(blockActions)) labels.push(`block ${formatActionList(blockActions.map(String))}`);
  return labels.length ? labels.join(", ") : "Custom boundary";
}

export function countConstraintViolations(
  events: unknown[] | undefined,
  violations: unknown[] | undefined,
  fallback = 0,
): number {
  if (events?.length) return events.length;
  if (violations?.length) return violations.length;
  return fallback;
}

function formatConstraintValue(value: unknown): string {
  if (Array.isArray(value)) return value.map(String).filter(Boolean).join(", ");
  return String(value);
}
