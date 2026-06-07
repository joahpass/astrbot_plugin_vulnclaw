import { useEffect, useMemo, useState } from "react";
import { SectionCard } from "../components/SectionCard";
import { useConstraintAuditQuery, useTargetQuery, useTargetsQuery } from "../hooks/queries";
import type { ConstraintAuditEventView, TaskOptions, TaskRecord } from "../types/api";
import { loadUiPreferences, subscribeUiPreferences, type BoundaryDefaults } from "../utils/preferences";
import { countConstraintViolations, formatActionList, formatPhaseLabel, formatSeverityLabel } from "../utils/taskLabels";

interface SafetyBoundaryPageProps {
  selectedTarget: string | null;
  activeTask: TaskRecord | null;
  onOpenHome: () => void;
  onOpenSettings: () => void;
  onSelectTarget: (target: string | null) => void;
}

interface BoundaryChip {
  label: string;
  value: string;
  tone: "allow" | "block" | "neutral";
}

interface BoundaryReadiness {
  tone: "ok" | "warn";
  title: string;
  copy: string;
}

function stringifyValue(key: string, value: unknown): string {
  if (Array.isArray(value)) {
    const values = value.map(String).filter(Boolean);
    return key.includes("actions") ? formatActionList(values) : values.join(", ");
  }
  if (typeof value === "string") return key.includes("actions") ? formatActionList([value]) : value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (value && typeof value === "object") return JSON.stringify(value);
  return "";
}

function boundaryLabel(key: string): string {
  const labels: Record<string, string> = {
    only_host: "Host only",
    only_path: "Path only",
    only_port: "Port only",
    allowed_hosts: "Host only",
    allowed_paths: "Path only",
    allowed_ports: "Port only",
    blocked_host: "Block host",
    blocked_path: "Block path",
    blocked_hosts: "Block host",
    blocked_paths: "Block path",
    allow_actions: "Allow actions",
    allowed_actions: "Allow actions",
    block_actions: "Block actions",
    blocked_actions: "Block actions",
  };
  return labels[key] ?? key;
}

function boundaryTone(key: string): BoundaryChip["tone"] {
  if (key.startsWith("blocked") || key.startsWith("block_")) return "block";
  if (key.startsWith("only") || key.startsWith("allow") || key.startsWith("allowed")) return "allow";
  return "neutral";
}

function normalizeConstraints(constraints: Record<string, unknown> | undefined): Record<string, unknown> {
  if (!constraints) return {};
  return {
    allowed_hosts: constraints.allowed_hosts ?? constraints.only_host,
    allowed_ports: constraints.allowed_ports ?? constraints.only_port,
    allowed_paths: constraints.allowed_paths ?? constraints.only_path,
    blocked_hosts: constraints.blocked_hosts ?? constraints.blocked_host,
    blocked_paths: constraints.blocked_paths ?? constraints.blocked_path,
    allowed_actions: constraints.allowed_actions ?? constraints.allow_actions,
    blocked_actions: constraints.blocked_actions ?? constraints.block_actions,
  };
}

function buildBoundaryChips(constraints: Record<string, unknown> | undefined): BoundaryChip[] {
  if (!constraints) return [];
  return Object.entries(normalizeConstraints(constraints))
    .map(([key, value]) => ({
      label: boundaryLabel(key),
      value: stringifyValue(key, value),
      tone: boundaryTone(key),
    }))
    .filter((item) => item.value && item.value !== "[]" && item.value !== "{}");
}

function boundaryDefaultsToConstraints(defaults: BoundaryDefaults): Record<string, unknown> {
  return {
    only_port: defaults.onlyPort,
    only_host: defaults.onlyHost,
    only_path: defaults.onlyPath,
    blocked_host: defaults.blockedHost,
    blocked_path: defaults.blockedPath,
    allow_actions: defaults.allowActions,
    block_actions: defaults.blockActions,
  };
}

function taskOptionsToConstraints(options: TaskOptions | undefined): Record<string, unknown> {
  if (!options) return {};
  return {
    only_port: options.only_port,
    only_host: options.only_host,
    only_path: options.only_path,
    blocked_host: options.blocked_host,
    blocked_path: options.blocked_path,
    allow_actions: options.allow_actions,
    block_actions: options.block_actions,
  };
}

function hasConstraintValue(value: unknown): boolean {
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === "string") return value.trim().length > 0;
  return value !== undefined && value !== null && value !== false;
}

function boundaryReadiness(constraints: Record<string, unknown> | undefined): BoundaryReadiness {
  const normalized = normalizeConstraints(constraints);
  if (!Object.values(normalized).some(hasConstraintValue)) {
    return {
      tone: "warn",
      title: "Add a scope boundary",
      copy: "No explicit host, port, path, or action limits are set.",
    };
  }

  const hasPreciseScope = ["allowed_hosts", "allowed_ports", "allowed_paths"].some((key) => hasConstraintValue(normalized[key]));
  const hasActionBoundary = ["allowed_actions", "blocked_actions"].some((key) => hasConstraintValue(normalized[key]));

  if (hasPreciseScope && hasActionBoundary) {
    return {
      tone: "ok",
      title: "Scope is clear",
      copy: "Target and action boundaries are both defined.",
    };
  }

  return {
    tone: "warn",
    title: "Boundary is active",
    copy: hasPreciseScope ? "Add action limits for tighter control." : "Add a host, port, or path boundary for precision.",
  };
}

function formatTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value || "Unknown";
  return date.toLocaleString();
}

function eventTone(event: ConstraintAuditEventView): "danger" | "warn" | "info" {
  const severity = event.severity.toLowerCase();
  if (severity.includes("high") || severity.includes("critical")) return "danger";
  if (severity.includes("medium") || severity.includes("warn")) return "warn";
  return "info";
}

export function SafetyBoundaryPage({ selectedTarget, activeTask, onOpenHome, onOpenSettings, onSelectTarget }: SafetyBoundaryPageProps) {
  const targetsQuery = useTargetsQuery();
  const auditQuery = useConstraintAuditQuery();
  const [localTarget, setLocalTarget] = useState("");
  const [showTechnical, setShowTechnical] = useState(false);
  const [defaultBoundary, setDefaultBoundary] = useState<BoundaryDefaults>(() => loadUiPreferences().defaultBoundary);

  useEffect(() => subscribeUiPreferences((preferences) => setDefaultBoundary(preferences.defaultBoundary)), []);

  useEffect(() => {
    if (selectedTarget) {
      setLocalTarget(selectedTarget);
      return;
    }
    const first = targetsQuery.data?.[0]?.target;
    if (first) {
      setLocalTarget(first);
      onSelectTarget(first);
    }
  }, [selectedTarget, targetsQuery.data, onSelectTarget]);

  const targetValue = selectedTarget ?? localTarget ?? null;
  const targetQuery = useTargetQuery(targetValue);
  const target = targetQuery.data;
  const audit = auditQuery.data;
  const defaultConstraints = useMemo(() => boundaryDefaultsToConstraints(defaultBoundary), [defaultBoundary]);
  const activeTaskConstraints = useMemo(() => taskOptionsToConstraints(activeTask?.options), [activeTask?.options]);
  const activeTaskMatchesTarget = Boolean(activeTask?.target && activeTask.target === targetValue);
  const displayedConstraints = activeTaskMatchesTarget && Object.values(activeTaskConstraints).some(hasConstraintValue)
    ? activeTaskConstraints
    : target?.constraints;
  const displayedConstraintsSource = activeTaskMatchesTarget && Object.values(activeTaskConstraints).some(hasConstraintValue)
    ? "Active task"
    : "Saved target";
  const chips = useMemo(() => buildBoundaryChips(displayedConstraints), [displayedConstraints]);
  const defaultChips = useMemo(() => buildBoundaryChips(defaultConstraints), [defaultConstraints]);
  const targetEvents = useMemo(() => {
    const selected = targetValue;
    const events = audit?.recent_events ?? [];
    return selected ? events.filter((event) => event.target === selected) : events;
  }, [audit?.recent_events, targetValue]);
  const blockedCount = countConstraintViolations(target?.constraint_violation_events, target?.constraint_violations, targetEvents.length);
  const highSeverityCount = targetEvents.filter((event) => eventTone(event) === "danger").length;
  const readiness = useMemo(() => boundaryReadiness(displayedConstraints), [displayedConstraints]);
  const defaultReadiness = useMemo(() => boundaryReadiness(defaultConstraints), [defaultConstraints]);

  return (
    <section className="boundary-page">
      <SectionCard
        title="Boundary"
        aside={<span className="status-badge">{blockedCount} blocked</span>}
      >
        <label className="field">
          <span>Target</span>
          <select
            value={targetValue ?? ""}
            onChange={(event) => {
              const value = event.target.value || null;
              setLocalTarget(value ?? "");
              onSelectTarget(value);
            }}
          >
            <option value="">All targets</option>
            {targetsQuery.data?.map((item) => (
              <option key={item.target} value={item.target}>
                {item.target}
              </option>
            ))}
          </select>
        </label>

        <div className="boundary-hero">
          <div>
            <span className="pill">Boundary watch</span>
            <h3>{blockedCount > 0 ? "Blocked boundary attempts" : "No blocked attempts yet"}</h3>
          </div>
          <div className="boundary-shield">
            <strong>{blockedCount}</strong>
            <span>blocked</span>
          </div>
        </div>

        <div className="stats-grid">
          <article className="stat">
            <span className="stat-label">Audit hits</span>
            <strong>{audit?.total_events ?? 0}</strong>
          </article>
          <article className="stat">
            <span className="stat-label">High severity</span>
            <strong>{audit?.high_severity_events ?? 0}</strong>
          </article>
          <article className="stat">
            <span className="stat-label">Current high</span>
            <strong>{highSeverityCount}</strong>
          </article>
          <article className="stat">
            <span className="stat-label">Rules</span>
            <strong>{chips.length}</strong>
          </article>
        </div>
      </SectionCard>

      <div className="split-grid">
        <SectionCard title="Current scope" aside={<span className="status-badge">{displayedConstraintsSource}</span>}>
          <div className={`boundary-readiness boundary-readiness-${readiness.tone}`}>
            <strong>{readiness.title}</strong>
            <span>{readiness.copy}</span>
          </div>
          <div className="boundary-chip-grid">
            {chips.length ? chips.map((chip) => (
              <div key={`${chip.label}-${chip.value}`} className={`boundary-chip boundary-chip-${chip.tone}`}>
                <span>{chip.label}</span>
                <strong>{chip.value}</strong>
              </div>
            )) : (
              <div className="empty-state boundary-empty-state">
                <span>{targetQuery.isLoading ? "Loading target boundary..." : "No extra scope is set for this target."}</span>
                {!targetQuery.isLoading && (
                  <button className="secondary-btn" type="button" onClick={onOpenHome}>
                    Set scope on home
                  </button>
                )}
              </div>
            )}
          </div>
        </SectionCard>

        <SectionCard title="Defaults">
          <div className={`boundary-readiness boundary-readiness-${defaultReadiness.tone}`}>
            <strong>{defaultReadiness.title}</strong>
            <span>{defaultReadiness.copy}</span>
          </div>
          <div className="boundary-chip-grid">
            {defaultChips.length ? defaultChips.map((chip) => (
              <div key={`default-${chip.label}-${chip.value}`} className={`boundary-chip boundary-chip-${chip.tone}`}>
                <span>{chip.label}</span>
                <strong>{chip.value}</strong>
              </div>
            )) : (
              <div className="empty-state boundary-empty-state">
                <span>No saved default boundary yet.</span>
                <button className="secondary-btn" type="button" onClick={onOpenSettings}>
                  Open settings
                </button>
              </div>
            )}
          </div>
        </SectionCard>

        <SectionCard title="Notes">
          <div className="boundary-explain-list">
            <div className="boundary-explain-item">
              <strong>Checked every run</strong>
              <span>Port, host, path, and action limits are revalidated before execution.</span>
            </div>
            <div className="boundary-explain-item">
              <strong>Blocked attempts are saved</strong>
              <span>Stops are written to audit data for later review.</span>
            </div>
            <div className="boundary-explain-item">
              <strong>Deeper runs need tighter scope</strong>
              <span>Deep or continuous modes work best with explicit boundaries.</span>
            </div>
          </div>
        </SectionCard>
      </div>

      <SectionCard title="Blocked attempts">
        <div className="boundary-timeline">
          {targetEvents.length ? (
            targetEvents.map((event, index) => (
              <article key={`${event.timestamp}-${event.code}-${index}`} className={`boundary-event boundary-event-${eventTone(event)}`}>
                <div className="boundary-event-time">
                  <span>{formatTime(event.timestamp)}</span>
                </div>
                <div className="boundary-event-body">
                  <div className="boundary-event-head">
                    <strong>{event.summary || "Blocked attempt"}</strong>
                    <span className={`severity-badge severity-${eventTone(event)}`}>{formatSeverityLabel(event.severity)}</span>
                  </div>
                  <p>{event.detail || "The action did not match the current boundary."}</p>
                  <div className="boundary-event-meta">
                    <span>Target: {event.target || "Unknown"}</span>
                    <span>Action: {formatActionList(event.action ? [event.action] : undefined, "Unrecorded")}</span>
                    <span>Tool: {event.tool_name || "Unrecorded"}</span>
                    <span>Phase: {formatPhaseLabel(event.phase)}</span>
                  </div>
                </div>
              </article>
            ))
          ) : (
            <div className="empty-state">No blocked attempts recorded.</div>
          )}
        </div>
      </SectionCard>

      <SectionCard
        title="Technical audit"
        aside={
          <button type="button" className="text-btn inline-text-btn" onClick={() => setShowTechnical((value) => !value)}>
            {showTechnical ? "Hide" : "Show"}
          </button>
        }
      >
        {showTechnical ? (
          <div className="split-grid no-top-gap">
            <article className="inset-card compact-card">
              <h4>By source</h4>
              <div className="list">
                {audit && Object.entries(audit.by_source).length ? Object.entries(audit.by_source).map(([key, value]) => (
                  <div key={key} className="list-item">
                    <strong>{key}</strong>
                    <span>{value}</span>
                  </div>
                )) : <div className="empty-state">No source data.</div>}
              </div>
            </article>
            <article className="inset-card compact-card">
              <h4>By rule</h4>
              <div className="list">
                {audit && Object.entries(audit.by_code).length ? Object.entries(audit.by_code).map(([key, value]) => (
                  <div key={key} className="list-item">
                    <strong>{key}</strong>
                    <span>{value}</span>
                  </div>
                )) : <div className="empty-state">No rule data.</div>}
              </div>
            </article>
          </div>
        ) : (
          <div className="empty-state">Technical audit hidden.</div>
        )}
      </SectionCard>
    </section>
  );
}
