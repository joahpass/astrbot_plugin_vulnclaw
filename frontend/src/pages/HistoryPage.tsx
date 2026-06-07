import { useEffect, useMemo, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { rollbackTarget } from "../api/web";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { SectionCard } from "../components/SectionCard";
import { useTargetDiffQuery, useTargetSnapshotsQuery, useTargetsQuery, useTasksQuery } from "../hooks/queries";
import { formatPhaseLabel, formatResumeStrategy, formatTaskCommand, formatTaskStatus, formatTaskTitle } from "../utils/taskLabels";

interface HistoryPageProps {
  selectedTarget: string | null;
  onSelectTarget: (target: string | null) => void;
  onOpenHome: () => void;
  onOpenReports: (target: string) => void;
  onOpenTarget: (target: string) => void;
}

function formatTime(value?: string): string {
  if (!value) return "Unknown";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function diffConclusion(diff: {
  added_findings: string[];
  updated_findings: string[];
  added_steps: string[];
  added_recon_assets: string[];
}): string {
  const total = diff.added_findings.length + diff.updated_findings.length + diff.added_steps.length + diff.added_recon_assets.length;
  if (diff.added_findings.length || diff.updated_findings.length) return "Risk data changed.";
  if (total > 0) return "The scan added new context.";
  return "No obvious delta between the snapshots.";
}

export function HistoryPage({ selectedTarget, onSelectTarget, onOpenHome, onOpenReports, onOpenTarget }: HistoryPageProps) {
  const queryClient = useQueryClient();
  const targetsQuery = useTargetsQuery();
  const tasksQuery = useTasksQuery();
  const [localTarget, setLocalTarget] = useState("");
  const [fromSnapshotId, setFromSnapshotId] = useState<string | null>(null);
  const [toSnapshotId, setToSnapshotId] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busySnapshot, setBusySnapshot] = useState<string | null>(null);
  const [pendingRollbackId, setPendingRollbackId] = useState<string | null>(null);

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
  const snapshotsQuery = useTargetSnapshotsQuery(targetValue);
  const diffQuery = useTargetDiffQuery(targetValue, fromSnapshotId, toSnapshotId);

  useEffect(() => {
    const snapshots = snapshotsQuery.data ?? [];
    if (snapshots.length >= 2) {
      setToSnapshotId((current) => current ?? snapshots[0].snapshot_id);
      setFromSnapshotId((current) => current ?? snapshots[1].snapshot_id);
    } else if (snapshots.length === 1) {
      setToSnapshotId(snapshots[0].snapshot_id);
      setFromSnapshotId(snapshots[0].snapshot_id);
    } else {
      setFromSnapshotId(null);
      setToSnapshotId(null);
    }
  }, [snapshotsQuery.data]);

  const targetTasks = useMemo(() => {
    const tasks = tasksQuery.data ?? [];
    return targetValue ? tasks.filter((task) => task.target === targetValue) : tasks;
  }, [tasksQuery.data, targetValue]);

  async function handleRollback(snapshotId: string) {
    if (!targetValue) return;
    try {
      setBusySnapshot(snapshotId);
      setError(null);
      setMessage(null);
      await rollbackTarget(targetValue, snapshotId);
      setMessage(`Restored ${targetValue} to ${snapshotId}.`);
      await Promise.all([
        snapshotsQuery.refetch(),
        targetsQuery.refetch(),
        queryClient.invalidateQueries({ queryKey: ["target", targetValue] }),
        queryClient.invalidateQueries({ queryKey: ["target-preview", targetValue] }),
        queryClient.invalidateQueries({ queryKey: ["target-diff", targetValue] }),
      ]);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Snapshot restore failed");
    } finally {
      setBusySnapshot(null);
    }
  }

  return (
    <section className="history-page">
      <SectionCard
        title="History"
        aside={<span className="status-badge">{targetTasks.length} tasks</span>}
      >
        <label className="field">
          <span>Target</span>
          <select
            value={targetValue ?? ""}
            onChange={(event) => {
              const value = event.target.value || null;
              setLocalTarget(value ?? "");
              onSelectTarget(value);
              setMessage(null);
              setError(null);
            }}
          >
            <option value="">All targets</option>
            {targetsQuery.data?.map((target) => (
              <option key={target.target} value={target.target}>
                {target.target}
              </option>
            ))}
          </select>
        </label>

        <div className="history-summary-grid">
          <article className="stat">
            <span className="stat-label">Tasks</span>
            <strong>{targetTasks.length}</strong>
          </article>
          <article className="stat">
            <span className="stat-label">Targets</span>
            <strong>{targetsQuery.data?.length ?? 0}</strong>
          </article>
          <article className="stat">
            <span className="stat-label">Snapshots</span>
            <strong>{snapshotsQuery.data?.length ?? 0}</strong>
          </article>
        </div>

        {message && <div className="success-box">{message}</div>}
        {error && <div className="error-box">{error}</div>}
      </SectionCard>

      <div className="history-grid">
        <SectionCard title="Tasks">
          <div className="list list-scroll history-list">
            {targetTasks.slice(0, 18).map((task) => (
              <article key={task.task_id} className="list-item history-task-item">
                <strong>{formatTaskTitle(task.command, task.target)}</strong>
                <span>{formatTaskStatus(task.status)}</span>
                <span className="muted-inline">{formatPhaseLabel(task.latest_phase)}</span>
                <span className="muted-inline">{formatTime(task.created_at)}</span>
                <div className="button-row compact-row">
                  <button className="secondary-btn" type="button" onClick={() => onOpenTarget(task.target)}>
                    Open results
                  </button>
                  <button className="secondary-btn" type="button" onClick={() => onOpenReports(task.target)}>
                    Open reports
                  </button>
                </div>
              </article>
            ))}
            {!targetTasks.length && (
              <div className="empty-state history-empty-state">
                <strong>No task history</strong>
                <button className="secondary-btn" onClick={onOpenHome} type="button">
                  New scan
                </button>
              </div>
            )}
          </div>
        </SectionCard>

        <SectionCard title="Targets">
          <div className="list list-scroll history-list">
            {targetsQuery.data?.slice(0, 18).map((target) => (
              <article key={target.target} className={`list-item ${targetValue === target.target ? "selected-item" : ""}`}>
                <strong>{target.target}</strong>
                <span>{target.verified_count} verified / {target.pending_count} pending</span>
                <span className="muted-inline">{formatResumeStrategy(target.resume_strategy)}</span>
                <div className="button-row compact-row">
                  <button className="secondary-btn" type="button" onClick={() => { onSelectTarget(target.target); onOpenTarget(target.target); }}>
                    Open results
                  </button>
                  <button className="secondary-btn" type="button" onClick={() => onOpenReports(target.target)}>
                    Open reports
                  </button>
                </div>
              </article>
            ))}
            {!targetsQuery.data?.length && (
              <div className="empty-state history-empty-state">
                <strong>No target state</strong>
                <button className="secondary-btn" onClick={onOpenHome} type="button">
                  New scan
                </button>
              </div>
            )}
          </div>
        </SectionCard>
      </div>

      <div className="history-grid">
        <SectionCard title="Snapshots">
          <div className="list list-scroll history-list">
            {snapshotsQuery.data?.map((snapshot) => (
              <div key={snapshot.snapshot_id} className="list-item">
                <strong>{snapshot.snapshot_id}</strong>
                <span>{formatTaskCommand(snapshot.last_command)}</span>
                <span className="muted-inline">{formatTime(snapshot.last_saved_at)}</span>
                <span className="muted-inline">Verified {snapshot.verified_findings} / Pending {snapshot.pending_findings}</span>
                <div className="button-row compact-row">
                  <button
                    className="secondary-btn"
                    disabled={busySnapshot === snapshot.snapshot_id}
                    onClick={() => setPendingRollbackId(snapshot.snapshot_id)}
                    type="button"
                  >
                    {busySnapshot === snapshot.snapshot_id ? "Restoring..." : "Restore"}
                  </button>
                </div>
              </div>
            ))}
            {!snapshotsQuery.data?.length && (
              <div className="empty-state">{targetValue ? "No snapshots for this target." : "Choose a target to view snapshots."}</div>
            )}
          </div>
        </SectionCard>

        <SectionCard title="Diff">
          <div className="form-grid compact-form">
            <label className="field">
              <span>From</span>
              <select value={fromSnapshotId ?? ""} onChange={(event) => setFromSnapshotId(event.target.value || null)}>
                <option value="">Select</option>
                {snapshotsQuery.data?.map((snapshot) => (
                  <option key={`from-${snapshot.snapshot_id}`} value={snapshot.snapshot_id}>
                    {snapshot.snapshot_id}
                  </option>
                ))}
              </select>
            </label>
            <label className="field">
              <span>To</span>
              <select value={toSnapshotId ?? ""} onChange={(event) => setToSnapshotId(event.target.value || null)}>
                <option value="">Current</option>
                {snapshotsQuery.data?.map((snapshot) => (
                  <option key={`to-${snapshot.snapshot_id}`} value={snapshot.snapshot_id}>
                    {snapshot.snapshot_id}
                  </option>
                ))}
              </select>
            </label>
          </div>

          {diffQuery.data ? (
            <div className="list dense-list">
              <div className="history-diff-summary">
                <strong>{diffConclusion(diffQuery.data)}</strong>
                <div>
                  <span>Findings {diffQuery.data.added_findings.length}</span>
                  <span>Updated {diffQuery.data.updated_findings.length}</span>
                  <span>Steps {diffQuery.data.added_steps.length}</span>
                  <span>Assets {diffQuery.data.added_recon_assets.length}</span>
                </div>
              </div>
              <div className="list-item">
                <strong>Added findings</strong>
                {diffQuery.data.added_findings.length ? diffQuery.data.added_findings.map((item) => <span key={item}>{item}</span>) : <span className="muted-inline">None</span>}
              </div>
              <div className="list-item">
                <strong>Updated findings</strong>
                {diffQuery.data.updated_findings.length ? diffQuery.data.updated_findings.map((item) => <span key={item}>{item}</span>) : <span className="muted-inline">None</span>}
              </div>
              <div className="list-item">
                <strong>Added steps</strong>
                {diffQuery.data.added_steps.length ? diffQuery.data.added_steps.map((item) => <span key={item}>{item}</span>) : <span className="muted-inline">None</span>}
              </div>
              <div className="list-item">
                <strong>Added assets</strong>
                {diffQuery.data.added_recon_assets.length ? diffQuery.data.added_recon_assets.map((item) => <span key={item}>{item}</span>) : <span className="muted-inline">None</span>}
              </div>
            </div>
          ) : (
            <div className="empty-state">{diffQuery.isLoading ? "Loading diff..." : "Pick snapshots to compare."}</div>
          )}
        </SectionCard>
      </div>

      <ConfirmDialog
        open={Boolean(pendingRollbackId)}
        title="Restore snapshot"
        copy="Restoring a snapshot rolls the current target state back to the selected point."
        tone="danger"
        confirmLabel="Restore"
        onCancel={() => setPendingRollbackId(null)}
        onConfirm={() => {
          const snapshotId = pendingRollbackId;
          setPendingRollbackId(null);
          if (snapshotId) void handleRollback(snapshotId);
        }}
      />
    </section>
  );
}
