import { useEffect, useState } from "react";
import { generateTargetReport, getReportDownloadUrl } from "../api/web";
import { ReportPreview, ReportPreviewDialog } from "../components/ReportPreviewDialog";
import { SectionCard } from "../components/SectionCard";
import { useReportContentQuery, useReportsQuery, useTargetsQuery } from "../hooks/queries";
import type { ReportListItem } from "../types/api";
import { loadUiPreferences, subscribeUiPreferences } from "../utils/preferences";

interface ReportsPageProps {
  selectedTarget: string | null;
  focus?: {
    target: string | null;
    path?: string;
    openPreview?: boolean;
  } | null;
}

export function ReportsPage({ selectedTarget, focus }: ReportsPageProps) {
  const reportsQuery = useReportsQuery();
  const targetsQuery = useTargetsQuery();
  const [selectedPath, setSelectedPath] = useState<string | null>(null);
  const [previewOpen, setPreviewOpen] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [generating, setGenerating] = useState(false);
  const [copyStatus, setCopyStatus] = useState<string | null>(null);
  const [search, setSearch] = useState(selectedTarget ?? "");
  const [reportTarget, setReportTarget] = useState(selectedTarget ?? "");
  const [generateFormat, setGenerateFormat] = useState<"markdown" | "html">(() => loadUiPreferences().reportFormat);
  const [kindFilter, setKindFilter] = useState<"all" | "markdown" | "html">("all");
  const [dateFilter, setDateFilter] = useState<"all" | "today" | "week">("all");

  useEffect(() => {
    if (!selectedPath && reportsQuery.data?.[0]?.path) setSelectedPath(reportsQuery.data[0].path);
  }, [selectedPath, reportsQuery.data]);

  useEffect(() => subscribeUiPreferences((preferences) => setGenerateFormat(preferences.reportFormat)), []);

  useEffect(() => {
    if (selectedTarget) {
      setSearch(selectedTarget);
      setReportTarget(selectedTarget);
    }
  }, [selectedTarget]);

  useEffect(() => {
    if (!focus) return;
    if (focus.target) {
      setSearch(focus.target);
      setReportTarget(focus.target);
    }
    if (focus.path) setSelectedPath(focus.path);
    if (focus.openPreview) setPreviewOpen(true);
  }, [focus]);

  useEffect(() => {
    if (!reportTarget && targetsQuery.data?.[0]?.target) {
      setReportTarget(targetsQuery.data[0].target);
    }
  }, [reportTarget, targetsQuery.data]);

  const reports = reportsQuery.data ?? [];
  const filteredReports = reports.filter((report) => reportMatchesFilters(report, search, kindFilter, dateFilter));
  const selectedReport = filteredReports.find((report) => report.path === selectedPath) ?? filteredReports[0] ?? null;
  const previewPath = selectedReport?.path ?? null;
  const contentQuery = useReportContentQuery(previewPath);
  const markdownCount = reports.filter((report) => report.kind === "markdown").length;
  const htmlCount = reports.filter((report) => report.kind === "html").length;
  const totalSize = reports.reduce((sum, report) => sum + (report.size_bytes ?? 0), 0);
  const canGenerate = Boolean(reportTarget.trim()) && !generating;
  const previewContent = selectedReport ? contentQuery.data?.content : undefined;
  const previewKind = selectedReport ? contentQuery.data?.kind : undefined;
  const previewLoading = Boolean(selectedReport) && contentQuery.isLoading;

  async function handleGenerate() {
    const target = reportTarget.trim();
    if (!target) {
      setError("Select a target first.");
      return;
    }
    try {
      setGenerating(true);
      setError(null);
      const result = await generateTargetReport(target, generateFormat);
      setStatus(result.path);
      setSearch(target);
      await reportsQuery.refetch();
      setSelectedPath(result.path);
      setPreviewOpen(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Report generation failed");
    } finally {
      setGenerating(false);
    }
  }

  async function handleCopyPath() {
    if (!selectedReport?.path) return;
    try {
      await navigator.clipboard.writeText(selectedReport.path);
      setCopyStatus("Path copied.");
    } catch {
      setCopyStatus("Clipboard unavailable.");
    }
  }

  function handleDownload() {
    const content = previewContent;
    if (!content || !selectedReport) return;
    const mime = previewKind === "html" ? "text/html;charset=utf-8" : "text/markdown;charset=utf-8";
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = selectedReport.name || `vulnclaw-report.${previewKind === "html" ? "html" : "md"}`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
    setCopyStatus("Download started.");
  }

  function handleOpenReportFile() {
    if (!selectedReport?.path) return;
    window.open(getReportDownloadUrl(selectedReport.path), "_blank", "noopener,noreferrer");
  }

  function resetReportFilters() {
    setSearch("");
    setKindFilter("all");
    setDateFilter("all");
    setSelectedPath(reports[0]?.path ?? null);
  }

  return (
    <section className="reports-page">
      <SectionCard
        title="Reports"
        aside={<span className="status-badge">{reports.length} files</span>}
      >
        <div className="report-hero">
          <div>
            <span className="pill">Selected</span>
            <h3>{selectedReport?.name ?? "No report selected"}</h3>
            <p>{reportStatusCopy(selectedReport)}</p>
          </div>
          <div className="report-actions">
            <label className="field report-target-field">
              <span>Target</span>
              <input
                list="report-targets"
                value={reportTarget}
                onChange={(event) => setReportTarget(event.target.value)}
                placeholder="Select or enter target"
              />
              <datalist id="report-targets">
                {targetsQuery.data?.map((target) => (
                  <option key={target.target} value={target.target} />
                ))}
              </datalist>
            </label>
            <label className="field report-format-field">
              <span>Format</span>
              <select value={generateFormat} onChange={(event) => setGenerateFormat(event.target.value as "markdown" | "html")}>
                <option value="markdown">Markdown</option>
                <option value="html">HTML</option>
              </select>
            </label>
            <button className="primary-btn" disabled={!canGenerate} onClick={handleGenerate} type="button">
              {generating ? "Generating..." : "Generate"}
            </button>
            <button className="secondary-btn" disabled={!selectedReport} onClick={() => setPreviewOpen(true)} type="button">
              Preview
            </button>
            <button className="secondary-btn" disabled={!selectedReport?.path} onClick={handleOpenReportFile} type="button">
              Open file
            </button>
          </div>
        </div>

        {status && <div className="success-box">Generated: {status}</div>}
        {copyStatus && <div className="success-box">{copyStatus}</div>}
        {error && <div className="error-box">{error}</div>}
      </SectionCard>

      <div className="report-center-grid">
        <SectionCard
          title="File list"
          aside={<span className="status-badge">{filteredReports.length} / {reports.length}</span>}
        >
          <div className="report-filter-grid">
            <label className="field">
              <span>Search</span>
              <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="target or filename" />
            </label>
            <label className="field">
              <span>Format</span>
              <select value={kindFilter} onChange={(event) => setKindFilter(event.target.value as "all" | "markdown" | "html")}>
                <option value="all">All</option>
                <option value="markdown">Markdown</option>
                <option value="html">HTML</option>
              </select>
            </label>
            <label className="field">
              <span>Time</span>
              <select value={dateFilter} onChange={(event) => setDateFilter(event.target.value as "all" | "today" | "week")}>
                <option value="all">All time</option>
                <option value="today">Today</option>
                <option value="week">Last 7 days</option>
              </select>
            </label>
          </div>
          <div className="list list-scroll report-file-list">
            {filteredReports.slice(0, 24).map((report) => (
              <button
                key={report.path}
                type="button"
                className={`list-item list-button report-file-item ${selectedReport?.path === report.path ? "selected-item" : ""}`}
                onClick={() => setSelectedPath(report.path)}
              >
                <strong>{report.name}</strong>
                <span>{report.kind} - {formatSize(report.size_bytes ?? 0)}</span>
                <span className="muted-inline">{formatDate(report.modified_at)}</span>
                <span className="muted-inline">{report.path}</span>
              </button>
            ))}
            {!reports.length && (
              <div className="empty-state report-empty-state">
                <strong>No reports yet</strong>
                <button className="secondary-btn" disabled={!canGenerate} onClick={handleGenerate} type="button">
                  {generating ? "Generating..." : "Generate"}
                </button>
              </div>
            )}
            {Boolean(reports.length) && !filteredReports.length && (
              <div className="empty-state report-filter-empty-state">
                <strong>No matches</strong>
                <button className="secondary-btn" onClick={resetReportFilters} type="button">
                  Clear filters
                </button>
              </div>
            )}
          </div>
        </SectionCard>

        <SectionCard
          title="Preview"
          aside={
            <div className="report-preview-actions">
              <button className="text-btn inline-text-btn" disabled={!previewContent} onClick={handleDownload} type="button">
                Export copy
              </button>
              <button className="text-btn inline-text-btn" disabled={!selectedReport?.path} onClick={handleOpenReportFile} type="button">
                Open file
              </button>
              <button className="text-btn inline-text-btn" disabled={!selectedReport?.path} onClick={() => void handleCopyPath()} type="button">
                Copy path
              </button>
              <button className="text-btn inline-text-btn" disabled={!selectedReport} onClick={() => setPreviewOpen(true)} type="button">
                Expand
              </button>
            </div>
          }
        >
          <ReportPreview content={previewContent} kind={previewKind} loading={previewLoading} />
        </SectionCard>
      </div>

      <ReportPreviewDialog
        open={previewOpen && Boolean(selectedReport)}
        title={selectedReport?.name ?? "Report preview"}
        path={selectedReport?.path}
        content={previewContent}
        kind={previewKind}
        loading={previewLoading}
        onDownload={handleDownload}
        onClose={() => setPreviewOpen(false)}
      />
    </section>
  );
}

function reportMatchesFilters(
  report: ReportListItem,
  search: string,
  kindFilter: "all" | "markdown" | "html",
  dateFilter: "all" | "today" | "week",
): boolean {
  const keyword = search.trim().toLowerCase();
  const haystack = `${report.name} ${report.path}`.toLowerCase();
  if (keyword && !haystack.includes(keyword)) return false;
  if (kindFilter !== "all" && report.kind !== kindFilter) return false;
  return matchesDateFilter(report.modified_at, dateFilter);
}

function matchesDateFilter(value: string | undefined, filter: "all" | "today" | "week"): boolean {
  if (filter === "all") return true;
  if (!value) return false;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return false;
  const now = new Date();
  if (filter === "today") {
    return date.toDateString() === now.toDateString();
  }
  const weekAgo = now.getTime() - 7 * 24 * 60 * 60 * 1000;
  return date.getTime() >= weekAgo;
}

function formatDate(value: string | undefined): string {
  if (!value) return "Unknown";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function formatSize(value: number): string {
  if (!value) return "0 B";
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1024 / 1024).toFixed(1)} MB`;
}

function reportStatusCopy(report: ReportListItem | null): string {
  if (!report) return "No report selected.";
  const kind = report.kind === "html" ? "HTML report" : "Markdown report";
  return `${kind} - ${formatSize(report.size_bytes ?? 0)} - ${formatDate(report.modified_at)}`;
}
