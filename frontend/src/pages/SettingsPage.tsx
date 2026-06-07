import { useEffect, useMemo, useState } from "react";
import { updateConfig } from "../api/web";
import { SectionCard } from "../components/SectionCard";
import { useConfigQuery, useMcpDiagnosticsQuery } from "../hooks/queries";
import { formatActionLabel, formatActionList, formatMcpExecutionMode, formatMcpHealth } from "../utils/taskLabels";
import { loadUiPreferences, saveUiPreferences, type UiPreferences } from "../utils/preferences";
import { parseOptionalPort } from "../utils/validation";

type SettingsSection = "basic" | "ai" | "checks" | "boundary" | "data" | "python" | "diagnostics";

const SECTIONS: Array<{ key: SettingsSection; title: string; copy: string }> = [
  { key: "basic", title: "Preferences", copy: "Local UI defaults" },
  { key: "ai", title: "Model", copy: "Provider and endpoint" },
  { key: "checks", title: "Scan Policy", copy: "Rounds and runtime" },
  { key: "boundary", title: "Boundary", copy: "Default scope" },
  { key: "data", title: "Data", copy: "Output paths" },
  { key: "python", title: "Scripts", copy: "Local execution" },
  { key: "diagnostics", title: "Diagnostics", copy: "MCP status" },
];

const ACTION_OPTIONS = [
  { value: "recon", copy: "Asset discovery and public signal collection." },
  { value: "scan", copy: "Service and entry-point discovery." },
  { value: "exploit", copy: "Verification actions requiring approval." },
  { value: "persistent", copy: "Multi-round continuous checks." },
  { value: "post_exploitation", copy: "Post-exploitation actions, usually blocked." },
];

const PYTHON_MODES = [
  {
    value: "safe",
    label: "Safe",
    copy: "Restricts file I/O, network access, and system calls.",
  },
  {
    value: "lab",
    label: "Lab",
    copy: "Allows more local analysis for controlled labs.",
  },
  {
    value: "trusted-local",
    label: "Trusted local",
    copy: "Full local capability for trusted authorized machines.",
  },
];

interface SettingsPageProps {
  initialSection?: SettingsSection;
  onOpenAdvanced: () => void;
}

export function SettingsPage({ initialSection = "basic", onOpenAdvanced }: SettingsPageProps) {
  const configQuery = useConfigQuery();
  const mcpQuery = useMcpDiagnosticsQuery();
  const [activeSection, setActiveSection] = useState<SettingsSection>(initialSection);
  const [provider, setProvider] = useState("openai");
  const [model, setModel] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [outputDir, setOutputDir] = useState("");
  const [maxRounds, setMaxRounds] = useState(15);
  const [persistentRounds, setPersistentRounds] = useState(100);
  const [persistentCycles, setPersistentCycles] = useState(10);
  const [showThinking, setShowThinking] = useState(false);
  const [pythonExecuteEnabled, setPythonExecuteEnabled] = useState(true);
  const [pythonExecuteMode, setPythonExecuteMode] = useState("trusted-local");
  const [pythonExecuteMaxLines, setPythonExecuteMaxLines] = useState(50);
  const [pythonExecuteAuditEnabled, setPythonExecuteAuditEnabled] = useState(true);
  const [language, setLanguage] = useState<UiPreferences["language"]>("en-US");
  const [defaultCheckMode, setDefaultCheckMode] = useState<UiPreferences["defaultCheckMode"]>("standard");
  const [reportFormat, setReportFormat] = useState<UiPreferences["reportFormat"]>("markdown");
  const [showTechnicalLogs, setShowTechnicalLogs] = useState(false);
  const [defaultOnlyPort, setDefaultOnlyPort] = useState("");
  const [defaultOnlyHost, setDefaultOnlyHost] = useState("");
  const [defaultOnlyPath, setDefaultOnlyPath] = useState("");
  const [defaultBlockedHost, setDefaultBlockedHost] = useState("");
  const [defaultBlockedPath, setDefaultBlockedPath] = useState("");
  const [defaultAllowActions, setDefaultAllowActions] = useState<string[]>([]);
  const [defaultBlockActions, setDefaultBlockActions] = useState<string[]>([]);
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    const preferences = loadUiPreferences();
    setLanguage(preferences.language);
    setDefaultCheckMode(preferences.defaultCheckMode);
    setReportFormat(preferences.reportFormat);
    setShowTechnicalLogs(preferences.showTechnicalLogs);
    setDefaultOnlyPort(preferences.defaultBoundary.onlyPort);
    setDefaultOnlyHost(preferences.defaultBoundary.onlyHost);
    setDefaultOnlyPath(preferences.defaultBoundary.onlyPath);
    setDefaultBlockedHost(preferences.defaultBoundary.blockedHost);
    setDefaultBlockedPath(preferences.defaultBoundary.blockedPath);
    setDefaultAllowActions(preferences.defaultBoundary.allowActions);
    setDefaultBlockActions(preferences.defaultBoundary.blockActions);
  }, []);

  useEffect(() => setActiveSection(initialSection), [initialSection]);

  useEffect(() => {
    if (!configQuery.data) return;
    setProvider(configQuery.data.provider);
    setModel(configQuery.data.model);
    setBaseUrl(configQuery.data.base_url);
    setOutputDir(configQuery.data.output_dir);
    setMaxRounds(configQuery.data.max_rounds);
    setPersistentRounds(configQuery.data.persistent_rounds_per_cycle);
    setPersistentCycles(configQuery.data.persistent_max_cycles);
    setShowThinking(configQuery.data.show_thinking);
    setPythonExecuteEnabled(configQuery.data.python_execute_enabled);
    setPythonExecuteMode(configQuery.data.python_execute_mode);
    setPythonExecuteMaxLines(configQuery.data.python_execute_max_lines);
    setPythonExecuteAuditEnabled(configQuery.data.python_execute_audit_enabled);
  }, [configQuery.data]);

  const activeMeta = useMemo(() => SECTIONS.find((section) => section.key === activeSection) ?? SECTIONS[0], [activeSection]);
  const saveButtonLabel = activeSection === "basic"
    ? "Save preferences"
    : activeSection === "boundary"
      ? "Save boundary"
      : "Save settings";

  function saveLocalPreferences() {
    saveUiPreferences({
      language,
      defaultCheckMode,
      reportFormat,
      showTechnicalLogs,
      defaultBoundary: {
        onlyPort: defaultOnlyPort,
        onlyHost: defaultOnlyHost,
        onlyPath: defaultOnlyPath,
        blockedHost: defaultBlockedHost,
        blockedPath: defaultBlockedPath,
        allowActions: defaultAllowActions,
        blockActions: defaultBlockActions,
      },
    });
  }

  async function handleSave() {
    try {
      setSaving(true);
      setError(null);
      setStatus(null);

      if (activeSection === "basic" || activeSection === "boundary") {
        if (activeSection === "boundary") parseOptionalPort(defaultOnlyPort);
        saveLocalPreferences();
        setStatus(activeSection === "boundary" ? "Boundary defaults saved." : "Preferences saved.");
        return;
      }

      await updateConfig({
        provider,
        model,
        base_url: baseUrl,
        output_dir: outputDir,
        max_rounds: maxRounds,
        persistent_rounds_per_cycle: persistentRounds,
        persistent_max_cycles: persistentCycles,
        show_thinking: showThinking,
        python_execute_enabled: pythonExecuteEnabled,
        python_execute_mode: pythonExecuteMode,
        python_execute_max_lines: pythonExecuteMaxLines,
        python_execute_audit_enabled: pythonExecuteAuditEnabled,
      });
      await configQuery.refetch();
      setStatus("Settings saved.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Save failed");
    } finally {
      setSaving(false);
    }
  }

  function toggleDefaultAction(
    value: string,
    selected: string[],
    setSelected: (next: string[]) => void,
    oppositeSelected: string[],
    setOppositeSelected: (next: string[]) => void,
  ) {
    const isSelected = selected.includes(value);
    setSelected(isSelected ? selected.filter((item) => item !== value) : [...selected, value]);
    if (!isSelected) setOppositeSelected(oppositeSelected.filter((item) => item !== value));
  }

  return (
    <section className="settings-page">
      <aside className="settings-nav">
        {SECTIONS.map((section) => (
          <button
            key={section.key}
            type="button"
            className={`settings-nav-item ${activeSection === section.key ? "active" : ""}`}
            onClick={() => setActiveSection(section.key)}
          >
            <strong>{section.title}</strong>
            <span>{section.copy}</span>
          </button>
        ))}
      </aside>

      <div className="settings-content">
        <SectionCard
          title={activeMeta.title}
          copy={activeMeta.copy}
          aside={<span className="status-badge">{configQuery.data?.api_key_configured ? "API key set" : "No API key"}</span>}
        >
          {activeSection === "basic" && (
            <div className="form-grid">
              <label className="field">
                <span>Language</span>
                <select value={language} onChange={(event) => setLanguage(event.target.value as UiPreferences["language"])}>
                  <option value="en-US">English</option>
                  <option value="zh-CN">Chinese</option>
                </select>
              </label>
              <label className="field">
                <span>Default scan mode</span>
                <select value={defaultCheckMode} onChange={(event) => setDefaultCheckMode(event.target.value as UiPreferences["defaultCheckMode"])}>
                  <option value="quick">Quick Recon</option>
                  <option value="standard">Standard Scan</option>
                  <option value="deep">Deep Scan</option>
                  <option value="continuous">Continuous Scan</option>
                </select>
              </label>
              <label className="field">
                <span>Default report format</span>
                <select value={reportFormat} onChange={(event) => setReportFormat(event.target.value as UiPreferences["reportFormat"])}>
                  <option value="markdown">Markdown</option>
                  <option value="html">HTML</option>
                </select>
              </label>
              <label className="check-row">
                <input checked={showTechnicalLogs} onChange={(event) => setShowTechnicalLogs(event.target.checked)} type="checkbox" />
                <span>Show raw event entry by default</span>
              </label>
              <div className="inline-panel field-wide">
                <strong>Local only</strong>
                <p className="inline-note">UI preferences are stored in this browser. Runtime settings are saved to the backend.</p>
              </div>
            </div>
          )}

          {activeSection === "ai" && (
            <div className="form-grid">
              <label className="field">
                <span>Provider</span>
                <input value={provider} onChange={(event) => setProvider(event.target.value)} />
                <small>Backend provider id, for example openai.</small>
              </label>
              <label className="field">
                <span>Model</span>
                <input value={model} onChange={(event) => setModel(event.target.value)} />
                <small>Use the model name configured for your backend.</small>
              </label>
              <label className="field field-wide">
                <span>Base URL</span>
                <input value={baseUrl} onChange={(event) => setBaseUrl(event.target.value)} />
                <small>Leave blank to use the backend default.</small>
              </label>
            </div>
          )}

          {activeSection === "checks" && (
            <div className="form-grid">
              <label className="field">
                <span>Max rounds</span>
                <input type="number" value={maxRounds} onChange={(event) => setMaxRounds(Number(event.target.value))} />
              </label>
              <label className="field">
                <span>Rounds per cycle</span>
                <input type="number" value={persistentRounds} onChange={(event) => setPersistentRounds(Number(event.target.value))} />
              </label>
              <label className="field">
                <span>Max cycles</span>
                <input type="number" value={persistentCycles} onChange={(event) => setPersistentCycles(Number(event.target.value))} />
              </label>
              <label className="check-row field-wide">
                <input checked={showThinking} onChange={(event) => setShowThinking(event.target.checked)} type="checkbox" />
                <span>Show model reasoning output</span>
              </label>
              <article className="stat">
                <span className="stat-label">MCP services</span>
                <strong>{mcpQuery.data?.total_services ?? 0}</strong>
              </article>
              <article className="stat">
                <span className="stat-label">Runnable</span>
                <strong>{mcpQuery.data?.running_services ?? 0}</strong>
              </article>
              <article className="stat">
                <span className="stat-label">Tools</span>
                <strong>{mcpQuery.data?.tool_count ?? 0}</strong>
              </article>
              <article className="stat">
                <span className="stat-label">nmap</span>
                <strong>Runtime check</strong>
              </article>
            </div>
          )}

          {activeSection === "boundary" && (
            <div className="form-grid">
              <label className="field">
                <span>Default port only</span>
                <input value={defaultOnlyPort} onChange={(event) => setDefaultOnlyPort(event.target.value)} inputMode="numeric" placeholder="443" />
                <small>Blank means set it per scan.</small>
              </label>
              <label className="field">
                <span>Default host only</span>
                <input value={defaultOnlyHost} onChange={(event) => setDefaultOnlyHost(event.target.value)} placeholder="example.com" />
              </label>
              <label className="field field-wide">
                <span>Default path only</span>
                <input value={defaultOnlyPath} onChange={(event) => setDefaultOnlyPath(event.target.value)} placeholder="/admin" />
              </label>
              <label className="field">
                <span>Default block host</span>
                <input value={defaultBlockedHost} onChange={(event) => setDefaultBlockedHost(event.target.value)} placeholder="staging.example.com" />
              </label>
              <label className="field">
                <span>Default block path</span>
                <input value={defaultBlockedPath} onChange={(event) => setDefaultBlockedPath(event.target.value)} placeholder="/internal" />
              </label>
              <div className="field field-wide">
                <span>Default allow actions</span>
                <div className="action-choice-grid">
                  {ACTION_OPTIONS.map((action) => (
                    <button
                      key={`settings-allow-${action.value}`}
                      type="button"
                      className={`action-choice ${defaultAllowActions.includes(action.value) ? "selected-item" : ""}`}
                      onClick={() => toggleDefaultAction(action.value, defaultAllowActions, setDefaultAllowActions, defaultBlockActions, setDefaultBlockActions)}
                    >
                      <strong>{formatActionLabel(action.value)}</strong>
                      <span>{action.copy}</span>
                    </button>
                  ))}
                </div>
              </div>
              <div className="field field-wide">
                <span>Default block actions</span>
                <div className="action-choice-grid">
                  {ACTION_OPTIONS.map((action) => (
                    <button
                      key={`settings-block-${action.value}`}
                      type="button"
                      className={`action-choice action-choice-block ${defaultBlockActions.includes(action.value) ? "selected-item" : ""}`}
                      onClick={() => toggleDefaultAction(action.value, defaultBlockActions, setDefaultBlockActions, defaultAllowActions, setDefaultAllowActions)}
                    >
                      <strong>{formatActionLabel(action.value)}</strong>
                      <span>{action.copy}</span>
                    </button>
                  ))}
                </div>
              </div>
              <div className="scope-summary field-wide">
                <strong>Allow</strong>
                <span>{formatActionList(defaultAllowActions)}</span>
                <strong>Block</strong>
                <span>{formatActionList(defaultBlockActions)}</span>
              </div>
            </div>
          )}

          {activeSection === "data" && (
            <div className="form-grid">
              <label className="field field-wide">
                <span>Output directory</span>
                <input value={outputDir} onChange={(event) => setOutputDir(event.target.value)} />
              </label>
              <div className="inline-panel field-wide">
                <strong>Reports</strong>
                <p className="inline-note">If not overridden, reports are written under the VulnClaw sessions report directory.</p>
              </div>
            </div>
          )}

          {activeSection === "python" && (
            <div className="form-grid">
              <label className="check-row">
                <input checked={pythonExecuteEnabled} onChange={(event) => setPythonExecuteEnabled(event.target.checked)} type="checkbox" />
                <span>Enable local script helper</span>
              </label>
              <label className="check-row">
                <input checked={pythonExecuteAuditEnabled} onChange={(event) => setPythonExecuteAuditEnabled(event.target.checked)} type="checkbox" />
                <span>Record local script audit</span>
              </label>
              <div className="field field-wide">
                <span>Execution guard</span>
                <div className="mode-grid settings-mode-grid">
                  {PYTHON_MODES.map((mode) => (
                    <button
                      key={mode.value}
                      type="button"
                      className={`mode-card settings-mode-card ${pythonExecuteMode === mode.value ? "selected-item" : ""}`}
                      onClick={() => setPythonExecuteMode(mode.value)}
                    >
                      <strong>{mode.label}</strong>
                      <span>{mode.copy}</span>
                    </button>
                  ))}
                </div>
              </div>
              <label className="field">
                <span>Max output lines</span>
                <input type="number" value={pythonExecuteMaxLines} onChange={(event) => setPythonExecuteMaxLines(Number(event.target.value))} />
              </label>
            </div>
          )}

          {activeSection === "diagnostics" && (
            <div className="diagnostics-grid">
              <div className="inline-panel field-wide">
                <strong>Need raw task inputs?</strong>
                <p className="inline-note">Open the task console for SSE events, raw command parameters, and boundary debugging.</p>
                <button className="secondary-btn" onClick={onOpenAdvanced} type="button">
                  Open task console
                </button>
              </div>
              <article className="stat">
                <span className="stat-label">MCP services</span>
                <strong>{mcpQuery.data?.total_services ?? 0}</strong>
              </article>
              <article className="stat">
                <span className="stat-label">Running</span>
                <strong>{mcpQuery.data?.running_services ?? 0}</strong>
              </article>
              <article className="stat">
                <span className="stat-label">Tools</span>
                <strong>{mcpQuery.data?.tool_count ?? 0}</strong>
              </article>
              <div className="list list-scroll diagnostics-list">
                {mcpQuery.data?.services.map((service) => (
                  <div key={service.name} className="list-item">
                    <strong>{service.name}</strong>
                    <span>Status: {formatMcpHealth(service.health_status)} - Mode: {formatMcpExecutionMode(service.execution_mode)} - Tools: {service.tool_count}</span>
                    <span className="muted-inline">
                      Calls {service.call_count} - Success {service.success_count} - Failed {service.failure_count}
                    </span>
                    {service.error && <span className="danger-inline">{service.error}</span>}
                  </div>
                ))}
                {!mcpQuery.data?.services.length && <div className="empty-state">No MCP diagnostics yet.</div>}
              </div>
            </div>
          )}

          <div className="button-row">
            <button className="primary-btn" disabled={saving || activeSection === "diagnostics"} onClick={handleSave} type="button">
              {saving ? "Saving..." : saveButtonLabel}
            </button>
          </div>

          {status && <div className="success-box">{status}</div>}
          {error && <div className="error-box">{error}</div>}
        </SectionCard>
      </div>
    </section>
  );
}
