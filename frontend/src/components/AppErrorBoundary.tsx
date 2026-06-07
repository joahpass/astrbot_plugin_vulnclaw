import { Component, type ErrorInfo, type ReactNode } from "react";

interface AppErrorBoundaryProps {
  children: ReactNode;
}

interface AppErrorBoundaryState {
  error: Error | null;
}

export class AppErrorBoundary extends Component<AppErrorBoundaryProps, AppErrorBoundaryState> {
  state: AppErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): AppErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("VulnClaw Web UI crashed", error, errorInfo);
  }

  render() {
    if (!this.state.error) return this.props.children;

    return (
      <main className="app-fallback-page">
        <section className="app-fallback-card">
          <span className="pill">UI guard</span>
          <h1>VulnClaw UI hit a rendering error</h1>
          <p>
            Saved targets, reports, and task history remain intact. Reload the UI, then continue from History or Reports.
          </p>
          <div className="app-fallback-actions">
            <button className="primary-btn" type="button" onClick={() => window.location.reload()}>
              Reload UI
            </button>
          </div>
          <details>
            <summary>Technical error</summary>
            <pre>{this.state.error.message}</pre>
          </details>
        </section>
      </main>
    );
  }
}
