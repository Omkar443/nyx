import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle, RefreshCw, LayoutDashboard } from 'lucide-react';

interface Props {
  children: ReactNode;
  fallbackTitle?: string;
  onReset?: () => void;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
    errorInfo: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error, errorInfo: null };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('NYX View ErrorBoundary caught exception:', error, errorInfo);
    this.setState({ error, errorInfo });
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
    if (this.props.onReset) {
      this.props.onReset();
    }
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div className="card space-y-4 border border-[#EF5350]/30 bg-[#251A1A] p-6 max-w-2xl mx-auto my-8 animate-fadeInUp">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-[#EF5350]/15 text-[#EF5350] border border-[#EF5350]/30">
              <AlertTriangle className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-[#F2F2F2]">
                {this.props.fallbackTitle || 'Component Rendering Error'}
              </h2>
              <p className="text-xs text-[#AAAAAA] mt-0.5">
                An unexpected exception occurred while rendering this view.
              </p>
            </div>
          </div>

          <div className="p-3 rounded bg-[#1A1A1A] border border-[#333333] font-mono text-xs text-[#EF5350] overflow-x-auto">
            {this.state.error?.toString() || 'Unknown error'}
          </div>

          {this.state.errorInfo?.componentStack && (
            <details className="text-[11px] font-mono text-[#888888]">
              <summary className="cursor-pointer hover:text-[#CCCCCC] mb-1">Component Stack Trace</summary>
              <pre className="p-2 rounded bg-[#161616] overflow-x-auto text-[10px] text-[#777777]">
                {this.state.errorInfo.componentStack}
              </pre>
            </details>
          )}

          <div className="flex items-center gap-2 pt-2 border-t border-[#333333]">
            <button
              onClick={this.handleReset}
              className="btn-primary text-xs py-1.5 px-3 flex items-center gap-1.5"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Retry Component</span>
            </button>
            <button
              onClick={() => {
                this.handleReset();
                window.location.hash = '';
                window.location.reload();
              }}
              className="btn-secondary text-xs py-1.5 px-3 flex items-center gap-1.5"
            >
              <LayoutDashboard className="w-3.5 h-3.5" />
              <span>Reload Interface</span>
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
