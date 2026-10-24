import React, { useState, useEffect } from 'react';
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import {
  Code2,
  Layers,
  History,
  BarChart3,
  BookOpenCheck,
  Settings,
  ChevronLeft,
  ChevronRight,
  Command,
  Search,
  Menu,
  X,
  Plus,
  Terminal,
  ShieldAlert,
  Puzzle,
  Keyboard,
  FileText,
} from 'lucide-react';
import { Logo } from '../brand/Logo';
import { ShortcutsDialog } from './ShortcutsDialog';
import { apiClient } from '../../lib/api/client';
import { checkBackendHealth } from '../../lib/api/health';
import { useTheme } from '../../lib/theme/ThemeContext';
import { ThemeSelector } from './ThemeSelector';

export const AppShell: React.FC = () => {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const { toggleTheme } = useTheme();
  const [connectionStatus, setConnectionStatus] = useState<{
    useMock: boolean;
    healthy: boolean;
    label: string;
  }>({
    useMock: true,
    healthy: true,
    label: 'Mock Engine Active',
  });
  const [commandOpen, setCommandOpen] = useState(false);
  const [commandQuery, setCommandQuery] = useState('');

  const location = useLocation();
  const navigate = useNavigate();

  // Periodic health check
  useEffect(() => {
    const updateHealth = async () => {
      const config = apiClient.getConfig();
      if (config.useMock) {
        setConnectionStatus({
          useMock: true,
          healthy: true,
          label: 'Deterministic Engine',
        });
      } else {
        const health = await checkBackendHealth();
        setConnectionStatus({
          useMock: false,
          healthy: health.isConnected,
          label: health.isConnected ? 'FastAPI Connected' : 'Backend Disconnected',
        });
      }
    };

    updateHealth();
    const interval = setInterval(updateHealth, 15000);
    return () => clearInterval(interval);
  }, [location.pathname]);

  // Global key listeners: Cmd+K and Cmd+?
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setCommandOpen((prev) => !prev);
      }
      if ((e.metaKey || e.ctrlKey) && (e.key === '?' || e.key === '/')) {
        e.preventDefault();
        setShortcutsOpen((prev) => !prev);
      }
      if (e.key === 'Escape') {
        if (commandOpen) setCommandOpen(false);
        if (shortcutsOpen) setShortcutsOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [commandOpen, shortcutsOpen]);

  const navItems = [
    { to: '/app/scan', label: 'Code Scanner', icon: Code2 },
    { to: '/app/batch', label: 'Batch Evaluation', icon: Layers },
    { to: '/app/history', label: 'Scan History', icon: History },
    { to: '/app/analytics', label: 'Security Analytics', icon: BarChart3 },
    { to: '/app/rules', label: 'Rules & Detections', icon: ShieldAlert },
    { to: '/app/playground', label: 'API Playground', icon: Terminal },
    { to: '/app/integrations', label: 'Integrations', icon: Puzzle },
    { to: '/app/responsible-ai', label: 'Responsible AI', icon: BookOpenCheck },
    { to: '/app/decisions', label: 'Design Decisions', icon: FileText },
    { to: '/app/settings', label: 'Settings', icon: Settings },
  ];

  const commandActions = [
    { title: 'New Code Scan', shortcut: 'N', action: () => navigate('/app/scan') },
    { title: 'Open Batch Evaluator', shortcut: 'G B', action: () => navigate('/app/batch') },
    { title: 'Inspect Scan History', shortcut: 'G H', action: () => navigate('/app/history') },
    { title: 'View Analytics & Performance', shortcut: 'G A', action: () => navigate('/app/analytics') },
    { title: 'Security Rules & Heuristics', shortcut: 'G R', action: () => navigate('/app/rules') },
    { title: 'Open API Playground', shortcut: 'G P', action: () => navigate('/app/playground') },
    { title: 'Developer Integrations', shortcut: 'G I', action: () => navigate('/app/integrations') },
    { title: 'Responsible AI & Trust', shortcut: 'G T', action: () => navigate('/app/responsible-ai') },
    { title: 'Design Decisions', shortcut: 'G D', action: () => navigate('/app/decisions') },
    { title: 'Engine Connection & Settings', shortcut: 'G S', action: () => navigate('/app/settings') },
    { title: 'Open Keyboard Shortcuts', shortcut: '?', action: () => setShortcutsOpen(true) },
    { title: 'Toggle Theme', shortcut: 'T', action: toggleTheme },
    { title: 'Landing Page', shortcut: 'Esc', action: () => navigate('/') },
  ];

  const filteredCommands = commandActions.filter((cmd) =>
    cmd.title.toLowerCase().includes(commandQuery.toLowerCase())
  );

  return (
    <div className="min-h-screen bg-[var(--surface)] text-[var(--text-primary)] flex flex-col font-sans transition-colors duration-150">
      {/* Top Header - White dominant & minimal */}
      <header className="h-14 border-b border-[var(--border)] bg-[var(--surface)] sticky top-0 z-30 px-4 lg:px-6 flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="p-1.5 rounded-md text-[var(--text-secondary)] hover:text-[var(--text-primary)] md:hidden hover:bg-[var(--surface-secondary)]"
            aria-label="Toggle navigation menu"
          >
            {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>

          <NavLink to="/" className="flex items-center gap-2 group">
            <Logo variant="full" size="md" />
          </NavLink>

          <span className="hidden sm:inline-block text-[var(--border)]">/</span>

          <span className="hidden sm:inline-block text-xs text-[var(--text-muted)] font-mono">
            Pre-Execution Safety Layer
          </span>
        </div>

        {/* Right Header Area */}
        <div className="flex items-center gap-2">
          {/* Connection Status Pill */}
          <div
            title={
              connectionStatus.useMock
                ? 'Deterministic offline safety evaluator active'
                : connectionStatus.label
            }
            className={`hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono border ${
              connectionStatus.healthy
                ? 'bg-[var(--allow-background)] text-[var(--allow)] border-[var(--allow-background)]'
                : 'bg-[var(--block-background)] text-[var(--block)] border-[var(--block-background)]'
            }`}
          >
            <span className="w-1.5 h-1.5 rounded-full bg-current" />
            <span className="truncate max-w-[140px]">{connectionStatus.label}</span>
          </div>

          {/* Command Palette Trigger */}
          <button
            onClick={() => setCommandOpen(true)}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-mono text-[var(--text-secondary)] bg-[var(--surface-secondary)] border border-[var(--border)] hover:text-[var(--text-primary)] transition-colors"
            title="Quick Command Menu (⌘K)"
          >
            <Command className="w-3.5 h-3.5 text-[var(--text-muted)]" />
            <span className="hidden md:inline">Commands</span>
            <kbd className="hidden md:inline text-[10px] bg-[var(--surface)] px-1 rounded border border-[var(--border)] text-[var(--text-primary)]">
              ⌘K
            </kbd>
          </button>

          {/* Keyboard Shortcuts Trigger */}
          <button
            onClick={() => setShortcutsOpen(true)}
            className="p-1.5 rounded-md text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-secondary)] transition-colors"
            title="Keyboard Shortcuts (⌘/)"
            aria-label="Keyboard Shortcuts"
          >
            <Keyboard className="w-4 h-4 text-[var(--text-muted)]" />
          </button>

          {/* Theme switcher */}
          <ThemeSelector />
        </div>
      </header>

      {/* Main Layout Area */}
      <div className="flex flex-1 min-h-[calc(100vh-3.5rem)] relative bg-[var(--surface)]">
        {/* Desktop Sidebar Navigation - Clean light grey #F9F9F9 */}
        <aside
          className={`hidden md:flex flex-col border-r border-[var(--border)] bg-[var(--sidebar-background)] transition-all duration-200 z-20 shrink-0 ${
            collapsed ? 'w-16' : 'w-60'
          }`}
        >
          {/* New Scan Action Button */}
          <div className="p-3">
            <button
              onClick={() => navigate('/app/scan')}
              className={`w-full flex items-center justify-center gap-2 py-2 px-3 rounded-lg border border-[var(--border)] bg-[var(--surface)] hover:bg-[var(--surface-hover)] text-[var(--text-primary)] text-xs font-medium transition-colors shadow-xs ${
                collapsed ? 'px-0' : ''
              }`}
              title="New code scan"
            >
              <Plus className="w-4 h-4 text-[var(--text-primary)] shrink-0" />
              {!collapsed && <span>New scan</span>}
            </button>
          </div>

          {/* Navigation Links */}
          <nav className="px-2 space-y-0.5 flex-1 overflow-y-auto">
            {navItems.map((item) => {
              const Icon = item.icon;
              return (
                <NavLink
                  key={item.to}
                  to={item.to}
                  className={({ isActive }) =>
                    `flex items-center gap-2.5 px-2.5 py-2 rounded-lg text-xs transition-colors ${
                      isActive
                        ? 'bg-[var(--surface-active)] text-[var(--text-primary)] font-medium'
                        : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-hover)]'
                    }`
                  }
                  title={item.label}
                >
                  <Icon className="w-4 h-4 shrink-0 text-[var(--text-secondary)]" />
                  {!collapsed && <span className="truncate">{item.label}</span>}
                </NavLink>
              );
            })}
          </nav>

          {/* Sidebar Footer */}
          <div className="p-3 border-t border-[var(--border)] bg-[var(--sidebar-background)] space-y-2">
            {!collapsed ? (
              <div className="flex items-center justify-between text-xs text-[var(--text-muted)]">
                <div className="flex items-center gap-2">
                  <div className="w-6 h-6 rounded-full bg-[var(--border-strong)] flex items-center justify-center text-[var(--text-primary)] text-[10px] font-bold">
                    CK
                  </div>
                  <div className="leading-tight">
                    <div className="font-medium text-[var(--text-primary)] text-[11px]">
                      Local Workspace
                    </div>
                    <div className="text-[10px]">Code Kavach v0.9</div>
                  </div>
                </div>

                <button
                  onClick={() => setCollapsed(!collapsed)}
                  className="p-1 rounded text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-hover)] transition-colors"
                  title="Collapse sidebar"
                  aria-label="Collapse sidebar"
                >
                  <ChevronLeft className="w-4 h-4" />
                </button>
              </div>
            ) : (
              <button
                onClick={() => setCollapsed(!collapsed)}
                className="w-full py-1 text-center rounded text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-hover)] transition-colors"
                title="Expand sidebar"
                aria-label="Expand sidebar"
              >
                <ChevronRight className="w-4 h-4 mx-auto" />
              </button>
            )}
          </div>
        </aside>

        {/* Mobile Navigation Drawer */}
        {mobileMenuOpen && (
          <div className="fixed inset-0 top-14 bg-black/30 z-40 md:hidden flex">
            <div className="w-72 bg-[var(--sidebar-background)] border-r border-[var(--border)] p-4 flex flex-col justify-between shadow-xl">
              <nav className="space-y-1">
                <button
                  onClick={() => {
                    navigate('/app/scan');
                    setMobileMenuOpen(false);
                  }}
                  className="w-full flex items-center justify-center gap-2 py-2 px-3 mb-3 rounded-lg border border-[var(--border)] bg-[var(--surface)] text-xs font-medium text-[var(--text-primary)]"
                >
                  <Plus className="w-4 h-4" />
                  <span>New scan</span>
                </button>

                {navItems.map((item) => {
                  const Icon = item.icon;
                  return (
                    <NavLink
                      key={item.to}
                      to={item.to}
                      onClick={() => setMobileMenuOpen(false)}
                      className={({ isActive }) =>
                        `flex items-center gap-3 px-3 py-2 rounded-lg text-xs ${
                          isActive
                            ? 'bg-[var(--surface-active)] text-[var(--text-primary)] font-medium'
                            : 'text-[var(--text-secondary)]'
                        }`
                      }
                    >
                      <Icon className="w-4 h-4 shrink-0" />
                      <span>{item.label}</span>
                    </NavLink>
                  );
                })}
              </nav>

              <div className="pt-4 border-t border-[var(--border)] text-xs font-mono text-[var(--text-muted)]">
                code_kavach · Safety Layer
              </div>
            </div>
            <div className="flex-1" onClick={() => setMobileMenuOpen(false)} />
          </div>
        )}

        {/* Viewport Content - Clean White Surface */}
        <main className="flex-1 flex flex-col min-w-0 overflow-y-auto bg-[var(--surface)]">
          <Outlet />
        </main>
      </div>

      {/* Command Palette Modal */}
      {commandOpen && (
        <div className="fixed inset-0 bg-black/40 z-50 flex items-start justify-center pt-20 px-4">
          <div className="w-full max-w-lg bg-[var(--surface)] border border-[var(--border)] rounded-lg shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-100">
            <div className="flex items-center px-4 border-b border-[var(--border)]">
              <Search className="w-4 h-4 text-[var(--text-muted)] mr-2 shrink-0" />
              <input
                type="text"
                value={commandQuery}
                onChange={(e) => setCommandQuery(e.target.value)}
                placeholder="Type a command or jump to page..."
                className="w-full py-3 bg-transparent text-sm text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none"
                autoFocus
              />
              <kbd
                onClick={() => setCommandOpen(false)}
                className="cursor-pointer text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--surface-secondary)] text-[var(--text-muted)] border border-[var(--border)]"
              >
                ESC
              </kbd>
            </div>

            <div className="max-h-64 overflow-y-auto p-2">
              {filteredCommands.length > 0 ? (
                filteredCommands.map((cmd, idx) => (
                  <button
                    key={idx}
                    onClick={() => {
                      cmd.action();
                      setCommandOpen(false);
                    }}
                    className="w-full flex items-center justify-between px-3 py-2 rounded-md text-xs text-[var(--text-primary)] hover:bg-[var(--surface-hover)] transition-colors text-left"
                  >
                    <span>{cmd.title}</span>
                    <span className="text-[11px] font-mono text-[var(--text-muted)]">
                      {cmd.shortcut}
                    </span>
                  </button>
                ))
              ) : (
                <div className="p-4 text-center text-xs text-[var(--text-muted)] font-mono">
                  No matching commands found.
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Keyboard Shortcuts Dialog */}
      <ShortcutsDialog open={shortcutsOpen} onClose={() => setShortcutsOpen(false)} />
    </div>
  );
};
