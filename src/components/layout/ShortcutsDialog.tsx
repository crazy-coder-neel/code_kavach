import React from 'react';
import { Keyboard, X } from 'lucide-react';

interface ShortcutsDialogProps {
  open: boolean;
  onClose: () => void;
}

export const ShortcutsDialog: React.FC<ShortcutsDialogProps> = ({ open, onClose }) => {
  if (!open) return null;

  const shortcuts = [
    { key: '⌘ / Ctrl + K', description: 'Open command menu' },
    { key: '⌘ / Ctrl + ↵', description: 'Run code security scan' },
    { key: '⌘ / Ctrl + ?', description: 'Open keyboard shortcuts dialog' },
    { key: 'G S', description: 'Navigate to Code Scanner' },
    { key: 'G B', description: 'Navigate to Batch Evaluation' },
    { key: 'G H', description: 'Navigate to Scan History' },
    { key: 'G A', description: 'Navigate to Analytics' },
    { key: 'G R', description: 'Navigate to Rules & Detections' },
    { key: 'G P', description: 'Navigate to Settings' },
    { key: 'Esc', description: 'Close open modal or dialog' },
  ];

  return (
    <div className="fixed inset-0 bg-black/45 z-50 flex items-center justify-center p-4">
      <div className="w-full max-w-md bg-[var(--surface-card)] border border-[var(--border)] rounded-xl shadow-2xl p-5 space-y-4 animate-in fade-in zoom-in-95 duration-100">
        <div className="flex items-center justify-between border-b border-[var(--border)] pb-3">
          <div className="flex items-center gap-2">
            <Keyboard className="w-4 h-4 text-[var(--text-primary)]" />
            <h3 className="font-semibold text-sm text-[var(--text-primary)]">
              Keyboard Shortcuts
            </h3>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded text-[var(--text-muted)] hover:text-[var(--text-primary)]"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="space-y-2 text-xs">
          {shortcuts.map((sc, i) => (
            <div
              key={i}
              className="flex items-center justify-between py-1.5 px-2 rounded hover:bg-[var(--surface-secondary)]"
            >
              <span className="text-[var(--text-secondary)]">{sc.description}</span>
              <kbd className="font-mono text-[11px] px-2 py-0.5 rounded bg-[var(--surface-secondary)] border border-[var(--border)] text-[var(--text-primary)] font-medium">
                {sc.key}
              </kbd>
            </div>
          ))}
        </div>

        <div className="pt-2 border-t border-[var(--border)] flex justify-end">
          <button
            onClick={onClose}
            className="px-3.5 py-1.5 rounded-lg bg-[var(--primary)] text-[var(--primary-foreground)] text-xs font-medium hover:bg-[var(--primary-hover)] transition-colors"
          >
            Got it
          </button>
        </div>
      </div>
    </div>
  );
};
