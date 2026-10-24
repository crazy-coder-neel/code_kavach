import React, { useState, useRef, useEffect } from 'react';
import { Sun, Moon, Check } from 'lucide-react';
import { useTheme, Theme } from '../../lib/theme/ThemeContext';

export const ThemeSelector: React.FC<{ className?: string }> = ({ className = '' }) => {
  const { theme, setTheme } = useTheme();
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);

  // Close dropdown on click outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (
        dropdownRef.current &&
        !dropdownRef.current.contains(event.target as Node) &&
        buttonRef.current &&
        !buttonRef.current.contains(event.target as Node)
      ) {
        setIsOpen(false);
      }
    };

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isOpen]);

  // Support Escape key to close
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (isOpen && event.key === 'Escape') {
        setIsOpen(false);
        buttonRef.current?.focus();
      }
    };

    if (isOpen) {
      document.addEventListener('keydown', handleKeyDown);
    }
    return () => {
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [isOpen]);

  const handleSelect = (selectedTheme: Theme) => {
    setTheme(selectedTheme);
    setIsOpen(false);
    buttonRef.current?.focus();
  };

  return (
    <div className={`relative inline-block ${className}`} ref={dropdownRef}>
      <button
        ref={buttonRef}
        type="button"
        onClick={() => setIsOpen((prev) => !prev)}
        className="p-1.5 rounded-md text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-hover)] transition-colors focus:outline-none focus-visible:ring-1 focus-visible:ring-[var(--focus-ring)]"
        title="Appearance"
        aria-label="Appearance"
        aria-haspopup="menu"
        aria-expanded={isOpen}
      >
        <Moon className="w-4 h-4 text-[var(--text-secondary)]" />
      </button>

      {/* Dropdown Menu */}
      {isOpen && (
        <div
          role="menu"
          aria-orientation="vertical"
          aria-label="Appearance"
          className="absolute right-0 mt-1.5 w-36 py-1 px-1 rounded-lg bg-[var(--surface)] border border-[var(--border)] shadow-lg z-50 animate-in fade-in zoom-in-95 duration-100"
        >
          {/* Light Option */}
          <button
            type="button"
            role="menuitem"
            aria-checked={theme === 'light'}
            onClick={() => handleSelect('light')}
            className={`w-full flex items-center gap-2.5 px-2.5 py-1.5 rounded-md text-xs transition-colors text-left ${
              theme === 'light'
                ? 'bg-[var(--surface-active)] font-medium text-[var(--text-primary)]'
                : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-hover)]'
            }`}
          >
            <Sun className="w-3.5 h-3.5 text-[var(--text-secondary)] shrink-0" />
            <span className="flex-1">Light</span>
            {theme === 'light' && (
              <Check className="w-3.5 h-3.5 text-[var(--text-primary)] shrink-0" />
            )}
          </button>

          {/* Dark Option */}
          <button
            type="button"
            role="menuitem"
            aria-checked={theme === 'dark'}
            onClick={() => handleSelect('dark')}
            className={`w-full flex items-center gap-2.5 px-2.5 py-1.5 rounded-md text-xs transition-colors text-left ${
              theme === 'dark'
                ? 'bg-[var(--surface-active)] font-medium text-[var(--text-primary)]'
                : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-hover)]'
            }`}
          >
            <Moon className="w-3.5 h-3.5 text-[var(--text-secondary)] shrink-0" />
            <span className="flex-1">Dark</span>
            {theme === 'dark' && (
              <Check className="w-3.5 h-3.5 text-[var(--text-primary)] shrink-0" />
            )}
          </button>
        </div>
      )}
    </div>
  );
};
