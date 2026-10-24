import React, { useRef, useEffect, useImperativeHandle, forwardRef } from 'react';
import Editor, { OnMount } from '@monaco-editor/react';
import { CodeLanguage } from '../../types/guard';
import { useTheme } from '../../lib/theme/ThemeContext';

export interface CodeEditorRef {
  scrollToLine: (lineNumber: number) => void;
  formatCode: () => void;
}

interface CodeEditorProps {
  value: string;
  onChange: (value: string) => void;
  language: CodeLanguage;
  vulnerableLines?: number[];
  activeLine?: number | null;
  readOnly?: boolean;
  isLoading?: boolean;
}

export const CodeEditor = forwardRef<CodeEditorRef, CodeEditorProps>(
  (
    {
      value,
      onChange,
      language,
      vulnerableLines = [],
      activeLine = null,
      readOnly = false,
      isLoading = false,
    },
    ref
  ) => {
    const { isDark } = useTheme();
    const editorTheme = isDark ? 'vs-dark' : 'kavach-dark';

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const editorRef = useRef<any>(null);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const monacoRef = useRef<any>(null);
    const decorationsRef = useRef<string[]>([]);

    const handleEditorDidMount: OnMount = (editor, monaco) => {
      editorRef.current = editor;
      monacoRef.current = monaco;

      // Define code_kavach security dark theme
      monaco.editor.defineTheme('kavach-dark', {
        base: 'vs-dark',
        inherit: true,
        rules: [
          { token: 'comment', foreground: '6C7870', fontStyle: 'italic' },
          { token: 'keyword', foreground: '52A37E', fontStyle: 'bold' },
          { token: 'string', foreground: 'E2A06E' },
          { token: 'number', foreground: '99CC99' },
          { token: 'identifier', foreground: 'D8DFD7' },
        ],
        colors: {
          'editor.background': '#171B19',
          'editor.foreground': '#D8DFD7',
          'editorCursor.foreground': '#52A37E',
          'editor.lineHighlightBackground': '#1F2522',
          'editorLineNumber.foreground': '#49524C',
          'editorLineNumber.activeForeground': '#8FA094',
          'editor.selectionBackground': '#2A3F33',
          'editorGutter.background': '#141816',
        },
      });

      monaco.editor.setTheme(editorTheme);
    };

    useEffect(() => {
      if (monacoRef.current) {
        monacoRef.current.editor.setTheme(editorTheme);
      }
    }, [editorTheme]);

    // Expose imperative methods to parent
    useImperativeHandle(ref, () => ({
      scrollToLine: (lineNumber: number) => {
        if (editorRef.current && lineNumber > 0) {
          editorRef.current.revealLineInCenter(lineNumber);
          editorRef.current.setPosition({ lineNumber, column: 1 });
          editorRef.current.focus();
        }
      },
      formatCode: () => {
        if (editorRef.current) {
          editorRef.current.getAction('editor.action.formatDocument')?.run();
        }
      },
    }));

    // Update decorations for vulnerable lines
    useEffect(() => {
      if (!editorRef.current || !monacoRef.current) return;

      const monaco = monacoRef.current;
      const editor = editorRef.current;

      const newDecorations = vulnerableLines.map((lineNum) => {
        const isActive = activeLine === lineNum;
        return {
          range: new monaco.Range(lineNum, 1, lineNum, 1),
          options: {
            isWholeLine: true,
            className: isActive
              ? 'bg-[var(--block)]/35 border-l-2 border-[var(--block)]'
              : 'bg-[var(--block)]/20 border-l-2 border-[var(--block)]/60',
            glyphMarginClassName: 'text-[var(--block)] font-bold',
            linesDecorationsClassName: 'text-[var(--block)] font-mono text-xs',
            hoverMessage: { value: `⚠️ **code_kavach threat detected on Line ${lineNum}**` },
          },
        };
      });

      decorationsRef.current = editor.deltaDecorations(decorationsRef.current, newDecorations);
    }, [vulnerableLines, activeLine]);

    const monacoLanguageMap: Record<CodeLanguage, string> = {
      python: 'python',
      bash: 'shell',
      javascript: 'javascript',
      sql: 'sql',
      yaml: 'yaml',
      markdown: 'markdown',
      unknown: 'plaintext',
    };

    return (
      <div className="relative w-full h-full flex flex-col bg-[#171B19] dark:bg-[var(--surface)] rounded border border-[var(--border)] overflow-hidden shadow-xs">
        {/* Editor internal header bar */}
        <div className="h-9 px-3 bg-[#141816] dark:bg-[var(--surface-secondary)] border-b border-[#242A27] dark:border-[var(--border)] flex items-center justify-between text-xs font-mono text-[#828D85] dark:text-[var(--text-muted)]">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-[#39423C]" />
            <span className="text-[#C5CEC7] dark:text-[var(--text-primary)] font-semibold">{language.toUpperCase()}</span>
            <span>·</span>
            <span>UTF-8</span>
          </div>

          <div className="flex items-center gap-3">
            {vulnerableLines.length > 0 && (
              <span className="text-[var(--block)] flex items-center gap-1 font-sans text-[11px] font-medium">
                <span className="font-mono font-bold">{vulnerableLines.length}</span> suspicious line{vulnerableLines.length > 1 ? 's' : ''}
              </span>
            )}
            <span className="text-[11px] text-[#5A635D] dark:text-[var(--text-secondary)]">Monaco Editor</span>
          </div>
        </div>

        {/* Monaco Container */}
        <div className="flex-1 relative min-h-[350px]">
          {isLoading && (
            <div className="absolute inset-0 bg-[#171B19]/75 dark:bg-[var(--background)]/75 z-20 flex items-center justify-center backdrop-blur-[1px]">
              <div className="flex items-center gap-3 px-4 py-2 bg-[#1F2522] dark:bg-[var(--surface-secondary)] border border-[#2E3631] dark:border-[var(--border)] rounded text-xs font-mono text-[#D8DFD7] dark:text-[var(--text-primary)] shadow-lg">
                <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                <span>Extracting AST signatures & threat patterns...</span>
              </div>
            </div>
          )}

          <Editor
            height="100%"
            language={monacoLanguageMap[language] || 'plaintext'}
            value={value}
            theme={editorTheme}
            onChange={(val) => onChange(val || '')}
            onMount={handleEditorDidMount}
            options={{
              readOnly,
              minimap: { enabled: false },
              fontSize: 13,
              fontFamily: 'JetBrains Mono, Menlo, monospace',
              lineNumbers: 'on',
              lineNumbersMinChars: 3,
              glyphMargin: false,
              scrollBeyondLastLine: false,
              automaticLayout: true,
              tabSize: 4,
              wordWrap: 'on',
              folding: true,
              renderLineHighlight: 'all',
              padding: { top: 12, bottom: 12 },
            }}
          />
        </div>
      </div>
    );
  }
);

CodeEditor.displayName = 'CodeEditor';
