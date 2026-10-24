import React from 'react';
import Chart from 'react-apexcharts';
import type { ApexOptions } from 'apexcharts';
import { useTheme } from '../../lib/theme/ThemeContext';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type ChartSeries = any[];

export interface BaseChartProps {
  type: 'line' | 'area' | 'bar' | 'donut' | 'pie' | 'radialBar';
  series: ChartSeries;
  options: ApexOptions;
  height?: number | string;
  width?: number | string;
  className?: string;
  empty?: boolean;
  emptyMessage?: string;
}

export const DEFAULT_CHART_COLORS = {
  ink: '#0D0D0D',
  secondary: '#5D5D5D',
  muted: '#8F8F8F',
  border: '#E5E5E5',
  borderStrong: '#D9D9D9',
  surface: '#FFFFFF',
  surfaceSecondary: '#F7F7F8',
  surfaceHover: '#F0F0F0',
  surfaceActive: '#EAEAEA',

  // Authoritative semantic states
  allow: '#16A34A',
  allowBackground: '#F0FDF4',
  critical: '#D97706',
  criticalBackground: '#FFFBEB',
  block: '#DC2626',
  blockBackground: '#FEF2F2',

  // Aliases for compatibility
  success: '#16A34A',
  successSoft: '#F0FDF4',
  danger: '#DC2626',
  dangerSoft: '#FEF2F2',
  warning: '#D97706',
  warningSoft: '#FFFBEB',
  info: '#0D0D0D',
  infoSoft: '#F7F7F8',
};

const DARK_CHART_COLORS: Record<string, string> = {
  '#0D0D0D': '#ECECEC',
  '#5D5D5D': '#B4B4B4',
  '#8F8F8F': '#8E8E8E',
  '#E5E5E5': '#3A3A3A',
  '#D9D9D9': '#4A4A4A',
  '#FFFFFF': '#2F2F2F',
  '#F7F7F8': '#2F2F2F',
  '#F0F0F0': '#2A2A2A',
  '#EAEAEA': '#333333',
  '#16A34A': '#4ADE80',
  '#F0FDF4': '#173323',
  '#D97706': '#FBBF24',
  '#FFFBEB': '#3A2C14',
  '#DC2626': '#F87171',
  '#FEF2F2': '#3B1F22',
};

const applyDarkChartColors = (value: unknown): unknown => {
  if (typeof value === 'string') {
    return DARK_CHART_COLORS[value.toUpperCase()] ?? value;
  }
  if (Array.isArray(value)) {
    return value.map(applyDarkChartColors);
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([key, nestedValue]) => [key, applyDarkChartColors(nestedValue)])
    );
  }
  return value;
};

export const getBaseChartOptions = (custom: ApexOptions = {}, isDark = false): ApexOptions => {
  const options: ApexOptions = {
    chart: {
      background: '#FFFFFF',
      foreColor: DEFAULT_CHART_COLORS.secondary,
      toolbar: {
        show: false,
      },
      fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, sans-serif',
      animations: {
        enabled: true,
        speed: 250,
      },
    },
    grid: {
      borderColor: DEFAULT_CHART_COLORS.border,
      strokeDashArray: 2,
      padding: {
        top: 0,
        right: 12,
        bottom: 0,
        left: 12,
      },
    },
    tooltip: {
      theme: 'light',
      style: {
        fontSize: '12px',
        fontFamily: '"JetBrains Mono", monospace',
      },
      x: {
        show: true,
      },
      marker: {
        show: true,
      },
    },
    legend: {
      fontFamily: '"Inter", -apple-system, sans-serif',
      fontSize: '12px',
      labels: {
        colors: DEFAULT_CHART_COLORS.ink,
      },
      markers: {
        size: 5,
        shape: 'circle',
      },
    },
    ...custom,
  };

  const themedOptions = isDark ? applyDarkChartColors(options) as ApexOptions : options;
  return {
    ...themedOptions,
    chart: {
      ...themedOptions.chart,
      background: isDark ? 'transparent' : '#FFFFFF',
      foreColor: isDark ? '#B4B4B4' : '#5D5D5D',
    },
    theme: { ...themedOptions.theme, mode: isDark ? 'dark' : 'light' },
    tooltip: {
      ...themedOptions.tooltip,
      theme: isDark ? 'dark' : 'light',
    },
  };
};

export const BaseChart: React.FC<BaseChartProps> = ({
  type,
  series,
  options,
  height = 280,
  width = '100%',
  className = '',
  empty = false,
  emptyMessage = 'No telemetry available for this view.',
}) => {
  const { isDark } = useTheme();
  const themedOptions = getBaseChartOptions(options, isDark);

  if (empty) {
    return (
      <div
        className={`w-full flex flex-col items-center justify-center p-8 bg-[var(--surface-card)] border border-[var(--border)] rounded-lg text-center ${className}`}
        style={{ minHeight: typeof height === 'number' ? `${height}px` : height }}
      >
        <div className="w-8 h-8 rounded-full bg-[var(--surface-secondary)] flex items-center justify-center mb-2 text-[var(--text-muted)]">
          <span className="font-mono text-xs">∅</span>
        </div>
        <p className="text-xs text-[var(--text-secondary)] font-mono">{emptyMessage}</p>
      </div>
    );
  }

  return (
    <div className={`w-full relative ${className}`}>
      <Chart
        type={type}
        series={series}
        options={themedOptions}
        height={height}
        width={width}
      />
    </div>
  );
};
