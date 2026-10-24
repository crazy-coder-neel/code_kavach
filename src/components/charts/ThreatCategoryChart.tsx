import React from 'react';
import type { ApexOptions } from 'apexcharts';
import { BaseChart, getBaseChartOptions, DEFAULT_CHART_COLORS } from './BaseChart';

interface CategoryDataPoint {
  category: string;
  count: number;
  cwe?: string;
}

interface ThreatCategoryChartProps {
  data: CategoryDataPoint[];
  height?: number;
}

export const ThreatCategoryChart: React.FC<ThreatCategoryChartProps> = ({
  data,
  height = 280,
}) => {
  const sorted = [...data].sort((a, b) => b.count - a.count);
  const categories = sorted.map((d) => (d.cwe ? `${d.category} (${d.cwe})` : d.category));
  const counts = sorted.map((d) => d.count);

  const series = [
    {
      name: 'Flagged Findings',
      data: counts,
    },
  ];

  const options: ApexOptions = getBaseChartOptions({
    chart: {
      type: 'bar',
      toolbar: { show: false },
      background: '#FFFFFF',
    },
    plotOptions: {
      bar: {
        horizontal: true,
        borderRadius: 4,
        barHeight: '48%',
        distributed: false,
      },
    },
    colors: [DEFAULT_CHART_COLORS.ink],
    dataLabels: {
      enabled: true,
      textAnchor: 'start',
      style: {
        colors: [DEFAULT_CHART_COLORS.ink],
        fontSize: '11px',
        fontFamily: '"JetBrains Mono", monospace',
        fontWeight: 500,
      },
      formatter: (val) => `${val}`,
      offsetX: 6,
    },
    xaxis: {
      categories,
      labels: {
        style: {
          colors: DEFAULT_CHART_COLORS.secondary,
          fontSize: '11px',
          fontFamily: '"JetBrains Mono", monospace',
        },
      },
      axisBorder: {
        color: DEFAULT_CHART_COLORS.border,
      },
    },
    yaxis: {
      labels: {
        style: {
          colors: DEFAULT_CHART_COLORS.ink,
          fontSize: '12px',
          fontFamily: '"Inter", sans-serif',
          fontWeight: 400,
        },
        maxWidth: 240,
      },
    },
    tooltip: {
      y: {
        formatter: (val) => `${val} detected instances`,
      },
    },
  });

  return (
    <BaseChart
      type="bar"
      series={series}
      options={options}
      height={height}
      empty={data.length === 0}
      emptyMessage="No threat violations identified."
    />
  );
};
