import React from 'react';
import type { ApexOptions } from 'apexcharts';
import { BaseChart, getBaseChartOptions, DEFAULT_CHART_COLORS } from './BaseChart';

interface LatencyPoint {
  percentile: string;
  ms: number;
}

interface LatencyDistributionChartProps {
  data: LatencyPoint[];
  height?: number;
}

export const LatencyDistributionChart: React.FC<LatencyDistributionChartProps> = ({
  data,
  height = 230,
}) => {
  const categories = data.map((d) => d.percentile);
  const values = data.map((d) => d.ms);

  const series = [
    {
      name: 'Evaluation Latency',
      data: values,
    },
  ];

  const options: ApexOptions = getBaseChartOptions({
    chart: {
      type: 'area',
      toolbar: { show: false },
      background: '#FFFFFF',
    },
    stroke: {
      curve: 'smooth',
      width: 2,
      colors: [DEFAULT_CHART_COLORS.ink],
    },
    fill: {
      type: 'gradient',
      gradient: {
        shadeIntensity: 1,
        opacityFrom: 0.12,
        opacityTo: 0.01,
        stops: [0, 95, 100],
        colorStops: [
          {
            offset: 0,
            color: DEFAULT_CHART_COLORS.ink,
            opacity: 0.12,
          },
          {
            offset: 100,
            color: DEFAULT_CHART_COLORS.ink,
            opacity: 0.01,
          },
        ],
      },
    },
    markers: {
      size: 3.5,
      colors: ['#FFFFFF'],
      strokeColors: DEFAULT_CHART_COLORS.ink,
      strokeWidth: 2,
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
          colors: DEFAULT_CHART_COLORS.secondary,
          fontSize: '11px',
          fontFamily: '"JetBrains Mono", monospace',
        },
        formatter: (val) => `${val}ms`,
      },
    },
    tooltip: {
      y: {
        formatter: (val) => `${val} ms latency`,
      },
    },
  });

  return (
    <BaseChart
      type="area"
      series={series}
      options={options}
      height={height}
      empty={data.length === 0}
      emptyMessage="No latency distribution available."
    />
  );
};
