import React from 'react';
import type { ApexOptions } from 'apexcharts';
import { BaseChart, getBaseChartOptions, DEFAULT_CHART_COLORS } from './BaseChart';

interface VolumeDataPoint {
  period: string;
  allowed: number;
  blocked: number;
}

interface ScanVolumeChartProps {
  data: VolumeDataPoint[];
  height?: number;
}

export const ScanVolumeChart: React.FC<ScanVolumeChartProps> = ({ data, height = 260 }) => {
  const categories = data.map((d) => d.period);
  const allowedSeries = data.map((d) => d.allowed);
  const blockedSeries = data.map((d) => d.blocked);

  const series = [
    {
      name: 'Allowed',
      data: allowedSeries,
    },
    {
      name: 'Blocked',
      data: blockedSeries,
    },
  ];

  const options: ApexOptions = getBaseChartOptions({
    chart: {
      type: 'bar',
      stacked: true,
      toolbar: { show: false },
      background: '#FFFFFF',
    },
    colors: [DEFAULT_CHART_COLORS.allow, DEFAULT_CHART_COLORS.block],
    plotOptions: {
      bar: {
        horizontal: false,
        columnWidth: '38%',
        borderRadius: 4,
        borderRadiusApplication: 'end',
      },
    },
    dataLabels: {
      enabled: false,
    },
    stroke: {
      show: true,
      width: 2,
      colors: ['transparent'],
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
      axisTicks: {
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
      },
    },
    fill: {
      opacity: 1,
    },
    legend: {
      position: 'top',
      horizontalAlign: 'right',
      fontSize: '12px',
      labels: {
        colors: DEFAULT_CHART_COLORS.ink,
      },
      markers: {
        size: 5,
        shape: 'circle',
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
    />
  );
};
