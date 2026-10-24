import React from 'react';
import type { ApexOptions } from 'apexcharts';
import { BaseChart, getBaseChartOptions, DEFAULT_CHART_COLORS } from './BaseChart';

interface VerdictDistributionChartProps {
  allowed: number;
  blocked: number;
  height?: number;
}

export const VerdictDistributionChart: React.FC<VerdictDistributionChartProps> = ({
  allowed,
  blocked,
  height = 230,
}) => {
  const total = allowed + blocked;
  const series = [allowed, blocked];

  const options: ApexOptions = getBaseChartOptions({
    chart: {
      type: 'donut',
      background: '#FFFFFF',
    },
    labels: ['Allowed', 'Blocked'],
    colors: [DEFAULT_CHART_COLORS.allow, DEFAULT_CHART_COLORS.block],
    stroke: {
      width: 2,
      colors: ['#FFFFFF'],
    },
    dataLabels: {
      enabled: false,
    },
    plotOptions: {
      pie: {
        donut: {
          size: '74%',
          labels: {
            show: true,
            name: {
              show: true,
              fontSize: '12px',
              fontFamily: '"Inter", sans-serif',
              color: DEFAULT_CHART_COLORS.secondary,
              offsetY: -4,
            },
            value: {
              show: true,
              fontSize: '20px',
              fontFamily: '"JetBrains Mono", monospace',
              fontWeight: 600,
              color: DEFAULT_CHART_COLORS.ink,
              offsetY: 4,
              formatter: (val) => `${val}`,
            },
            total: {
              show: true,
              label: 'Total Scans',
              color: DEFAULT_CHART_COLORS.secondary,
              fontSize: '11px',
              fontFamily: '"Inter", sans-serif',
              formatter: () => `${total}`,
            },
          },
        },
      },
    },
    legend: {
      position: 'bottom',
      horizontalAlign: 'center',
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
      type="donut"
      series={series}
      options={options}
      height={height}
      empty={total === 0}
      emptyMessage="No scans recorded."
    />
  );
};
