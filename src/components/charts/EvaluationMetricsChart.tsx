import React from 'react';
import type { ApexOptions } from 'apexcharts';
import { BaseChart, getBaseChartOptions, DEFAULT_CHART_COLORS } from './BaseChart';

interface EvaluationMetricsChartProps {
  precision: number;
  recall: number;
  f1Score: number;
  falsePositiveRate: number;
  height?: number;
}

export const EvaluationMetricsChart: React.FC<EvaluationMetricsChartProps> = ({
  precision,
  recall,
  f1Score,
  falsePositiveRate,
  height = 190,
}) => {
  const categories = ['Precision', 'Recall', 'F1-Score', 'False Positive Rate'];
  const values = [
    Math.round(precision * 100),
    Math.round(recall * 100),
    Math.round(f1Score * 100),
    Math.round(falsePositiveRate * 100),
  ];

  const series = [
    {
      name: 'Benchmark Score (%)',
      data: values,
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
        barHeight: '44%',
        distributed: true,
      },
    },
    colors: [
      DEFAULT_CHART_COLORS.allow,
      DEFAULT_CHART_COLORS.allow,
      DEFAULT_CHART_COLORS.ink,
      DEFAULT_CHART_COLORS.block,
    ],
    dataLabels: {
      enabled: true,
      textAnchor: 'start',
      style: {
        colors: [DEFAULT_CHART_COLORS.ink],
        fontSize: '11px',
        fontFamily: '"JetBrains Mono", monospace',
        fontWeight: 500,
      },
      formatter: (val) => `${val}%`,
      offsetX: 6,
    },
    xaxis: {
      categories,
      max: 100,
      labels: {
        style: {
          colors: DEFAULT_CHART_COLORS.secondary,
          fontSize: '11px',
          fontFamily: '"JetBrains Mono", monospace',
        },
        formatter: (val) => `${val}%`,
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
          fontWeight: 500,
        },
      },
    },
    legend: {
      show: false,
    },
    tooltip: {
      y: {
        formatter: (val) => `${val}%`,
      },
    },
  });

  return (
    <BaseChart
      type="bar"
      series={series}
      options={options}
      height={height}
    />
  );
};
