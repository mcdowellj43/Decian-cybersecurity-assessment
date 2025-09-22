import { HTMLAttributes } from 'react';
import { cn, getRiskLevel, getRiskColorClasses, formatRiskScore } from '@/lib/utils';
import type { RiskLevel } from '@/types';

export interface RiskIndicatorProps extends HTMLAttributes<HTMLDivElement> {
  score?: number;
  level?: RiskLevel;
  showScore?: boolean;
  size?: 'sm' | 'md' | 'lg';
}

export function RiskIndicator({
  score,
  level,
  showScore = true,
  size = 'md',
  className,
  ...props
}: RiskIndicatorProps) {
  // Determine risk level from score if not provided
  const riskLevel = level || (score !== undefined ? getRiskLevel(score) : 'low');

  const colorClasses = getRiskColorClasses(riskLevel);

  const sizeClasses = {
    sm: 'px-2 py-1 text-xs',
    md: 'px-2.5 py-0.5 text-sm',
    lg: 'px-3 py-1 text-base',
  };

  const getRiskLevelText = (level: RiskLevel): string => {
    switch (level) {
      case 'critical':
        return 'Critical';
      case 'high':
        return 'High';
      case 'medium':
        return 'Medium';
      case 'low':
        return 'Low';
      default:
        return 'Unknown';
    }
  };

  return (
    <div
      className={cn(
        'inline-flex items-center rounded-full font-medium border',
        colorClasses,
        sizeClasses[size],
        className
      )}
      {...props}
    >
      <div className={cn(
        'w-2 h-2 rounded-full mr-1.5',
        riskLevel === 'critical' && 'bg-red-600',
        riskLevel === 'high' && 'bg-red-600',
        riskLevel === 'medium' && 'bg-orange-600',
        riskLevel === 'low' && 'bg-green-600'
      )} />
      <span>
        {getRiskLevelText(riskLevel)}
        {showScore && score !== undefined && (
          <span className="ml-1">({formatRiskScore(score)})</span>
        )}
      </span>
    </div>
  );
}

// Progress bar variant for risk scores
export interface RiskProgressBarProps extends HTMLAttributes<HTMLDivElement> {
  score: number;
  showLabel?: boolean;
}

export function RiskProgressBar({
  score,
  showLabel = true,
  className,
  ...props
}: RiskProgressBarProps) {
  const level = getRiskLevel(score);

  const getProgressColor = (level: RiskLevel): string => {
    switch (level) {
      case 'critical':
        return 'bg-red-600';
      case 'high':
        return 'bg-red-500';
      case 'medium':
        return 'bg-orange-500';
      case 'low':
        return 'bg-green-500';
      default:
        return 'bg-gray-500';
    }
  };

  return (
    <div className={cn('w-full', className)} {...props}>
      {showLabel && (
        <div className="flex justify-between items-center mb-2">
          <span className="text-sm font-medium text-gray-700">Risk Score</span>
          <span className="text-sm text-gray-500">{formatRiskScore(score)}</span>
        </div>
      )}
      <div className="w-full bg-gray-200 rounded-full h-2">
        <div
          className={cn('h-2 rounded-full transition-all duration-300', getProgressColor(level))}
          style={{ width: `${Math.min(score, 100)}%` }}
        />
      </div>
    </div>
  );
}