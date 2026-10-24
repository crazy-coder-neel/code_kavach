import React from 'react';

interface LogoProps {
  variant?: 'full' | 'mark' | 'monochrome';
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

export const Logo: React.FC<LogoProps> = ({ variant = 'full', size = 'md', className = '' }) => {
  const iconSizes = {
    sm: 'w-5 h-5',
    md: 'w-6 h-6',
    lg: 'w-8 h-8',
  };

  const textSizes = {
    sm: 'text-xs',
    md: 'text-sm',
    lg: 'text-base',
  };

  const iconElement = (
    <svg
      viewBox="0 0 32 32"
      className={`${iconSizes[size]} shrink-0 transition-transform`}
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-label="code_kavach mark"
    >
      {/* Outer geometric frame adapts to primary brand token */}
      <rect
        x="3"
        y="3"
        width="26"
        height="26"
        rx="6"
        fill="var(--primary)"
      />
      {/* Left Code Bracket Boundary */}
      <path
        d="M11 10L7 16L11 22"
        stroke="var(--primary-foreground)"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      {/* Right Code Bracket Boundary */}
      <path
        d="M21 10L25 16L21 22"
        stroke="var(--primary-foreground)"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      {/* Center Containment Node */}
      <circle
        cx="16"
        cy="16"
        r="2"
        fill="var(--primary-foreground)"
      />
    </svg>
  );

  if (variant === 'mark') {
    return <div className={`inline-flex items-center ${className}`}>{iconElement}</div>;
  }

  return (
    <div className={`inline-flex items-center gap-2 ${className}`}>
      {iconElement}
      <span
        className={`font-semibold tracking-tight text-[var(--text-primary)] ${textSizes[size]}`}
      >
        code_kavach
      </span>
    </div>
  );
};
