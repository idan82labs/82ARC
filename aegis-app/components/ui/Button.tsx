import React from 'react';

type ButtonVariant = 'primary' | 'secondary' | 'tertiary' | 'smallSecondary';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  children: React.ReactNode;
}

const BUTTON_STYLES: Record<ButtonVariant, string> = {
  primary: 'h-11 px-5 rounded-[10px] bg-blue-600 text-white font-medium transition-all duration-200 hover:-translate-y-px hover:shadow-lg flex items-center justify-center gap-2 hover:bg-blue-700',
  secondary: 'h-11 px-5 rounded-[10px] bg-white border border-slate-200 text-slate-900 font-medium transition-all duration-200 hover:bg-slate-50 hover:border-blue-200 flex items-center justify-center gap-2',
  tertiary: 'text-blue-600 hover:underline font-medium inline-flex items-center gap-1',
  smallSecondary: 'h-8 px-3 rounded-lg text-sm border border-slate-200 bg-white text-slate-600 hover:text-blue-600 hover:border-blue-200 transition-colors',
};

export const Button: React.FC<ButtonProps> = ({
  variant = 'primary',
  children,
  className = '',
  ...props
}) => {
  return (
    <button
      className={`${BUTTON_STYLES[variant]} ${className}`}
      {...props}
    >
      {children}
    </button>
  );
};
