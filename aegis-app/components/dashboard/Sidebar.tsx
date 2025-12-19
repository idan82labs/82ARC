'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { LayoutDashboard, Key, BarChart3, CreditCard, LogOut } from 'lucide-react';
import { UserButton } from '@clerk/nextjs';

const navItems = [
  { href: '/dashboard', icon: LayoutDashboard, label: 'Overview' },
  { href: '/dashboard/api-keys', icon: Key, label: 'API Keys' },
  { href: '/dashboard/usage', icon: BarChart3, label: 'Usage' },
  { href: '/dashboard/billing', icon: CreditCard, label: 'Billing' },
];

export const Sidebar: React.FC = () => {
  const pathname = usePathname();

  return (
    <div className="w-64 h-screen bg-white border-r border-slate-200 flex flex-col">
      <div className="p-6 border-b border-slate-200">
        <h1 className="text-2xl font-extrabold tracking-tighter text-slate-900">Aegis.</h1>
        <p className="text-xs text-slate-500 mt-1">Security Dashboard</p>
      </div>

      <nav className="flex-1 p-4 space-y-1">
        {navItems.map((item) => {
          const isActive = pathname === item.href;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
                isActive
                  ? 'bg-blue-50 text-blue-600 font-medium'
                  : 'text-slate-600 hover:bg-slate-50'
              }`}
            >
              <item.icon size={20} />
              <span>{item.label}</span>
            </Link>
          );
        })}
      </nav>

      <div className="p-4 border-t border-slate-200 flex items-center justify-between">
        <UserButton afterSignOutUrl="/" />
        <span className="text-sm text-slate-500">Account</span>
      </div>
    </div>
  );
};
