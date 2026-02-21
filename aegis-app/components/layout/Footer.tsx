'use client';

import React from 'react';
import Link from 'next/link';
import { Logo } from './Logo';

export const Footer: React.FC = () => {
  return (
    <footer className="bg-white border-t border-slate-200 pt-16 pb-12">
      <div className="max-w-[1120px] mx-auto px-6">
        <div className="grid grid-cols-2 md:grid-cols-5 gap-8 mb-12">
          <div className="col-span-2">
            <Logo />
            <p className="mt-4 text-slate-500 text-sm leading-relaxed max-w-xs">
              Stress-test AI agents before attackers do. The enterprise standard for permissioned
              agentic security assessments.
            </p>
          </div>
          <div>
            <h4 className="font-bold text-slate-900 mb-4 text-sm">Product</h4>
            <ul className="space-y-3 text-sm text-slate-500">
              <li>
                <Link href="/product" className="hover:text-blue-600">
                  Features
                </Link>
              </li>
              <li>
                <Link href="/methodology" className="hover:text-blue-600">
                  Methodology
                </Link>
              </li>
              <li>
                <Link href="/solutions" className="hover:text-blue-600">
                  Integrations
                </Link>
              </li>
            </ul>
          </div>
          <div>
            <h4 className="font-bold text-slate-900 mb-4 text-sm">Company</h4>
            <ul className="space-y-3 text-sm text-slate-500">
              <li>
                <button className="hover:text-blue-600">About</button>
              </li>
              <li>
                <button className="hover:text-blue-600">Careers</button>
              </li>
              <li>
                <button className="hover:text-blue-600">Blog</button>
              </li>
            </ul>
          </div>
          <div>
            <h4 className="font-bold text-slate-900 mb-4 text-sm">Legal</h4>
            <ul className="space-y-3 text-sm text-slate-500">
              <li>
                <button className="hover:text-blue-600">Terms</button>
              </li>
              <li>
                <button className="hover:text-blue-600">Privacy</button>
              </li>
              <li>
                <button className="hover:text-blue-600">Testing Policy</button>
              </li>
            </ul>
          </div>
        </div>
        <div className="flex flex-col md:flex-row justify-between items-center pt-8 border-t border-slate-100 text-sm text-slate-400">
          <p>© 2024 Aegis Security Inc.</p>
          <div className="flex gap-6 mt-4 md:mt-0">
            <button className="hover:text-slate-600">LinkedIn</button>
            <button className="hover:text-slate-600">Security & Trust</button>
          </div>
        </div>
      </div>
    </footer>
  );
};
