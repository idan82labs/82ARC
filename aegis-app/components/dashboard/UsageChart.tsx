'use client';

import React from 'react';
import { motion } from 'framer-motion';

interface UsageData {
  date: string;
  scans: number;
  credits: number;
}

export const UsageChart: React.FC = () => {
  const data: UsageData[] = [
    { date: 'Jan 1', scans: 5, credits: 150 },
    { date: 'Jan 2', scans: 8, credits: 240 },
    { date: 'Jan 3', scans: 3, credits: 90 },
    { date: 'Jan 4', scans: 12, credits: 360 },
    { date: 'Jan 5', scans: 7, credits: 210 },
    { date: 'Jan 6', scans: 15, credits: 450 },
    { date: 'Jan 7', scans: 10, credits: 300 },
  ];

  const maxScans = Math.max(...data.map((d) => d.scans));

  return (
    <div className="bg-white border border-slate-200 rounded-xl p-6">
      <h3 className="font-bold text-slate-900 mb-6">Usage Overview (Last 7 Days)</h3>
      <div className="flex items-end justify-between gap-2 h-48">
        {data.map((item, i) => {
          const height = (item.scans / maxScans) * 100;
          return (
            <div key={i} className="flex-1 flex flex-col items-center gap-2">
              <motion.div
                initial={{ height: 0 }}
                animate={{ height: `${height}%` }}
                transition={{ delay: i * 0.1, duration: 0.5 }}
                className="w-full bg-blue-500 rounded-t-lg relative group cursor-pointer hover:bg-blue-600 transition-colors"
              >
                <div className="absolute -top-8 left-1/2 -translate-x-1/2 bg-slate-900 text-white text-xs px-2 py-1 rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap">
                  {item.scans} scans
                  <br />
                  {item.credits} credits
                </div>
              </motion.div>
              <span className="text-xs text-slate-500">{item.date.split(' ')[1]}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
};
