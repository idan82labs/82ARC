'use client';

import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { CheckCircle } from 'lucide-react';

interface ToastProps {
  message: string;
  visible: boolean;
}

export const Toast: React.FC<ToastProps> = ({ message, visible }) => (
  <AnimatePresence>
    {visible && (
      <motion.div
        initial={{ opacity: 0, y: 20, x: '-50%' }}
        animate={{ opacity: 1, y: 0, x: '-50%' }}
        exit={{ opacity: 0, y: 20, x: '-50%' }}
        className="fixed bottom-8 left-1/2 z-50 w-full max-w-sm px-4"
      >
        <div className="bg-slate-900 text-white px-4 py-3 rounded-lg shadow-xl flex items-center gap-3 text-sm font-medium">
          <CheckCircle size={16} className="text-green-400 shrink-0" />
          {message}
        </div>
      </motion.div>
    )}
  </AnimatePresence>
);
