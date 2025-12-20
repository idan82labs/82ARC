'use client';

import React from 'react';
import { motion } from 'framer-motion';

interface LogoProps {
  dark?: boolean;
}

export const Logo: React.FC<LogoProps> = ({ dark = false }) => (
  <motion.div
    whileHover={{ scale: 1.05 }}
    whileTap={{ scale: 0.95 }}
    className="flex items-center gap-2 cursor-pointer"
  >
    <span className={`font-extrabold text-3xl tracking-tighter ${dark ? 'text-white' : 'text-slate-900'}`}>
      Aegis.
    </span>
  </motion.div>
);
