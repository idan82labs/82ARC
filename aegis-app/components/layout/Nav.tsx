'use client';

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Menu, X } from 'lucide-react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Logo } from './Logo';
import { Button } from '@/components/ui/Button';

const navLinks = [
  { id: 'product', label: 'Product', href: '/product' },
  { id: 'methodology', label: 'Methodology', href: '/methodology' },
  { id: 'solutions', label: 'Solutions', href: '/solutions' },
  { id: 'pricing', label: 'Pricing', href: '/pricing' },
  { id: 'contact', label: 'Contact', href: '/contact' },
];

export const Nav: React.FC = () => {
  const [isScrolled, setIsScrolled] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const pathname = usePathname();

  useEffect(() => {
    const handleScroll = () => setIsScrolled(window.scrollY > 24);
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  return (
    <nav
      className={`fixed top-0 left-0 right-0 z-40 transition-all duration-300 border-b ${
        isScrolled
          ? 'h-[72px] bg-white/90 backdrop-blur-md border-slate-200 shadow-sm'
          : 'h-[80px] bg-transparent border-transparent'
      }`}
    >
      <div className="max-w-[1120px] mx-auto px-6 h-full flex items-center justify-between">
        <Link href="/">
          <Logo />
        </Link>

        {/* Desktop Nav */}
        <div className="hidden md:flex items-center gap-8">
          {navLinks.map((link) => (
            <Link
              key={link.id}
              href={link.href}
              className={`text-sm font-medium transition-colors ${
                pathname === link.href ? 'text-blue-600' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              {link.label}
            </Link>
          ))}
        </div>

        <div className="hidden md:flex items-center gap-4">
          <Link href="/product">
            <Button variant="secondary">View Sample Report</Button>
          </Link>
          <Link href="/contact">
            <Button variant="primary">Request Assessment</Button>
          </Link>
        </div>

        {/* Mobile Toggle */}
        <button
          className="md:hidden text-slate-700"
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
        >
          {mobileMenuOpen ? <X /> : <Menu />}
        </button>
      </div>

      {/* Mobile Menu Overlay */}
      <AnimatePresence>
        {mobileMenuOpen && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setMobileMenuOpen(false)}
              className="fixed inset-0 bg-slate-900/20 backdrop-blur-sm z-40 md:hidden"
            />
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="absolute top-[72px] left-0 right-0 bg-white border-b border-slate-200 p-6 flex flex-col gap-4 shadow-xl md:hidden overflow-hidden z-50"
            >
              {navLinks.map((link) => (
                <Link
                  key={link.id}
                  href={link.href}
                  onClick={() => setMobileMenuOpen(false)}
                  className="text-left py-3 text-slate-700 font-medium border-b border-slate-50 last:border-0 hover:text-blue-600 transition-colors"
                >
                  {link.label}
                </Link>
              ))}
              <div className="flex flex-col gap-3 mt-4 pt-4 border-t border-slate-100">
                <Link href="/product">
                  <Button variant="secondary" className="w-full">
                    View Sample Report
                  </Button>
                </Link>
                <Link href="/contact">
                  <Button variant="primary" className="w-full">
                    Request Assessment
                  </Button>
                </Link>
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </nav>
  );
};
