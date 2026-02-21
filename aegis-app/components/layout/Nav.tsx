'use client';

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Menu, X, User, LogOut, LayoutDashboard } from 'lucide-react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Logo } from './Logo';
import { Button } from '@/components/ui/Button';
import { useUser, useClerk } from '@clerk/nextjs';

const navLinks = [
  { id: 'product', label: 'Product', href: '/product' },
  { id: 'methodology', label: 'Methodology', href: '/methodology' },
  { id: 'solutions', label: 'Solutions', href: '/solutions' },
  { id: 'pricing', label: 'Pricing', href: '/pricing' },
];

export const Nav: React.FC = () => {
  const [isScrolled, setIsScrolled] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const pathname = usePathname();
  const { isSignedIn, user } = useUser();
  const { signOut } = useClerk();

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
          {isSignedIn && (
            <Link
              href="/dashboard"
              className={`text-sm font-medium transition-colors ${
                pathname === '/dashboard' ? 'text-blue-600' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Dashboard
            </Link>
          )}
        </div>

        <div className="hidden md:flex items-center gap-3">
          {isSignedIn ? (
            <div className="relative">
              <button
                onClick={() => setUserMenuOpen(!userMenuOpen)}
                className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-100 hover:bg-slate-200 transition-colors"
              >
                <User size={18} className="text-slate-600" />
                <span className="text-sm font-medium text-slate-900">
                  {user?.firstName || user?.username || 'User'}
                </span>
                <div className="flex items-center gap-1 px-2 py-0.5 bg-blue-600 text-white text-xs font-bold rounded-full">
                  500 credits
                </div>
              </button>

              <AnimatePresence>
                {userMenuOpen && (
                  <>
                    <motion.div
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                      onClick={() => setUserMenuOpen(false)}
                      className="fixed inset-0 z-40"
                    />
                    <motion.div
                      initial={{ opacity: 0, y: -10 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -10 }}
                      className="absolute right-0 mt-2 w-64 bg-white rounded-xl shadow-xl border border-slate-200 py-2 z-50"
                    >
                      <div className="px-4 py-3 border-b border-slate-100">
                        <p className="text-sm font-semibold text-slate-900">
                          {user?.primaryEmailAddress?.emailAddress}
                        </p>
                        <p className="text-xs text-slate-500">Professional Plan</p>
                      </div>
                      <Link
                        href="/dashboard"
                        onClick={() => setUserMenuOpen(false)}
                        className="flex items-center gap-3 px-4 py-2 hover:bg-slate-50 transition-colors"
                      >
                        <LayoutDashboard size={16} className="text-slate-600" />
                        <span className="text-sm text-slate-700">Dashboard</span>
                      </Link>
                      <button
                        onClick={() => {
                          signOut();
                          setUserMenuOpen(false);
                        }}
                        className="w-full flex items-center gap-3 px-4 py-2 hover:bg-slate-50 transition-colors text-left"
                      >
                        <LogOut size={16} className="text-slate-600" />
                        <span className="text-sm text-slate-700">Sign Out</span>
                      </button>
                    </motion.div>
                  </>
                )}
              </AnimatePresence>
            </div>
          ) : (
            <>
              <Link href="/sign-in">
                <Button variant="secondary" className="text-sm">
                  Sign In
                </Button>
              </Link>
              <Link href="/sign-up">
                <Button variant="primary" className="text-sm">
                  Get Started Free
                </Button>
              </Link>
            </>
          )}
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
              {isSignedIn && user && (
                <div className="pb-4 mb-4 border-b border-slate-100">
                  <div className="flex items-center gap-3 mb-2">
                    <div className="p-2 bg-slate-100 rounded-lg">
                      <User size={20} className="text-slate-600" />
                    </div>
                    <div>
                      <p className="font-semibold text-slate-900">
                        {user.firstName || user.username || 'User'}
                      </p>
                      <p className="text-xs text-slate-500">{user.primaryEmailAddress?.emailAddress}</p>
                    </div>
                  </div>
                  <div className="flex items-center justify-between mt-3 px-3 py-2 bg-blue-50 rounded-lg">
                    <span className="text-sm text-slate-600">Credits</span>
                    <span className="text-sm font-bold text-blue-600">500</span>
                  </div>
                </div>
              )}

              {navLinks.map((link) => (
                <Link
                  key={link.id}
                  href={link.href}
                  onClick={() => setMobileMenuOpen(false)}
                  className="text-left py-3 text-slate-700 font-medium border-b border-slate-50 hover:text-blue-600 transition-colors"
                >
                  {link.label}
                </Link>
              ))}

              {isSignedIn && (
                <Link
                  href="/dashboard"
                  onClick={() => setMobileMenuOpen(false)}
                  className="text-left py-3 text-slate-700 font-medium border-b border-slate-50 hover:text-blue-600 transition-colors"
                >
                  Dashboard
                </Link>
              )}

              <div className="flex flex-col gap-3 mt-4 pt-4 border-t border-slate-100">
                {isSignedIn ? (
                  <button
                    onClick={() => {
                      signOut();
                      setMobileMenuOpen(false);
                    }}
                    className="w-full flex items-center justify-center gap-2 h-11 px-5 rounded-[10px] bg-slate-100 text-slate-700 font-medium hover:bg-slate-200 transition-colors"
                  >
                    <LogOut size={18} />
                    Sign Out
                  </button>
                ) : (
                  <>
                    <Link href="/sign-in" onClick={() => setMobileMenuOpen(false)}>
                      <Button variant="secondary" className="w-full">
                        Sign In
                      </Button>
                    </Link>
                    <Link href="/sign-up" onClick={() => setMobileMenuOpen(false)}>
                      <Button variant="primary" className="w-full">
                        Get Started Free
                      </Button>
                    </Link>
                  </>
                )}
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </nav>
  );
};
