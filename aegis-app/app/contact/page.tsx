'use client';

import React, { useState } from 'react';
import { Nav } from '@/components/layout/Nav';
import { Footer } from '@/components/layout/Footer';
import { Button } from '@/components/ui/Button';
import { Toast } from '@/components/ui/Toast';

export default function ContactPage() {
  const [toast, setToast] = useState({ visible: false, message: '' });

  const showToast = (msg: string) => {
    setToast({ visible: true, message: msg });
    setTimeout(() => setToast({ visible: false, message: '' }), 3000);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    showToast('Request sent successfully.');
  };

  return (
    <>
      <Nav />
      <main className="pt-32 pb-24 max-w-[600px] mx-auto px-6">
        <div className="text-center mb-12">
          <h1 className="text-3xl font-bold text-slate-900 mb-4">Get started with Aegis</h1>
          <p className="text-slate-500">
            Fill out the form below and we'll get back to you within 1 business day.
          </p>
        </div>

        <form className="space-y-6" onSubmit={handleSubmit}>
          <div className="grid md:grid-cols-2 gap-6">
            <div className="space-y-2">
              <label className="text-sm font-medium text-slate-700">First Name</label>
              <input
                type="text"
                className="w-full px-4 py-2 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all"
                required
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium text-slate-700">Last Name</label>
              <input
                type="text"
                className="w-full px-4 py-2 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all"
                required
              />
            </div>
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium text-slate-700">Work Email</label>
            <input
              type="email"
              className="w-full px-4 py-2 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all"
              required
            />
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium text-slate-700">Company Website</label>
            <input
              type="url"
              className="w-full px-4 py-2 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all"
            />
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium text-slate-700">What are you building?</label>
            <textarea
              className="w-full px-4 py-2 border border-slate-200 rounded-lg h-32 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all"
              placeholder="Briefly describe your agent architecture..."
              required
            ></textarea>
          </div>

          <div className="flex items-start gap-3">
            <input type="checkbox" id="auth" className="mt-1" required />
            <label htmlFor="auth" className="text-sm text-slate-600">
              I confirm I have authorization to request security testing for this organization.
              <a href="#" className="text-blue-600 hover:underline ml-1">
                Read Policy
              </a>
            </label>
          </div>

          <Button type="submit" variant="primary" className="w-full">
            Request Assessment
          </Button>
        </form>
      </main>
      <Footer />
      <Toast message={toast.message} visible={toast.visible} />
    </>
  );
}
