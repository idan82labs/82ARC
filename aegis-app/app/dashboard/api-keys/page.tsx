'use client';

import React from 'react';
import { Sidebar } from '@/components/dashboard/Sidebar';
import { APIKeyManager } from '@/components/dashboard/APIKeyManager';

export default function APIKeysPage() {
  return (
    <div className="flex min-h-screen bg-slate-50">
      <Sidebar />
      <main className="flex-1 p-8">
        <div className="max-w-4xl mx-auto">
          <div className="mb-8">
            <h1 className="text-3xl font-bold text-slate-900 mb-2">API Keys</h1>
            <p className="text-slate-500">Manage your API keys for programmatic access</p>
          </div>
          <APIKeyManager />
        </div>
      </main>
    </div>
  );
}
