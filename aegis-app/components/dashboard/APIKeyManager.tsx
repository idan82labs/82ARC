'use client';

import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Copy, Eye, EyeOff, Trash2, Plus } from 'lucide-react';
import { Button } from '@/components/ui/Button';

interface APIKey {
  id: string;
  name: string;
  key: string;
  created: string;
  lastUsed?: string;
}

export const APIKeyManager: React.FC = () => {
  const [keys, setKeys] = useState<APIKey[]>([
    {
      id: '1',
      name: 'Production API',
      key: 'sk_live_abc123...xyz789',
      created: '2024-01-15',
      lastUsed: '2 hours ago',
    },
  ]);
  const [showKey, setShowKey] = useState<string | null>(null);

  const copyToClipboard = (key: string) => {
    navigator.clipboard.writeText(key);
  };

  const deleteKey = (id: string) => {
    setKeys(keys.filter((k) => k.id !== id));
  };

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h2 className="text-xl font-bold text-slate-900">API Keys</h2>
        <Button variant="primary">
          <Plus size={16} /> Create New Key
        </Button>
      </div>

      <div className="space-y-3">
        {keys.map((apiKey) => (
          <motion.div
            key={apiKey.id}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-white border border-slate-200 rounded-xl p-4"
          >
            <div className="flex items-start justify-between mb-3">
              <div>
                <h3 className="font-semibold text-slate-900">{apiKey.name}</h3>
                <p className="text-xs text-slate-500">Created {apiKey.created}</p>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => setShowKey(showKey === apiKey.id ? null : apiKey.id)}
                  className="p-2 hover:bg-slate-100 rounded-lg transition-colors"
                >
                  {showKey === apiKey.id ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
                <button
                  onClick={() => copyToClipboard(apiKey.key)}
                  className="p-2 hover:bg-slate-100 rounded-lg transition-colors"
                >
                  <Copy size={16} />
                </button>
                <button
                  onClick={() => deleteKey(apiKey.id)}
                  className="p-2 hover:bg-red-50 text-red-600 rounded-lg transition-colors"
                >
                  <Trash2 size={16} />
                </button>
              </div>
            </div>
            <div className="bg-slate-900 rounded-lg p-3 font-mono text-sm text-slate-300">
              {showKey === apiKey.id ? apiKey.key : '••••••••••••••••••••'}
            </div>
            {apiKey.lastUsed && (
              <p className="text-xs text-slate-400 mt-2">Last used: {apiKey.lastUsed}</p>
            )}
          </motion.div>
        ))}
      </div>
    </div>
  );
};
