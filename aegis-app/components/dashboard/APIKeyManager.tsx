'use client';

import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Copy, Eye, EyeOff, Trash2, Plus, Key } from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { Toast } from '@/components/ui/Toast';

interface APIKey {
  id: string;
  name: string;
  key: string;
  created: string;
  lastUsed?: string;
}

export const APIKeyManager: React.FC = () => {
  const [keys, setKeys] = useState<APIKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showKey, setShowKey] = useState<string | null>(null);
  const [toastMessage, setToastMessage] = useState('');
  const [showToast, setShowToast] = useState(false);

  useEffect(() => {
    fetchKeys();
  }, []);

  const fetchKeys = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await fetch('/api/keys');

      if (!response.ok) {
        throw new Error('Failed to fetch API keys');
      }

      const data = await response.json();
      setKeys(data.keys || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
      setKeys([]);
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = async (key: string) => {
    try {
      await navigator.clipboard.writeText(key);
      showToastMessage('API key copied to clipboard');
    } catch (err) {
      showToastMessage('Failed to copy to clipboard');
    }
  };

  const deleteKey = async (id: string) => {
    try {
      const response = await fetch(`/api/keys/${id}`, {
        method: 'DELETE',
      });

      if (!response.ok) {
        throw new Error('Failed to delete API key');
      }

      setKeys(keys.filter((k) => k.id !== id));
      showToastMessage('API key deleted successfully');
    } catch (err) {
      showToastMessage('Failed to delete API key');
    }
  };

  const showToastMessage = (message: string) => {
    setToastMessage(message);
    setShowToast(true);
    setTimeout(() => setShowToast(false), 3000);
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  };

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h2 className="text-xl font-bold text-slate-900">API Keys</h2>
        <Button variant="primary">
          <Plus size={16} /> Create New Key
        </Button>
      </div>

      {loading && (
        <div className="space-y-3">
          {[1, 2].map((i) => (
            <div
              key={i}
              className="bg-white border border-slate-200 rounded-xl p-4 animate-pulse"
            >
              <div className="flex items-start justify-between mb-3">
                <div className="space-y-2">
                  <div className="h-5 w-32 bg-slate-200 rounded"></div>
                  <div className="h-3 w-24 bg-slate-200 rounded"></div>
                </div>
                <div className="flex gap-2">
                  <div className="w-8 h-8 bg-slate-200 rounded-lg"></div>
                  <div className="w-8 h-8 bg-slate-200 rounded-lg"></div>
                  <div className="w-8 h-8 bg-slate-200 rounded-lg"></div>
                </div>
              </div>
              <div className="h-10 bg-slate-200 rounded-lg"></div>
            </div>
          ))}
        </div>
      )}

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-xl p-4 text-red-700">
          <p className="font-semibold">Error loading API keys</p>
          <p className="text-sm mt-1">{error}</p>
          <Button
            variant="secondary"
            onClick={fetchKeys}
            className="mt-3"
          >
            Retry
          </Button>
        </div>
      )}

      {!loading && !error && keys.length === 0 && (
        <div className="bg-white border-2 border-dashed border-slate-200 rounded-xl p-12 text-center">
          <div className="w-16 h-16 bg-slate-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <Key size={32} className="text-slate-400" />
          </div>
          <h3 className="text-lg font-semibold text-slate-900 mb-2">No API keys yet</h3>
          <p className="text-slate-500 mb-6 max-w-sm mx-auto">
            Create your first API key to start integrating AEGIS security scans into your applications.
          </p>
          <Button variant="primary">
            <Plus size={16} /> Create Your First API Key
          </Button>
        </div>
      )}

      {!loading && !error && keys.length > 0 && (
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
                  <p className="text-xs text-slate-500">
                    Created {formatDate(apiKey.created)}
                  </p>
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={() => setShowKey(showKey === apiKey.id ? null : apiKey.id)}
                    className="p-2 hover:bg-slate-100 rounded-lg transition-colors"
                    title={showKey === apiKey.id ? 'Hide key' : 'Show key'}
                  >
                    {showKey === apiKey.id ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                  <button
                    onClick={() => copyToClipboard(apiKey.key)}
                    className="p-2 hover:bg-slate-100 rounded-lg transition-colors"
                    title="Copy to clipboard"
                  >
                    <Copy size={16} />
                  </button>
                  <button
                    onClick={() => deleteKey(apiKey.id)}
                    className="p-2 hover:bg-red-50 text-red-600 rounded-lg transition-colors"
                    title="Delete key"
                  >
                    <Trash2 size={16} />
                  </button>
                </div>
              </div>
              <div className="bg-slate-900 rounded-lg p-3 font-mono text-sm text-slate-300">
                {showKey === apiKey.id ? apiKey.key : '••••••••••••••••••••'}
              </div>
              {apiKey.lastUsed && (
                <p className="text-xs text-slate-400 mt-2">
                  Last used: {formatDate(apiKey.lastUsed)}
                </p>
              )}
            </motion.div>
          ))}
        </div>
      )}

      <Toast message={toastMessage} visible={showToast} />
    </div>
  );
};
