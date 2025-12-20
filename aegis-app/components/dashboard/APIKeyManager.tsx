'use client';

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Copy, Eye, EyeOff, Trash2, Plus, Key, Settings, X, Terminal, CheckCircle } from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { Toast } from '@/components/ui/Toast';
import { ToolGroupSelector, ToolGroupBadge, TOOL_GROUPS } from './ToolGroupSelector';

interface APIKey {
  id: string;
  name: string;
  key_prefix: string;
  tool_groups: string[] | null;
  created_at: string;
  last_used_at?: string | null;
}

interface CreateKeyModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: (key: string, apiKey: APIKey) => void;
  userTier: 'free' | 'pro' | 'enterprise';
}

const CreateKeyModal: React.FC<CreateKeyModalProps> = ({ isOpen, onClose, onSuccess, userTier }) => {
  const [name, setName] = useState('');
  const [selectedGroups, setSelectedGroups] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleCreate = async () => {
    if (!name.trim()) {
      setError('Name is required');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await fetch('/api/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: name.trim(),
          tool_groups: selectedGroups.length > 0 ? selectedGroups : null,
        }),
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Failed to create API key');
      }

      const data = await response.json();
      onSuccess(data.key, {
        id: data.id,
        name: data.name,
        key_prefix: data.key.substring(0, 11),
        tool_groups: data.tool_groups,
        created_at: new Date().toISOString(),
      });
      setName('');
      setSelectedGroups([]);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.95 }}
        className="bg-white rounded-2xl shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto"
      >
        <div className="sticky top-0 bg-white border-b border-slate-200 p-6 flex justify-between items-center">
          <div>
            <h2 className="text-xl font-bold text-slate-900">Create New API Key</h2>
            <p className="text-sm text-slate-500">Configure access for your MCP client</p>
          </div>
          <button onClick={onClose} className="p-2 hover:bg-slate-100 rounded-lg">
            <X size={20} />
          </button>
        </div>

        <div className="p-6 space-y-6">
          {/* Name input */}
          <div>
            <label className="block text-sm font-semibold text-slate-700 mb-2">
              Key Name
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g., Claude Desktop, ChatGPT, Production..."
              className="w-full px-4 py-3 border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>

          {/* Tool group selection */}
          <ToolGroupSelector
            selectedGroups={selectedGroups}
            onSelectionChange={setSelectedGroups}
            userTier={userTier}
          />

          {error && (
            <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm">
              {error}
            </div>
          )}
        </div>

        <div className="sticky bottom-0 bg-white border-t border-slate-200 p-6 flex justify-end gap-3">
          <Button variant="secondary" onClick={onClose} disabled={loading}>
            Cancel
          </Button>
          <Button variant="primary" onClick={handleCreate} disabled={loading}>
            {loading ? 'Creating...' : 'Create API Key'}
          </Button>
        </div>
      </motion.div>
    </div>
  );
};

interface EditKeyModalProps {
  isOpen: boolean;
  apiKey: APIKey | null;
  onClose: () => void;
  onSuccess: (updated: APIKey) => void;
  userTier: 'free' | 'pro' | 'enterprise';
}

const EditKeyModal: React.FC<EditKeyModalProps> = ({ isOpen, apiKey, onClose, onSuccess, userTier }) => {
  const [name, setName] = useState(apiKey?.name || '');
  const [selectedGroups, setSelectedGroups] = useState<string[]>(apiKey?.tool_groups || []);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (apiKey) {
      setName(apiKey.name);
      setSelectedGroups(apiKey.tool_groups || []);
    }
  }, [apiKey]);

  const handleSave = async () => {
    if (!apiKey) return;

    setLoading(true);
    setError(null);

    try {
      const response = await fetch('/api/keys', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: apiKey.id,
          name: name.trim(),
          tool_groups: selectedGroups.length > 0 ? selectedGroups : null,
        }),
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Failed to update API key');
      }

      const data = await response.json();
      onSuccess({
        ...apiKey,
        name: data.name,
        tool_groups: data.tool_groups,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen || !apiKey) return null;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.95 }}
        className="bg-white rounded-2xl shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto"
      >
        <div className="sticky top-0 bg-white border-b border-slate-200 p-6 flex justify-between items-center">
          <div>
            <h2 className="text-xl font-bold text-slate-900">Edit API Key</h2>
            <p className="text-sm text-slate-500">Update tool group access</p>
          </div>
          <button onClick={onClose} className="p-2 hover:bg-slate-100 rounded-lg">
            <X size={20} />
          </button>
        </div>

        <div className="p-6 space-y-6">
          <div>
            <label className="block text-sm font-semibold text-slate-700 mb-2">
              Key Name
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full px-4 py-3 border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>

          <ToolGroupSelector
            selectedGroups={selectedGroups}
            onSelectionChange={setSelectedGroups}
            userTier={userTier}
          />

          {error && (
            <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm">
              {error}
            </div>
          )}
        </div>

        <div className="sticky bottom-0 bg-white border-t border-slate-200 p-6 flex justify-end gap-3">
          <Button variant="secondary" onClick={onClose} disabled={loading}>
            Cancel
          </Button>
          <Button variant="primary" onClick={handleSave} disabled={loading}>
            {loading ? 'Saving...' : 'Save Changes'}
          </Button>
        </div>
      </motion.div>
    </div>
  );
};

interface MCPInstructionsModalProps {
  isOpen: boolean;
  apiKey: string;
  onClose: () => void;
}

const MCPInstructionsModal: React.FC<MCPInstructionsModalProps> = ({ isOpen, apiKey, onClose }) => {
  const [copied, setCopied] = useState<string | null>(null);

  const mcpServerUrl = process.env.NEXT_PUBLIC_MCP_SERVER_URL || 'https://aegis-mcp.your-domain.com';

  const claudeDesktopConfig = {
    mcpServers: {
      aegis: {
        command: 'npx',
        args: ['-y', '@anthropic/mcp-client', mcpServerUrl],
        env: {
          AEGIS_API_KEY: apiKey,
        },
      },
    },
  };

  const directConfig = {
    url: mcpServerUrl,
    headers: {
      'X-API-Key': apiKey,
    },
  };

  const copyToClipboard = async (text: string, key: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(key);
      setTimeout(() => setCopied(null), 2000);
    } catch {
      // Ignore
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.95 }}
        className="bg-white rounded-2xl shadow-xl max-w-3xl w-full max-h-[90vh] overflow-y-auto"
      >
        <div className="sticky top-0 bg-white border-b border-slate-200 p-6 flex justify-between items-center">
          <div>
            <h2 className="text-xl font-bold text-slate-900 flex items-center gap-2">
              <Terminal size={24} className="text-blue-600" />
              MCP Connection Setup
            </h2>
            <p className="text-sm text-slate-500">Connect your AI client to AEGIS</p>
          </div>
          <button onClick={onClose} className="p-2 hover:bg-slate-100 rounded-lg">
            <X size={20} />
          </button>
        </div>

        <div className="p-6 space-y-6">
          {/* API Key Display */}
          <div className="bg-green-50 border border-green-200 rounded-xl p-4">
            <div className="flex items-start gap-3">
              <CheckCircle size={20} className="text-green-600 mt-0.5" />
              <div className="flex-1">
                <p className="font-semibold text-green-800">API Key Created Successfully</p>
                <p className="text-sm text-green-700 mt-1">
                  Save this key now - you won&apos;t be able to see it again!
                </p>
                <div className="mt-3 flex items-center gap-2">
                  <code className="flex-1 bg-green-100 px-3 py-2 rounded-lg font-mono text-sm text-green-900 break-all">
                    {apiKey}
                  </code>
                  <button
                    onClick={() => copyToClipboard(apiKey, 'key')}
                    className="p-2 bg-green-600 text-white rounded-lg hover:bg-green-700"
                  >
                    {copied === 'key' ? <CheckCircle size={16} /> : <Copy size={16} />}
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* Claude Desktop Setup */}
          <div className="border border-slate-200 rounded-xl overflow-hidden">
            <div className="bg-slate-50 px-4 py-3 border-b border-slate-200">
              <h3 className="font-semibold text-slate-900">Claude Desktop Configuration</h3>
              <p className="text-xs text-slate-500">Add to your claude_desktop_config.json</p>
            </div>
            <div className="relative">
              <pre className="p-4 bg-slate-900 text-slate-100 text-sm overflow-x-auto">
                <code>{JSON.stringify(claudeDesktopConfig, null, 2)}</code>
              </pre>
              <button
                onClick={() => copyToClipboard(JSON.stringify(claudeDesktopConfig, null, 2), 'claude')}
                className="absolute top-2 right-2 p-2 bg-slate-700 text-white rounded-lg hover:bg-slate-600"
              >
                {copied === 'claude' ? <CheckCircle size={16} /> : <Copy size={16} />}
              </button>
            </div>
          </div>

          {/* Direct HTTP Connection */}
          <div className="border border-slate-200 rounded-xl overflow-hidden">
            <div className="bg-slate-50 px-4 py-3 border-b border-slate-200">
              <h3 className="font-semibold text-slate-900">Direct HTTP Connection</h3>
              <p className="text-xs text-slate-500">For custom MCP clients or direct API access</p>
            </div>
            <div className="relative">
              <pre className="p-4 bg-slate-900 text-slate-100 text-sm overflow-x-auto">
                <code>{JSON.stringify(directConfig, null, 2)}</code>
              </pre>
              <button
                onClick={() => copyToClipboard(JSON.stringify(directConfig, null, 2), 'direct')}
                className="absolute top-2 right-2 p-2 bg-slate-700 text-white rounded-lg hover:bg-slate-600"
              >
                {copied === 'direct' ? <CheckCircle size={16} /> : <Copy size={16} />}
              </button>
            </div>
          </div>

          {/* SSE Endpoint */}
          <div className="border border-slate-200 rounded-xl overflow-hidden">
            <div className="bg-slate-50 px-4 py-3 border-b border-slate-200">
              <h3 className="font-semibold text-slate-900">SSE Endpoint (OpenAI/ChatGPT)</h3>
              <p className="text-xs text-slate-500">For tools that support Server-Sent Events</p>
            </div>
            <div className="p-4 space-y-3">
              <div className="flex items-center gap-2">
                <span className="text-sm text-slate-600 w-16">URL:</span>
                <code className="flex-1 bg-slate-100 px-3 py-2 rounded-lg font-mono text-sm break-all">
                  {mcpServerUrl}/sse
                </code>
                <button
                  onClick={() => copyToClipboard(`${mcpServerUrl}/sse`, 'sse-url')}
                  className="p-2 hover:bg-slate-100 rounded-lg"
                >
                  {copied === 'sse-url' ? <CheckCircle size={16} className="text-green-600" /> : <Copy size={16} />}
                </button>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-sm text-slate-600 w-16">Header:</span>
                <code className="flex-1 bg-slate-100 px-3 py-2 rounded-lg font-mono text-sm">
                  X-API-Key: {apiKey.substring(0, 11)}...
                </code>
              </div>
            </div>
          </div>

          {/* Quick Start */}
          <div className="bg-blue-50 border border-blue-200 rounded-xl p-4">
            <h3 className="font-semibold text-blue-900 mb-2">Quick Start</h3>
            <ol className="list-decimal list-inside text-sm text-blue-800 space-y-1">
              <li>Copy the API key above</li>
              <li>Add the configuration to your MCP client</li>
              <li>Restart your AI client (Claude Desktop, etc.)</li>
              <li>Start using AEGIS tools in your conversations!</li>
            </ol>
          </div>
        </div>

        <div className="sticky bottom-0 bg-white border-t border-slate-200 p-6">
          <Button variant="primary" onClick={onClose} className="w-full">
            Done
          </Button>
        </div>
      </motion.div>
    </div>
  );
};

export const APIKeyManager: React.FC = () => {
  const [keys, setKeys] = useState<APIKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [toastMessage, setToastMessage] = useState('');
  const [showToast, setShowToast] = useState(false);
  const [userTier, setUserTier] = useState<'free' | 'pro' | 'enterprise'>('free');

  // Modal states
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [editingKey, setEditingKey] = useState<APIKey | null>(null);
  const [showInstructions, setShowInstructions] = useState<string | null>(null);

  useEffect(() => {
    fetchKeys();
    fetchUserTier();
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

  const fetchUserTier = async () => {
    try {
      const response = await fetch('/api/user/credits');
      if (response.ok) {
        const data = await response.json();
        setUserTier(data.tier || 'free');
      }
    } catch {
      // Default to free tier
    }
  };

  const deleteKey = async (id: string) => {
    if (!confirm('Are you sure you want to delete this API key? This action cannot be undone.')) {
      return;
    }

    try {
      const response = await fetch(`/api/keys?id=${id}`, {
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
      day: 'numeric',
    });
  };

  const getEnabledToolsCount = (toolGroups: string[] | null): number => {
    if (!toolGroups || toolGroups.length === 0) {
      // All tier-allowed groups
      return Object.values(TOOL_GROUPS).reduce((acc, g) => acc + g.tools.length, 0);
    }
    return toolGroups.reduce((acc, groupId) => {
      const group = TOOL_GROUPS[groupId as keyof typeof TOOL_GROUPS];
      return acc + (group?.tools.length || 0);
    }, 0);
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-xl font-bold text-slate-900">Your API Keys</h2>
          <p className="text-sm text-slate-500">Manage access to AEGIS MCP tools</p>
        </div>
        <Button variant="primary" onClick={() => setShowCreateModal(true)}>
          <Plus size={16} /> Create New Key
        </Button>
      </div>

      {loading && (
        <div className="space-y-3">
          {[1, 2].map((i) => (
            <div
              key={i}
              className="bg-white border border-slate-200 rounded-xl p-5 animate-pulse"
            >
              <div className="flex items-start justify-between mb-4">
                <div className="space-y-2">
                  <div className="h-5 w-32 bg-slate-200 rounded"></div>
                  <div className="h-3 w-24 bg-slate-200 rounded"></div>
                </div>
              </div>
              <div className="flex gap-2">
                <div className="h-6 w-24 bg-slate-200 rounded-full"></div>
                <div className="h-6 w-24 bg-slate-200 rounded-full"></div>
              </div>
            </div>
          ))}
        </div>
      )}

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-xl p-4 text-red-700">
          <p className="font-semibold">Error loading API keys</p>
          <p className="text-sm mt-1">{error}</p>
          <Button variant="secondary" onClick={fetchKeys} className="mt-3">
            Retry
          </Button>
        </div>
      )}

      {!loading && !error && keys.length === 0 && (
        <div className="bg-white border-2 border-dashed border-slate-200 rounded-xl p-12 text-center">
          <div className="w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <Key size={32} className="text-blue-600" />
          </div>
          <h3 className="text-lg font-semibold text-slate-900 mb-2">No API keys yet</h3>
          <p className="text-slate-500 mb-6 max-w-sm mx-auto">
            Create your first API key to connect Claude Desktop, ChatGPT, or any MCP-compatible client to AEGIS.
          </p>
          <Button variant="primary" onClick={() => setShowCreateModal(true)}>
            <Plus size={16} /> Create Your First API Key
          </Button>
        </div>
      )}

      {!loading && !error && keys.length > 0 && (
        <div className="space-y-4">
          {keys.map((apiKey) => (
            <motion.div
              key={apiKey.id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className="bg-white border border-slate-200 rounded-xl p-5 hover:border-slate-300 transition-colors"
            >
              <div className="flex items-start justify-between mb-4">
                <div>
                  <h3 className="font-semibold text-slate-900 flex items-center gap-2">
                    <Key size={16} className="text-slate-400" />
                    {apiKey.name}
                  </h3>
                  <div className="flex items-center gap-3 mt-1">
                    <code className="text-xs text-slate-500 font-mono bg-slate-100 px-2 py-0.5 rounded">
                      {apiKey.key_prefix}...
                    </code>
                    <span className="text-xs text-slate-400">
                      Created {formatDate(apiKey.created_at)}
                    </span>
                    {apiKey.last_used_at && (
                      <span className="text-xs text-slate-400">
                        · Last used {formatDate(apiKey.last_used_at)}
                      </span>
                    )}
                  </div>
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={() => setEditingKey(apiKey)}
                    className="p-2 hover:bg-slate-100 rounded-lg transition-colors"
                    title="Edit tool groups"
                  >
                    <Settings size={16} className="text-slate-600" />
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

              {/* Tool groups display */}
              <div className="flex items-center gap-2 flex-wrap">
                {apiKey.tool_groups && apiKey.tool_groups.length > 0 ? (
                  <>
                    {apiKey.tool_groups.slice(0, 4).map((groupId) => (
                      <ToolGroupBadge key={groupId} groupId={groupId} />
                    ))}
                    {apiKey.tool_groups.length > 4 && (
                      <span className="text-xs text-slate-500 bg-slate-100 px-2 py-1 rounded-full">
                        +{apiKey.tool_groups.length - 4} more
                      </span>
                    )}
                  </>
                ) : (
                  <span className="text-xs text-slate-500 bg-slate-100 px-2 py-1 rounded-full">
                    All tier-allowed groups ({getEnabledToolsCount(null)} tools)
                  </span>
                )}
                <span className="ml-auto text-xs text-slate-400">
                  {getEnabledToolsCount(apiKey.tool_groups)} tools enabled
                </span>
              </div>
            </motion.div>
          ))}
        </div>
      )}

      {/* Create Key Modal */}
      <AnimatePresence>
        {showCreateModal && (
          <CreateKeyModal
            isOpen={showCreateModal}
            onClose={() => setShowCreateModal(false)}
            onSuccess={(key, newKey) => {
              setKeys([newKey, ...keys]);
              setShowCreateModal(false);
              setShowInstructions(key);
            }}
            userTier={userTier}
          />
        )}
      </AnimatePresence>

      {/* Edit Key Modal */}
      <AnimatePresence>
        {editingKey && (
          <EditKeyModal
            isOpen={!!editingKey}
            apiKey={editingKey}
            onClose={() => setEditingKey(null)}
            onSuccess={(updated) => {
              setKeys(keys.map((k) => (k.id === updated.id ? updated : k)));
              setEditingKey(null);
              showToastMessage('API key updated successfully');
            }}
            userTier={userTier}
          />
        )}
      </AnimatePresence>

      {/* MCP Instructions Modal */}
      <AnimatePresence>
        {showInstructions && (
          <MCPInstructionsModal
            isOpen={!!showInstructions}
            apiKey={showInstructions}
            onClose={() => setShowInstructions(null)}
          />
        )}
      </AnimatePresence>

      <Toast message={toastMessage} visible={showToast} />
    </div>
  );
};
