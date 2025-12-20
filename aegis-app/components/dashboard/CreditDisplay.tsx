'use client';

import React, { useState, useEffect } from 'react';
import { Zap, X, Crown, Calendar } from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';

interface CreditData {
  credits: number;
  tier: 'free' | 'pro' | 'enterprise';
  autoRefillDate?: string;
}

export const CreditDisplay: React.FC = () => {
  const [data, setData] = useState<CreditData | null>(null);
  const [loading, setLoading] = useState(true);
  const [showPurchaseModal, setShowPurchaseModal] = useState(false);
  const [selectedPackage, setSelectedPackage] = useState<string | null>(null);

  useEffect(() => {
    fetchCreditData();
  }, []);

  const fetchCreditData = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/credits');

      if (!response.ok) {
        throw new Error('Failed to fetch credit data');
      }

      const result = await response.json();
      setData(result);
    } catch (err) {
      console.error('Error fetching credit data:', err);
    } finally {
      setLoading(false);
    }
  };

  const handlePurchase = async (packageId: string) => {
    try {
      const response = await fetch('/api/credits/purchase', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ packageId }),
      });

      if (!response.ok) {
        throw new Error('Failed to purchase credits');
      }

      const result = await response.json();
      setData(result);
      setShowPurchaseModal(false);
    } catch (err) {
      console.error('Error purchasing credits:', err);
    }
  };

  const formatRefillDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
      month: 'long',
      day: 'numeric',
      year: 'numeric',
    });
  };

  const getTierColor = (tier: string) => {
    switch (tier) {
      case 'pro':
        return 'from-purple-500 to-purple-600';
      case 'enterprise':
        return 'from-amber-500 to-amber-600';
      default:
        return 'from-blue-500 to-blue-600';
    }
  };

  const getTierLabel = (tier: string) => {
    switch (tier) {
      case 'pro':
        return 'Pro';
      case 'enterprise':
        return 'Enterprise';
      default:
        return 'Free';
    }
  };

  if (loading) {
    return (
      <div className="bg-gradient-to-br from-blue-500 to-blue-600 rounded-2xl p-6 text-white animate-pulse">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 bg-white/20 rounded-lg"></div>
          <div className="flex-1">
            <div className="h-3 w-24 bg-white/20 rounded mb-2"></div>
            <div className="h-8 w-32 bg-white/20 rounded"></div>
          </div>
        </div>
        <div className="h-4 bg-white/20 rounded mb-2"></div>
        <div className="h-4 w-3/4 bg-white/20 rounded mb-4"></div>
        <div className="h-11 bg-white/20 rounded"></div>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="bg-gradient-to-br from-slate-500 to-slate-600 rounded-2xl p-6 text-white">
        <p className="text-center">Failed to load credit data</p>
      </div>
    );
  }

  return (
    <>
      <div className={`bg-gradient-to-br ${getTierColor(data.tier)} rounded-2xl p-6 text-white relative overflow-hidden`}>
        <div className="absolute top-4 right-4">
          <Badge color={data.tier === 'free' ? 'blue' : data.tier === 'pro' ? 'cyan' : 'amber'}>
            {data.tier === 'pro' && <Crown size={12} className="mr-1" />}
            {getTierLabel(data.tier)}
          </Badge>
        </div>

        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 bg-white/20 rounded-lg flex items-center justify-center">
            <Zap size={20} className="text-white" />
          </div>
          <div>
            <p className="text-xs text-white/80 uppercase tracking-wider">Available Credits</p>
            <p className="text-3xl font-bold">{data.credits.toLocaleString()}</p>
          </div>
        </div>

        <p className="text-sm text-white/90 mb-4">
          Use credits to run security scans and access premium features.
        </p>

        {data.tier === 'pro' && data.autoRefillDate && (
          <div className="flex items-center gap-2 text-xs text-white/80 mb-4 bg-white/10 rounded-lg px-3 py-2">
            <Calendar size={14} />
            <span>Auto-refill on {formatRefillDate(data.autoRefillDate)}</span>
          </div>
        )}

        <Button
          onClick={() => setShowPurchaseModal(true)}
          className="bg-white text-blue-600 hover:bg-blue-50 w-full"
        >
          Purchase Credits
        </Button>
      </div>

      {showPurchaseModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-slate-200 flex items-center justify-between sticky top-0 bg-white">
              <h2 className="text-2xl font-bold text-slate-900">Purchase Credits</h2>
              <button
                onClick={() => setShowPurchaseModal(false)}
                className="p-2 hover:bg-slate-100 rounded-lg transition-colors"
              >
                <X size={20} />
              </button>
            </div>

            <div className="p-6 space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {[
                  { id: 'starter', credits: 1000, price: 10, popular: false },
                  { id: 'growth', credits: 5000, price: 40, popular: true },
                  { id: 'scale', credits: 15000, price: 100, popular: false },
                ].map((pkg) => (
                  <div
                    key={pkg.id}
                    className={`border-2 rounded-xl p-6 cursor-pointer transition-all ${
                      selectedPackage === pkg.id
                        ? 'border-blue-500 bg-blue-50'
                        : 'border-slate-200 hover:border-blue-200'
                    } ${pkg.popular ? 'ring-2 ring-blue-500 ring-offset-2' : ''}`}
                    onClick={() => setSelectedPackage(pkg.id)}
                  >
                    {pkg.popular && (
                      <div className="text-xs font-semibold text-blue-600 mb-2">MOST POPULAR</div>
                    )}
                    <div className="text-3xl font-bold text-slate-900 mb-1">
                      {pkg.credits.toLocaleString()}
                    </div>
                    <div className="text-sm text-slate-500 mb-4">credits</div>
                    <div className="text-2xl font-bold text-slate-900 mb-1">${pkg.price}</div>
                    <div className="text-xs text-slate-500">
                      ${(pkg.price / pkg.credits * 1000).toFixed(2)} per 1k credits
                    </div>
                  </div>
                ))}
              </div>

              <div className="bg-slate-50 rounded-lg p-4">
                <h3 className="font-semibold text-slate-900 mb-2">What you get:</h3>
                <ul className="space-y-2 text-sm text-slate-600">
                  <li className="flex items-center gap-2">
                    <Zap size={14} className="text-blue-600" />
                    Credits never expire
                  </li>
                  <li className="flex items-center gap-2">
                    <Zap size={14} className="text-blue-600" />
                    Use across all security scans
                  </li>
                  <li className="flex items-center gap-2">
                    <Zap size={14} className="text-blue-600" />
                    Priority support included
                  </li>
                </ul>
              </div>

              <div className="flex gap-3">
                <Button
                  variant="secondary"
                  onClick={() => setShowPurchaseModal(false)}
                  className="flex-1"
                >
                  Cancel
                </Button>
                <Button
                  variant="primary"
                  onClick={() => selectedPackage && handlePurchase(selectedPackage)}
                  disabled={!selectedPackage}
                  className="flex-1"
                >
                  Purchase Credits
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
