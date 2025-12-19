'use client';

import React from 'react';
import { Zap } from 'lucide-react';
import { Button } from '@/components/ui/Button';

interface CreditDisplayProps {
  credits: number;
  onPurchase?: () => void;
}

export const CreditDisplay: React.FC<CreditDisplayProps> = ({ credits, onPurchase }) => {
  return (
    <div className="bg-gradient-to-br from-blue-500 to-blue-600 rounded-2xl p-6 text-white">
      <div className="flex items-center gap-3 mb-4">
        <div className="w-10 h-10 bg-white/20 rounded-lg flex items-center justify-center">
          <Zap size={20} className="text-white" />
        </div>
        <div>
          <p className="text-xs text-blue-100 uppercase tracking-wider">Available Credits</p>
          <p className="text-3xl font-bold">{credits.toLocaleString()}</p>
        </div>
      </div>
      <p className="text-sm text-blue-100 mb-4">
        Use credits to run security scans and access premium features.
      </p>
      {onPurchase && (
        <Button
          onClick={onPurchase}
          className="bg-white text-blue-600 hover:bg-blue-50 w-full"
        >
          Purchase Credits
        </Button>
      )}
    </div>
  );
};
