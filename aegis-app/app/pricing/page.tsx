'use client';

import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Check, X, Calculator, ArrowRight, Zap, Shield, Users, Crown } from 'lucide-react';
import Link from 'next/link';
import { Nav } from '@/components/layout/Nav';
import { Footer } from '@/components/layout/Footer';
import { Button } from '@/components/ui/Button';

const fadeInUp = {
  hidden: { opacity: 0, y: 20 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.5 } },
};

export default function PricingPage() {
  const [testsPerMonth, setTestsPerMonth] = useState(50);
  const [agentsCount, setAgentsCount] = useState(1);

  // Estimate average 10 credits per test
  const estimatedCredits = testsPerMonth * agentsCount * 10;

  const getRecommendedPlan = () => {
    if (estimatedCredits <= 500) return 'Starter';
    if (estimatedCredits <= 2500) return 'Professional';
    if (estimatedCredits <= 10000) return 'Team';
    return 'Enterprise';
  };

  return (
    <>
      <Nav />
      <main className="pt-32 pb-24">
        {/* HEADER */}
        <div className="max-w-[1120px] mx-auto px-6 text-center mb-16">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
          >
            <h1 className="text-4xl md:text-5xl font-bold text-slate-900 mb-4">
              Pay only for what you use
            </h1>
            <p className="text-lg text-slate-500 max-w-2xl mx-auto">
              Credit-based pricing that scales with your testing needs. Start free, upgrade anytime.
            </p>
          </motion.div>
        </div>

        {/* PRICING TIERS */}
        <div className="max-w-[1120px] mx-auto px-6 mb-20">
          <div className="grid md:grid-cols-4 gap-6">
            {[
              {
                name: 'Starter',
                icon: Zap,
                price: 'Free',
                priceDetail: '',
                credits: '100 credits',
                creditsDetail: 'One-time',
                desc: 'Perfect for trying out the platform',
                features: [
                  '100 free credits',
                  'Access to all test types',
                  'Basic reporting',
                  'Community support',
                  '7-day result retention',
                ],
                cta: 'Get Started Free',
                ctaLink: '/sign-up',
                highlight: false,
              },
              {
                name: 'Professional',
                icon: Shield,
                price: '$49',
                priceDetail: '/month',
                credits: '500 credits',
                creditsDetail: 'per month',
                desc: 'For individual developers and small teams',
                features: [
                  '500 credits/month',
                  'Rollover unused credits',
                  'Advanced reporting',
                  'Email support',
                  '30-day result retention',
                  'Jira/Linear integration',
                ],
                cta: 'Start Free Trial',
                ctaLink: '/sign-up',
                highlight: true,
              },
              {
                name: 'Team',
                icon: Users,
                price: '$199',
                priceDetail: '/month',
                credits: '2,500 credits',
                creditsDetail: 'per month',
                desc: 'For teams running continuous testing',
                features: [
                  '2,500 credits/month',
                  'Unlimited team members',
                  'Priority support',
                  'Custom integrations',
                  '90-day result retention',
                  'Scheduled scans',
                  'API access',
                ],
                cta: 'Start Free Trial',
                ctaLink: '/sign-up',
                highlight: false,
              },
              {
                name: 'Enterprise',
                icon: Crown,
                price: 'Custom',
                priceDetail: '',
                credits: 'Unlimited',
                creditsDetail: 'credits',
                desc: 'For organizations with advanced needs',
                features: [
                  'Custom credit allocation',
                  'Self-hosted option',
                  'Dedicated support',
                  'SLA guarantees',
                  'Unlimited retention',
                  'Custom threat modeling',
                  'Hands-on remediation',
                ],
                cta: 'Contact Sales',
                ctaLink: '/contact',
                highlight: false,
              },
            ].map((plan, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.1 }}
                className={`p-6 rounded-2xl border relative ${
                  plan.highlight
                    ? 'border-blue-500 bg-gradient-to-br from-blue-50 to-white ring-2 ring-blue-200 shadow-xl -translate-y-2'
                    : 'border-slate-200 bg-white hover:border-blue-200 hover:shadow-lg transition-all'
                }`}
              >
                {plan.highlight && (
                  <div className="absolute -top-4 left-1/2 -translate-x-1/2 bg-blue-600 text-white px-4 py-1 rounded-full text-xs font-bold">
                    MOST POPULAR
                  </div>
                )}
                <div className="flex items-center gap-3 mb-4">
                  <div
                    className={`p-2 rounded-lg ${
                      plan.highlight ? 'bg-blue-600 text-white' : 'bg-slate-100 text-slate-600'
                    }`}
                  >
                    <plan.icon size={20} />
                  </div>
                  <h3 className="font-bold text-slate-900 text-lg">{plan.name}</h3>
                </div>
                <div className="mb-2">
                  <span className="text-4xl font-bold text-slate-900">{plan.price}</span>
                  <span className="text-slate-500 ml-1">{plan.priceDetail}</span>
                </div>
                <div className="mb-4">
                  <span className="text-sm font-semibold text-blue-600">{plan.credits}</span>
                  <span className="text-sm text-slate-500"> {plan.creditsDetail}</span>
                </div>
                <p className="text-sm text-slate-500 mb-6">{plan.desc}</p>
                <Link href={plan.ctaLink}>
                  <Button
                    variant={plan.highlight ? 'primary' : 'secondary'}
                    className="w-full mb-6 h-11"
                  >
                    {plan.cta}
                  </Button>
                </Link>
                <ul className="space-y-3">
                  {plan.features.map((f, idx) => (
                    <li key={idx} className="flex items-start gap-2 text-sm text-slate-700">
                      <Check size={16} className="text-blue-600 mt-0.5 shrink-0" />
                      <span>{f}</span>
                    </li>
                  ))}
                </ul>
              </motion.div>
            ))}
          </div>
        </div>

        {/* CREDITS CALCULATOR */}
        <div className="max-w-[800px] mx-auto px-6 mb-20">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="bg-gradient-to-br from-slate-50 to-blue-50/30 rounded-2xl border border-slate-200 p-8"
          >
            <div className="flex items-center gap-3 mb-6">
              <div className="p-3 bg-blue-600 rounded-xl text-white">
                <Calculator size={24} />
              </div>
              <div>
                <h2 className="text-2xl font-bold text-slate-900">Credits Calculator</h2>
                <p className="text-slate-500">Estimate your monthly credit usage</p>
              </div>
            </div>

            <div className="space-y-6 mb-6">
              <div>
                <label className="block text-sm font-semibold text-slate-700 mb-3">
                  How many tests will you run per month?
                </label>
                <input
                  type="range"
                  min="10"
                  max="500"
                  step="10"
                  value={testsPerMonth}
                  onChange={(e) => setTestsPerMonth(parseInt(e.target.value))}
                  className="w-full h-2 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-blue-600"
                />
                <div className="flex justify-between mt-2 text-sm text-slate-500">
                  <span>10</span>
                  <span className="font-bold text-blue-600">{testsPerMonth} tests</span>
                  <span>500</span>
                </div>
              </div>

              <div>
                <label className="block text-sm font-semibold text-slate-700 mb-3">
                  How many agents will you test?
                </label>
                <input
                  type="range"
                  min="1"
                  max="20"
                  step="1"
                  value={agentsCount}
                  onChange={(e) => setAgentsCount(parseInt(e.target.value))}
                  className="w-full h-2 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-blue-600"
                />
                <div className="flex justify-between mt-2 text-sm text-slate-500">
                  <span>1</span>
                  <span className="font-bold text-blue-600">{agentsCount} agents</span>
                  <span>20</span>
                </div>
              </div>
            </div>

            <div className="bg-white rounded-xl border border-slate-200 p-6">
              <div className="flex justify-between items-center mb-4">
                <span className="text-slate-600">Estimated monthly credits needed:</span>
                <span className="text-3xl font-bold text-blue-600">{estimatedCredits.toLocaleString()}</span>
              </div>
              <div className="flex justify-between items-center p-4 bg-blue-50 rounded-lg border border-blue-100">
                <span className="font-semibold text-slate-900">Recommended plan:</span>
                <span className="text-xl font-bold text-blue-600">{getRecommendedPlan()}</span>
              </div>
              <p className="text-xs text-slate-500 mt-3">
                * Based on average of 10 credits per test. Actual usage may vary based on test complexity.
              </p>
            </div>

            <div className="mt-6 text-center">
              <Link href="/pricing/tools">
                <button className="text-blue-600 hover:text-blue-700 font-medium inline-flex items-center gap-2">
                  View detailed credit costs by tool <ArrowRight size={16} />
                </button>
              </Link>
            </div>
          </motion.div>
        </div>

        {/* CREDIT COSTS BY CATEGORY */}
        <div className="max-w-[1120px] mx-auto px-6 mb-20">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="text-center mb-12"
          >
            <h2 className="text-3xl font-bold text-slate-900 mb-4">Credit costs by category</h2>
            <p className="text-slate-500">
              Transparent pricing for every type of security test
            </p>
          </motion.div>

          <div className="grid md:grid-cols-3 gap-6">
            {[
              {
                category: 'AI Testing',
                range: '1-10 credits',
                desc: 'Prompt injection, jailbreaks, goal hijacking',
                examples: ['Basic prompt injection: 1-2 credits', 'Advanced jailbreak: 5-10 credits'],
              },
              {
                category: 'Reconnaissance',
                range: '2-8 credits',
                desc: 'Data extraction, PII leakage, context probing',
                examples: ['Simple data probe: 2-3 credits', 'Deep context analysis: 5-8 credits'],
              },
              {
                category: 'Vulnerability Scanning',
                range: '5-50 credits',
                desc: 'Tool misuse, permission bypass, API testing',
                examples: ['Single tool test: 5-10 credits', 'Full vulnerability scan: 30-50 credits'],
              },
            ].map((item, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.1 }}
                className="bg-white rounded-2xl border border-slate-200 p-6 hover:border-blue-200 hover:shadow-lg transition-all"
              >
                <h3 className="text-xl font-bold text-slate-900 mb-2">{item.category}</h3>
                <div className="text-2xl font-bold text-blue-600 mb-3">{item.range}</div>
                <p className="text-slate-500 text-sm mb-4">{item.desc}</p>
                <ul className="space-y-2">
                  {item.examples.map((ex, idx) => (
                    <li key={idx} className="text-sm text-slate-600 flex items-start gap-2">
                      <span className="text-blue-600 mt-0.5">•</span> {ex}
                    </li>
                  ))}
                </ul>
              </motion.div>
            ))}
          </div>

          <div className="text-center mt-8">
            <Link href="/pricing/tools">
              <Button variant="secondary">
                See all tools and pricing <ArrowRight size={16} className="ml-2" />
              </Button>
            </Link>
          </div>
        </div>

        {/* COMPARISON TABLE */}
        <div className="max-w-[1120px] mx-auto px-6 mb-20">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="text-center mb-12"
          >
            <h2 className="text-3xl font-bold text-slate-900 mb-4">Feature comparison</h2>
          </motion.div>

          <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="bg-slate-50 border-b border-slate-200">
                    <th className="text-left p-4 font-semibold text-slate-900">Feature</th>
                    <th className="text-center p-4 font-semibold text-slate-900">Starter</th>
                    <th className="text-center p-4 font-semibold text-slate-900 bg-blue-50">Professional</th>
                    <th className="text-center p-4 font-semibold text-slate-900">Team</th>
                    <th className="text-center p-4 font-semibold text-slate-900">Enterprise</th>
                  </tr>
                </thead>
                <tbody>
                  {[
                    { feature: 'Monthly credits', starter: '100', pro: '500', team: '2,500', enterprise: 'Custom' },
                    { feature: 'Credit rollover', starter: false, pro: true, team: true, enterprise: true },
                    { feature: 'Team members', starter: '1', pro: '3', team: 'Unlimited', enterprise: 'Unlimited' },
                    { feature: 'Result retention', starter: '7 days', pro: '30 days', team: '90 days', enterprise: 'Unlimited' },
                    { feature: 'API access', starter: false, pro: false, team: true, enterprise: true },
                    { feature: 'Scheduled scans', starter: false, pro: false, team: true, enterprise: true },
                    { feature: 'Custom integrations', starter: false, pro: false, team: true, enterprise: true },
                    { feature: 'Self-hosted option', starter: false, pro: false, team: false, enterprise: true },
                    { feature: 'SLA guarantee', starter: false, pro: false, team: false, enterprise: true },
                    { feature: 'Support', starter: 'Community', pro: 'Email', team: 'Priority', enterprise: 'Dedicated' },
                  ].map((row, i) => (
                    <tr key={i} className="border-b border-slate-100 hover:bg-slate-50/50">
                      <td className="p-4 font-medium text-slate-900">{row.feature}</td>
                      <td className="p-4 text-center text-slate-600">
                        {typeof row.starter === 'boolean' ? (
                          row.starter ? (
                            <Check size={20} className="inline text-blue-600" />
                          ) : (
                            <X size={20} className="inline text-slate-300" />
                          )
                        ) : (
                          row.starter
                        )}
                      </td>
                      <td className="p-4 text-center text-slate-900 bg-blue-50/30">
                        {typeof row.pro === 'boolean' ? (
                          row.pro ? (
                            <Check size={20} className="inline text-blue-600" />
                          ) : (
                            <X size={20} className="inline text-slate-300" />
                          )
                        ) : (
                          row.pro
                        )}
                      </td>
                      <td className="p-4 text-center text-slate-600">
                        {typeof row.team === 'boolean' ? (
                          row.team ? (
                            <Check size={20} className="inline text-blue-600" />
                          ) : (
                            <X size={20} className="inline text-slate-300" />
                          )
                        ) : (
                          row.team
                        )}
                      </td>
                      <td className="p-4 text-center text-slate-600">
                        {typeof row.enterprise === 'boolean' ? (
                          row.enterprise ? (
                            <Check size={20} className="inline text-blue-600" />
                          ) : (
                            <X size={20} className="inline text-slate-300" />
                          )
                        ) : (
                          row.enterprise
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* FAQ */}
        <div className="max-w-[800px] mx-auto px-6 mb-20">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="text-center mb-12"
          >
            <h2 className="text-3xl font-bold text-slate-900">Pricing FAQs</h2>
          </motion.div>

          <div className="space-y-4">
            {[
              {
                q: 'Can I buy additional credits?',
                a: 'Yes! You can purchase credit top-ups at any time. Credit packs start at $25 for 100 credits.',
              },
              {
                q: 'What happens to unused credits?',
                a: 'On Professional, Team, and Enterprise plans, unused credits roll over to the next month. Starter plan credits do not roll over.',
              },
              {
                q: 'Can I change plans anytime?',
                a: 'Yes, you can upgrade or downgrade at any time. Changes take effect immediately, and we prorate the billing.',
              },
              {
                q: 'Do you offer refunds?',
                a: 'We offer a 30-day money-back guarantee on all paid plans. If you are not satisfied, contact us for a full refund.',
              },
            ].map((faq, i) => (
              <motion.details
                key={i}
                initial={{ opacity: 0, y: 10 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.1 }}
                className="group bg-white rounded-xl border border-slate-200 open:border-blue-200 open:ring-1 open:ring-blue-100"
              >
                <summary className="flex items-center justify-between p-6 cursor-pointer list-none font-medium text-slate-900 hover:text-blue-600">
                  {faq.q}
                  <span className="transition-transform duration-300 group-open:rotate-180">▼</span>
                </summary>
                <div className="px-6 pb-6 text-slate-600 leading-relaxed">{faq.a}</div>
              </motion.details>
            ))}
          </div>
        </div>

        {/* CTA */}
        <div className="max-w-[1120px] mx-auto px-6">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            whileInView={{ opacity: 1, scale: 1 }}
            viewport={{ once: true }}
            className="bg-gradient-to-br from-blue-600 to-blue-700 rounded-2xl p-12 text-center text-white"
          >
            <h2 className="text-3xl font-bold mb-4">Ready to secure your AI agents?</h2>
            <p className="text-blue-50 mb-8 max-w-2xl mx-auto">
              Start with 100 free credits. No credit card required.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <Link href="/sign-up">
                <Button variant="primary" className="bg-white text-blue-600 hover:bg-blue-50 px-8 py-3">
                  Get Started Free
                </Button>
              </Link>
              <Link href="/contact">
                <button className="h-12 px-8 rounded-[10px] bg-white/10 text-white font-medium hover:bg-white/20 transition-colors border border-white/20">
                  Contact Sales
                </button>
              </Link>
            </div>
          </motion.div>
        </div>
      </main>
      <Footer />
    </>
  );
}
