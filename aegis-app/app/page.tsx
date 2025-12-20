'use client';

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield,
  ChevronDown,
  Check,
  ArrowRight,
  Activity,
  Lock,
  AlertTriangle,
  Database,
  Plug,
} from 'lucide-react';
import Link from 'next/link';
import { Nav } from '@/components/layout/Nav';
import { Footer } from '@/components/layout/Footer';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { AttackSimulation } from '@/components/home/AttackSimulation';

const fadeInUp = {
  hidden: { opacity: 0, y: 20 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.5, ease: 'easeOut' } },
};

const staggerContainer = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.1,
      delayChildren: 0.1,
    },
  },
};

const cardHover = {
  rest: { scale: 1, y: 0 },
  hover: { scale: 1.01, y: -4, transition: { type: 'spring', stiffness: 300, damping: 20 } },
};

export default function HomePage() {
  const [scorecardExpanded, setScorecardExpanded] = useState('injection');

  const scrollToEvidence = () => {
    const element = document.getElementById('evidence');
    if (element) element.scrollIntoView({ behavior: 'smooth' });
  };

  const scorecardItems = [
    { id: 'injection', icon: Shield, title: 'Prompt Injection', risk: 'Critical', findings: 2 },
    { id: 'leakage', icon: Database, title: 'Data Leakage', risk: 'High', findings: 4 },
    { id: 'misuse', icon: Plug, title: 'Tool Misuse', risk: 'Medium', findings: 1 },
  ];

  return (
    <>
      <Nav />
      <main>
        {/* HERO SECTION */}
        <section className="relative pt-32 pb-24 overflow-hidden">
          {/* Background Network SVG */}
          <div className="absolute inset-0 z-0 opacity-[0.04] pointer-events-none">
            <svg width="100%" height="100%" xmlns="http://www.w3.org/2000/svg">
              <defs>
                <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                  <path d="M 40 0 L 0 0 0 40" fill="none" stroke="black" strokeWidth="0.5" />
                </pattern>
              </defs>
              <rect width="100%" height="100%" fill="url(#grid)" />
            </svg>
          </div>

          <div className="max-w-[1120px] mx-auto px-6 grid lg:grid-cols-2 gap-16 relative z-10 items-center">
            {/* Left Content */}
            <motion.div
              variants={staggerContainer}
              initial="hidden"
              animate="visible"
              className="space-y-8"
            >
              <motion.h1
                variants={fadeInUp}
                className="text-4xl md:text-6xl font-extrabold tracking-tight text-slate-900 leading-[1.05]"
              >
                Stress-test your <span className="text-blue-600">AI agents</span> before attackers
                do.
              </motion.h1>
              <motion.p
                variants={fadeInUp}
                className="text-lg md:text-xl text-slate-500 leading-relaxed max-w-lg"
              >
                Automated security testing platform that uncovers prompt injection, data leakage, and
                tool misuse. Get started in minutes with 100 free credits.
              </motion.p>
              <motion.div variants={fadeInUp} className="flex flex-col sm:flex-row gap-4">
                <Link href="/sign-up">
                  <Button variant="primary" className="text-base px-8 py-3">
                    Get Started Free
                  </Button>
                </Link>
                <Link href="/product">
                  <Button variant="secondary">View Sample Report</Button>
                </Link>
              </motion.div>
              <motion.p
                variants={fadeInUp}
                className="text-sm text-slate-400"
              >
                No credit card required • 100 free credits • Setup in 5 minutes
              </motion.p>
              <motion.p
                variants={fadeInUp}
                className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2"
              >
                <Lock size={12} /> Authorization-first. Evidence-driven.
              </motion.p>
            </motion.div>

            {/* Right Card: Risk Scorecard */}
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.6, delay: 0.2 }}
              className="bg-white rounded-2xl shadow-xl border border-slate-100 p-6 md:p-8 w-full"
            >
              <div className="flex justify-between items-start mb-6">
                <div>
                  <h3 className="font-bold text-slate-900 text-lg">AI Risk Scorecard</h3>
                  <p className="text-sm text-slate-500">Agent: Customer_Svc_v2</p>
                </div>
                <motion.div
                  animate={{ scale: [1, 1.05, 1] }}
                  transition={{ duration: 2, repeat: Infinity }}
                  className="bg-amber-50 text-amber-700 px-3 py-1 rounded-full text-sm font-bold border border-amber-100 flex items-center gap-2"
                >
                  <div className="w-2 h-2 rounded-full bg-amber-500"></div>
                  7.7 High
                </motion.div>
              </div>

              <div className="space-y-3">
                {scorecardItems.map((item) => (
                  <div
                    key={item.id}
                    className="border border-slate-100 rounded-xl overflow-hidden transition-all duration-300"
                  >
                    <button
                      onClick={() =>
                        setScorecardExpanded(scorecardExpanded === item.id ? '' : item.id)
                      }
                      className={`w-full flex items-center justify-between p-4 bg-slate-50/50 hover:bg-slate-50 transition-colors ${
                        scorecardExpanded === item.id ? 'bg-slate-50' : ''
                      }`}
                    >
                      <div className="flex items-center gap-3">
                        <div
                          className={`p-2 rounded-lg ${
                            scorecardExpanded === item.id
                              ? 'bg-white shadow-sm text-blue-600'
                              : 'bg-transparent text-slate-400'
                          }`}
                        >
                          <item.icon size={18} />
                        </div>
                        <span className="font-semibold text-slate-700 text-sm">{item.title}</span>
                      </div>
                      <motion.div
                        animate={{ rotate: scorecardExpanded === item.id ? 180 : 0 }}
                        transition={{ duration: 0.3 }}
                      >
                        <ChevronDown size={16} className="text-slate-400" />
                      </motion.div>
                    </button>

                    {/* Expanded Content */}
                    <AnimatePresence>
                      {scorecardExpanded === item.id && (
                        <motion.div
                          initial={{ height: 0, opacity: 0 }}
                          animate={{ height: 'auto', opacity: 1 }}
                          exit={{ height: 0, opacity: 0 }}
                          transition={{ duration: 0.3, ease: 'easeInOut' }}
                          className="overflow-hidden"
                        >
                          <div className="p-4 pt-0 text-sm text-slate-600 bg-slate-50/50 border-t border-slate-100">
                            <ul className="space-y-2 mb-3">
                              <li className="flex items-start gap-2">
                                <AlertTriangle size={14} className="text-amber-500 mt-0.5 shrink-0" />
                                <span>Privilege escalation via tool parameter injection.</span>
                              </li>
                              <li className="flex items-start gap-2">
                                <AlertTriangle size={14} className="text-amber-500 mt-0.5 shrink-0" />
                                <span>Bypassed system prompt constraints.</span>
                              </li>
                            </ul>
                            <div className="flex items-center justify-between mt-3 pt-3 border-t border-slate-200/50">
                              <span className="text-xs text-slate-400 font-medium uppercase">
                                Severity: {item.risk}
                              </span>
                              <button
                                onClick={scrollToEvidence}
                                className="h-8 px-3 rounded-lg text-sm border border-slate-200 bg-white text-slate-600 hover:text-blue-600 hover:border-blue-200 transition-colors"
                              >
                                View Trace
                              </button>
                            </div>
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </div>
                ))}
              </div>
            </motion.div>
          </div>
        </section>

        {/* LOGOS */}
        <section className="py-8 border-y border-slate-100 bg-slate-50/50 overflow-x-hidden">
          <div className="max-w-[1120px] mx-auto px-6 text-center">
            <p className="text-sm font-semibold text-slate-400 mb-6 uppercase tracking-wider">
              Trusted by teams shipping secure AI agents
            </p>
            <motion.div
              initial="hidden"
              whileInView="visible"
              viewport={{ once: true }}
              variants={staggerContainer}
              className="flex flex-wrap justify-center gap-8 md:gap-16 opacity-60 grayscale"
            >
              {['FinTech.io', 'HealthPlus', 'DevTool', 'MARKETPLACE', 'LegalAI'].map((logo, i) => (
                <motion.span
                  key={i}
                  variants={fadeInUp}
                  className={`text-xl font-bold text-slate-600 ${
                    i % 2 === 0 ? 'font-serif' : 'font-sans'
                  }`}
                >
                  {logo}
                </motion.span>
              ))}
            </motion.div>
          </div>
        </section>

        {/* SOCIAL PROOF - TESTIMONIALS */}
        <section className="py-24 bg-white">
          <div className="max-w-[1120px] mx-auto px-6">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              className="text-center mb-16"
            >
              <h2 className="text-3xl font-bold text-slate-900 mb-4">
                What security teams are saying
              </h2>
            </motion.div>

            <motion.div
              variants={staggerContainer}
              initial="hidden"
              whileInView="visible"
              viewport={{ once: true }}
              className="grid md:grid-cols-3 gap-8"
            >
              {[
                {
                  quote:
                    'Found 3 critical prompt injection vulnerabilities in our customer service agent within the first hour. The reproduction steps were detailed enough that our dev team fixed them same-day.',
                  author: 'Sarah Chen',
                  role: 'Head of Security',
                  company: 'FinTech.io',
                },
                {
                  quote:
                    'The credit system is perfect for our CI/CD pipeline. We run regression tests on every PR for just a few credits each, catching issues before they reach production.',
                  author: 'Marcus Rodriguez',
                  role: 'VP Engineering',
                  company: 'DevTool',
                },
                {
                  quote:
                    'We were skeptical about automated security testing for LLMs, but the AI-powered discovery mode found attack vectors our pen testers missed. Game changer.',
                  author: 'Dr. Emily Watson',
                  role: 'Chief Information Security Officer',
                  company: 'HealthPlus',
                },
              ].map((testimonial, i) => (
                <motion.div
                  key={i}
                  variants={fadeInUp}
                  className="bg-slate-50 rounded-2xl p-8 border border-slate-100 hover:border-blue-200 hover:shadow-lg transition-all duration-300"
                >
                  <div className="mb-6">
                    <svg
                      className="w-10 h-10 text-blue-600 opacity-20"
                      fill="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path d="M14.017 21v-7.391c0-5.704 3.731-9.57 8.983-10.609l.995 2.151c-2.432.917-3.995 3.638-3.995 5.849h4v10h-9.983zm-14.017 0v-7.391c0-5.704 3.748-9.57 9-10.609l.996 2.151c-2.433.917-3.996 3.638-3.996 5.849h3.983v10h-9.983z" />
                    </svg>
                  </div>
                  <p className="text-slate-700 leading-relaxed mb-6 italic">{testimonial.quote}</p>
                  <div className="border-t border-slate-200 pt-4">
                    <p className="font-bold text-slate-900">{testimonial.author}</p>
                    <p className="text-sm text-slate-500">
                      {testimonial.role}, {testimonial.company}
                    </p>
                  </div>
                </motion.div>
              ))}
            </motion.div>
          </div>
        </section>

        {/* WHAT WE TEST */}
        <section className="py-24">
          <div className="max-w-[1120px] mx-auto px-6">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5 }}
              className="text-center mb-16"
            >
              <h2 className="text-3xl font-bold text-slate-900 mb-4">What we test</h2>
              <p className="text-slate-500 text-lg">
                Coverage aligned to real-world agent failure modes.
              </p>
            </motion.div>

            <motion.div
              variants={staggerContainer}
              initial="hidden"
              whileInView="visible"
              viewport={{ once: true }}
              className="grid md:grid-cols-3 gap-8"
            >
              {[
                {
                  icon: Shield,
                  title: 'Prompt Injection',
                  desc: 'Attacks that hijack agent control flow to execute unauthorized instructions.',
                  bullets: ['Indirect injection', 'Jailbreaking', 'Goal hijacking'],
                },
                {
                  icon: Database,
                  title: 'Data Leakage',
                  desc: 'Unintentional exposure of sensitive RAG data or session history.',
                  bullets: ['PII extraction', 'Cross-session memory leak', 'Verbatim training replay'],
                },
                {
                  icon: Plug,
                  title: 'Tool Misuse',
                  desc: 'Agents tricked into taking privileged actions via connected APIs.',
                  bullets: ['Excessive permissioning', 'Parameter tampering', 'Approval bypass'],
                },
              ].map((card, idx) => (
                <motion.div
                  key={idx}
                  variants={fadeInUp}
                  whileHover="hover"
                  initial="rest"
                  animate="rest"
                  className="group p-8 rounded-2xl bg-white border border-slate-200 hover:border-blue-200 hover:shadow-lg transition-colors duration-300"
                >
                  <motion.div
                    variants={cardHover}
                    className="w-12 h-12 bg-slate-50 rounded-xl flex items-center justify-center text-slate-600 mb-6 group-hover:bg-blue-50 group-hover:text-blue-600 transition-colors"
                  >
                    <card.icon size={24} />
                  </motion.div>
                  <h3 className="text-xl font-bold text-slate-900 mb-3">{card.title}</h3>
                  <p className="text-slate-500 mb-6 leading-relaxed">{card.desc}</p>
                  <ul className="space-y-2">
                    {card.bullets.map((b, i) => (
                      <li key={i} className="flex items-center gap-2 text-sm text-slate-600">
                        <Check size={14} className="text-blue-500" /> {b}
                      </li>
                    ))}
                  </ul>
                </motion.div>
              ))}
            </motion.div>
          </div>
        </section>

        {/* EVIDENCE SECTION */}
        <section
          id="evidence"
          className="py-24 bg-slate-900 text-white relative overflow-hidden"
        >
          <div className="max-w-[1120px] mx-auto px-6 relative z-10 grid lg:grid-cols-2 gap-12 items-center">
            {/* Left: Interactive Attack Simulation */}
            <motion.div
              initial={{ opacity: 0, x: -30 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.7 }}
            >
              <AttackSimulation />
            </motion.div>

            {/* Right: Copy */}
            <motion.div
              initial={{ opacity: 0, x: 30 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.7 }}
              className="space-y-6"
            >
              <h2 className="text-3xl font-bold">Evidence you can act on.</h2>
              <p className="text-slate-400 text-lg leading-relaxed">
                We don't just tell you there's a problem. We provide reproducible attack traces,
                risk scoring based on real impact, and regression tests to ensure the fix sticks.
              </p>
              <ul className="space-y-4">
                {[
                  'Complete prompt logs and chain-of-thought',
                  'Redacted sensitive data by default',
                  'Jira/Linear integration for one-click tickets',
                  'Regression pack for CI/CD',
                ].map((item, i) => (
                  <motion.li
                    key={i}
                    initial={{ opacity: 0, x: 20 }}
                    whileInView={{ opacity: 1, x: 0 }}
                    viewport={{ once: true }}
                    transition={{ delay: 0.1 * i }}
                    className="flex items-center gap-3 text-slate-300"
                  >
                    <div className="w-6 h-6 rounded-full bg-blue-500/20 flex items-center justify-center text-blue-400">
                      <Check size={14} />
                    </div>
                    {item}
                  </motion.li>
                ))}
              </ul>
              <div className="pt-4">
                <Link
                  href="/methodology"
                  className="text-blue-600 hover:underline font-medium inline-flex items-center gap-1 text-blue-400 hover:text-white"
                >
                  See how we score risks <ArrowRight size={16} />
                </Link>
              </div>
            </motion.div>
          </div>
        </section>

        {/* HOW IT WORKS */}
        <section className="py-24 bg-slate-50">
          <div className="max-w-[1120px] mx-auto px-6">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              className="text-center mb-16"
            >
              <h2 className="text-3xl font-bold text-slate-900 mb-4">
                How It Works
              </h2>
              <p className="text-slate-500 text-lg">
                Start testing your AI agents in three simple steps
              </p>
            </motion.div>

            <motion.div
              variants={staggerContainer}
              initial="hidden"
              whileInView="visible"
              viewport={{ once: true }}
              className="grid md:grid-cols-3 gap-12"
            >
              {[
                {
                  number: '1',
                  title: 'Connect Your Agent',
                  desc: 'Provide your API endpoint or agent configuration. We support OpenAI, Anthropic, custom frameworks, and more.',
                  icon: Plug,
                },
                {
                  number: '2',
                  title: 'Run Security Tests',
                  desc: 'Choose from 50+ attack patterns or let our AI discover vulnerabilities automatically. Each test uses credits based on complexity.',
                  icon: Shield,
                },
                {
                  number: '3',
                  title: 'Get Actionable Results',
                  desc: 'Review detailed findings with reproduction steps, severity scores, and recommended fixes. Export to Jira or Linear.',
                  icon: Activity,
                },
              ].map((step, i) => (
                <motion.div
                  key={i}
                  variants={fadeInUp}
                  className="relative flex flex-col items-center text-center"
                >
                  <div className="w-20 h-20 rounded-full bg-blue-600 text-white flex items-center justify-center text-3xl font-bold mb-6 shadow-lg shadow-blue-600/20">
                    {step.number}
                  </div>
                  <div className="mb-4 p-3 bg-white rounded-xl shadow-sm">
                    <step.icon size={28} className="text-blue-600" />
                  </div>
                  <h3 className="text-xl font-bold text-slate-900 mb-3">{step.title}</h3>
                  <p className="text-slate-500 leading-relaxed">{step.desc}</p>
                </motion.div>
              ))}
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: 0.4 }}
              className="text-center mt-12"
            >
              <Link href="/sign-up">
                <Button variant="primary" className="px-8 py-3">
                  Start Testing Now
                </Button>
              </Link>
            </motion.div>
          </div>
        </section>

        {/* FAQ */}
        <section className="py-24">
          <div className="max-w-[700px] mx-auto px-6">
            <motion.h2
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              className="text-3xl font-bold text-slate-900 mb-12 text-center"
            >
              Frequently Asked Questions
            </motion.h2>
            <div className="space-y-4">
              {[
                {
                  q: 'How does the credit system work?',
                  a: 'Each security test consumes credits based on complexity. Simple tests (like prompt injection) cost 1-5 credits, while comprehensive AI-powered scans cost 10-50 credits. You can see exact costs on the pricing page.',
                },
                {
                  q: 'What happens if I run out of credits?',
                  a: "You can purchase additional credits anytime or upgrade to a higher tier. Your account won't be charged automatically - you control when to add credits.",
                },
                {
                  q: 'Can I test in production?',
                  a: 'Yes, but we recommend testing in staging first. Our platform includes rate limiting and safety controls to prevent disrupting production systems.',
                },
                {
                  q: 'How do you handle sensitive data?',
                  a: 'All data is encrypted in transit and at rest. We redact PII automatically and never train models on your data. You can also use our self-hosted option for complete data isolation.',
                },
                {
                  q: 'What AI platforms do you support?',
                  a: 'We support OpenAI, Anthropic, Azure OpenAI, AWS Bedrock, Google Vertex AI, and custom frameworks via API. If your agent has an API endpoint, we can test it.',
                },
                {
                  q: 'Do you provide fixes?',
                  a: 'We provide detailed remediation guidance, including updated system prompts, input validation rules, and tool permission recommendations. For Enterprise plans, we offer hands-on implementation support.',
                },
              ].map((faq, i) => (
                <motion.details
                  key={i}
                  initial={{ opacity: 0, y: 10 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ delay: i * 0.1 }}
                  className="group bg-white rounded-xl border border-slate-200 open:border-blue-200 open:ring-1 open:ring-blue-100 transition-all"
                >
                  <summary className="flex items-center justify-between p-6 cursor-pointer list-none font-medium text-slate-900 group-hover:text-blue-600">
                    {faq.q}
                    <ChevronDown className="transition-transform duration-300 group-open:rotate-180 text-slate-400" />
                  </summary>
                  <div className="px-6 pb-6 text-slate-500 leading-relaxed">{faq.a}</div>
                </motion.details>
              ))}
            </div>
          </div>
        </section>

        {/* FINAL CTA */}
        <section className="py-24 px-6">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            whileInView={{ opacity: 1, scale: 1 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5 }}
            className="max-w-[1120px] mx-auto bg-gradient-to-br from-blue-600 to-blue-700 rounded-[32px] overflow-hidden relative text-center py-20 px-6 shadow-2xl shadow-blue-600/20"
          >
            <div className="absolute top-0 left-0 w-full h-full bg-blue-600/10 radial-gradient"></div>
            <div className="relative z-10 max-w-2xl mx-auto space-y-8">
              <h2 className="text-3xl md:text-5xl font-bold text-white">
                Start securing your AI agents today
              </h2>
              <p className="text-blue-50 text-lg">
                Get 100 free credits. No credit card required. Find vulnerabilities in minutes.
              </p>
              <div className="flex flex-col sm:flex-row justify-center gap-4">
                <Link href="/sign-up">
                  <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
                    <Button
                      variant="primary"
                      className="bg-white text-blue-600 hover:bg-blue-50 px-8 py-3 text-base shadow-lg"
                    >
                      Get Started Free
                    </Button>
                  </motion.div>
                </Link>
                <Link href="/pricing">
                  <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
                    <button className="h-12 px-8 rounded-[10px] bg-white/10 text-white font-medium hover:bg-white/20 transition-colors border border-white/20">
                      View Pricing
                    </button>
                  </motion.div>
                </Link>
              </div>
              <p className="text-sm text-blue-200">
                Join 500+ teams already testing with 82ARC
              </p>
            </div>
          </motion.div>
        </section>
      </main>
      <Footer />
    </>
  );
}
