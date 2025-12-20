'use client';

import React from 'react';
import { motion } from 'framer-motion';
import { Search, Terminal, Activity, Database, Lock, Plug } from 'lucide-react';
import { Nav } from '@/components/layout/Nav';
import { Footer } from '@/components/layout/Footer';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';

export default function ProductPage() {
  return (
    <>
      <Nav />
      <main className="pt-32 pb-24 max-w-[1120px] mx-auto px-6">
        <div className="text-center max-w-3xl mx-auto mb-16">
          <Badge color="blue">Capabilities</Badge>
          <h1 className="text-4xl md:text-5xl font-bold text-slate-900 mt-6 mb-6">
            Agent Security Testing, <br />
            end to end.
          </h1>
          <p className="text-xl text-slate-500">
            From initial automated scan to manual red-teaming and continuous regression testing.
          </p>
        </div>

        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8 mb-24">
          {[
            {
              title: 'Automated Scanning',
              icon: Search,
              desc: 'High-volume probe generation to find weak spots in system prompts.',
            },
            {
              title: 'Manual Red Teaming',
              icon: Terminal,
              desc: 'Expert human validation for complex, multi-step logic attacks.',
            },
            {
              title: 'Regression Suite',
              icon: Activity,
              desc: 'Turn findings into automated tests that run on every PR.',
            },
            {
              title: 'RAG Evaluation',
              icon: Database,
              desc: 'Assess retrieval mechanisms for poisonous content injection.',
            },
            {
              title: 'Privilege Mapping',
              icon: Lock,
              desc: 'Visualize and restrict what tools your agent can access.',
            },
            {
              title: 'Integrations',
              icon: Plug,
              desc: 'Connects with GitHub, Jira, and Linear for seamless workflows.',
            },
          ].map((item, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.1 }}
              className="bg-white p-8 rounded-2xl border border-slate-200 shadow-sm hover:shadow-md transition-shadow"
            >
              <item.icon className="text-blue-600 mb-4" size={32} />
              <h3 className="text-xl font-bold text-slate-900 mb-2">{item.title}</h3>
              <p className="text-slate-500">{item.desc}</p>
            </motion.div>
          ))}
        </div>

        <div className="bg-slate-50 rounded-2xl p-12 text-center">
          <h3 className="text-2xl font-bold text-slate-900 mb-4">Sample Deliverables</h3>
          <p className="text-slate-500 mb-8">
            See exactly what you get when you work with Aegis.
          </p>
          <Button variant="secondary">Download Sample Report (PDF)</Button>
        </div>
      </main>
      <Footer />
    </>
  );
}
