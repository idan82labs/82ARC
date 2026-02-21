# Aegis Security Platform

**Stress-test your AI agents before attackers do.**

Aegis is an enterprise-grade security testing platform for AI agents. We provide permissioned red-teaming assessments that uncover prompt injection, data leakage, and tool misuse vulnerabilities—then deliver actionable fixes and regression test suites.

## Features

- **Automated Scanning**: High-volume probe generation targeting system prompts
- **Manual Red Teaming**: Expert human validation for complex multi-step attacks
- **Prompt Injection Detection**: Identify hijacking and jailbreaking vectors
- **Data Leakage Testing**: Uncover PII extraction and RAG poisoning risks
- **Tool Misuse Assessment**: Test agent privilege escalation and parameter tampering
- **Regression Testing**: Integrated CI/CD test suites to prevent recurrence
- **RAG Evaluation**: Assess retrieval mechanisms for injected malicious content
- **Risk Scoring**: Impact-based severity ratings for findings

## Tech Stack

- **React 18** - UI framework
- **Framer Motion** - Advanced animations
- **Tailwind CSS** - Styling
- **Lucide React** - Icons
- **Vite** - Build tooling

## Getting Started

### Prerequisites

- Node.js 16+ 
- npm or yarn

### Installation

```bash
git clone https://github.com/aegis-security/aegis-platform.git
cd aegis-security
npm install
```

### Development

```bash
npm run dev
```

Opens at `http://localhost:5173`

### Production Build

```bash
npm run build
npm run preview
```

## Project Structure

```
aegis-security/
├── AegisApp.jsx          # Main React application
├── package.json          # Dependencies
├── .gitignore           # Git exclusions
├── README.md            # This file
├── tailwind.config.js   # Tailwind configuration
├── vite.config.js       # Vite configuration
└── public/              # Static assets
```

## Components

### Pages
- **HomePage**: Hero, risk scorecard, testing coverage, methodology timeline, FAQ
- **ProductPage**: Capabilities and deliverables showcase
- **MethodologyPage**: Four-stage security assessment process with visualizations
- **SolutionsPage**: Industry-specific threat modeling (Fintech, Healthcare, Enterprise SaaS)
- **PricingPage**: Engagement models (Spot, Continuous, Enterprise)
- **ContactPage**: Assessment request form

### Interactive Elements
- **AttackSimulation**: Live demo of prompt injection attack scenario
- **ScanVisual**: Animated attack surface mapping visualization
- **ThreatVisual**: Threat model diagram
- **AttackVisual**: Terminal-style attack sequence
- **ReportVisual**: Animated security report mockup
- **SplashScreen**: Loading animation with progress tracking

## Key Features

### Risk Scorecard
Expandable security findings organized by threat category:
- Prompt Injection (Critical)
- Data Leakage (High)
- Tool Misuse (Medium)

### Timeline Engagement Model
Four-phase assessment with detailed phase descriptions:
1. Scope & Authorization
2. Test & Observe
3. Report & Readout
4. Fix Validation

### Mobile Responsive
- Sticky navigation bar with scroll behavior
- Responsive grid layouts
- Mobile menu with smooth animations
- Touch-friendly buttons and forms

## Customization

### Colors
Update the `COLORS` object in `AegisApp.jsx`:

```javascript
const COLORS = {
  primary: "bg-blue-600",
  secondary: "bg-white",
  // ... more colors
};
```

### Content
Edit page content directly in page components:
- `HomePage`: Hero copy, scorecard items, timeline steps
- `ProductPage`: Feature descriptions
- `MethodologyPage`: Process steps
- `SolutionsPage`: Industry vertical messaging
- `PricingPage`: Plans and features
- `ContactPage`: Form fields

### Animations
Framer Motion variants control all animations:
```javascript
const pageVariants = {
  initial: { opacity: 0, y: 10 },
  animate: { opacity: 1, y: 0, transition: { duration: 0.4 } },
};
```

## Configuration Files

### `tailwind.config.js`
Tailwind CSS customization (if present)

### `vite.config.js`
Vite build configuration (if present)

## Performance Optimizations

- Motion animations use GPU-accelerated transforms
- Lazy loading for images and components
- Optimized bundle size with tree-shaking
- Code splitting by page route

## Browser Support

- Chrome/Edge 90+
- Firefox 88+
- Safari 14+
- Mobile browsers (iOS Safari, Chrome Mobile)

## Deployment

### Vercel
```bash
vercel
```

### Netlify
```bash
netlify deploy --prod --dir=dist
```

### Docker
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build
EXPOSE 5173
CMD ["npm", "run", "preview"]
```

## Contributing

1. Clone the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License - see LICENSE file for details

## Support

- **Documentation**: See `/docs` folder
- **Issues**: GitHub Issues
- **Security**: Report to security@aegis.com

## Contact

- **Website**: https://aegis.com
- **Email**: hello@aegis.com
- **LinkedIn**: https://linkedin.com/company/aegis-security

---

**v2.4.0-security_preview**

Built with React, Framer Motion, and Tailwind CSS.
