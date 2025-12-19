# How to Push to GitHub

Your repo is ready locally. Follow these steps to push to GitHub:

## Step 1: Create a GitHub Repository
1. Go to https://github.com/new
2. Name it: `aegis-security`
3. DO NOT initialize with README, .gitignore, or license (we already have these)
4. Click "Create repository"

## Step 2: Add Remote & Push

Copy the HTTPS or SSH URL from GitHub, then run:

**Using HTTPS (recommended for first-time):**
```bash
cd /home/claude/aegis-security
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/aegis-security.git
git push -u origin main
```

**Using SSH (if you have SSH keys configured):**
```bash
git branch -M main
git remote add origin git@github.com:YOUR_USERNAME/aegis-security.git
git push -u origin main
```

## Step 3: Verify
- Visit https://github.com/YOUR_USERNAME/aegis-security
- You should see all 4 files: README.md, package.json, .gitignore, AegisApp.jsx

## Repository Info

**Current status:**
- Local repo initialized ✓
- Files staged and committed ✓
- Initial commit: `7e89d15`
- Branch: `master` (rename to `main` before pushing)

**Files included:**
- `AegisApp.jsx` (1842 lines) - Full React application
- `package.json` - Dependencies and scripts
- `.gitignore` - Standard Node.js ignores
- `README.md` - Complete documentation

## Optional: Additional Setup

After pushing, consider:

```bash
# Create development branch
git checkout -b develop
git push -u origin develop

# Add GitHub collaborators via Settings > Collaborators

# Enable GitHub Pages (optional)
# Settings > Pages > Deploy from main branch > /root directory
```

## Environment Setup

To run locally after cloning:
```bash
npm install
npm run dev    # Development server
npm run build  # Production build
npm run lint   # Check code
```

**Note:** Replace `YOUR_USERNAME` with your actual GitHub username.
