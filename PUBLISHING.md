# Publishing to PyPI (Recommended Method)

## Overview

This project uses **GitHub Actions with Trusted Publishers (OIDC)** for automated publishing.

**✅ NO CREDENTIALS NEEDED** - No API tokens required!

---

## One-Time Setup (5 minutes)

### Step 1: Configure Trusted Publishers

#### On TestPyPI (for testing):
1. Go to: https://test.pypi.org/manage/account/publishing/
2. Scroll to **"Add a new pending publisher"**
3. Fill in:
   - **PyPI Project Name:** `pysigma-backend-sumologic`
   - **Owner:** `SumoLogic`
   - **Repository name:** `pySigma-backend-sumologic`
   - **Workflow name:** `release.yml`
   - **Environment name:** `release`
4. Click **"Add"**

#### On Production PyPI:
1. Go to: https://pypi.org/manage/account/publishing/
2. Repeat the same configuration as above

### Step 2: Configure GitHub Environment

1. Go to: https://github.com/SumoLogic/pySigma-backend-sumologic/settings/environments
2. Click **"New environment"**
3. Name it: `release`
4. Click **"Configure environment"**
5. (Optional) Add protection rules:
   - ✅ Required reviewers
   - ✅ Branch protection (main only)

**Setup Complete!** No API tokens needed.

---

## Publishing Process

### Publishing to TestPyPI

```bash
# 1. Ensure version is correct in pyproject.toml
poetry version  # Shows current version, e.g., 0.1.0

# 2. Run tests
poetry run pytest -vv

# 3. Create and push version tag
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

**What happens automatically:**
- ✅ GitHub Actions workflow runs
- ✅ Tests execute
- ✅ Package builds
- ✅ Publishes to **TestPyPI**

**Monitor:** https://github.com/SumoLogic/pySigma-backend-sumologic/actions

### Testing from TestPyPI

```bash
# Install from TestPyPI
pip install --index-url https://test.pypi.org/simple/ \
            --extra-index-url https://pypi.org/simple/ \
            pysigma-backend-sumologic==0.1.0

# Verify it works
python -c "from sigma.backends.sumologic import SumoLogicBackend; print('Success!')"

# Test with Sigma CLI
sigma convert -t sumologic-cse-rule -p sumologic_cse your_rule.yml
```

### Publishing to Production PyPI

After testing on TestPyPI, create a GitHub release:

1. Go to: https://github.com/SumoLogic/pySigma-backend-sumologic/releases
2. Click **"Draft a new release"**
3. **Choose existing tag:** `v0.1.0`
4. Add release notes (describe changes)
5. Click **"Publish release"**

**What happens automatically:**
- ✅ GitHub Actions workflow runs
- ✅ Tests execute
- ✅ Package builds
- ✅ Publishes to **Production PyPI**

---

## Version Management

```bash
# Patch release (0.1.0 → 0.1.1) - bug fixes
poetry version patch

# Minor release (0.1.0 → 0.2.0) - new features
poetry version minor

# Major release (0.1.0 → 1.0.0) - breaking changes
poetry version major

# After bumping version:
git add pyproject.toml
git commit -m "Bump version to $(poetry version -s)"
git push
```

---

## How Trusted Publishers Work

```
┌──────────────────┐
│ Push tag v0.1.0  │
└────────┬─────────┘
         │
         ▼
┌──────────────────────────────┐
│ GitHub Actions Workflow      │
│  1. Run tests                │
│  2. Build package            │
│  3. Request OIDC token       │
└────────┬─────────────────────┘
         │
         ▼
┌──────────────────────────────┐
│ GitHub issues OIDC token     │
│ (contains repo, workflow     │
│  environment info)           │
└────────┬─────────────────────┘
         │
         ▼
┌──────────────────────────────┐
│ PyPI validates OIDC token    │
│ against trusted publisher    │
│ configuration                │
└────────┬─────────────────────┘
         │
         ▼
┌──────────────────────────────┐
│ PyPI issues short-lived      │
│ API token (15 minutes)       │
└────────┬─────────────────────┘
         │
         ▼
┌──────────────────────────────┐
│ Package published to PyPI ✓  │
└──────────────────────────────┘
```

**Security Benefits:**
- 🔒 No long-lived API tokens
- 🔒 No secrets stored in GitHub
- 🔒 Automatic credential rotation
- 🔒 Verified publisher identity

---

## Pre-Release Checklist

- [ ] All tests pass: `poetry run pytest -vv`
- [ ] Version bumped in `pyproject.toml`
- [ ] Changes committed and pushed to `main`
- [ ] Trusted publishers configured on PyPI/TestPyPI
- [ ] GitHub environment `release` exists

---

## Troubleshooting

### "Environment 'release' not found"
**Solution:** Create environment in GitHub repo Settings → Environments → New → `release`

### "Trusted publisher configuration not found"
**Solution:** Add publisher at https://test.pypi.org/manage/account/publishing/ with exact configuration:
- Owner: `SumoLogic`
- Repository: `pySigma-backend-sumologic`
- Workflow: `release.yml`
- Environment: `release`

### "Version X.Y.Z already exists"
**Solution:** Bump version with `poetry version patch` and create new tag

### Tests fail during workflow
**Solution:** 
1. Fix tests locally: `poetry run pytest -vv`
2. Delete tag: `git tag -d v0.1.0 && git push origin :refs/tags/v0.1.0`
3. Create new tag after fixes

---

## Quick Reference

```bash
# Check current version
poetry version

# Bump version
poetry version patch

# Run tests
poetry run pytest -vv

# Tag and trigger TestPyPI release
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0

# After testing, create GitHub release to publish to PyPI
# (via web UI at github.com/.../releases)
```

---

## Resources

- **PyPI Trusted Publishers:** https://docs.pypi.org/trusted-publishers/
- **SigmaHQ Template:** https://github.com/SigmaHQ/cookiecutter-pySigma-backend
- **GitHub Environments:** https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment
