# Publishing to PyPI (Recommended Method)

## Overview

This project uses **GitHub Actions with Trusted Publishers (OIDC)** for automated publishing.

**✅ NO CREDENTIALS NEEDED** - No API tokens required!

### Quick Navigation

| Task | Section |
|------|---------|
| **First-time setup** | [One-Time Setup](#one-time-setup-5-minutes) |
| **Complete first-time publish** | [Complete First-Time Publishing Workflow](#complete-first-time-publishing-workflow) |
| **Regular releases** | [Regular Release Process](#regular-release-process) |
| **Plugin registration** | [Plugin Directory Registration](#plugin-directory-registration) |
| **Version bumping** | [Version Management](#version-management) |
| **Troubleshooting** | [Troubleshooting](#troubleshooting) |

### Publishing Summary

| Environment | Purpose | Required? | When |
|-------------|---------|-----------|------|
| **TestPyPI** | Pre-release testing | Optional (recommended) | Before production release |
| **Production PyPI** | Public release | **Required** | After TestPyPI validation |
| **Plugin Directory** | Sigma-cli integration | Optional (recommended) | After production PyPI release |

**Key Points:**
- ✅ **TestPyPI** - Optional but recommended for testing before production
- ✅ **Production PyPI** - Required for public use
- ✅ **Plugin Directory** - Optional but recommended for community discovery and `sigma plugin install` support
- ✅ Users can install via `pip` without plugin directory registration

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

## Complete First-Time Publishing Workflow

For the initial release of a new backend, follow this complete end-to-end workflow:

### Phase 1: Setup (One-Time, 10 minutes)

**Prerequisites:**
- [ ] Trusted Publishers configured on TestPyPI
- [ ] Trusted Publishers configured on production PyPI
- [ ] GitHub environment `release` created
- [ ] All tests passing locally: `poetry run pytest -vv`

### Phase 2: TestPyPI Release (Testing)

**Purpose:** Test the package in a safe environment before production release.

```bash
# 1. Verify version is correct
poetry version  # Should show 0.1.0

# 2. Create and push version tag
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

**What happens automatically:**
- ✅ GitHub Actions workflow triggers
- ✅ All tests run
- ✅ Package builds
- ✅ Publishes to TestPyPI

**Monitor:** https://github.com/SumoLogic/pySigma-backend-sumologic/actions

**Test the TestPyPI package:**
```bash
# Create clean test environment
python -m venv test-env
source test-env/bin/activate  # On Windows: test-env\Scripts\activate

# Install from TestPyPI
pip install --index-url https://test.pypi.org/simple/ \
            --extra-index-url https://pypi.org/simple/ \
            pysigma-backend-sumologic==0.1.0

# Test basic import
python -c "from sigma.backends.sumologic import SumoLogicBackend; print('✓ Backend imported successfully')"

# Test conversion (if you have a test rule)
# sigma convert -t sumologic-cse-rule -p sumologic_cse your_test_rule.yml

# Cleanup
deactivate
rm -rf test-env
```

**If issues found:** Fix them, delete the tag, and re-release to TestPyPI:
```bash
# Delete tag locally and remotely
git tag -d v0.1.0
git push origin :refs/tags/v0.1.0

# Fix issues, commit, then re-tag
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

### Phase 3: Production PyPI Release

**Only proceed if TestPyPI testing succeeded!**

1. Go to: https://github.com/SumoLogic/pySigma-backend-sumologic/releases
2. Click **"Draft a new release"**
3. **Choose existing tag:** `v0.1.0`
4. Add release notes describing changes:
   ```markdown
   ## Features
   - CSE rule conversion support
   - Field mapping for Sysmon, network, and AWS CloudTrail
   - Pipeline support for Sumo Logic data models
   
   ## Installation
   pip install pysigma-backend-sumologic
   ```
5. Click **"Publish release"**

**What happens automatically:**
- ✅ GitHub Actions workflow triggers
- ✅ All tests run
- ✅ Package builds
- ✅ Publishes to **Production PyPI**

**Verify publication:**
```bash
# Check PyPI page (after 1-2 minutes)
open https://pypi.org/project/pysigma-backend-sumologic/

# Test installation from production PyPI
pip install pysigma-backend-sumologic
```

**🎉 Your backend is now publicly available on PyPI!**

---

## Plugin Directory Registration

### Overview

The **pySigma Plugin Directory** is a central registry of all pySigma backends and pipelines that enables:
- 📦 Installation via `sigma plugin install sumologic`
- 📋 Listing in `sigma plugin list`
- ✅ Automatic compatibility checking
- 🌐 Community discovery and visibility

**Repository:** https://github.com/SigmaHQ/pySigma-plugin-directory

### Is Plugin Registration Required?

**No, plugin directory registration is optional.**

| Scenario | With Plugin Directory | Without Plugin Directory |
|----------|----------------------|-------------------------|
| **Installation** | `sigma plugin install sumologic` | `pip install pysigma-backend-sumologic` |
| **Discovery** | Listed in `sigma plugin list` | Manual (GitHub/PyPI search) |
| **Compatibility** | Automatic by sigma-cli | Manual checking |
| **Visibility** | High (official registry) | Low (requires manual discovery) |
| **Backend Functionality** | ✅ Works | ✅ Works |
| **Conversion Commands** | ✅ Works | ✅ Works |

**Recommendation:** Register in the plugin directory for better community adoption and ease of use.

### When to Register

**Timing:** Register **AFTER** your first **production PyPI release**.

- ✅ **After production PyPI release** (required)
- ❌ **NOT after TestPyPI release** (plugin directory only references production PyPI)
- ⏰ **Wait 5-10 minutes** after PyPI publish for package indexing

**Publishing Flow:**
```
Local Development → TestPyPI (test) → Production PyPI (public) → Plugin Directory (discoverable)
                                             ↑                           ↑
                                          REQUIRED                    OPTIONAL
```

### Registration Process

#### Step 1: Generate Plugin UUID

Every plugin needs a unique UUID identifier.

```bash
# On macOS/Linux:
uuidgen

# Using Python:
python3 -c "import uuid; print(uuid.uuid4())"

# Example output: 
# 12345678-1234-1234-1234-123456789abc
```

**💾 Save this UUID** - it's the permanent identifier for your plugin (you'll need it in the next step).

#### Step 2: Prepare Plugin Entry

Create a JSON entry with your plugin information. Replace `<YOUR-UUID>` with the UUID from Step 1.

```json
{
  "<YOUR-UUID>": {
    "id": "sumologic",
    "type": "backend",
    "description": "pySigma Sumo Logic backend for CSE rule conversion with field mapping support",
    "package": "pysigma-backend-sumologic",
    "project-url": "https://github.com/SumoLogic/pySigma-backend-sumologic",
    "report-issue-url": "https://github.com/SumoLogic/pySigma-backend-sumologic/issues/new",
    "state": "stable"
  }
}
```

**Field Reference:**

| Field | Description | Example |
|-------|-------------|---------|
| **UUID** | Unique identifier (from Step 1) | `12345678-1234-1234-1234-123456789abc` |
| **id** | Short name for `sigma plugin install <id>` | `sumologic` |
| **type** | Plugin type | `backend`, `pipeline`, or `validator` |
| **description** | One-line description (max 120 chars) | Describe backend purpose and key features |
| **package** | PyPI package name (exact) | `pysigma-backend-sumologic` |
| **project-url** | Repository URL | GitHub repo URL |
| **report-issue-url** | Issue tracker URL | GitHub issues page URL |
| **state** | Development state | `stable`, `testing`, `devel`, `broken`, `orphaned` |

#### Step 3: Fork and Edit Plugin Directory

**Option A: Via GitHub Web UI (Easier)**

1. Go to: https://github.com/SigmaHQ/pySigma-plugin-directory/edit/main/pySigma-plugins-v1.json
2. Click **"Fork this repository"**
3. Add your plugin entry to the `"plugins"` section
4. Scroll down and click **"Commit changes"**

**Option B: Via Git (More Control)**

```bash
# 1. Fork repository on GitHub
# Go to: https://github.com/SigmaHQ/pySigma-plugin-directory
# Click "Fork"

# 2. Clone your fork
git clone https://github.com/YOUR-USERNAME/pySigma-plugin-directory
cd pySigma-plugin-directory

# 3. Edit the plugin file
nano pySigma-plugins-v1.json  # or use your preferred editor

# 4. Commit and push
git add pySigma-plugins-v1.json
git commit -m "Add pySigma-backend-sumologic to plugin directory"
git push origin main
```

**Where to add your entry:**

```json
{
  "note": "...",
  "plugins": {
    "existing-plugin-uuid-1": { ... },
    "existing-plugin-uuid-2": { ... },
    "<YOUR-UUID>": {
      "id": "sumologic",
      "type": "backend",
      "description": "pySigma Sumo Logic backend for CSE rule conversion with field mapping support",
      "package": "pysigma-backend-sumologic",
      "project-url": "https://github.com/SumoLogic/pySigma-backend-sumologic",
      "report-issue-url": "https://github.com/SumoLogic/pySigma-backend-sumologic/issues/new",
      "state": "stable"
    }
  }
}
```

#### Step 4: Submit Pull Request

1. Go to: https://github.com/SigmaHQ/pySigma-plugin-directory/pulls
2. Click **"New pull request"**
3. Click **"compare across forks"**
4. Select your fork
5. Click **"Create pull request"**
6. Title: `Add pySigma-backend-sumologic backend`
7. Description:
   ```markdown
   Add pySigma-backend-sumologic backend
   
   - Backend for Sumo Logic CSE rule conversion
   - Published to PyPI: https://pypi.org/project/pysigma-backend-sumologic/0.1.0/
   - Repository: https://github.com/SumoLogic/pySigma-backend-sumologic
   - All tests passing
   - Maintainer: @your-github-username
   ```
8. Click **"Create pull request"**

#### Step 5: Wait for Review and Approval

**Review Process:**
- 👀 SigmaHQ maintainers review your PR
- ✅ Verify package exists on production PyPI
- ✅ Check JSON formatting is valid
- ✅ Verify repository is accessible
- ⏰ **Typical approval time: 1-7 days**

**After PR is merged:**
Your backend is now discoverable in the pySigma ecosystem! 🎉

### After Plugin Directory Registration

Once your PR is merged and the plugin is in the directory:

#### 1. Re-enable Sigma CLI Integration Test

```bash
# Edit .github/workflows/test.yml
# Change from:
- name: Run Sigma CLI integration test
  if: false  # ← Remove this line
  run: sh 'tests/test_sigma_cli_integration_sumologic.sh'

# To:
- name: Run Sigma CLI integration test
  run: sh 'tests/test_sigma_cli_integration_sumologic.sh'
```

Commit and push this change:
```bash
git add .github/workflows/test.yml
git commit -m "Re-enable Sigma CLI integration test after plugin registration"
git push
```

#### 2. Verify Plugin Registration

```bash
# List all plugins (should include sumologic)
sigma plugin list | grep sumologic

# Expected output:
# | sumologic | backend | pySigma Sumo Logic backend for CSE rule conversion... |

# Install your plugin
sigma plugin install sumologic

# Verify installation
sigma plugin list --installed
```

#### 3. Update Documentation

Update your `README.md` to show both installation methods:

```markdown
## Installation

### Via sigma-cli (Recommended)
```bash
sigma plugin install sumologic
```

### Via pip
```bash
pip install pysigma-backend-sumologic
```

## Usage

```bash
# Convert Sigma rules to Sumo Logic CSE rules
sigma convert -t sumologic-cse-rule -p sumologic_cse your_rule.yml
```
```

#### 4. Announce Your Backend

Consider announcing your backend:
- 📢 SigmaHQ Discussions: https://github.com/orgs/SigmaHQ/discussions
- 🐦 Social media with hashtag #pySigma
- 📝 Blog post or documentation

**🎊 First-time publishing complete!**

---

## Regular Release Process

After the first release, subsequent releases are simpler:

### For Minor Updates and Bug Fixes

```bash
# 1. Bump version
poetry version patch  # 0.1.0 → 0.1.1

# 2. Commit version change
git add pyproject.toml
git commit -m "Bump version to $(poetry version -s)"
git push

# 3. Run tests locally
poetry run pytest -vv

# 4. Tag and push to TestPyPI (optional but recommended)
git tag -a v0.1.1 -m "Release v0.1.1"
git push origin v0.1.1

# 5. Test from TestPyPI (optional)
pip install --index-url https://test.pypi.org/simple/ \
            --extra-index-url https://pypi.org/simple/ \
            pysigma-backend-sumologic==0.1.1

# 6. Create GitHub release for production PyPI
# Go to: https://github.com/SumoLogic/pySigma-backend-sumologic/releases
# Click "Draft a new release"
# Select tag: v0.1.1
# Add release notes
# Click "Publish release"
```

**Note:** Plugin directory registration is **only needed once**. Subsequent releases automatically appear in the plugin directory as users will pull from PyPI.

---

## Version Management

```bash
# Patch release (0.1.0 → 0.1.1) - bug fixes
poetry version patch

# Minor release (0.1.0 → 0.2.0) - new features, backward compatible
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
│ (contains repo, workflow,    │
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

### Before TestPyPI Release:
- [ ] All tests pass: `poetry run pytest -vv`
- [ ] Version set in `pyproject.toml`
- [ ] Changes committed and pushed to `main`
- [ ] Trusted publishers configured on TestPyPI
- [ ] GitHub environment `release` exists

### Before Production PyPI Release:
- [ ] TestPyPI version tested successfully
- [ ] Trusted publishers configured on production PyPI
- [ ] Release notes prepared
- [ ] README.md updated with usage instructions

### After Production PyPI Release (First-Time Only):
- [ ] Wait 5-10 minutes for PyPI indexing
- [ ] Generate UUID: `python3 -c "import uuid; print(uuid.uuid4())"`
- [ ] Fork pySigma-plugin-directory
- [ ] Add plugin entry to `pySigma-plugins-v1.json`
- [ ] Submit PR with title "Add pySigma-backend-sumologic backend"
- [ ] Wait for PR approval (1-7 days)
- [ ] After merge, re-enable Sigma CLI integration test
- [ ] Verify: `sigma plugin list | grep sumologic`
- [ ] Update README with both installation methods

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
3. Commit fixes
4. Create new tag after fixes

### "Could not find metadata for pySigma-backend-sumologic in plugin directory"
**Solution:** This is expected before plugin registration. The Sigma CLI integration test is disabled until after plugin directory registration. See `SIGMA_CLI_TEST_EXPLANATION.md` for details.

### Plugin not showing in `sigma plugin list` after registration
**Solution:** 
1. Verify PR was merged: Check https://github.com/SigmaHQ/pySigma-plugin-directory/pulls
2. Update sigma-cli: `pip install --upgrade sigma-cli`
3. Clear cache: `sigma plugin list --refresh`

---

## Quick Reference

```bash
# Check current version
poetry version

# Run tests
poetry run pytest -vv

# Tag for TestPyPI
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0

# Create GitHub release for production PyPI
# (via web UI at github.com/.../releases)

# Generate UUID for plugin registration (first-time only)
python3 -c "import uuid; print(uuid.uuid4())"

# Verify plugin registration
sigma plugin list | grep sumologic
```

---

## Resources

- **PyPI Trusted Publishers:** https://docs.pypi.org/trusted-publishers/
- **pySigma Plugin Directory:** https://github.com/SigmaHQ/pySigma-plugin-directory
- **SigmaHQ Cookiecutter Template:** https://github.com/SigmaHQ/cookiecutter-pySigma-backend
- **GitHub Environments:** https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment
- **Sigma CLI Documentation:** https://github.com/SigmaHQ/sigma-cli
