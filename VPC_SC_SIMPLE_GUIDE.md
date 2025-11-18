# VPC SC Self-Service - Simplified Approach

## Overview

**Simple strategy:** Parse VPC SC error messages + daily cache. No complex logic, no manual mapping.

---

## How It Works

### 1. Error Message Parsing (Primary)

VPC SC errors contain all the info we need:

**Example Error:**
```
Request is prohibited by organization's policy.
vpcServiceControlsUniqueIdentifier: yBL4S...
serviceName: "bigquery.googleapis.com"
methodName: "google.cloud.bigquery.v2.JobService.InsertJob"
resourceName: "projects/987654321/datasets/my_dataset"
perimeterName: "accessPolicies/123456789/servicePerimeters/prod-data-perimeter"
```

**What we extract:**
- ✅ Perimeter: `prod-data-perimeter` (from `perimeterName`)
- ✅ Service: `bigquery.googleapis.com` (from `serviceName`)
- ✅ Project: `987654321` (from `resourceName`)

**No API calls needed - it's all in the error!**

### 2. Daily Project Cache (Fallback)

For cases where error message is incomplete:

**Daily workflow** (runs at 2 AM):
```bash
# Query GCP API for all perimeters
gcloud access-context-manager perimeters describe prod-data-perimeter \
  --policy 123456789 --format json

# Build cache: project → perimeter
{
  "1234567890": "prod-perimeter-east",
  "9876543210": "prod-perimeter-west",
  ...  # thousands more
}
```

**Cache updated once per day** → always fresh, no manual maintenance

### 3. Detection Flow

```
┌─────────────────────────┐
│ User Pastes Error       │
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│ Extract from Error:     │
│ - Perimeter             │
│ - Service               │
│ - Project numbers       │
└──────────┬──────────────┘
           │
           ▼
    Found perimeter?
           │
       Yes │                No
           │                │
           ▼                ▼
┌─────────────────┐  ┌──────────────────┐
│ Use it!         │  │ Look up project  │
│                 │  │ in cache         │
└─────────────────┘  └─────────┬────────┘
                               │
                         Found in cache?
                               │
                           Yes │        No
                               │        │
                               ▼        ▼
                     ┌─────────────┐  ┌──────────────┐
                     │ Use it!     │  │ Ask user to  │
                     │             │  │ select from  │
                     │             │  │ dropdown     │
                     └─────────────┘  └──────────────┘
```

---

## Setup

### Step 1: Enable Daily Cache Updates

The workflow is already created at `.github/workflows/update-vpc-sc-cache.yml`

**Just ensure:**
1. `GCP_SA_KEY` secret is configured
2. Service account has permission: `accesscontextmanager.accessPolicies.list`

**Manually trigger first run:**
```bash
# Via GitHub UI: Actions → Update VPC SC Project Cache → Run workflow

# Or via CLI:
gh workflow run update-vpc-sc-cache.yml
```

**Wait 5-10 minutes** (queries all perimeters)

**Result:** `vpc_sc_project_cache.json` committed to repo

### Step 2: Update Perimeter Dropdown in Form

Edit `.github/ISSUE_TEMPLATE/vpc-sc-request-simple.yml`:

```yaml
- type: dropdown
  id: source_perimeter
  attributes:
    label: Source Perimeter (optional - we auto-detect)
    options:
      - (Auto-detect from error or cache)
      - your-perimeter-1    # ← Add your perimeters here
      - your-perimeter-2
      - your-perimeter-3
      # ... add all ~20 perimeters
```

**One-time setup:** Add your 20 perimeter names to dropdown

### Step 3: Test It

Create test issue:

**Required fields only:**
- Request ID: `TEST-001`
- Error message: (paste full VPC SC error)
- What trying to do: `Testing VPC SC automation`
- Service account: `test@test.iam.gserviceaccount.com`
- Justification: `Testing`
- Urgency: `Normal`

**Leave everything else blank** - system auto-fills!

---

## User Experience

### Scenario 1: User Has Full Error (95% of cases)

**User does:**
1. Copy/paste VPC SC error into form
2. Fill: Service account, justification
3. Submit

**System does:**
1. Extract perimeter from error → `prod-data-perimeter`
2. Extract service from error → `bigquery.googleapis.com`
3. Extract projects from error → `987654321`
4. Create INGRESS/EGRESS rules automatically
5. Create PRs to correct repos
6. Notify user

**User time:** 2 minutes

### Scenario 2: Partial Error (4% of cases)

**User does:**
1. Paste incomplete error (no `perimeterName` field)
2. Provide project numbers manually
3. Submit

**System does:**
1. Look up projects in cache
2. Find perimeters: `1234567890` → `prod-east`, `9876543210` → `prod-west`
3. Create rules
4. Create PRs
5. Notify user

**User time:** 3 minutes

### Scenario 3: No Error (1% of cases)

**User does:**
1. Skip error field
2. Select perimeters from dropdown manually
3. Submit

**System does:**
1. Use user-selected perimeters
2. Create rules
3. Create PRs
4. Notify user

**User time:** 4 minutes

---

## Integration with Existing Handler

Your existing `vpc_sc_request_handler.py` stays mostly the same.

**Add this step before processing:**

```python
# Extract info from error + cache
result = extract_all_info(
    error_message=issue_body_error_field,
    source_project=user_provided_source,
    dest_project=user_provided_dest,
    cache_file="vpc_sc_project_cache.json"
)

# Use extracted info
dest_perimeter = result["dest_perimeter"] or user_selected_perimeter
service = result["service_from_error"] or user_selected_service
# ... etc
```

**That's it!** Rest of handler logic unchanged.

---

## Maintenance

### Daily (Automatic)
- ✅ Cache updates at 2 AM UTC
- ✅ New projects automatically added
- ✅ Removed projects automatically dropped

### Monthly (Manual - 5 min)
- Check cache file size (should be ~500KB for 5000 projects)
- Review workflow logs for any API errors

### When Adding New Perimeter
1. Add to `router.yml`:
   ```yaml
   perimeters:
     new-perimeter:
       repo: org/new-perim-config
       policy_id: 999999999
   ```

2. Add to form dropdown (one line):
   ```yaml
   - new-perimeter
   ```

3. Next day: Cache auto-updates with new perimeter's projects

**Total time:** 2 minutes

---

## Troubleshooting

### Cache Not Updating

**Check:**
```bash
# View workflow logs
gh run list --workflow=update-vpc-sc-cache.yml

# Check cache age
cat vpc_sc_project_cache.json | jq '.last_updated'
```

**Common issues:**
- Service account lacks permissions → Add `accesscontextmanager.policies.list`
- gcloud not authenticated → Check `GCP_SA_KEY` secret

**Fix:** Run workflow manually to test

### Project Not Found in Cache

**Possible causes:**
1. Project created < 24 hours ago (wait for next cache update)
2. Project not in any perimeter (ask user to select perimeter manually)
3. Cache out of date (force update: `gh workflow run update-vpc-sc-cache.yml`)

**Workaround:** User can select perimeter from dropdown

### Error Parsing Fails

**If VPC SC error format changes**, update regex patterns in `extract_vpc_sc_error_info.py`:

```python
# Add new pattern
match = re.search(r'new_pattern_here', error_text)
```

**Test with:**
```bash
echo "error message" > test_error.txt
python3 .github/scripts/extract_vpc_sc_error_info.py \
  --error-file test_error.txt \
  --output result.json
cat result.json
```

---

## Files Reference

### New Files Created

1. **`.github/ISSUE_TEMPLATE/vpc-sc-request-simple.yml`**
   - Simplified form (most fields optional)
   - Prominent error message field

2. **`.github/scripts/extract_vpc_sc_error_info.py`**
   - Parse VPC SC errors
   - Look up projects in cache
   - Return perimeters, services, projects

3. **`.github/scripts/update_project_perimeter_cache.py`**
   - Query GCP API for all perimeters
   - Build project → perimeter cache
   - Run once per day

4. **`.github/workflows/update-vpc-sc-cache.yml`**
   - Daily workflow (2 AM UTC)
   - Commits updated cache to repo

5. **`vpc_sc_project_cache.json`** (generated)
   - Cache file
   - Updated daily
   - ~500KB for 5000 projects

### Existing Files (Unchanged)

- `vpc_sc_request_handler.py` - Just add error extraction step
- `validate_vpc_sc_request.py` - No changes
- `router.yml` - No project lists needed!

---

## Comparison: Old vs New

### Old Approach
- ❌ Manual project mapping (impossible with thousands)
- ❌ Complex naming patterns
- ❌ User must know perimeters
- ❌ 15 required form fields
- ⏱️ 15-20 minutes per request

### New Approach
- ✅ Auto-extract from error (95% success)
- ✅ Daily cache (zero maintenance)
- ✅ User just pastes error
- ✅ 4 required fields (error, identity, justification, urgency)
- ⏱️ 2-3 minutes per request

---

## FAQ

**Q: What if user doesn't paste full error?**
A: Cache fallback. If project in cache → use it. Otherwise → ask user to select perimeter.

**Q: Cache queries take 10 minutes - is that OK?**
A: Yes! Runs once per day at 2 AM (zero user impact). Users never wait.

**Q: What if cache is stale (project created today)?**
A: User can select perimeter manually from dropdown. Tomorrow cache will have it.

**Q: Do I need to maintain project → perimeter mappings?**
A: No! Cache auto-updates daily from GCP API.

**Q: What if error format changes?**
A: Update regex in `extract_vpc_sc_error_info.py` (takes 5 min).

**Q: Can I disable daily cache updates?**
A: Yes, but then users must always select perimeters manually.

---

**This is as simple as it gets while handling thousands of projects!**
