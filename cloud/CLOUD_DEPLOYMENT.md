# Cloud Deployment Guide for 82ARC

Run the full ARC-AGI 2 benchmark at scale using cloud infrastructure.

## Quick Cost Estimate

| Strategy | Per Task | 400 Tasks (Full Test) | Compute Overhead |
|----------|----------|----------------------|------------------|
| fast     | ~$2      | ~$800                | ~$10-20         |
| default  | ~$5      | ~$2,000              | ~$20-50         |
| thorough | ~$10     | ~$4,000              | ~$50-100        |

**Note**: 90%+ of costs are API calls to LLM providers (Groq, Together AI), not compute.

---

## Option 1: Modal (Recommended)

**Best for**: Quick setup, automatic scaling, pay-per-use

### Setup (5 minutes)

```bash
# 1. Install Modal CLI
pip install modal

# 2. Authenticate (one-time)
modal setup

# 3. Create secrets for API keys
modal secret create arc-api-keys \
    GROQ_API_KEY=gsk_your_groq_key \
    TOGETHER_API_KEY=your_together_key

# 4. Run the benchmark!
modal run cloud/modal_app.py --num-tasks 10 --strategy fast
```

### Run Full ARC-AGI 2 Test Set

```bash
# Run all 400 evaluation tasks with 20 parallel workers
modal run cloud/modal_app.py \
    --dataset evaluation \
    --num-tasks 400 \
    --parallel 20 \
    --strategy default
```

### Advanced Options

```bash
# Resume from task 100
modal run cloud/modal_app.py --start 100 --num-tasks 300

# Use thorough strategy for difficult tasks
modal run cloud/modal_app.py --strategy thorough --parallel 10

# Deploy as persistent web endpoint
modal deploy cloud/modal_app.py
```

### Pricing
- **Compute**: ~$0.0001/second (~$0.36/hour) per worker
- **Free tier**: $30/month included
- **Full benchmark (400 tasks)**: ~$5-20 compute (API costs separate)

---

## Option 2: Google Cloud Run

**Best for**: Production deployments, GCP ecosystem

### Setup

```bash
# 1. Install gcloud CLI and authenticate
gcloud auth login
gcloud config set project YOUR_PROJECT_ID

# 2. Enable required APIs
gcloud services enable run.googleapis.com containerregistry.googleapis.com

# 3. Build and push container
docker build -f cloud/Dockerfile.cloud -t gcr.io/YOUR_PROJECT/82arc:latest .
docker push gcr.io/YOUR_PROJECT/82arc:latest

# 4. Deploy to Cloud Run
gcloud run deploy 82arc \
    --image gcr.io/YOUR_PROJECT/82arc:latest \
    --platform managed \
    --region us-central1 \
    --memory 2Gi \
    --timeout 600 \
    --set-env-vars "GROQ_API_KEY=your_key,TOGETHER_API_KEY=your_key"
```

### Run Benchmark via Cloud Run Jobs

```bash
# Create a job for batch processing
gcloud run jobs create arc-benchmark \
    --image gcr.io/YOUR_PROJECT/82arc:latest \
    --memory 2Gi \
    --task-timeout 3600 \
    --tasks 400 \
    --parallelism 20 \
    --set-env-vars "GROQ_API_KEY=your_key" \
    --command "python" \
    --args "benchmark.py,--dataset,evaluation,--num-tasks,1,--start,\$CLOUD_RUN_TASK_INDEX"

# Execute the job
gcloud run jobs execute arc-benchmark
```

### Pricing
- **Cloud Run**: $0.00002400/vCPU-second, $0.00000250/GiB-second
- **Free tier**: 2 million requests/month
- **Full benchmark**: ~$10-30 compute

---

## Option 3: RunPod Serverless

**Best for**: ML workloads, simple pricing

### Setup

```bash
# 1. Create account at runpod.io

# 2. Build the container
docker build -f cloud/Dockerfile.cloud -t your-dockerhub/82arc-runpod:latest .
docker push your-dockerhub/82arc-runpod:latest

# 3. Create Serverless Endpoint
#    - Go to runpod.io > Serverless > New Endpoint
#    - Container Image: your-dockerhub/82arc-runpod:latest
#    - Container Start Command: python -u cloud/runpod_handler.py
#    - Environment Variables: GROQ_API_KEY, TOGETHER_API_KEY

# 4. Use the endpoint
curl -X POST https://api.runpod.ai/v2/YOUR_ENDPOINT_ID/runsync \
    -H "Authorization: Bearer YOUR_RUNPOD_KEY" \
    -H "Content-Type: application/json" \
    -d '{
        "input": {
            "task": {"train": [...], "test": [...]},
            "strategy": "default"
        }
    }'
```

### Batch Processing Script

```python
# run_runpod_batch.py
import runpod
import json
from pathlib import Path

runpod.api_key = "YOUR_RUNPOD_API_KEY"
endpoint = runpod.Endpoint("YOUR_ENDPOINT_ID")

# Load all tasks
tasks = []
for task_file in Path("data/evaluation").glob("*.json"):
    with open(task_file) as f:
        tasks.append((task_file.stem, json.load(f)))

# Submit all tasks
jobs = []
for task_id, task_data in tasks:
    job = endpoint.run({
        "task": task_data,
        "task_id": task_id,
        "strategy": "default"
    })
    jobs.append((task_id, job))

# Collect results
results = []
for task_id, job in jobs:
    result = job.output()
    results.append(result)
    print(f"{task_id}: {'✓' if result.get('solved') else '✗'}")
```

### Pricing
- **Serverless**: $0.00025/second (~$0.90/hour)
- **Full benchmark**: ~$10-25 compute

---

## Option 4: AWS Batch

**Best for**: Maximum parallelism, AWS ecosystem

### Setup with Terraform

```hcl
# main.tf
resource "aws_batch_compute_environment" "arc" {
  compute_environment_name = "arc-benchmark"
  type                     = "MANAGED"

  compute_resources {
    type               = "FARGATE"
    max_vcpus          = 256
    subnets            = var.subnet_ids
    security_group_ids = var.security_group_ids
  }
}

resource "aws_batch_job_queue" "arc" {
  name     = "arc-queue"
  state    = "ENABLED"
  priority = 1
  compute_environments = [aws_batch_compute_environment.arc.arn]
}

resource "aws_batch_job_definition" "arc_task" {
  name = "arc-task"
  type = "container"

  platform_capabilities = ["FARGATE"]

  container_properties = jsonencode({
    image      = "${var.ecr_repo}:latest"
    command    = ["python", "benchmark.py", "--num-tasks", "1"]

    resourceRequirements = [
      { type = "VCPU", value = "1" },
      { type = "MEMORY", value = "2048" }
    ]

    environment = [
      { name = "GROQ_API_KEY", value = var.groq_api_key }
    ]
  })
}
```

### Submit Array Job

```bash
aws batch submit-job \
    --job-name arc-full-benchmark \
    --job-queue arc-queue \
    --job-definition arc-task \
    --array-properties size=400
```

---

## Option 5: Railway / Render (Simplest)

**Best for**: Quick deploys, no DevOps experience needed

### Railway

```bash
# 1. Install Railway CLI
npm install -g @railway/cli

# 2. Login and init
railway login
railway init

# 3. Deploy
railway up

# 4. Set environment variables in Railway dashboard
#    GROQ_API_KEY, TOGETHER_API_KEY

# 5. Run benchmark via Railway shell
railway run python benchmark.py --dataset evaluation --num-tasks 400
```

### Render

1. Connect GitHub repo to Render
2. Create new "Background Worker" service
3. Set Dockerfile path: `cloud/Dockerfile.cloud`
4. Add environment variables
5. Deploy and run via Render shell

---

## Optimizing for the Full ARC-AGI 2 Test

### Rate Limit Management

The biggest bottleneck is API rate limits. Strategies:

```yaml
# configs/cloud.yaml - optimized for parallel execution
strategies:
  cloud:
    cost_budget_usd: 5.0
    solver:
      max_iterations: 8
      max_hypotheses_per_iteration: 2  # Lower to reduce API calls
      parallel_hypotheses: false  # Serial to avoid rate limits
    mcts:
      max_iterations: 4
      parallel_expansions: 1
```

### Multi-Provider Setup

Distribute load across providers:

```bash
# .env for cloud deployment
GROQ_API_KEY=gsk_key1
TOGETHER_API_KEY=together_key1
OPENROUTER_API_KEY=or_key1
FIREWORKS_API_KEY=fw_key1
```

### Estimated Runtimes

| Parallel Workers | Est. Time (400 tasks) | API Rate Limit Risk |
|------------------|----------------------|---------------------|
| 5                | ~8 hours             | Low                 |
| 10               | ~4 hours             | Medium              |
| 20               | ~2 hours             | High                |
| 50               | ~1 hour              | Very High           |

**Recommendation**: Start with 10 workers, increase if no rate limit errors.

---

## Monitoring & Results

### View Results on Modal

```bash
# List result files
modal volume ls arc-results

# Download results
modal volume get arc-results benchmark_evaluation_20241216_123456.json ./results/
```

### Results Format

```json
{
    "timestamp": "2024-12-16T12:34:56",
    "dataset": "evaluation",
    "strategy": "default",
    "num_tasks": 400,
    "solved": 120,
    "accuracy": 30.0,
    "total_cost_usd": 1850.50,
    "total_tokens": 45000000,
    "tasks": [
        {
            "task_id": "abc123",
            "solved": true,
            "iterations": 7,
            "cost": 4.25,
            "duration": 145.3
        }
    ]
}
```

---

## Troubleshooting

### Rate Limit Errors
```
Error: 429 Too Many Requests
```
**Fix**: Reduce `parallel_workers` or add delays between tasks.

### Timeout Errors
```
Error: Task timed out after 600s
```
**Fix**: Use `fast` strategy or increase timeout in cloud config.

### Memory Errors
```
Error: Container killed - OOM
```
**Fix**: Increase memory allocation (2GB → 4GB).

---

## Next Steps

1. **Start small**: Run 10 tasks locally to verify setup
2. **Test cloud**: Run 50 tasks on Modal with `--parallel 5`
3. **Scale up**: Run full 400 tasks with `--parallel 10-20`
4. **Optimize**: Adjust strategy based on results

For questions or issues, see the main README or open a GitHub issue.
