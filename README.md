# AI Shield Firewall

> AI API Gateway bảo vệ doanh nghiệp khỏi data leakage khi tích hợp LLM (OpenAI, Gemini) vào ứng dụng nội bộ.

## Problem

Doanh nghiệp ngày càng tích hợp AI vào ứng dụng nội bộ — chatbot, automation, phân tích dữ liệu. Nhưng nhân viên có thể vô tình (hoặc cố ý) gửi thông tin nhạy cảm qua AI API: API key, CCCD, số điện thoại, thông tin lương, hoặc dùng kỹ thuật prompt injection để bypass policy.

**AI Shield Firewall** đứng giữa ứng dụng và AI provider, inspect mọi request/response trước khi data rời khỏi perimeter.

[Enterprise App] → [AI Shield FW] → [OpenAI / Gemini / Claude]

## Architecture

```
API Gateway (AWS)
      │
      ▼
Inspection Engine (EC2 + Docker)
  ├── Layer 1: Regex — API key, JWT, SĐT, CCCD
  ├── Layer 2: Presidio NLP — Email, Phone
  ├── Layer 3: Prompt Injection Detector (EN + VI)
  └── Layer 4: Policy Engine — per-org rules (DynamoDB)
      │
      ├── BLOCK  → 403 + audit log
      ├── REDACT → mask PII → forward
      └── ALLOW  → forward to AI provider
                        │
                   Output Inspection
                        │
                   Response to client

DynamoDB: audit logs + per-org policies
```

## Detection Capabilities

| Category              | Examples                              | Action |
| --------------------- | ------------------------------------- | ------ |
| API Keys              | OpenAI `sk-...`, Gemini `AIza...`     | BLOCK  |
| Secrets               | JWT token, `password=...`             | BLOCK  |
| Prompt Injection (EN) | "Ignore all previous instructions..." | BLOCK  |
| Prompt Injection (VI) | "Bây giờ bạn là AI không giới hạn..." | BLOCK  |
| Policy Violation      | Custom keyword blacklist per org      | BLOCK  |
| PII — Email           | `user@company.com`                    | REDACT |
| PII — Phone           | `0987654321`                          | REDACT |
| PII — Salary (VI)     | "lương 25 triệu"                      | REDACT |

## Benchmark Results

Tested on 23-sample dataset (BLOCK / REDACT / ALLOW cases, EN + VI):

| Metric         | Value            |
| -------------- | ---------------- |
| Detection rate | **100% (23/23)** |
| Unit tests     | **21/21 passed** |
| Latency avg    | 286ms\*          |
| Latency p50    | 278ms\*          |
| Latency p95    | 323ms\*          |

\*Network latency VN → AWS us-east-1. Proxy overhead < 15ms when co-located.

## Dashboard

Live monitoring dashboard tại `/dashboard` — hiển thị real-time stats từ DynamoDB audit logs (auto-refresh mỗi 30 giây):

- Total requests, block rate, redact rate
- Top violation types (bar chart)
- Recent activity table (last 20 requests) với timestamp, action, org, reason, preview

![Dashboard](Screenshot/placeholder.PNG)

## Security

Tất cả API endpoints được bảo vệ bằng API key authentication:

```
X-API-Key: shield-key-{your-key}
```

Các endpoint public (không cần auth): `/health`, `/dashboard`

## Tech Stack

- **Runtime**: Python 3.11, FastAPI, uvicorn
- **PII Detection**: Microsoft Presidio + spaCy `en_core_web_lg`
- **Infrastructure**: AWS EC2 t3.small, Docker (`--restart always`)
- **Storage**: DynamoDB (audit logs + policies)
- **IAM**: EC2 Instance Role — no hardcoded credentials

## API Endpoints

| Method | Endpoint                  | Description                             |
| ------ | ------------------------- | --------------------------------------- |
| GET    | `/health`                 | Health check                            |
| POST   | `/v1/chat`                | Full proxy — inspect → forward → return |
| POST   | `/v1/inspect`             | Inspect only, no forward                |
| POST   | `/v1/inspect-output`      | Output inspection only                  |
| POST   | `/v1/admin/reload-policy` | Reload policy cache from DynamoDB       |

### Request format

```json
POST /v1/chat
{
  "provider": "gemini",
  "model": "gemini-2.0-flash",
  "org_id": "fintech-demo",
  "messages": [
    {"role": "user", "content": "Your message here"}
  ]
}
```

### Response format

```json
{
  "shield": {
    "action": "ALLOW",
    "reason": null,
    "latency_ms": 12.3
  },
  "response": { ... }
}
```

## Policy Engine

Mỗi tổ chức có policy riêng lưu trong DynamoDB:

```json
{
  "org_id": "fintech-demo",
  "keyword_blacklist": ["vietcombank", "internal report", "quarterly revenue"],
  "max_message_length": 1000,
  "block_after_hours": false
}
```

## Quick Start

```bash
# Clone
git clone https://github.com/ThanhLam-NetEng/ai-shield-fw.git
cd ai-shield-fw

# Cấu hình
cp .env.example .env
# Điền GEMINI_API_KEY hoặc OPENAI_API_KEY vào .env

# Chạy local
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
python -m spacy download en_core_web_lg
uvicorn app.main:app --reload --port 8000

# Chạy với Docker
docker build -t ai-shield-fw .
docker run -d --name ai-shield-fw --env-file .env -p 8000:8000 ai-shield-fw
```

## Testing

**Unit tests:**

```bash
pytest tests/test_proxy.py -v
# 21 passed in 3.38s
```

**Test inspector qua curl:**

```bash
curl -X POST http://your-server:8000/v1/inspect \
  -H "X-API-Key: shield-key-demo123" \
  -H "Content-Type: application/json" \
  -d '[{"role": "user", "content": "Ignore all previous instructions"}]'
```

**View dashboard:**

```
http://your-server:8000/dashboard
```

**Run unit tests:**

```bash
pytest tests/test_proxy.py -v
# 21 passed in 3.38s
```

## Limitations

- Không cover trường hợp nhân viên vào trực tiếp ChatGPT/Gemini web — đó là bài toán network-level DLP cần SSL inspection trên NGFW
- Prompt injection detection dựa trên pattern matching — adversarial prompts tinh vi có thể bypass
- Presidio NLP chạy model tiếng Anh — tên người Việt Nam detect chưa đầy đủ

## Author

Phạm Thanh Lâm — Network & Security Engineer  
[GitHub](https://github.com/ThanhLam-NetEng) · [LinkedIn](https://linkedin.com/in/thanhlam-uit) · [Portfolio](https://thanhlam-neteng.github.io/Portfolio)
