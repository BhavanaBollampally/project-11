#  Project-11: CloudTrail Log Processing Pipeline  
### **Terraform + S3 + Lambda (ETL) + Glue + Athena**

---

##  Overview

Project-11 is a complete AWS log analytics pipeline that ingests CloudTrail logs, processes them through a Lambda ETL function, stores clean NDJSON output, and enables SQL analytics through Athena.  
Everything is deployed and managed using Terraform.

This project demonstrates:

- Infrastructure-as-Code (Terraform)
- Serverless ETL (Lambda)
- S3 event-driven pipelines
- Gzip + JSON parsing
- Glue + Athena analytics
- Real-world DevOps debugging and data engineering fundamentals

---

##  Project Structure

project-11/
└── terraform
├── dev
│ ├── backend.tf
│ ├── lambda
│ │ └── process_event.py
│ ├── lambda_function.zip
│ ├── main.tf
│ ├── outputs.tf
│ ├── plan.tfout
│ ├── terraform.tfvars
│ └── variables.tf
└── scripts
└── monitor.sh

---

##  Architecture

CloudTrail → S3 (raw/) → S3 Event Trigger → Lambda ETL
→ S3 (processed/) → Glue Table → Athena Queries


### Processing Flow

1. CloudTrail sends `.json.gz` logs to the **raw folder**.
2. S3 event triggers **Lambda**.
3. Lambda:
   - decompresses gzip
   - parses JSON
   - extracts and flattens CloudTrail events
   - writes **NDJSON** to `processed/`
4. Glue table maps the processed folder.
5. Athena queries the cleaned events.

---

##  Lambda ETL Summary

### Key Actions:

- Read compressed `.gz` file from S3  
- `gzip.decompress()` → UTF-8 decode  
- Load JSON → extract `"Records"`  
- Flatten:
  - eventTime  
  - eventName  
  - eventSource  
  - awsRegion  
  - userIdentity  
  - sourceIPAddress  
  - requestParameters  
  - responseElements  
  - raw_event  
- Convert to **NDJSON** (1 JSON per line)  
- Store back to S3 `processed/` prefix  

### NDJSON output example:

{"eventTime":"2025-11-15T18:02:34Z","eventName":"ListManagedNotificationEvents", ...}


---

##  Glue + Athena

Glue table (via Terraform):

- input format: `TextInputFormat`
- SerDe: `org.openx.data.jsonserde.JsonSerDe`
- columns mapped as **string**
- works with NDJSON (line-delimited JSON)

### Example Athena query:

```sql
SELECT eventTime, eventName
FROM project11_processed
ORDER BY eventTime DESC
LIMIT 20;
Terraform Commands

Initialize:

terraform init


Plan:

terraform plan


Apply:

terraform apply

After Lambda code update:
cd terraform/dev/lambda
rm ../lambda_function.zip
zip -r ../lambda_function.zip process_event.py
cd ..
terraform apply

Debugging Summary (Real Issues Solved)
1. Gzip decompression errors

Fixed via correct gzip.decompress() usage.

2. Lambda not triggering

Cause: Missing source and wrong prefix.
Fix: Updated S3 event block.

3. Wrong processed output path

Cause: raw path had deeper prefix.
Fix: Corrected:

key.replace("raw/", "processed/")

4. Athena errors (INVALID_FUNCTION_ARGUMENT)

Cause: processed output was single big JSON array.
Fix: Changed to NDJSON (each event on new line).

5. Timestamp type mismatches

Fix: set Glue schema column type to string.

Final Outcome

This project delivers:

automated CloudTrail ingestion

serverless ETL using Python Lambda

clean NDJSON suitable for Athena

Glue-based schema management

full Terraform-deployed pipeline

real-world debugging experience

A complete production-style log analytics pipeline and a strong DevOps + Data Engineering portfolio project.
