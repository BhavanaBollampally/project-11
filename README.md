#  Project-11: CloudTrail Log Processing Pipeline  
### **Terraform + S3 + Lambda (ETL) + Glue + Athena**

---

##  Overview

Project-11 is a complete AWS log analytics pipeline that ingests CloudTrail logs, processes them through a Lambda ETL function, stores clean NDJSON output, and enables SQL analytics through Athena.  
Everything is deployed and managed using Terraform.

This project demonstrates:

- Infrastructure-as-Code (Terraform)
- Serverless ETL (Lambda)
- S3 event-driven processing
- Gzip + JSON parsing
- Glue + Athena analytics
- Real-world DevOps debugging and data engineering steps

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

yaml
Copy code

---

##  Architecture

CloudTrail → S3 (raw/) → S3 Event Trigger → Lambda ETL
→ S3 (processed/) → Glue Table → Athena Queries

markdown
Copy code

---

##  Processing Flow

1. CloudTrail delivers `.json.gz` logs into the **raw/** folder.  
2. S3 triggers **Lambda** automatically on new file creation.  
3. Lambda ETL:
   - decompresses gzip  
   - parses CloudTrail JSON  
   - extracts and flattens fields  
   - converts to **NDJSON** (1 JSON per line)  
   - uploads into **processed/** prefix  
4. Glue Catalog maps the processed folder.  
5. Athena queries the flattened NDJSON.

---

##  Lambda ETL Summary

### Key Actions Performed

- Read raw compressed `.gz` file from S3  
- `gzip.decompress()` → decode UTF-8  
- Load JSON → extract `"Records"` array  
- Flatten fields:
  - eventTime  
  - eventName  
  - eventSource  
  - awsRegion  
  - userIdentity  
  - sourceIPAddress  
  - requestParameters  
  - responseElements  
  - raw_event  
- Convert into **NDJSON format** (each event on its own line)
- Write output into:

processed/<same_path>/<file>.json

shell
Copy code

### NDJSON Output Example

{"eventTime":"2025-11-15T18:02:34Z","eventName":"ListManagedNotificationEvents", ...}

yaml
Copy code

---

##  Glue + Athena

Glue table created via Terraform:

- Input format: `TextInputFormat`
- Output format: `HiveIgnoreKeyTextOutputFormat`
- SerDe: `org.openx.data.jsonserde.JsonSerDe`
- Every column mapped as **string**
- Works with NDJSON perfectly

###  Example Athena Query


SELECT eventTime, eventName
FROM project11_processed
ORDER BY eventTime DESC
LIMIT 20;

### Updating Lambda Code (IMPORTANT)
bash
Copy code
cd terraform/dev/lambda
rm ../lambda_function.zip
zip -r ../lambda_function.zip process_event.py
cd ..
terraform apply
## Debugging Summary (Real Issues Solved)
1. Gzip Decompression Errors
Reason: Trying to decode binary gzip directly.
Fix: Use gzip.decompress() correctly.

2. Lambda Not Triggering
Reason: Missing source argument & wrong prefix in event block.
Fix: Corrected S3 trigger path and added proper event configuration.

3. Wrong Processed File Path
Reason: CloudTrail delivers logs in deep nested structure.
Fix:

python
Copy code
output_key = key.replace("raw/", "processed/").replace(".gz", ".json")
4. Athena INVALID_FUNCTION_ARGUMENT
Reason: Lambda returned single large JSON array, not line-delimited JSON.
Fix: Changed ETL to NDJSON output.

5. Timestamp Casting Issues
Reason: Glue schema had incorrect types.
Fix: All columns changed to string.

## Final Outcome
This project delivers:

Automated CloudTrail ingestion

End-to-end serverless ETL using Lambda

NDJSON output ready for analytics

Glue-based metadata catalog

Athena SQL querying on processed events

Full Terraform-managed deployment

Practical debugging experience across AWS services

A production-style AWS log analytics pipeline and a strong DevOps + Data Engineering portfolio project.
