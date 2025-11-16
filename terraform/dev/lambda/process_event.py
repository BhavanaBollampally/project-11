import boto3
import gzip
import json

def lambda_handler(event, context):
    print("Event received:", json.dumps(event))

    bucket = event["Records"][0]["s3"]["bucket"]["name"]
    key = event["Records"][0]["s3"]["object"]["key"]

    print(f"Processing file: s3://{bucket}/{key}")

    s3 = boto3.client("s3")

    raw_object = s3.get_object(Bucket=bucket, Key=key)
    compressed = raw_object["Body"].read()

    try:
        raw_json_text = gzip.decompress(compressed).decode("utf-8")
    except Exception as e:
        print("[ERROR] Gzip decompression failed:", e)
        raise e

    raw_data = json.loads(raw_json_text)

    records = raw_data.get("Records", [])

    processed_lines = []

    for rec in records:
        flat = {
            "eventTime": rec.get("eventTime"),
            "eventName": rec.get("eventName"),
            "eventSource": rec.get("eventSource"),
            "awsRegion": rec.get("awsRegion"),
            "userIdentity": rec.get("userIdentity"),
            "sourceIPAddress": rec.get("sourceIPAddress"),
            "requestParameters": rec.get("requestParameters"),
            "responseElements": rec.get("responseElements"),
            "raw_event": rec
        }

        processed_lines.append(flat)

    # NDJSON encoding
    ndjson_text = "\n".join([json.dumps(line) for line in processed_lines])

    output_key = key.replace("raw/", "processed/").replace(".gz", ".json")

    s3.put_object(
        Bucket=bucket,
        Key=output_key,
        Body=ndjson_text.encode("utf-8")
    )

    print("Uploaded processed:", output_key)

    return {"status": "success", "processed_file": output_key}
