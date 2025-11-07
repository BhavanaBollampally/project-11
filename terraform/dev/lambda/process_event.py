import json
import boto3
import datetime

def lambda_handler(event, context):
    print("===== Lambda Triggered Successfully =====")
    print("Event received:", json.dumps(event))

    s3 = boto3.client("s3")

    for record in event.get("Records", []):
        bucket = record["s3"]["bucket"]["name"]
        key = record["s3"]["object"]["key"]

        # build metadata entry
        metadata = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "source_file": key,
            "event": record["eventName"]
        }

        # dynamic object name (one per trigger)
        dest_key = f"events/event_{key.replace('/', '_')}.json"

        s3.put_object(
            Bucket=bucket,
            Key=dest_key,
            Body=json.dumps(metadata)
        )

    print("Metadata written successfully.")
    return {"status": "ok"}
