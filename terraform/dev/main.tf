provider "aws" {
  region = "ap-south-1"
}

resource "aws_s3_bucket" "logs" {
  bucket = "bhavana-p11-logs-dev-bhv123"
}

resource "aws_s3_bucket_versioning" "logs_versioning" {
  bucket = aws_s3_bucket.logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs_lifecycle" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "log-retention-rule"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }
  }
}

resource "aws_s3_object" "raw" {
  bucket = aws_s3_bucket.logs.id
  key    = "raw/"
}

resource "aws_s3_object" "processed" {
  bucket = aws_s3_bucket.logs.id
  key    = "processed/"
}

resource "aws_s3_object" "archived" {
  bucket = aws_s3_bucket.logs.id
  key    = "archived/"
}

resource "aws_s3_object" "athena_results" {
  bucket = aws_s3_bucket.logs.id
  key    = "athena-results/"
}

data "aws_iam_policy_document" "logs_bucket_policy" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.logs.arn,
      "${aws_s3_bucket.logs.arn}/*"
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "logs_bucket" {
  bucket = aws_s3_bucket.logs.id
  policy = data.aws_iam_policy_document.logs_bucket_policy.json
}

resource "aws_iam_role" "cloudwatch_to_s3" {
  name = "cloudwatch-to-s3-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "logs.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "cloudwatch_to_s3_policy" {
  name        = "cloudwatch-to-s3-policy"
  description = "Allows CloudWatch to write logs to S3 raw prefix"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:PutObject"
      ]
      Resource = "${aws_s3_bucket.logs.arn}/raw/*"
    }]
  })
}

# ---------- LAYER 6.1 : IAM ROLE FOR CLOUDTRAIL → CLOUDWATCH LOGS LINK ----------

resource "aws_iam_role" "cloudtrail_to_cw_role" {
  name = "cloudtrail-to-cw-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "cloudtrail_to_cw_policy" {
  role = aws_iam_role.cloudtrail_to_cw_role.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource = "${aws_cloudwatch_log_group.project11_log_group.arn}:*"
      }
    ]
  })
}









resource "aws_iam_role_policy_attachment" "attach_cloudwatch_policy" {
  role       = aws_iam_role.cloudwatch_to_s3.name
  policy_arn = aws_iam_policy.cloudwatch_to_s3_policy.arn
}

resource "aws_cloudtrail" "project11_trail" {
  name                          = "project11-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.logs.id
  s3_key_prefix                 = "raw/"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true
  depends_on = [
    aws_s3_bucket_policy.logs_bucket
  ]
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.project11_log_group.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_to_cw_role.arn

}

resource "aws_s3_bucket_policy" "cloudtrail_s3_policy" {
  bucket = aws_s3_bucket.logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.logs.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.logs.arn}/raw/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role" "glue_service_role" {
  name = "project11-glue-service-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "glue.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "glue_s3_read_policy" {
  name        = "glue-s3-read-policy"
  description = "Allows AWS Glue to read data from S3 processed and archived folders"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.logs.arn,
          "${aws_s3_bucket.logs.arn}/processed/*",
          "${aws_s3_bucket.logs.arn}/archived/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "glue_s3_read_attach" {
  role       = aws_iam_role.glue_service_role.name
  policy_arn = aws_iam_policy.glue_s3_read_policy.arn
}

resource "aws_glue_catalog_database" "project11_db" {
  name = "project11_logs_db"
}

resource "aws_glue_catalog_table" "project11_processed_table" {
  database_name = aws_glue_catalog_database.project11_db.name
  name          = "project11_processed"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "classification"  = "json"
    "compressionType" = "none"
    "typeOfData"      = "file"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.logs.bucket}/processed/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      name                  = "json"
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
    }

    columns {
      name = "eventTime"
      type = "string"
    }
    columns {
      name = "eventName"
      type = "string"
    }
    columns {
      name = "eventSource"
      type = "string"
    }
    columns {
      name = "awsRegion"
      type = "string"
    }
    columns {
      name = "userIdentity"
      type = "string"
    }
    columns {
      name = "sourceIPAddress"
      type = "string"
    }
    columns {
      name = "requestParameters"
      type = "string"
    }
    columns {
      name = "responseElements"
      type = "string"
    }
    columns {
      name = "raw_event"
      type = "string"
    }
  }
}

# Athena Workgroup for Project-11
resource "aws_athena_workgroup" "project11_wg" {
  name = "project11-athena-wg"

  configuration {
    result_configuration {
      output_location = "s3://${aws_s3_bucket.logs.bucket}/athena-results/"

      encryption_configuration {
        encryption_option = "SSE_S3" # Server-side encryption (S3 managed keys)
      }
    }
  }

  description   = "Workgroup for Project 11 Athena queries"
  state         = "ENABLED"
  force_destroy = true
}

# Athena Named Query for Project-11
resource "aws_athena_named_query" "project11_top_events" {
  name        = "top_events_query"
  description = "List top 10 most frequent CloudTrail events"
  database    = aws_glue_catalog_database.project11_db.name
  workgroup   = aws_athena_workgroup.project11_wg.name

  query = <<EOT
SELECT eventName, count(*) AS event_count
FROM ${aws_glue_catalog_database.project11_db.name}.${aws_glue_catalog_table.project11_processed_table.name}
GROUP BY eventName
ORDER BY event_count DESC
LIMIT 10;
EOT
}

resource "aws_cloudwatch_log_group" "project11_log_group" {
  name              = "/project11/monitoring"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_metric_filter" "access_denied_filter" {
  name           = "AccessDeniedFilter"
  log_group_name = aws_cloudwatch_log_group.project11_log_group.name

  # Match both AccessDenied and UnauthorizedOperation patterns
  pattern = "{ ($.errorCode = \"AccessDenied*\" || $.errorCode = \"Client.UnauthorizedOperation\") }"

  metric_transformation {
    name      = "AccessDeniedCount"
    namespace = "Project11/Monitoring"
    value     = "1"
  }
}


resource "aws_cloudwatch_metric_alarm" "access_denied_alarm" {
  alarm_name          = "Project11-AccessDenied-Alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = aws_cloudwatch_log_metric_filter.access_denied_filter.metric_transformation[0].name
  namespace           = "Project11/Monitoring"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  alarm_description   = "Triggers when 5+ AccessDenied events occur within 5 minutes"
  alarm_actions       = [aws_sns_topic.alerts_topic.arn]
}

resource "aws_sns_topic" "alerts_topic" {
  name = "project11-alerts"
}

resource "aws_sns_topic_subscription" "email_alert" {
  topic_arn = aws_sns_topic.alerts_topic.arn
  protocol  = "email"
  endpoint  = "bhavanabollampally3@gmail.com"
}








