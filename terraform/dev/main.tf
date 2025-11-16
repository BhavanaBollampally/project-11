provider "aws" {
  region = var.aws_region
}

resource "aws_s3_bucket" "logs" {
  bucket = var.s3_logs_bucket
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
        Effect = "Allow",
        Action = [
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
  
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.project11_log_group.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_to_cw_role.arn

}
############################################
resource "aws_s3_bucket_policy" "logs_bucket" {
  bucket = aws_s3_bucket.logs.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [

      # 1) Deny insecure HTTP access
      {
        Sid: "DenyInsecureTransport",
        Effect: "Deny",
        Principal: "*",
        Action: "s3:*",
        Resource: [
          aws_s3_bucket.logs.arn,
          "${aws_s3_bucket.logs.arn}/*"
        ],
        Condition: {
          Bool: {
            "aws:SecureTransport": "false"
          }
        }
      },

      # 2) CloudTrail requires ACL check on bucket
      {
        Sid: "AWSCloudTrailAclCheck",
        Effect: "Allow",
        Principal: {
          Service: "cloudtrail.amazonaws.com"
        },
        Action: "s3:GetBucketAcl",
        Resource: aws_s3_bucket.logs.arn
      },

      # 3) CloudTrail must be allowed to write to raw/ prefix
      {
        Sid: "AWSCloudTrailWrite",
        Effect: "Allow",
        Principal: {
          Service: "cloudtrail.amazonaws.com"
        },
        Action: "s3:PutObject",
        Resource: "${aws_s3_bucket.logs.arn}/raw/*",
        Condition: {
          StringEquals: {
            "s3:x-amz-acl": "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}


############################################
resource "aws_iam_role" "glue_service_role" {
  name = "project11-glue-service-role-v2"

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
##################################################################
# Glue S3 access policy (read raw, read processed, read archived)
resource "aws_iam_policy" "project11_glue_s3_policy" {
  name        = "project11-glue-s3-policy"
  description = "Glue access to raw CloudTrail logs and processed/archived data"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [

      # Allow listing bucket for all relevant prefixes
      {
        Effect = "Allow",
        Action = [
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ],
        Resource = aws_s3_bucket.logs.arn,
        Condition = {
          StringLike = {
            "s3:prefix" = [
              "${var.raw_prefix}*",
              "${var.raw_prefix}AWSLogs/*",
              "${var.raw_prefix}AWSLogs/*/CloudTrail/*",
              "${var.processed_prefix}*",
              "${var.archived_prefix}*",
              "${var.athena_results_prefix}*"
            ]
          }
        }
      },

      # Raw folder CloudTrail read
      {
        Effect = "Allow",
        Action = [
          "s3:GetObject"
        ],
        Resource = [
          "${aws_s3_bucket.logs.arn}/${var.raw_prefix}*",
          "${aws_s3_bucket.logs.arn}/${var.raw_prefix}AWSLogs/*"
        ]
      },

      # Processed + Archived folders read
      {
        Effect = "Allow",
        Action = [
          "s3:GetObject"
        ],
        Resource = [
          "${aws_s3_bucket.logs.arn}/${var.processed_prefix}*",
          "${aws_s3_bucket.logs.arn}/${var.archived_prefix}*"
        ]
      }
    ]
  })
}

##################################################################################################################################################################################################################################################################################################################
##############################################################################################################################
# Attach the policy to Glue role
resource "aws_iam_role_policy_attachment" "glue_s3_attach" {
  role       = aws_iam_role.glue_service_role.name
  policy_arn = aws_iam_policy.project11_glue_s3_policy.arn
}

# Attach AWS managed Glue service role policy
resource "aws_iam_role_policy_attachment" "glue_service_managed" {
  role       = aws_iam_role.glue_service_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
}

resource "aws_glue_catalog_database" "project11_db" {
  name = "project11_logs_db"
}
########################################################################################################
#######################################################################################################################
resource "aws_glue_catalog_table" "project11_processed_table" {
  database_name = aws_glue_catalog_database.project11_db.name
  name          = "project11_processed"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "classification"  = "json"
    "typeOfData"      = "file"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.logs.bucket}/processed/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      name                  = "json-serde"
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
    }

    columns {
      name = "eventtime"     # matches your JSON output
      type = "string"
    }
    columns {
      name = "eventname"
      type = "string"
    }
    columns {
      name = "eventsource"
      type = "string"
    }
    columns {
      name = "awsregion"
      type = "string"
    }
    columns {
      name = "useridentity"
      type = "string"
    }
    columns {
      name = "sourceipaddress"
      type = "string"
    }
    columns {
      name = "requestparameters"
      type = "string"
    }
    columns {
      name = "responseelements"
      type = "string"
    }
    columns {
      name = "raw_event"
      type = "string"
    }
  }
}
####################################################################################################################################################
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
  endpoint  = var.alerts_email
}


# ---------- LAYER 7 : LAMBDA EVENT TRIGGER ----------

resource "aws_iam_role" "lambda_exec_role" {
  name = "project11-lambda-exec-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "lambda.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "lambda_policy" {
  name = "lambda-basic-policy"
  role = aws_iam_role.lambda_exec_role.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "s3:GetObject",
          "s3:PutObject"
        ],
        Resource = "*"
      }
    ]
  })
}
###################################################################################################################################################################################################
resource "aws_lambda_function" "process_event" {
  function_name = "project11-process-event"
  filename      = "lambda_function.zip"
  handler       = "process_event.lambda_handler"
  runtime       = "python3.12"
  role          = aws_iam_role.lambda_exec_role.arn
  timeout       = 15

  source_code_hash = filebase64sha256("lambda_function.zip")
}


###############################################################################################################################################################################################################################################################################

resource "aws_lambda_permission" "allow_s3_invoke" {
  statement_id  = "AllowS3Invoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.process_event.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.logs.arn
}
##############################################################################################################################################################################################################################
resource "aws_s3_bucket_notification" "raw_trigger" {
  bucket = aws_s3_bucket.logs.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.process_event.arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = var.raw_prefix # "raw/"
  }

  depends_on = [aws_lambda_permission.allow_s3_invoke]
}

# ---------- LAYER 8.1 : EC2 IAM ROLE ----------
resource "aws_iam_role" "ec2_role" {
  name = "project11-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "ec2.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })
}
#####################################################
resource "aws_iam_policy" "ec2_s3_policy" {
  name        = "ec2-s3-policy"
  description = "Allow EC2 to write logs into S3 and push metrics to CloudWatch"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [

      # ✅ Allows listing only Terraform bucket
      {
        Effect = "Allow",
        Action = [
          "s3:ListBucket"
        ],
        Resource = "${aws_s3_bucket.logs.arn}"
      },

      # ✅ Allow Put/Get on BOTH buckets
      {
        Effect = "Allow",
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "cloudwatch:PutMetricData"
        ],
        Resource = [
          "${aws_s3_bucket.logs.arn}/*",
          "arn:aws:s3:::bhavana-monitor-logs/*"
        ]
      },

      # ✅ Needed for ListBucket on monitor bucket
      {
        Effect   = "Allow",
        Action   = ["s3:ListBucket"],
        Resource = "arn:aws:s3:::bhavana-monitor-logs"
      }
    ]
  })
}

# Attach the ec2_s3_policy to the EC2 role
resource "aws_iam_role_policy_attachment" "attach_ec2_s3_policy" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.ec2_s3_policy.arn
}

# Instance profile for EC2 to assume the role
resource "aws_iam_instance_profile" "ec2_profile" {
  name = "project11-ec2-profile"
  role = aws_iam_role.ec2_role.name
}

# Attach AWS managed SSM policy to EC2 role
resource "aws_iam_role_policy_attachment" "ec2_ssm_attach" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}


#########################################################
resource "aws_instance" "project11_ec2" {
  ami                  = var.ami
  instance_type        = var.instance_type
  key_name             = var.key_name
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name

  user_data = <<-EOF
              #!/bin/bash
              apt-get update -y
              apt-get install -y awscli
              echo "===== EC2 Bootstrap Started ====="
              aws s3 ls s3://${aws_s3_bucket.logs.bucket}/
              echo "===== EC2 Bootstrap Completed ====="
              EOF

  # ✅ SINGLE CONNECTION BLOCK — for both provisioners
  connection {
    type        = "ssh"
    user        = "ubuntu"
    private_key = file(var.private_key_path)
    host        = self.public_ip
  }

  ## =========================
  ## Copy monitor.sh to EC2
  ## =========================
  provisioner "file" {
    source      = "../scripts/monitor.sh"
    destination = "/home/ubuntu/monitor.sh"
  }

  ## =========================
  ## Set cron job to run every 2 mins
  ## =========================
  provisioner "remote-exec" {
    inline = [
      "chmod +x /home/ubuntu/monitor.sh",
      "crontab -l 2>/dev/null | { cat; echo '*/2 * * * * /home/ubuntu/monitor.sh'; } | crontab -"
    ]
  }

  tags = {
    Name    = "project11-ec2-instance"
    Project = "DevOps-Pipeline"
  }
}


