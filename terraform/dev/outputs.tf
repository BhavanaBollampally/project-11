# outputs.tf — useful outputs for Project-11

output "s3_logs_bucket" {
  description = "Main logs S3 bucket name"
  value       = aws_s3_bucket.logs.bucket
}

output "lambda_name" {
  description = "Lambda function name"
  value       = try(aws_lambda_function.process_event.function_name, null)
}

output "ec2_public_ip" {
  description = "Public IP of EC2 (if created)"
  value       = try(aws_instance.project11_ec2.public_ip, "")
}

output "ec2_role_name" {
  description = "EC2 IAM role name"
  value       = try(aws_iam_role.ec2_role.name, "")
}
output "glue_database" {
  description = "Glue database name"
  value       = var.glue_database_name
}


output "athena_workgroup" {
  description = "Athena workgroup name"
  value       = aws_athena_workgroup.project11_wg.name
}

output "athena_results_s3" {
  description = "S3 location for Athena query results"
  value       = "s3://${aws_s3_bucket.logs.bucket}/${var.athena_results_prefix}"
}
