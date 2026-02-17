output "alb_dns_name" {
  description = "Public URL of the application"
  value       = "http://${aws_lb.main.dns_name}"
}

output "github_actions_role_arn" {
  description = "ARN to set as AWS_ROLE_ARN GitHub secret"
  value       = aws_iam_role.github_actions.arn
}

output "ecr_repository_url" {
  description = "ECR repository URL for CI"
  value       = aws_ecr_repository.app.repository_url
}
