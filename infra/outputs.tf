output "alb_dns_name" {
  description = "Public URL of the application"
  value       = "http://${aws_lb.main.dns_name}"
}

output "ecr_repository_url" {
  description = "ECR repository URL for CI"
  value       = aws_ecr_repository.app.repository_url
}
