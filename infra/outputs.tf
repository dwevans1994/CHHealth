output "alb_dns_name" {
  description = "Public URL of the application"
  value       = "http://${aws_lb.main.dns_name}"
}
