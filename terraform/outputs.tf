output "token_issuer_arn" {
  value = aws_lambda_function.token_issuer.arn
}

output "jwt_authorizer_arn" {
  value = aws_lambda_function.jwt_authorizer.arn
}

output "lambda_token_issuer_name" {
  description = "Lambda Token Issuer function name"
  value       = aws_lambda_function.token_issuer.function_name
}

output "lambda_jwt_authorizer_name" {
  description = "Lambda JWT Authorizer function name"
  value       = aws_lambda_function.jwt_authorizer.function_name
}