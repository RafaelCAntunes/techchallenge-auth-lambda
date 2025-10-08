output "token_issuer_arn" {
  value = aws_lambda_function.token_issuer.arn
}

output "jwt_authorizer_arn" {
  value = aws_lambda_function.jwt_authorizer.arn
}