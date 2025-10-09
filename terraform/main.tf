terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

terraform {
  backend "remote" {
    organization = "techchallenge-lanchonete"

    workspaces {
      name = "techchallenge-auth-lambda"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# --- IAM Role para Lambda ---
resource "aws_iam_role" "lambda_exec" {
  name = "${var.service_name}-lambda-exec"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# --- Lambda TokenIssuer ---
resource "aws_lambda_function" "token_issuer" {
  filename      = "../target/auth-lambda.jar"
  function_name = "${var.service_name}-token-issuer"
  handler       = "com.techchallenge.auth.TokenIssuerHandler"
  runtime       = "java17"
  role          = aws_iam_role.lambda_exec.arn
  memory_size   = 512
  timeout       = 20

  environment {
    variables = {
      DB_HOST         = var.db_host
      DB_USER         = var.db_user
      DB_PASSWORD     = var.db_password
      DB_NAME         = var.db_name
      JWT_SECRET      = var.jwt_secret
      JWT_TTL_SECONDS = tostring(var.jwt_ttl_seconds)
    }
  }
}

# --- Lambda JwtAuthorizer ---
resource "aws_lambda_function" "jwt_authorizer" {
  filename      = "../target/auth-lambda.jar"
  function_name = "${var.service_name}-jwt-authorizer"
  handler       = "com.techchallenge.auth.JwtAuthorizerHandler"
  runtime       = "java17"
  role          = aws_iam_role.lambda_exec.arn
  memory_size   = 512
  timeout       = 15

  environment {
    variables = {
      JWT_SECRET = var.jwt_secret
    }
  }
}