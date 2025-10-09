  variable "aws_region" {}
variable "service_name" {}
variable "db_host" {}
variable "db_user" {}
variable "db_password" {}
variable "db_name" {}
variable "jwt_secret" {}
variable "jwt_ttl_seconds" {
  type    = number
  default = 3600
}