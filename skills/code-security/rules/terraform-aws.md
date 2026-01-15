---
title: Secure AWS Terraform Configurations
impact: HIGH
---

## Secure AWS Terraform Configurations

This guide provides security best practices for AWS Terraform configurations. Following these patterns helps prevent common security misconfigurations that could expose your infrastructure to attacks.

**Incorrect (EC2 - instance with public IP):**

```hcl
# ruleid: aws-ec2-has-public-ip
resource "aws_instance" "public" {
  ami           = "ami-12345"
  instance_type = "t3.micro"

  associate_public_ip_address = true
}
```

**Correct (EC2 - instance without public IP):**

```hcl
resource "aws_instance" "private" {
  ami           = "ami-12345"
  instance_type = "t3.micro"

  associate_public_ip_address = false
}
```

**Incorrect (EC2 - launch template with public IP):**

```hcl
# ruleid: aws-ec2-has-public-ip
resource "aws_launch_template" "public" {
  image_id      = "ami-12345"
  instance_type = "t3.micro"

  network_interfaces {
    associate_public_ip_address = true
  }
}
```

**Correct (EC2 - launch template without public IP):**

```hcl
resource "aws_launch_template" "private" {
  image_id      = "ami-12345"
  instance_type = "t3.micro"

  network_interfaces {
    associate_public_ip_address = false
  }
}
```

**Incorrect (EC2 - security group allowing public SSH access):**

```hcl
# ruleid: aws-ec2-security-group-allows-public-ingress
resource "aws_security_group_rule" "fail_open_1" {
  type        = "ingress"
  protocol    = "tcp"
  from_port   = 22
  to_port     = 22
  cidr_blocks = ["0.0.0.0/0"]
}
```

```hcl
resource "aws_security_group" "fail_open_1" {
  vpc_id = aws_vpc.example.id

  # ruleid: aws-ec2-security-group-allows-public-ingress
  ingress {
    protocol    = "tcp"
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

**Correct (EC2 - security group with restricted CIDR):**

```hcl
# ok: aws-ec2-security-group-allows-public-ingress
resource "aws_security_group_rule" "pass_inside_private_network_1" {
  type        = "ingress"
  protocol    = "tcp"
  from_port   = 22
  to_port     = 22
  cidr_blocks = ["10.0.0.0/8"]
}
```

```hcl
resource "aws_security_group" "pass_inside_private_network_1" {
  vpc_id = aws_vpc.example.id

  # ok: aws-ec2-security-group-allows-public-ingress
  ingress {
    protocol    = "tcp"
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["10.0.0.0/8"]
  }
}
```

**Incorrect (EBS - unencrypted volume):**

```hcl
# ruleid: aws-ebs-volume-unencrypted
resource "aws_ebs_volume" "fail_1" {
  availability_zone = "us-west-2a"
}

# ruleid: aws-ebs-volume-unencrypted
resource "aws_ebs_volume" "fail_2" {
  availability_zone = "us-west-2a"
  encrypted         = false
}
```

**Correct (EBS - encrypted volume):**

```hcl
# ok: aws-ebs-volume-unencrypted
resource "aws_ebs_volume" "pass" {
  availability_zone = "us-west-2a"
  encrypted         = true
}
```

**Incorrect (S3 - object without CMK encryption):**

```hcl
# ruleid: aws-s3-bucket-object-encrypted-with-cmk
resource "aws_s3_bucket_object" "fail" {
  bucket       = aws_s3_bucket.object_bucket.bucket
  key          = "tf-testing-obj-%[1]d-encrypted"
  content      = "Keep Calm and Carry On"
  content_type = "text/plain"
}
```

**Correct (S3 - object with CMK encryption):**

```hcl
resource "aws_s3_bucket_object" "pass" {
  bucket       = aws_s3_bucket.object_bucket.bucket
  key          = "tf-testing-obj-%[1]d-encrypted"
  content      = "Keep Calm and Carry On"
  content_type = "text/plain"
  kms_key_id   = aws_kms_key.example.arn
}
```

**Incorrect (RDS - without backup retention):**

```hcl
# ruleid: aws-rds-backup-no-retention
resource "aws_rds_cluster" "fail2" {
  backup_retention_period = 0
}

# ruleid: aws-rds-backup-no-retention
resource "aws_db_instance" "fail" {
  backup_retention_period = 0
}
```

**Correct (RDS - with backup retention):**

```hcl
resource "aws_rds_cluster" "pass" {
  backup_retention_period = 35
}

resource "aws_db_instance" "pass" {
  backup_retention_period = 35
}
```

**Incorrect (IAM - policy with wildcard admin access):**

```hcl
resource "aws_iam_policy" "fail3" {
  name = "fail3"
  path = "/"
  # ruleid: aws-iam-admin-policy
  policy = <<POLICY
{
  "Statement": [
    {
      "Action": "*",
      "Effect": "Allow",
      "Resource": "*",
      "Sid": ""
    }
  ],
  "Version": "2012-10-17"
}
POLICY
}
```

**Correct (IAM - policy with specific permissions):**

```hcl
resource "aws_iam_policy" "pass1" {
  name = "pass1"
  path = "/"
  policy = <<POLICY
{
  "Statement": [
    {
      "Action": [
        "s3:ListBucket*",
        "s3:HeadBucket",
        "s3:Get*"
      ],
      "Effect": "Allow",
      "Resource": [
        "arn:aws:s3:::b1",
        "arn:aws:s3:::b1/*",
        "arn:aws:s3:::b2",
        "arn:aws:s3:::b2/*"
      ],
      "Sid": ""
    },
    {
      "Action": "s3:PutObject*",
      "Effect": "Allow",
      "Resource": "arn:aws:s3:::b1/*",
      "Sid": ""
    }
  ],
  "Version": "2012-10-17"
}
POLICY
}
```

**Incorrect (IAM - wildcard AssumeRole policy):**

```hcl
resource "aws_iam_role" "bad" {
  name = var.role_name
  # ruleid: wildcard-assume-role
  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": "sts:AssumeRole",
      "Condition": {}
    }
  ]
}
POLICY
}
```

**Correct (IAM - restricted AssumeRole policy):**

```hcl
resource "aws_iam_role" "ok" {
  name = var.role_name
  # ok: wildcard-assume-role
  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root",
      "Condition": {}
    }
  ]
}
POLICY
}
```

**Incorrect (Lambda - with hard-coded credentials):**

```hcl
resource "aws_lambda_function" "fail" {
  function_name = "stest-env"
  role = ""
  runtime = "python3.8"

  environment {
    variables = {
      # ruleid: aws-lambda-environment-credentials
      AWS_ACCESS_KEY_ID     = "AKIAIOSFODNN7EXAMPLE",
      # ruleid: aws-lambda-environment-credentials
      AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      AWS_DEFAULT_REGION    = "us-west-2"
    }
  }
}
```

**Correct (Lambda - without credentials):**

```hcl
resource "aws_lambda_function" "pass" {
  function_name = "test-env"
  role = ""
  runtime = "python3.8"

  environment {
    variables = {
      AWS_DEFAULT_REGION = "us-west-2"
    }
  }
}
```

**Incorrect (Lambda - permission without source ARN):**

```hcl
# ruleid: aws-lambda-permission-unrestricted-source-arn
resource "aws_lambda_permission" "fail_1" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.func.function_name
  principal     = "sns.amazonaws.com"
}

# ruleid: aws-lambda-permission-unrestricted-source-arn
resource "aws_lambda_permission" "fail_3" {
  statement_id  = "AllowMyDemoAPIInvoke"
  action        = "lambda:InvokeFunction"
  function_name = "MyDemoFunction"
  principal     = "apigateway.amazonaws.com"
}
```

**Correct (Lambda - permission with source ARN):**

```hcl
# ok: aws-lambda-permission-unrestricted-source-arn
resource "aws_lambda_permission" "pass_1" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.func.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.default.arn
}

# ok: aws-lambda-permission-unrestricted-source-arn
resource "aws_lambda_permission" "pass_3" {
  statement_id  = "AllowMyDemoAPIInvoke"
  action        = "lambda:InvokeFunction"
  function_name = "MyDemoFunction"
  principal     = "apigateway.amazonaws.com"

  # The /* part allows invocation from any stage, method and resource path
  # within API Gateway.
  source_arn = "${aws_api_gateway_rest_api.MyDemoAPI.execution_arn}/*"
}
```

**Incorrect (KMS - key without rotation):**

```hcl
# ruleid: aws-kms-no-rotation
resource "aws_kms_key" "fail1" {
  description             = "KMS key 1"
  deletion_window_in_days = 10
}

# ruleid: aws-kms-no-rotation
resource "aws_kms_key" "fail2" {
  description             = "KMS key 1"
  deletion_window_in_days = 10
  enable_key_rotation = false
}
```

**Correct (KMS - key with rotation enabled):**

```hcl
resource "aws_kms_key" "pass1" {
  description             = "KMS key 1"
  deletion_window_in_days = 10
  enable_key_rotation = true
}
```

**Incorrect (SQS - unencrypted queue):**

```hcl
# ruleid: aws-sqs-queue-unencrypted
resource "aws_sqs_queue" "fail_1" {
  name = "terraform-example-queue"
}

# ruleid: aws-sqs-queue-unencrypted
resource "aws_sqs_queue" "fail_2" {
  name                    = "terraform-example-queue"
  sqs_managed_sse_enabled = false
}
```

**Correct (SQS - encrypted queue):**

```hcl
# ok: aws-sqs-queue-unencrypted
resource "aws_sqs_queue" "pass_1" {
  name                    = "terraform-example-queue"
  sqs_managed_sse_enabled = true
}

# ok: aws-sqs-queue-unencrypted
resource "aws_sqs_queue" "pass_2" {
  name                              = "terraform-example-queue"
  kms_master_key_id                 = "alias/aws/sqs"
  kms_data_key_reuse_period_seconds = 300
}
```

**Incorrect (SNS - unencrypted topic):**

```hcl
# ruleid: aws-sns-topic-unencrypted
resource "aws_sns_topic" "fail" {}
```

**Correct (SNS - encrypted topic):**

```hcl
# ok: aws-sns-topic-unencrypted
resource "aws_sns_topic" "pass" {
  kms_master_key_id = "someKey"
}
```

**Incorrect (DynamoDB - without CMK encryption):**

```hcl
# ruleid: aws-dynamodb-table-unencrypted
resource "aws_dynamodb_table" "default" {
  name           = "GameScores"
  billing_mode   = "PROVISIONED"
  read_capacity  = 20
  write_capacity = 20
  hash_key       = "UserId"
  range_key      = "UserId"

  attribute {
    name = "UserId"
    type = "S"
  }
}

# ruleid: aws-dynamodb-table-unencrypted
resource "aws_dynamodb_table" "encrypted_no_cmk" {
  name           = "GameScores"
  billing_mode   = "PROVISIONED"
  read_capacity  = 20
  write_capacity = 20
  hash_key       = "UserId"
  range_key      = "UserId"

  attribute {
    name = "UserId"
    type = "S"
  }

  server_side_encryption {
      enabled = true
  }
}
```

**Correct (DynamoDB - with CMK encryption):**

```hcl
resource "aws_dynamodb_table" "cmk" {
  name           = "GameScores"
  billing_mode   = "PROVISIONED"
  read_capacity  = 20
  write_capacity = 20
  hash_key       = "UserId"
  range_key      = "UserId"

  attribute {
    name = "UserId"
    type = "S"
  }

  server_side_encryption {
      enabled = true
      kms_key_arn = "arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"
  }
}
```

**Incorrect (ECR - with mutable tags):**

```hcl
# ruleid: aws-ecr-mutable-image-tags
resource "aws_ecr_repository" "fail_1" {
  name = "example"
}

# ruleid: aws-ecr-mutable-image-tags
resource "aws_ecr_repository" "fail_2" {
  name                 = "example"
  image_tag_mutability = "MUTABLE"
}
```

**Correct (ECR - with immutable tags):**

```hcl
# ok: aws-ecr-mutable-image-tags
resource "aws_ecr_repository" "pass" {
  name                 = "example"
  image_tag_mutability = "IMMUTABLE"
}
```

**Incorrect (CloudTrail - without encryption):**

```hcl
# ruleid: aws-cloudtrail-encrypted-with-cmk
resource "aws_cloudtrail" "fail" {
  name                          = "TRAIL"
  s3_bucket_name                = aws_s3_bucket.test.id
  include_global_service_events = true
}
```

**Correct (CloudTrail - with CMK encryption):**

```hcl
resource "aws_cloudtrail" "pass" {
  name                          = "TRAIL"
  s3_bucket_name                = aws_s3_bucket.test.id
  include_global_service_events = true
  kms_key_id                    = aws_kms_key.test.arn
}
```

**Incorrect (Elasticsearch - with insecure TLS):**

```hcl
# ruleid: aws-elasticsearch-insecure-tls-version
resource "aws_elasticsearch_domain" "badCode" {
  domain_name = "badCode"
  domain_endpoint_options {
    enforce_https = true
    tls_security_policy = "Policy-Min-TLS-1-0-2019-07"
  }
}
```

**Correct (Elasticsearch - with TLS 1.2):**

```hcl
resource "aws_elasticsearch_domain" "okCode" {
  domain_name = "okCode"
  domain_endpoint_options {
    enforce_https = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }
}
```

**Incorrect (Load Balancer - with insecure TLS):**

```hcl
resource "aws_lb_listener" "https_2016" {
  load_balancer_arn = var.aws_lb_arn
  protocol          = "HTTPS"
  port              = "443"
  # ruleid: insecure-load-balancer-tls-version
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = var.aws_lb_target_group_arn
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = var.aws_lb_arn
  # ruleid: insecure-load-balancer-tls-version
  protocol          = "HTTP"
  port              = "80"

  default_action {
    type             = "forward"
    target_group_arn = var.aws_lb_target_group_arn
  }
}
```

**Correct (Load Balancer - with TLS 1.2+):**

```hcl
resource "aws_lb_listener" "https_fs_1_2" {
  load_balancer_arn = var.aws_lb_arn
  protocol          = "HTTPS"
  port              = "443"
  # ok: insecure-load-balancer-tls-version
  ssl_policy        = "ELBSecurityPolicy-FS-1-2-Res-2019-08"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = var.aws_lb_target_group_arn
  }
}

resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = var.aws_lb_arn
  # ok: insecure-load-balancer-tls-version
  protocol          = "HTTP"
  port              = "80"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}
```

**Incorrect (VPC - subnet with public IP assignment):**

```hcl
# ruleid: aws-subnet-has-public-ip-address
resource "aws_subnet" "fail_1" {
  vpc_id                  = "vpc-123456"
  map_public_ip_on_launch = true
}

# ruleid: aws-subnet-has-public-ip-address
resource "aws_default_subnet" "fail_2" {
  availability_zone = "us-west-2a"
}
```

**Correct (VPC - subnet without public IP assignment):**

```hcl
# ok: aws-subnet-has-public-ip-address
resource "aws_subnet" "pass_1" {
  vpc_id = "vpc-123456"
}

# ok: aws-subnet-has-public-ip-address
resource "aws_subnet" "pass_2" {
  vpc_id                  = "vpc-123456"
  map_public_ip_on_launch = false
}

# ok: aws-subnet-has-public-ip-address
resource "aws_default_subnet" "pass_3" {
  availability_zone       = "us-west-2a"
  map_public_ip_on_launch = false
}
```

**Incorrect (CodeBuild - with unencrypted artifacts):**

```hcl
resource "aws_codebuild_project" "fail_1" {
  name         = "test-project"
  service_role = aws_iam_role.example.arn

  # ruleid: aws-codebuild-artifacts-unencrypted
  artifacts {
    encryption_disabled = true
    type                = "CODEPIPELINE"
  }

  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/standard:1.0"
    type         = "LINUX_CONTAINER"
  }

  source {
    type            = "GITHUB"
    location        = "https://github.com/mitchellh/packer.git"
    git_clone_depth = 1
  }
}
```

**Correct (CodeBuild - with encrypted artifacts):**

```hcl
resource "aws_codebuild_project" "pass_4" {
  name         = "test-project"
  service_role = aws_iam_role.example.arn

  # ok: aws-codebuild-artifacts-unencrypted
  artifacts {
    type                = "CODEPIPELINE"
    encryption_disabled = false
  }

  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/standard:1.0"
    type         = "LINUX_CONTAINER"
  }

  source {
    type            = "GITHUB"
    location        = "https://github.com/mitchellh/packer.git"
    git_clone_depth = 1
  }
}
```

**Incorrect (AWS Provider - with hard-coded credentials):**

```hcl
provider "aws" {
  region     = "us-west-2"
  access_key = "AKIAEXAMPLEKEY"
  # ruleid: aws-provider-static-credentials
  secret_key = "randomcharactersabcdef"
  profile = "customprofile"
}
```

**Correct (AWS Provider - using shared credentials file):**

```hcl
# ok: aws-provider-static-credentials
provider "aws" {
  region                  = "us-west-2"
  shared_credentials_file = "/Users/tf_user/.aws/creds"
  profile                 = "customprofile"
}
```
