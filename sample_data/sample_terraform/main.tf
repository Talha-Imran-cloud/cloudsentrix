# Sample Terraform file with intentional misconfigurations
# Used for CloudSentrix Terraform scan testing

# TF-001: Wildcard policy
resource "aws_iam_policy" "admin_policy" {
  name = "DangerousAdminPolicy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# TF-002: Public trust policy
resource "aws_iam_role" "public_role" {
  name = "PubliclyAssumableRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "sts:AssumeRole"
    }]
  })
}

# TF-003: AdministratorAccess attached
resource "aws_iam_role_policy_attachment" "admin_attach" {
  role       = aws_iam_role.public_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# TF-004: GCP public binding
resource "google_project_iam_binding" "public_binding" {
  project = "my-project"
  role    = "roles/storage.objectViewer"
  members = ["allUsers"]
}

# TF-005: GCP owner role
resource "google_project_iam_member" "owner_member" {
  project = "my-project"
  role    = "roles/owner"
  member  = "user:admin@company.com"
}

# TF-006: Azure Owner
resource "azurerm_role_assignment" "owner_assignment" {
  principal_id         = "aaaa-1111-bbbb-2222"
  role_definition_name = "Owner"
  scope                = "/subscriptions/sub-0001"
}

# TF-007: Hardcoded secret (safe to test with fake value)
resource "aws_iam_access_key" "bad_key" {
  user = "test-user"
}

# TF-009: Inline user policy
resource "aws_iam_user_policy" "inline_policy" {
  name = "InlineUserPolicy"
  user = "developer-bob"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "*"
    }]
  })
}

# Safe resource (should not trigger)
resource "aws_iam_role" "safe_role" {
  name = "SafeLambdaRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}
