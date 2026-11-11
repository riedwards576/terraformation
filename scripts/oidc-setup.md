# GitHub OIDC → AWS (no long-lived keys)

Create once in AWS, per account. No secrets to rotate, no keys in GitHub.

## 1. Identity provider (once per account)
- IAM → Identity providers → Add provider → OpenID Connect
- URL: `https://token.actions.githubusercontent.com`
- Audience: `sts.amazonaws.com`
- Thumbprint: AWS fills this in (GitHub's root CA)

## 2. Three roles — least privilege, separate blast radius

| Role | Trust condition (`sub`) | Permissions |
|---|---|---|
| `github-tf-readonly` | `repo:<org>/<repo>:pull_request` | ReadOnlyAccess + S3/DynamoDB state read |
| `github-tf-dev` | `repo:<org>/<repo>:ref:refs/heads/main` | S3/DynamoDB state RW + dev resources only |
| `github-tf-prod` | `repo:<org>/<repo>:environment:prod` | S3/DynamoDB state RW + prod resources only |

Trust policy snippet (prod — note the `environment:prod` subject):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "repo:YOUR-ORG/YOUR-REPO:environment:prod"
      }
    }
  }]
}
```

## 3. GitHub variables (not secrets — ARNs aren't secret)
Repo → Settings → Secrets and variables → Actions → Variables:
- `AWS_ROLE_ARN_READONLY`
- `AWS_ROLE_ARN_DEV`
- `AWS_ROLE_ARN_PROD`

## 4. Prod approval gate
Repo → Settings → Environments → `prod` → Required reviewers: add 1-2 people.
No reviewer = no prod apply, even if the workflow runs.
