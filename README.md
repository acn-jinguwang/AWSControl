# AWSControl MCP Server

Claude Desktop / Claude.ai (mobile) から AWS インフラを操作する MCP サーバー。

## 構成

```
AWSControl/
├── .github/workflows/deploy.yml   # GitHub Actions（EC2 自動デプロイ）
├── aws_infra_mcp_server.py        # MCP サーバー本体（34ツール）
├── ec2_cloudformation.yaml        # EC2 インフラ構築テンプレート
└── README.md
```

## セットアップ

### 1. EC2 デプロイ（初回のみ）

```bash
aws cloudformation deploy \
  --template-file ec2_cloudformation.yaml \
  --stack-name AWSControl-mcp \
  --parameter-overrides \
    KeyPairName=your-key \
    ApiKey=your-api-key-here \
  --capabilities CAPABILITY_NAMED_IAM \
  --region ap-northeast-1
```

### 2. GitHub Secrets の設定

リポジトリの Settings → Secrets and variables → Actions に以下を追加：

| Secret 名 | 値 |
|---|---|
| `EC2_HOST` | EC2 の Elastic IP |
| `EC2_USER` | `ec2-user` |
| `EC2_SSH_KEY` | SSH 秘密鍵の内容（`-----BEGIN...`から全文） |

### 3. 初回ファイル配置

```bash
scp -i your-key.pem aws_infra_mcp_server.py ec2-user@<EC2-IP>:/opt/mcp/
ssh -i your-key.pem ec2-user@<EC2-IP> "sudo systemctl start mcp-aws"
```

### 4. Claude.ai への登録

Settings → Integrations → Add custom integration:
- URL: `http://<EC2-IP>/mcp`
- Header: `x-api-key: <your-api-key>`

## 自動デプロイ

`main` ブランチに `aws_infra_mcp_server.py` の変更をプッシュすると、GitHub Actions が自動的に EC2 にデプロイして MCP サービスを再起動します。

## ツール一覧（34個）

| カテゴリ | ツール |
|---|---|
| AWS接続 | hello_aws, check_aws_credentials |
| リージョン | list_available_regions |
| CloudFormation | validate, estimate_cost, deploy, change_set, status, events, list, delete, wait, generate |
| CDK | cdk_synth, cdk_deploy, cdk_destroy |
| Terraform | plan, apply, destroy |
| EC2 | list, start, stop, reboot |
| RDS | list, start, stop |
| ECS | list_services, scale_service |
| Scheduler | create, list, delete |
| 一括操作 | start_testspp, stop_testspp |
| 設定 | get_mcp_config |
