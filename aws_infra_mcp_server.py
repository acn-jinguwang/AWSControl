"""
AWS Infrastructure MCP Server

Claudeが生成したAWSアーキテクチャを自動的にAWSで構築するMCPサーバー。
CloudFormation / AWS CDK / Terraform のいずれかでインフラをデプロイできます。

提供ツール:
  [認証確認]
  - check_aws_credentials     : AWS接続・アカウント情報を確認
  - list_available_regions    : 利用可能なリージョン一覧

  [バリデーション]
  - validate_cloudformation_template : テンプレートの構文・論理チェック
  - estimate_stack_cost              : コスト見積もりURL生成

  [デプロイ]
  - deploy_stack      : スタック新規作成 / 更新（自動判定）
  - create_change_set : 本番変更前の影響範囲プレビュー

  [デプロイ待機]
  - wait_for_stack : スタック完了まで自動ポーリング待機

  [状態確認]
  - get_stack_status : 現在の状態・リソース・Outputs
  - get_stack_events : デプロイログ・エラー詳細

  [管理]
  - list_stacks  : スタック一覧
  - delete_stack : スタック削除

  [テンプレート生成]
  - generate_cloudformation_template : アーキテクチャ仕様からYAMLテンプレートを生成
    対応サービス: VPC, SecurityGroup, EC2, S3, RDS, Lambda, IAMRole,
                  APIGateway, SQS, DynamoDB, SNS, ELB, ECS, CloudFront

  [CDK サポート] ※ npm install -g aws-cdk + pip install aws-cdk-lib 必要
  - cdk_synth   : CDK Python コードからCloudFormationテンプレートを生成
  - cdk_deploy  : CDK スタックをデプロイ
  - cdk_destroy : CDK スタックを削除

  [Terraform サポート] ※ Terraform CLI インストール必要
  - terraform_plan    : Terraform 変更プランを表示
  - terraform_apply   : Terraform 設定を適用
  - terraform_destroy : Terraform リソースを削除

  [MCP設定]
  - get_mcp_config : Claude Desktop への登録設定JSONと手順を返す

典型的なワークフロー（CloudFormation）:
  1. check_aws_credentials    → 認証確認
  2. generate_cloudformation_template → アーキテクチャからテンプレート生成
  3. validate_cloudformation_template → テンプレート検証
  4. estimate_stack_cost       → コスト見積もり（任意）
  5. deploy_stack              → デプロイ開始
  6. wait_for_stack            → 完了待機
  7. get_stack_status          → 結果・Outputs確認
"""

import json
import math
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

import botocore.exceptions  # 軽量(0.25s)、except句で参照されるためモジュールレベルで必要
from mcp.server.fastmcp import FastMCP
# boto3, yaml は遅延インポート（各関数内で import）→ 起動時間短縮

# ─────────────────────────────────────────
# OAuth プロバイダー（EC2 リモートアクセス用）
# MCP_OAUTH_ISSUER 環境変数が設定されている場合のみ有効
# ─────────────────────────────────────────
_OAUTH_ISSUER = os.environ.get("MCP_OAUTH_ISSUER")

if _OAUTH_ISSUER:
    import secrets as _secrets
    import time as _time
    from mcp.server.auth.provider import (
        OAuthAuthorizationServerProvider,
        AuthorizationCode,
        AuthorizationParams,
        AccessToken,
        RefreshToken,
        construct_redirect_uri,
    )
    from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
    from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

    class _AutoApproveOAuthProvider(OAuthAuthorizationServerProvider):
        """インメモリ OAuth プロバイダー（Claude.ai からの接続を自動承認）"""

        def __init__(self):
            self._clients: dict = {}
            self._auth_codes: dict = {}
            self._access_tokens: dict = {}

        async def get_client(self, client_id: str):
            return self._clients.get(client_id)

        async def register_client(self, client_info: OAuthClientInformationFull) -> None:
            self._clients[client_info.client_id] = client_info

        async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
            # Claude.ai からの接続のみ自動承認（redirect_uri で判定）
            if not str(params.redirect_uri).startswith("https://claude.ai/"):
                from mcp.server.auth.provider import AuthorizeError
                raise AuthorizeError(error="access_denied", error_description="Only claude.ai connections are allowed")
            code = _secrets.token_urlsafe(32)
            self._auth_codes[code] = AuthorizationCode(
                code=code,
                client_id=client.client_id,
                redirect_uri=str(params.redirect_uri),
                redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
                code_challenge=params.code_challenge,
                expires_at=_time.time() + 300,
                scopes=params.scopes,
                resource=params.resource,
            )
            return construct_redirect_uri(str(params.redirect_uri), code=code, state=params.state)

        async def load_authorization_code(self, client, authorization_code: str):
            return self._auth_codes.get(authorization_code)

        async def exchange_authorization_code(self, client, auth_code: AuthorizationCode) -> OAuthToken:
            self._auth_codes.pop(auth_code.code, None)
            token = _secrets.token_urlsafe(32)
            self._access_tokens[token] = AccessToken(
                token=token,
                client_id=client.client_id,
                scopes=auth_code.scopes,
                expires_at=None,
            )
            return OAuthToken(
                access_token=token,
                token_type="Bearer",
                scope=" ".join(auth_code.scopes),
            )

        async def load_refresh_token(self, client, refresh_token: str):
            return None

        async def exchange_refresh_token(self, client, refresh_token, scopes) -> OAuthToken:
            raise NotImplementedError("Refresh tokens not supported")

        async def load_access_token(self, token: str):
            return self._access_tokens.get(token)

        async def revoke_token(self, token, token_type_hint=None) -> None:
            if isinstance(token, AccessToken):
                self._access_tokens.pop(token.token, None)

    _oauth_provider = _AutoApproveOAuthProvider()
    _auth_settings = AuthSettings(
        issuer_url=_OAUTH_ISSUER,
        resource_server_url=_OAUTH_ISSUER,
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=["claudeai"],
            default_scopes=["claudeai"],
        ),
    )

# ─────────────────────────────────────────
# サーバー初期化
# ─────────────────────────────────────────
if _OAUTH_ISSUER:
    from mcp.server.transport_security import TransportSecuritySettings
    mcp = FastMCP(
        "aws-infra-tools",
        auth_server_provider=_oauth_provider,
        auth=_auth_settings,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )
else:
    mcp = FastMCP("aws-infra-tools")

DEFAULT_REGION = "ap-northeast-1"


# ─────────────────────────────────────────
# 共通ヘルパー
# ─────────────────────────────────────────

def _cf_client(region: str):
    import boto3
    return boto3.client("cloudformation", region_name=region)


def _params_to_boto(params: dict) -> list:
    """{"Key": "Value"} → [{"ParameterKey": "Key", "ParameterValue": "Value"}]"""
    if not params:
        return []
    return [{"ParameterKey": k, "ParameterValue": str(v)} for k, v in params.items()]


def _tags_to_boto(tags: dict) -> list:
    """{"Key": "Value"} → [{"Key": "Key", "Value": "Value"}]"""
    if not tags:
        return []
    return [{"Key": k, "Value": str(v)} for k, v in tags.items()]


def _handle_aws_error(e: Exception, context: str) -> dict:
    """AWS例外を構造化エラー dict に変換する共通ヘルパー"""
    if isinstance(e, botocore.exceptions.ClientError):
        error_code = e.response["Error"]["Code"]
        error_msg = e.response["Error"]["Message"]
        guidance_map = {
            "AccessDenied": (
                "IAM権限が不足しています。"
                "cloudformation:* および関連サービス（ec2:*, rds:* 等）の"
                "権限をIAMポリシーに追加してください。"
            ),
            "ValidationError": (
                "テンプレートまたはパラメータが無効です。"
                "CloudFormation の構文・リソースプロパティを確認してください。"
            ),
            "AlreadyExistsException": (
                "同名のスタックが既に存在します。"
                "deploy_stack は既存スタックを自動更新するので、再度お試しください。"
            ),
            "LimitExceededException": (
                "AWSリソースの上限に達しました。"
                "Service Quotas でクォータ引き上げを申請してください。"
            ),
            "InsufficientCapabilitiesException": (
                "IAMリソースを作成するには CAPABILITY_IAM が必要です。"
                "deploy_stack の capabilities パラメータに ['CAPABILITY_IAM'] を指定してください。"
            ),
            "StackNotFoundException": (
                "指定したスタックが見つかりません。"
                "list_stacks でスタック名を確認してください。"
            ),
        }
        return {
            "status": "error",
            "error_type": "aws_client_error",
            "error_code": error_code,
            "error_message": error_msg,
            "guidance": guidance_map.get(error_code, f"AWSエラー: {error_msg}"),
            "context": context,
        }
    if isinstance(e, botocore.exceptions.NoCredentialsError):
        return {
            "status": "error",
            "error_type": "no_credentials",
            "guidance": (
                "AWS認証情報が設定されていません。"
                "check_aws_credentials ツールを呼んで確認し、"
                "aws configure コマンドでセットアップしてください。"
            ),
            "context": context,
        }
    if isinstance(e, botocore.exceptions.EndpointConnectionError):
        return {
            "status": "error",
            "error_type": "network_error",
            "guidance": "AWSエンドポイントに接続できません。ネットワーク・プロキシ設定を確認してください。",
            "context": context,
        }
    if isinstance(e, botocore.exceptions.WaiterError):
        return {
            "status": "error",
            "error_type": "waiter_error",
            "error_message": str(e),
            "guidance": (
                "スタック操作がタイムアウトまたは失敗しました。"
                "get_stack_events でエラー詳細を確認してください。"
            ),
            "context": context,
        }
    return {
        "status": "error",
        "error_type": "unexpected_error",
        "error_message": str(e),
        "context": context,
    }


def _detect_capabilities(template_body: str) -> list:
    """テンプレートに IAM リソースが含まれる場合 CAPABILITY_IAM を自動返却"""
    if "AWS::IAM::" in template_body:
        return ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"]
    return []


def _fmt_ts(dt) -> str:
    """datetime を ISO8601 文字列に変換"""
    if dt is None:
        return ""
    if hasattr(dt, "isoformat"):
        return dt.isoformat()
    return str(dt)


def _get_stack_error_events(cf_client, stack_name: str) -> list:
    """スタックの失敗イベントを収集して返す内部ヘルパー"""
    try:
        response = cf_client.describe_stack_events(StackName=stack_name)
        error_events = []
        for e in response.get("StackEvents", []):
            status = e.get("ResourceStatus", "")
            reason = e.get("ResourceStatusReason", "")
            if "FAILED" in status and reason and "User Initiated" not in reason:
                error_events.append({
                    "timestamp": _fmt_ts(e.get("Timestamp")),
                    "resource_type": e.get("ResourceType", ""),
                    "logical_id": e.get("LogicalResourceId", ""),
                    "status": status,
                    "reason": reason,
                })
        return error_events
    except Exception:
        return []


def _run_subprocess(
    cmd: list,
    cwd: str,
    timeout: int = 300,
    env: dict = None,
) -> dict:
    """
    サブプロセスを安全に実行して結果を返す内部ヘルパー。
    戻り値: {"returncode": int, "stdout": str, "stderr": str, "timed_out": bool}
    """
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as e:
        return {
            "returncode": -1,
            "stdout": (e.stdout or b"").decode("utf-8", errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or ""),
            "stderr": (e.stderr or b"").decode("utf-8", errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or ""),
            "timed_out": True,
        }
    except FileNotFoundError as e:
        return {"returncode": -2, "stdout": "", "stderr": str(e), "timed_out": False}
    except Exception as e:
        return {"returncode": -3, "stdout": "", "stderr": str(e), "timed_out": False}


def _find_cli(name: str) -> str | None:
    """
    CLIツールのパスを探す（Windows の .cmd 拡張子に対応）。
    見つからない場合は None を返す。
    """
    path = shutil.which(name)
    if path:
        return path
    if sys.platform == "win32":
        for suffix in (".cmd", ".ps1", ".bat"):
            path = shutil.which(name + suffix)
            if path:
                return path
    return None


def _make_temp_dir() -> str:
    """一時ディレクトリを作成してパスを返す"""
    return tempfile.mkdtemp(prefix="mcp_aws_")


def _cleanup_temp_dir(path: str) -> None:
    """一時ディレクトリを安全に削除する"""
    try:
        if path and os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
    except Exception:
        pass


# ─────────────────────────────────────────
# ショートカット（ツール＋プロンプト両対応）
# ─────────────────────────────────────────

@mcp.tool()
def hello_aws() -> dict:
    """
    AWS接続確認のショートカットです。
    「Hello AWS」「hello aws」「AWS接続確認」「接続確認」と入力すると呼び出されます。
    AWS の接続状態・認証情報・アカウントID・リージョンを確認して返します。
    check_aws_credentials と同等の機能です。

    Returns:
        status, account_id, user_arn, region, message を含む dict
    """
    try:
        import boto3
        sts = boto3.client("sts")
        identity = sts.get_caller_identity()
        session = boto3.session.Session()
        return {
            "status": "ok",
            "account_id": identity["Account"],
            "user_arn": identity["Arn"],
            "user_id": identity["UserId"],
            "region": session.region_name or DEFAULT_REGION,
            "message": "AWS に接続できています。",
        }
    except Exception as e:
        return _handle_aws_error(e, "hello_aws")


@mcp.prompt()
def hello_aws_prompt() -> str:
    """Hello AWS — AWS接続確認（/hello_aws_prompt で起動）"""
    return "hello_aws ツールを呼び出して、AWS の接続状態と認証情報を確認してください。"


# ─────────────────────────────────────────
# カテゴリ1: AWS認証確認
# ─────────────────────────────────────────

@mcp.tool()
def check_aws_credentials() -> dict:
    """
    現在設定されているAWS認証情報と接続可能なアカウントを確認します。
    最初に必ず呼び出して、AWS接続が正しく設定されているか確認してください。

    Returns:
        status, account_id, user_arn, region, message を含む dict
    """
    try:
        import boto3
        sts = boto3.client("sts")
        identity = sts.get_caller_identity()
        session = boto3.session.Session()
        return {
            "status": "ok",
            "account_id": identity["Account"],
            "user_arn": identity["Arn"],
            "user_id": identity["UserId"],
            "region": session.region_name or DEFAULT_REGION,
            "message": "AWS認証情報は正常に設定されています。",
        }
    except Exception as e:
        return _handle_aws_error(e, "check_aws_credentials")


@mcp.tool()
def list_available_regions() -> dict:
    """
    CloudFormation が利用可能なAWSリージョン一覧を返します。

    Returns:
        regions リストを含む dict
    """
    try:
        import boto3
        ec2 = boto3.client("ec2", region_name=DEFAULT_REGION)
        response = ec2.describe_regions(AllRegions=False)
        regions = sorted([r["RegionName"] for r in response["Regions"]])
        return {"status": "ok", "regions": regions, "total": len(regions)}
    except Exception as e:
        return _handle_aws_error(e, "list_available_regions")


# ─────────────────────────────────────────
# カテゴリ2: テンプレートバリデーション
# ─────────────────────────────────────────

@mcp.tool()
def validate_cloudformation_template(
    template_body: str,
    template_format: str = "yaml",
) -> dict:
    """
    CloudFormation テンプレートの構文・論理バリデーションをAWS APIで実行します。
    deploy_stack の前に必ずこのツールを呼んでください。

    Args:
        template_body:   CloudFormation テンプレートの文字列（YAML または JSON）
        template_format: "yaml" または "json"

    Returns:
        valid(bool), parameters, capabilities, description, errors を含む dict
    """
    try:
        import boto3
        import yaml
        # YAML → JSON 変換（AWS API は JSON/YAML どちらも受け付けるが確認のため）
        if template_format.lower() == "yaml":
            parsed = yaml.safe_load(template_body)
            template_str = json.dumps(parsed)
        else:
            template_str = template_body

        cf = boto3.client("cloudformation", region_name=DEFAULT_REGION)
        response = cf.validate_template(TemplateBody=template_str)

        parameters = [
            {
                "key": p.get("ParameterKey", ""),
                "default_value": p.get("DefaultValue", "（なし）"),
                "no_echo": p.get("NoEcho", False),
                "description": p.get("Description", ""),
            }
            for p in response.get("Parameters", [])
        ]

        return {
            "status": "ok",
            "valid": True,
            "description": response.get("Description", ""),
            "parameters": parameters,
            "capabilities": response.get("Capabilities", []),
            "capabilities_reason": response.get("CapabilitiesReason", ""),
        }
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "ValidationError":
            return {
                "status": "ok",
                "valid": False,
                "errors": [e.response["Error"]["Message"]],
                "guidance": "テンプレートの構文またはリソース定義を見直してください。",
            }
        return _handle_aws_error(e, "validate_cloudformation_template")
    except yaml.YAMLError as e:
        return {
            "status": "error",
            "error_type": "yaml_parse_error",
            "error_message": str(e),
            "guidance": "YAML の構文が正しくありません。インデントやコロンを確認してください。",
        }
    except Exception as e:
        return _handle_aws_error(e, "validate_cloudformation_template")


@mcp.tool()
def estimate_stack_cost(
    template_body: str,
    stack_name: str,
    parameters: dict = None,
    region: str = DEFAULT_REGION,
) -> dict:
    """
    CloudFormation スタックのデプロイコストをAWS Cost Calculator で見積もります。

    Args:
        template_body: テンプレート文字列（YAML/JSON）
        stack_name:    スタック名（見積もりの識別に使用）
        parameters:    {"KeyName": "Value"} 形式のパラメータ
        region:        対象リージョン

    Returns:
        estimate_url（AWS Calculator URL）を含む dict
    """
    try:
        cf = _cf_client(region)
        boto_params = _params_to_boto(parameters)
        kwargs = {"TemplateBody": template_body}
        if boto_params:
            kwargs["Parameters"] = boto_params

        response = cf.estimate_template_cost(**kwargs)
        return {
            "status": "ok",
            "estimate_url": response.get("Url", ""),
            "message": (
                "AWSコスト見積もりURLを生成しました。"
                "ブラウザで開いて詳細を確認してください。"
            ),
        }
    except Exception as e:
        return _handle_aws_error(e, f"estimate_stack_cost(stack_name={stack_name})")


# ─────────────────────────────────────────
# カテゴリ3: デプロイ
# ─────────────────────────────────────────

@mcp.tool()
def deploy_stack(
    stack_name: str,
    template_body: str,
    parameters: dict = None,
    region: str = DEFAULT_REGION,
    tags: dict = None,
    capabilities: list = None,
    on_failure: str = "ROLLBACK",
) -> dict:
    """
    CloudFormation スタックを新規作成または更新します。
    スタックが存在しない場合は create_stack、存在する場合は update_stack を自動判定します。
    このツールはデプロイを開始するだけです。完了確認には get_stack_status または
    get_stack_events を使ってください。

    Args:
        stack_name:   スタックの識別名（例: "my-web-app-prod"）
        template_body: CloudFormation テンプレート文字列（YAML/JSON）
        parameters:   {"KeyName": "Value"} 形式のパラメータ
        region:       デプロイ先リージョン（デフォルト: ap-northeast-1）
        tags:         {"Environment": "prod"} 形式のタグ
        capabilities: ["CAPABILITY_IAM"] 等。省略時はテンプレートから自動検出
        on_failure:   新規作成失敗時の動作 "ROLLBACK" | "DO_NOTHING" | "DELETE"

    Returns:
        action("CREATE"|"UPDATE"), stack_id, status, message を含む dict
    """
    try:
        cf = _cf_client(region)
        boto_params = _params_to_boto(parameters)
        boto_tags = _tags_to_boto(tags)
        caps = capabilities if capabilities is not None else _detect_capabilities(template_body)

        # スタック存在確認
        stack_exists = False
        try:
            desc = cf.describe_stacks(StackName=stack_name)
            current_status = desc["Stacks"][0]["StackStatus"]
            # REVIEW_IN_PROGRESS はまだ作成途中なので create 扱い
            if current_status != "REVIEW_IN_PROGRESS":
                stack_exists = True
        except botocore.exceptions.ClientError as e:
            if "does not exist" in str(e):
                stack_exists = False
            else:
                raise

        common_kwargs = {
            "StackName": stack_name,
            "TemplateBody": template_body,
        }
        if boto_params:
            common_kwargs["Parameters"] = boto_params
        if boto_tags:
            common_kwargs["Tags"] = boto_tags
        if caps:
            common_kwargs["Capabilities"] = caps

        if stack_exists:
            response = cf.update_stack(**common_kwargs)
            action = "UPDATE"
        else:
            response = cf.create_stack(
                **common_kwargs,
                OnFailure=on_failure,
            )
            action = "CREATE"

        return {
            "status": "ok",
            "action": action,
            "stack_id": response.get("StackId", ""),
            "stack_name": stack_name,
            "region": region,
            "message": (
                f"スタック '{stack_name}' の{action}を開始しました。"
                "get_stack_events でデプロイ進捗を確認してください。"
            ),
        }
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "ValidationError" and "No updates" in str(e):
            return {
                "status": "ok",
                "action": "NO_CHANGE",
                "stack_name": stack_name,
                "message": "テンプレートに変更がないため、更新はスキップされました。",
            }
        return _handle_aws_error(e, f"deploy_stack(stack_name={stack_name})")
    except Exception as e:
        return _handle_aws_error(e, f"deploy_stack(stack_name={stack_name})")


@mcp.tool()
def create_change_set(
    stack_name: str,
    template_body: str,
    parameters: dict = None,
    region: str = DEFAULT_REGION,
    change_set_name: str = None,
) -> dict:
    """
    既存スタックへの変更をプレビューするチェンジセットを作成します。
    本番環境へのデプロイ前に影響範囲（追加/変更/削除されるリソース）を確認するために使用します。

    Args:
        stack_name:      対象スタック名（存在しない場合は新規作成用チェンジセットを作成）
        template_body:   新しいテンプレート文字列（YAML/JSON）
        parameters:      {"KeyName": "Value"} 形式のパラメータ
        region:          リージョン
        change_set_name: チェンジセット名（省略時は自動生成）

    Returns:
        change_set_id, changes（追加/変更/削除リソース一覧）を含む dict
    """
    try:
        cf = _cf_client(region)
        cs_name = change_set_name or f"changeset-{uuid.uuid4().hex[:8]}"
        boto_params = _params_to_boto(parameters)
        caps = _detect_capabilities(template_body)

        # スタック存在確認でチェンジセットタイプを決定
        change_set_type = "UPDATE"
        try:
            cf.describe_stacks(StackName=stack_name)
        except botocore.exceptions.ClientError as e:
            if "does not exist" in str(e):
                change_set_type = "CREATE"
            else:
                raise

        kwargs = {
            "StackName": stack_name,
            "ChangeSetName": cs_name,
            "TemplateBody": template_body,
            "ChangeSetType": change_set_type,
        }
        if boto_params:
            kwargs["Parameters"] = boto_params
        if caps:
            kwargs["Capabilities"] = caps

        create_resp = cf.create_change_set(**kwargs)
        cs_id = create_resp.get("Id", "")

        # チェンジセット完成を待機（最大30秒）
        waiter = cf.get_waiter("change_set_create_complete")
        try:
            waiter.wait(
                ChangeSetName=cs_name,
                StackName=stack_name,
                WaiterConfig={"Delay": 3, "MaxAttempts": 10},
            )
        except botocore.exceptions.WaiterError:
            pass  # タイムアウトでも現状を返す

        # 変更内容を取得
        desc = cf.describe_change_set(ChangeSetName=cs_name, StackName=stack_name)
        changes = []
        for c in desc.get("Changes", []):
            rc = c.get("ResourceChange", {})
            changes.append({
                "action": rc.get("Action", ""),          # Add / Modify / Remove
                "resource_type": rc.get("ResourceType", ""),
                "logical_id": rc.get("LogicalResourceId", ""),
                "physical_id": rc.get("PhysicalResourceId", ""),
                "replacement": rc.get("Replacement", ""),  # True / False / Conditional
            })

        return {
            "status": "ok",
            "change_set_id": cs_id,
            "change_set_name": cs_name,
            "change_set_type": change_set_type,
            "execution_status": desc.get("ExecutionStatus", ""),
            "changes": changes,
            "message": (
                f"{len(changes)} 件のリソース変更があります。"
                "内容を確認後 deploy_stack でデプロイしてください。"
            ),
        }
    except Exception as e:
        return _handle_aws_error(e, f"create_change_set(stack_name={stack_name})")


# ─────────────────────────────────────────
# カテゴリ4: 状態確認
# ─────────────────────────────────────────

@mcp.tool()
def get_stack_status(
    stack_name: str,
    region: str = DEFAULT_REGION,
) -> dict:
    """
    指定スタックの現在の状態・リソース一覧・Outputs を取得します。

    Args:
        stack_name: スタック名またはスタックID
        region:     リージョン

    Returns:
        stack_name, status, outputs, resources を含む dict
    """
    try:
        cf = _cf_client(region)

        # スタック情報
        stack_resp = cf.describe_stacks(StackName=stack_name)
        stack = stack_resp["Stacks"][0]

        outputs = [
            {
                "key": o.get("OutputKey", ""),
                "value": o.get("OutputValue", ""),
                "description": o.get("Description", ""),
                "export_name": o.get("ExportName", ""),
            }
            for o in stack.get("Outputs", [])
        ]

        # リソース一覧
        resources_resp = cf.describe_stack_resources(StackName=stack_name)
        resources = [
            {
                "logical_id": r.get("LogicalResourceId", ""),
                "physical_id": r.get("PhysicalResourceId", ""),
                "resource_type": r.get("ResourceType", ""),
                "status": r.get("ResourceStatus", ""),
                "status_reason": r.get("ResourceStatusReason", ""),
            }
            for r in resources_resp.get("StackResources", [])
        ]

        return {
            "status": "ok",
            "stack_name": stack.get("StackName", ""),
            "stack_status": stack.get("StackStatus", ""),
            "stack_status_reason": stack.get("StackStatusReason", ""),
            "description": stack.get("Description", ""),
            "created_at": _fmt_ts(stack.get("CreationTime")),
            "updated_at": _fmt_ts(stack.get("LastUpdatedTime")),
            "outputs": outputs,
            "resources": resources,
        }
    except Exception as e:
        return _handle_aws_error(e, f"get_stack_status(stack_name={stack_name})")


@mcp.tool()
def get_stack_events(
    stack_name: str,
    region: str = DEFAULT_REGION,
    max_events: int = 20,
) -> dict:
    """
    スタックのイベントログ（デプロイ進捗・エラー詳細）を取得します。
    deploy_stack 実行後にこのツールを繰り返し呼んでデプロイ完了を確認してください。

    Args:
        stack_name: スタック名
        region:     リージョン
        max_events: 取得するイベント数（デフォルト20件）

    Returns:
        events（timestamp, resource_type, logical_id, status, reason）を含む dict
    """
    try:
        cf = _cf_client(region)
        response = cf.describe_stack_events(StackName=stack_name)

        events = []
        for e in response.get("StackEvents", [])[:max_events]:
            events.append({
                "timestamp": _fmt_ts(e.get("Timestamp")),
                "resource_type": e.get("ResourceType", ""),
                "logical_id": e.get("LogicalResourceId", ""),
                "physical_id": e.get("PhysicalResourceId", ""),
                "status": e.get("ResourceStatus", ""),
                "reason": e.get("ResourceStatusReason", ""),
            })

        # スタック全体の現在ステータス
        stack_resp = cf.describe_stacks(StackName=stack_name)
        stack_status = stack_resp["Stacks"][0].get("StackStatus", "UNKNOWN")

        is_complete = stack_status in (
            "CREATE_COMPLETE", "UPDATE_COMPLETE", "DELETE_COMPLETE",
            "ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
        )
        is_failed = "FAILED" in stack_status or "ROLLBACK" in stack_status

        return {
            "status": "ok",
            "stack_name": stack_name,
            "stack_status": stack_status,
            "is_complete": is_complete,
            "is_failed": is_failed,
            "events": events,
            "message": (
                "デプロイが完了しました。get_stack_status で Outputs を確認してください。"
                if is_complete and not is_failed
                else "デプロイが失敗またはロールバックされました。events の reason を確認してください。"
                if is_failed
                else "デプロイ進行中です。再度 get_stack_events を呼んで進捗を確認してください。"
            ),
        }
    except Exception as e:
        return _handle_aws_error(e, f"get_stack_events(stack_name={stack_name})")


# ─────────────────────────────────────────
# カテゴリ5: 一覧・削除
# ─────────────────────────────────────────

@mcp.tool()
def list_stacks(
    region: str = DEFAULT_REGION,
    status_filter: list = None,
) -> dict:
    """
    指定リージョンのCloudFormationスタック一覧を返します。

    Args:
        region:        リージョン
        status_filter: 絞り込むステータスのリスト
                       例: ["CREATE_COMPLETE", "UPDATE_COMPLETE"]
                       省略時はアクティブなスタックのみ（DELETE_COMPLETE を除く）

    Returns:
        stacks リスト（stack_name, status, description, created_at）を含む dict
    """
    try:
        cf = _cf_client(region)

        active_statuses = [
            "CREATE_IN_PROGRESS", "CREATE_FAILED", "CREATE_COMPLETE",
            "ROLLBACK_IN_PROGRESS", "ROLLBACK_FAILED", "ROLLBACK_COMPLETE",
            "DELETE_IN_PROGRESS", "DELETE_FAILED",
            "UPDATE_IN_PROGRESS", "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS",
            "UPDATE_COMPLETE", "UPDATE_FAILED",
            "UPDATE_ROLLBACK_IN_PROGRESS", "UPDATE_ROLLBACK_FAILED",
            "UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS",
            "UPDATE_ROLLBACK_COMPLETE",
            "REVIEW_IN_PROGRESS", "IMPORT_IN_PROGRESS",
            "IMPORT_COMPLETE", "IMPORT_ROLLBACK_IN_PROGRESS",
            "IMPORT_ROLLBACK_FAILED", "IMPORT_ROLLBACK_COMPLETE",
        ]
        filters = status_filter if status_filter else active_statuses

        response = cf.list_stacks(StackStatusFilter=filters)
        stacks = [
            {
                "stack_name": s.get("StackName", ""),
                "stack_id": s.get("StackId", ""),
                "status": s.get("StackStatus", ""),
                "description": s.get("TemplateDescription", ""),
                "created_at": _fmt_ts(s.get("CreationTime")),
                "deleted_at": _fmt_ts(s.get("DeletionTime")),
            }
            for s in response.get("StackSummaries", [])
        ]

        return {
            "status": "ok",
            "region": region,
            "stacks": stacks,
            "total": len(stacks),
        }
    except Exception as e:
        return _handle_aws_error(e, f"list_stacks(region={region})")


@mcp.tool()
def delete_stack(
    stack_name: str,
    region: str = DEFAULT_REGION,
    retain_resources: list = None,
) -> dict:
    """
    CloudFormation スタックとその管理リソースを削除します。
    削除すると元に戻せません。実行前に必ずユーザーに確認を求めてください。

    Args:
        stack_name:        削除するスタック名
        region:            リージョン
        retain_resources:  削除せずに保持するリソースの Logical ID リスト
                           例: ["S3BucketLogs"]（データが残っている S3 バケット等）

    Returns:
        status, message を含む dict
    """
    try:
        cf = _cf_client(region)
        kwargs = {"StackName": stack_name}
        if retain_resources:
            kwargs["RetainResources"] = retain_resources

        cf.delete_stack(**kwargs)
        return {
            "status": "ok",
            "stack_name": stack_name,
            "region": region,
            "message": (
                f"スタック '{stack_name}' の削除を開始しました。"
                "get_stack_events で進捗を確認できます。"
            ),
        }
    except Exception as e:
        return _handle_aws_error(e, f"delete_stack(stack_name={stack_name})")


# ─────────────────────────────────────────
# カテゴリ6: デプロイ待機
# ─────────────────────────────────────────

@mcp.tool()
def wait_for_stack(
    stack_name: str,
    wait_type: str = "auto",
    region: str = DEFAULT_REGION,
    timeout_seconds: int = 600,
) -> dict:
    """
    CloudFormation スタックの操作完了まで待機します。
    deploy_stack / delete_stack の直後に呼んで、完了を確認してください。

    Args:
        stack_name:       スタック名またはスタックID
        wait_type:        "create" | "update" | "delete" | "auto"（デフォルト）
                          "auto" の場合は現在の StackStatus から自動判定します
        region:           リージョン
        timeout_seconds:  最大待機秒数（デフォルト: 600秒）

    Returns:
        final_status, outputs, resources, elapsed_seconds を含む dict
    """
    import time
    start_time = time.time()

    try:
        cf = _cf_client(region)

        # wait_type の自動判定
        if wait_type == "auto":
            try:
                desc = cf.describe_stacks(StackName=stack_name)
                current_status = desc["Stacks"][0].get("StackStatus", "")
            except botocore.exceptions.ClientError as e:
                if "does not exist" in str(e):
                    # スタックが存在しない = DELETE_COMPLETE 相当
                    return {
                        "status": "ok",
                        "stack_name": stack_name,
                        "final_status": "DELETE_COMPLETE",
                        "elapsed_seconds": round(time.time() - start_time, 1),
                        "outputs": [],
                        "resources": [],
                        "message": f"スタック '{stack_name}' は既に削除済みです。",
                    }
                raise

            # 既に終端ステータスの場合は即返却
            terminal_statuses = {
                "CREATE_COMPLETE", "UPDATE_COMPLETE", "DELETE_COMPLETE",
                "CREATE_FAILED", "ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
                "UPDATE_FAILED", "ROLLBACK_FAILED", "DELETE_FAILED",
                "UPDATE_ROLLBACK_FAILED",
            }
            if current_status in terminal_statuses:
                elapsed = round(time.time() - start_time, 1)
                is_ok = current_status in {"CREATE_COMPLETE", "UPDATE_COMPLETE", "DELETE_COMPLETE"}
                outputs, resources = [], []
                if current_status != "DELETE_COMPLETE":
                    try:
                        stack_resp = cf.describe_stacks(StackName=stack_name)
                        s = stack_resp["Stacks"][0]
                        outputs = [{"key": o.get("OutputKey",""), "value": o.get("OutputValue",""), "description": o.get("Description","")} for o in s.get("Outputs", [])]
                        res_resp = cf.describe_stack_resources(StackName=stack_name)
                        resources = [{"logical_id": r.get("LogicalResourceId",""), "resource_type": r.get("ResourceType",""), "status": r.get("ResourceStatus","")} for r in res_resp.get("StackResources", [])]
                    except Exception:
                        pass
                return {
                    "status": "ok" if is_ok else "error",
                    "stack_name": stack_name,
                    "final_status": current_status,
                    "elapsed_seconds": elapsed,
                    "outputs": outputs,
                    "resources": resources,
                    "message": f"スタック '{stack_name}' はすでに終端ステータス ({current_status}) です。",
                }

            # IN_PROGRESS からwaiterを決定
            if "DELETE" in current_status:
                resolved_type = "delete"
            elif "UPDATE" in current_status:
                resolved_type = "update"
            else:
                resolved_type = "create"
        else:
            resolved_type = wait_type.lower()

        waiter_map = {
            "create": "stack_create_complete",
            "update": "stack_update_complete",
            "delete": "stack_delete_complete",
        }
        waiter_name = waiter_map.get(resolved_type, "stack_create_complete")

        max_attempts = max(1, math.ceil(timeout_seconds / 30))
        waiter = cf.get_waiter(waiter_name)
        waiter.wait(
            StackName=stack_name,
            WaiterConfig={"Delay": 30, "MaxAttempts": max_attempts},
        )

        # 成功時の情報収集
        elapsed = round(time.time() - start_time, 1)
        outputs, resources = [], []
        final_status = "UNKNOWN"
        if resolved_type != "delete":
            try:
                stack_resp = cf.describe_stacks(StackName=stack_name)
                s = stack_resp["Stacks"][0]
                final_status = s.get("StackStatus", "UNKNOWN")
                outputs = [{"key": o.get("OutputKey",""), "value": o.get("OutputValue",""), "description": o.get("Description","")} for o in s.get("Outputs", [])]
                res_resp = cf.describe_stack_resources(StackName=stack_name)
                resources = [{"logical_id": r.get("LogicalResourceId",""), "resource_type": r.get("ResourceType",""), "status": r.get("ResourceStatus","")} for r in res_resp.get("StackResources", [])]
            except Exception:
                pass
        else:
            final_status = "DELETE_COMPLETE"

        return {
            "status": "ok",
            "stack_name": stack_name,
            "final_status": final_status,
            "elapsed_seconds": elapsed,
            "outputs": outputs,
            "resources": resources,
            "message": (
                f"スタック '{stack_name}' の操作が完了しました ({final_status})。"
                f"所要時間: {elapsed}秒"
            ),
        }

    except botocore.exceptions.WaiterError as e:
        elapsed = round(time.time() - start_time, 1)
        # タイムアウト vs 実際の失敗を区別するためにステータスを再確認
        error_type = "waiter_timeout"
        actual_status = "UNKNOWN"
        error_events = []
        try:
            desc = cf.describe_stacks(StackName=stack_name)
            actual_status = desc["Stacks"][0].get("StackStatus", "UNKNOWN")
            if "FAILED" in actual_status or ("ROLLBACK" in actual_status and actual_status != "UPDATE_ROLLBACK_COMPLETE"):
                error_type = "stack_failed"
                error_events = _get_stack_error_events(cf, stack_name)
        except Exception:
            pass

        return {
            "status": "error",
            "error_type": error_type,
            "stack_name": stack_name,
            "final_status": actual_status,
            "elapsed_seconds": elapsed,
            "error_events": error_events,
            "guidance": (
                f"タイムアウト ({timeout_seconds}秒) しました。get_stack_events で進捗を確認してください。"
                if error_type == "waiter_timeout"
                else "スタック操作が失敗しました。error_events の reason を確認してください。"
            ),
            "message": str(e),
        }
    except Exception as e:
        return _handle_aws_error(e, f"wait_for_stack(stack_name={stack_name})")


# ─────────────────────────────────────────
# カテゴリ7: テンプレート生成
# ─────────────────────────────────────────

def _gen_vpc(logical_id: str, config: dict) -> tuple:
    """VPC + サブネット + IGW + ルートテーブルを生成"""
    resources = {}
    outputs = {}
    cidr = config.get("cidr", "10.0.0.0/16")
    enable_dns = config.get("enable_dns", True)

    resources[logical_id] = {
        "Type": "AWS::EC2::VPC",
        "Properties": {
            "CidrBlock": cidr,
            "EnableDnsHostnames": enable_dns,
            "EnableDnsSupport": enable_dns,
            "Tags": [{"Key": "Name", "Value": logical_id}],
        },
    }
    outputs[f"{logical_id}Id"] = {
        "Description": f"{logical_id} VPC ID",
        "Value": {"Ref": logical_id},
    }

    igw_id = f"{logical_id}IGW"
    resources[igw_id] = {"Type": "AWS::EC2::InternetGateway", "Properties": {"Tags": [{"Key": "Name", "Value": igw_id}]}}
    attach_id = f"{logical_id}IGWAttach"
    resources[attach_id] = {"Type": "AWS::EC2::VPCGatewayAttachment", "Properties": {"VpcId": {"Ref": logical_id}, "InternetGatewayId": {"Ref": igw_id}}}

    pub_rt_id = f"{logical_id}PublicRT"
    resources[pub_rt_id] = {"Type": "AWS::EC2::RouteTable", "Properties": {"VpcId": {"Ref": logical_id}, "Tags": [{"Key": "Name", "Value": pub_rt_id}]}}
    pub_route_id = f"{logical_id}PublicRoute"
    resources[pub_route_id] = {"Type": "AWS::EC2::Route", "DependsOn": attach_id, "Properties": {"RouteTableId": {"Ref": pub_rt_id}, "DestinationCidrBlock": "0.0.0.0/0", "GatewayId": {"Ref": igw_id}}}

    for subnet_cfg in config.get("subnets", []):
        sn_id = subnet_cfg.get("logical_id", f"{logical_id}Subnet")
        sn_cidr = subnet_cfg.get("cidr", "10.0.1.0/24")
        is_public = subnet_cfg.get("public", True)
        az_index = subnet_cfg.get("az", 0)
        resources[sn_id] = {
            "Type": "AWS::EC2::Subnet",
            "Properties": {
                "VpcId": {"Ref": logical_id},
                "CidrBlock": sn_cidr,
                "MapPublicIpOnLaunch": is_public,
                "AvailabilityZone": {"Fn::Select": [az_index, {"Fn::GetAZs": ""}]},
                "Tags": [{"Key": "Name", "Value": sn_id}],
            },
        }
        outputs[f"{sn_id}Id"] = {"Description": f"{sn_id} Subnet ID", "Value": {"Ref": sn_id}}
        if is_public:
            assoc_id = f"{sn_id}RTAssoc"
            resources[assoc_id] = {"Type": "AWS::EC2::SubnetRouteTableAssociation", "Properties": {"SubnetId": {"Ref": sn_id}, "RouteTableId": {"Ref": pub_rt_id}}}

    return resources, outputs


def _gen_security_group(logical_id: str, config: dict) -> tuple:
    ingress_rules = []
    for rule in config.get("ingress", []):
        ingress_rules.append({
            "IpProtocol": rule.get("protocol", "tcp"),
            "FromPort": rule.get("from_port", 80),
            "ToPort": rule.get("to_port", 80),
            "CidrIp": rule.get("cidr", "0.0.0.0/0"),
        })
    resources = {
        logical_id: {
            "Type": "AWS::EC2::SecurityGroup",
            "Properties": {
                "GroupDescription": config.get("description", f"{logical_id} Security Group"),
                "VpcId": {"Ref": config["vpc_ref"]} if "vpc_ref" in config else {"Ref": "AWS::NoValue"},
                "SecurityGroupIngress": ingress_rules,
                "Tags": [{"Key": "Name", "Value": logical_id}],
            },
        }
    }
    outputs = {f"{logical_id}Id": {"Description": f"{logical_id} Security Group ID", "Value": {"Fn::GetAtt": [logical_id, "GroupId"]}}}
    return resources, outputs


def _gen_ec2(logical_id: str, config: dict) -> tuple:
    props = {
        "InstanceType": config.get("instance_type", "t3.micro"),
        "ImageId": config.get("ami", "ami-0abc000000000000"),
        "Tags": [{"Key": "Name", "Value": logical_id}],
    }
    if "subnet_ref" in config:
        props["SubnetId"] = {"Ref": config["subnet_ref"]}
    if "security_group_refs" in config:
        props["SecurityGroupIds"] = [{"Ref": sg} for sg in config["security_group_refs"]]
    if "key_name_param" in config:
        props["KeyName"] = {"Ref": config["key_name_param"]}
    if "user_data" in config:
        props["UserData"] = {"Fn::Base64": config["user_data"]}
    resources = {logical_id: {"Type": "AWS::EC2::Instance", "Properties": props}}
    outputs = {
        f"{logical_id}Id": {"Description": f"{logical_id} Instance ID", "Value": {"Ref": logical_id}},
        f"{logical_id}PublicIp": {"Description": f"{logical_id} Public IP", "Value": {"Fn::GetAtt": [logical_id, "PublicIp"]}},
    }
    return resources, outputs


def _gen_s3(logical_id: str, config: dict) -> tuple:
    props = {}
    if config.get("versioning"):
        props["VersioningConfiguration"] = {"Status": "Enabled"}
    if config.get("encryption"):
        props["BucketEncryption"] = {"ServerSideEncryptionConfiguration": [{"ServerSideEncryptionByDefault": {"SSEAlgorithm": config["encryption"]}}]}
    if config.get("public_access_block", True):
        props["PublicAccessBlockConfiguration"] = {"BlockPublicAcls": True, "BlockPublicPolicy": True, "IgnorePublicAcls": True, "RestrictPublicBuckets": True}
    resources = {logical_id: {"Type": "AWS::S3::Bucket", "Properties": props}}
    outputs = {
        f"{logical_id}Name": {"Description": f"{logical_id} Bucket Name", "Value": {"Ref": logical_id}},
        f"{logical_id}Arn": {"Description": f"{logical_id} Bucket ARN", "Value": {"Fn::GetAtt": [logical_id, "Arn"]}},
    }
    return resources, outputs


def _gen_rds(logical_id: str, config: dict) -> tuple:
    resources = {}
    subnet_group_id = f"{logical_id}SubnetGroup"
    subnet_refs = [{"Ref": s} for s in config.get("subnet_group_refs", [])]
    if subnet_refs:
        resources[subnet_group_id] = {
            "Type": "AWS::RDS::DBSubnetGroup",
            "Properties": {"DBSubnetGroupDescription": f"{logical_id} subnet group", "SubnetIds": subnet_refs},
        }
    props = {
        "DBInstanceClass": config.get("instance_class", "db.t3.micro"),
        "Engine": config.get("engine", "mysql"),
        "EngineVersion": config.get("engine_version", "8.0"),
        "DBName": config.get("db_name", "appdb"),
        "MasterUsername": {"Ref": config["master_username_param"]} if "master_username_param" in config else "admin",
        "MasterUserPassword": {"Ref": config["master_password_param"]} if "master_password_param" in config else "ChangeMe123!",
        "AllocatedStorage": str(config.get("storage", 20)),
        "MultiAZ": config.get("multi_az", False),
        "StorageType": "gp2",
        "DeletionProtection": False,
    }
    if subnet_refs:
        props["DBSubnetGroupName"] = {"Ref": subnet_group_id}
    resources[logical_id] = {"Type": "AWS::RDS::DBInstance", "Properties": props}
    outputs = {
        f"{logical_id}Endpoint": {"Description": f"{logical_id} DB Endpoint", "Value": {"Fn::GetAtt": [logical_id, "Endpoint.Address"]}},
        f"{logical_id}Port": {"Description": f"{logical_id} DB Port", "Value": {"Fn::GetAtt": [logical_id, "Endpoint.Port"]}},
    }
    return resources, outputs


def _gen_lambda(logical_id: str, config: dict) -> tuple:
    code = {}
    if "code_s3_bucket_ref" in config:
        code["S3Bucket"] = {"Ref": config["code_s3_bucket_ref"]}
        code["S3Key"] = config.get("code_s3_key", "lambda/function.zip")
    else:
        code["ZipFile"] = config.get("inline_code", "def handler(event, context): return {}")
    props = {
        "Runtime": config.get("runtime", "python3.13"),
        "Handler": config.get("handler", "index.handler"),
        "Code": code,
        "MemorySize": config.get("memory", 128),
        "Timeout": config.get("timeout", 30),
        "Role": {"Fn::GetAtt": [config["role_ref"], "Arn"]} if "role_ref" in config else "arn:aws:iam::123456789012:role/placeholder",
    }
    if "environment" in config:
        props["Environment"] = {"Variables": config["environment"]}
    resources = {logical_id: {"Type": "AWS::Lambda::Function", "Properties": props}}
    outputs = {f"{logical_id}Arn": {"Description": f"{logical_id} Function ARN", "Value": {"Fn::GetAtt": [logical_id, "Arn"]}}}
    return resources, outputs


def _gen_iam_role(logical_id: str, config: dict) -> tuple:
    service = config.get("assumed_by", "lambda.amazonaws.com")
    props = {
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}],
        },
    }
    if "managed_policies" in config:
        props["ManagedPolicyArns"] = config["managed_policies"]
    resources = {logical_id: {"Type": "AWS::IAM::Role", "Properties": props}}
    outputs = {f"{logical_id}Arn": {"Description": f"{logical_id} Role ARN", "Value": {"Fn::GetAtt": [logical_id, "Arn"]}}}
    return resources, outputs


def _gen_api_gateway(logical_id: str, config: dict) -> tuple:
    api_name = config.get("name", logical_id)
    stage = config.get("stage_name", "v1")
    resources = {}
    resources[logical_id] = {"Type": "AWS::ApiGateway::RestApi", "Properties": {"Name": api_name}}
    deploy_id = f"{logical_id}Deployment"
    resources[deploy_id] = {
        "Type": "AWS::ApiGateway::Deployment",
        "DependsOn": logical_id,
        "Properties": {"RestApiId": {"Ref": logical_id}},
    }
    stage_id = f"{logical_id}Stage"
    resources[stage_id] = {
        "Type": "AWS::ApiGateway::Stage",
        "Properties": {"RestApiId": {"Ref": logical_id}, "DeploymentId": {"Ref": deploy_id}, "StageName": stage},
    }
    outputs = {
        f"{logical_id}Url": {
            "Description": f"{logical_id} API URL",
            "Value": {"Fn::Sub": f"https://${{${logical_id}}}.execute-api.${{AWS::Region}}.amazonaws.com/{stage}"},
        }
    }
    return resources, outputs


def _gen_sqs(logical_id: str, config: dict) -> tuple:
    props = {
        "VisibilityTimeout": config.get("visibility_timeout", 30),
        "MessageRetentionPeriod": config.get("retention_seconds", 345600),
    }
    if config.get("fifo"):
        props["FifoQueue"] = True
    resources = {logical_id: {"Type": "AWS::SQS::Queue", "Properties": props}}
    outputs = {
        f"{logical_id}Url": {"Description": f"{logical_id} Queue URL", "Value": {"Ref": logical_id}},
        f"{logical_id}Arn": {"Description": f"{logical_id} Queue ARN", "Value": {"Fn::GetAtt": [logical_id, "Arn"]}},
    }
    return resources, outputs


def _gen_dynamodb(logical_id: str, config: dict) -> tuple:
    pk = config.get("partition_key", {"name": "Id", "type": "S"})
    attrs = [{"AttributeName": pk["name"], "AttributeType": pk["type"]}]
    key_schema = [{"AttributeName": pk["name"], "KeyType": "HASH"}]
    if "sort_key" in config:
        sk = config["sort_key"]
        attrs.append({"AttributeName": sk["name"], "AttributeType": sk["type"]})
        key_schema.append({"AttributeName": sk["name"], "KeyType": "RANGE"})
    props = {
        "AttributeDefinitions": attrs,
        "KeySchema": key_schema,
        "BillingMode": config.get("billing_mode", "PAY_PER_REQUEST"),
    }
    if "ttl_attribute" in config:
        props["TimeToLiveSpecification"] = {"AttributeName": config["ttl_attribute"], "Enabled": True}
    resources = {logical_id: {"Type": "AWS::DynamoDB::Table", "Properties": props}}
    outputs = {
        f"{logical_id}Name": {"Description": f"{logical_id} Table Name", "Value": {"Ref": logical_id}},
        f"{logical_id}Arn": {"Description": f"{logical_id} Table ARN", "Value": {"Fn::GetAtt": [logical_id, "Arn"]}},
    }
    return resources, outputs


def _gen_sns(logical_id: str, config: dict) -> tuple:
    props = {}
    if config.get("display_name"):
        props["DisplayName"] = config["display_name"]
    resources = {logical_id: {"Type": "AWS::SNS::Topic", "Properties": props}}
    outputs = {f"{logical_id}Arn": {"Description": f"{logical_id} Topic ARN", "Value": {"Ref": logical_id}}}
    return resources, outputs


def _gen_elb(logical_id: str, config: dict) -> tuple:
    resources = {}
    lb_type = config.get("type", "application")
    subnets = [{"Ref": s} for s in config.get("subnet_refs", [])]
    resources[logical_id] = {
        "Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
        "Properties": {"Type": lb_type, "Subnets": subnets, "Scheme": config.get("scheme", "internet-facing")},
    }
    tg_id = f"{logical_id}TG"
    resources[tg_id] = {
        "Type": "AWS::ElasticLoadBalancingV2::TargetGroup",
        "Properties": {
            "Port": config.get("port", 80),
            "Protocol": config.get("protocol", "HTTP"),
            "VpcId": {"Ref": config["vpc_ref"]} if "vpc_ref" in config else {"Ref": "AWS::NoValue"},
            "TargetType": config.get("target_type", "instance"),
        },
    }
    listener_id = f"{logical_id}Listener"
    resources[listener_id] = {
        "Type": "AWS::ElasticLoadBalancingV2::Listener",
        "Properties": {
            "LoadBalancerArn": {"Ref": logical_id},
            "Port": config.get("port", 80),
            "Protocol": config.get("protocol", "HTTP"),
            "DefaultActions": [{"Type": "forward", "TargetGroupArn": {"Ref": tg_id}}],
        },
    }
    outputs = {f"{logical_id}Dns": {"Description": f"{logical_id} DNS Name", "Value": {"Fn::GetAtt": [logical_id, "DNSName"]}}}
    return resources, outputs


def _gen_ecs(logical_id: str, config: dict) -> tuple:
    resources = {}
    cluster_id = f"{logical_id}Cluster"
    resources[cluster_id] = {"Type": "AWS::ECS::Cluster", "Properties": {"ClusterName": config.get("cluster_name", cluster_id)}}
    td_id = f"{logical_id}TaskDef"
    container_defs = config.get("containers", [{"name": "app", "image": "nginx:latest", "cpu": 256, "memory": 512}])
    resources[td_id] = {
        "Type": "AWS::ECS::TaskDefinition",
        "Properties": {
            "Family": td_id,
            "Cpu": str(config.get("cpu", 256)),
            "Memory": str(config.get("memory", 512)),
            "NetworkMode": "awsvpc",
            "RequiresCompatibilities": ["FARGATE"],
            "ContainerDefinitions": container_defs,
        },
    }
    outputs = {f"{cluster_id}Arn": {"Description": f"{cluster_id} ARN", "Value": {"Fn::GetAtt": [cluster_id, "Arn"]}}}
    return resources, outputs


def _gen_cloudfront(logical_id: str, config: dict) -> tuple:
    origin_domain = config.get("origin_domain", "example.com")
    props = {
        "DistributionConfig": {
            "Enabled": True,
            "DefaultCacheBehavior": {
                "ViewerProtocolPolicy": "redirect-to-https",
                "AllowedMethods": ["GET", "HEAD"],
                "CachedMethods": ["GET", "HEAD"],
                "TargetOriginId": "Origin1",
                "ForwardedValues": {"QueryString": False, "Cookies": {"Forward": "none"}},
            },
            "Origins": [{"Id": "Origin1", "DomainName": origin_domain, "CustomOriginConfig": {"HTTPPort": 80, "HTTPSPort": 443, "OriginProtocolPolicy": "https-only"}}],
        }
    }
    if "s3_bucket_ref" in config:
        props["DistributionConfig"]["Origins"] = [{
            "Id": "Origin1",
            "DomainName": {"Fn::GetAtt": [config["s3_bucket_ref"], "RegionalDomainName"]},
            "S3OriginConfig": {"OriginAccessIdentity": ""},
        }]
    resources = {logical_id: {"Type": "AWS::CloudFront::Distribution", "Properties": props}}
    outputs = {
        f"{logical_id}Domain": {"Description": f"{logical_id} Distribution Domain", "Value": {"Fn::GetAtt": [logical_id, "DomainName"]}},
        f"{logical_id}Id": {"Description": f"{logical_id} Distribution ID", "Value": {"Ref": logical_id}},
    }
    return resources, outputs


_RESOURCE_GENERATORS = {
    "VPC": _gen_vpc,
    "SecurityGroup": _gen_security_group,
    "EC2": _gen_ec2,
    "S3": _gen_s3,
    "RDS": _gen_rds,
    "Lambda": _gen_lambda,
    "IAMRole": _gen_iam_role,
    "APIGateway": _gen_api_gateway,
    "SQS": _gen_sqs,
    "DynamoDB": _gen_dynamodb,
    "SNS": _gen_sns,
    "ELB": _gen_elb,
    "ECS": _gen_ecs,
    "CloudFront": _gen_cloudfront,
}


@mcp.tool()
def generate_cloudformation_template(
    architecture_spec: dict,
    stack_description: str = "",
    output_format: str = "yaml",
) -> dict:
    """
    アーキテクチャ仕様からCloudFormationテンプレートをローカルで生成します。
    AWS APIへの接続は不要です。生成後は validate_cloudformation_template で検証してください。

    Args:
        architecture_spec: アーキテクチャ仕様 dict。以下のキーを持ちます:
            parameters: {"ParamName": {"type": "String", "default": "val", "description": "説明"}}
            services:   [{"type": "S3", "logical_id": "MyBucket", "config": {...}}, ...]
            outputs:    [{"key": "MyKey", "value_ref": "MyBucket", "attribute": "Arn", "description": "説明"}]
          サービスタイプ: VPC, SecurityGroup, EC2, S3, RDS, Lambda, IAMRole,
                        APIGateway, SQS, DynamoDB, SNS, ELB, ECS, CloudFront
        stack_description: テンプレートの Description フィールド
        output_format:    "yaml"（デフォルト）または "json"

    Returns:
        template_body, resource_count, warnings, next_steps を含む dict
    """
    all_resources = {}
    all_outputs = {}
    warnings = []

    # Parameters セクション生成
    parameters_section = {}
    for param_name, param_cfg in architecture_spec.get("parameters", {}).items():
        param_def = {"Type": param_cfg.get("type", "String")}
        if "default" in param_cfg:
            param_def["Default"] = param_cfg["default"]
        if "description" in param_cfg:
            param_def["Description"] = param_cfg["description"]
        if param_cfg.get("no_echo"):
            param_def["NoEcho"] = True
        parameters_section[param_name] = param_def

    # Resources / Outputs 生成
    for svc in architecture_spec.get("services", []):
        svc_type = svc.get("type", "")
        logical_id = svc.get("logical_id", f"{svc_type}Resource")
        config = svc.get("config", {})
        gen_fn = _RESOURCE_GENERATORS.get(svc_type)
        if gen_fn is None:
            warnings.append(f"未対応のサービスタイプ '{svc_type}'（logical_id: {logical_id}）はスキップされました。")
            continue
        svc_resources, svc_outputs = gen_fn(logical_id, config)
        all_resources.update(svc_resources)
        all_outputs.update(svc_outputs)

    # 明示 outputs で上書き
    for out_cfg in architecture_spec.get("outputs", []):
        key = out_cfg.get("key", "Output")
        value_ref = out_cfg.get("value_ref", "")
        attribute = out_cfg.get("attribute")
        value = {"Fn::GetAtt": [value_ref, attribute]} if attribute else {"Ref": value_ref}
        out_entry = {"Value": value}
        if out_cfg.get("description"):
            out_entry["Description"] = out_cfg["description"]
        if out_cfg.get("export_name"):
            out_entry["Export"] = {"Name": out_cfg["export_name"]}
        all_outputs[key] = out_entry

    # テンプレート組み立て
    template = {"AWSTemplateFormatVersion": "2010-09-09"}
    if stack_description:
        template["Description"] = stack_description
    if parameters_section:
        template["Parameters"] = parameters_section
    template["Resources"] = all_resources
    if all_outputs:
        template["Outputs"] = all_outputs

    # シリアライズ
    import yaml
    if output_format.lower() == "json":
        template_body = json.dumps(template, ensure_ascii=False, indent=2)
    else:
        template_body = yaml.dump(template, allow_unicode=True, default_flow_style=False, sort_keys=False)

    return {
        "status": "ok",
        "template_body": template_body,
        "format": output_format.lower(),
        "resource_count": len(all_resources),
        "supported_types": list(_RESOURCE_GENERATORS.keys()),
        "warnings": warnings,
        "next_steps": [
            "validate_cloudformation_template でテンプレートをバリデーションしてください",
            "estimate_stack_cost でコスト見積もりを確認できます",
            "deploy_stack でAWSにデプロイできます",
        ],
        "message": (
            f"{len(all_resources)} 件のリソースを含むテンプレートを生成しました。"
            + (f" 警告: {len(warnings)} 件" if warnings else "")
        ),
    }


# ─────────────────────────────────────────
# カテゴリ8: CDK サポート
# ─────────────────────────────────────────

_CDK_JSON_TEMPLATE = json.dumps({
    "app": "python app.py",
    "context": {
        "@aws-cdk/aws-apigateway:usagePlanKeyOrderInsensitiveId": True,
        "@aws-cdk/core:enableStackNameDuplicates": "true",
        "aws-cdk:enableDiffNoFail": "true",
    },
}, indent=2)


def _run_cdk_command(
    app_code: str,
    cdk_args: list,
    region: str,
    timeout: int,
) -> dict:
    """CDKコマンドを一時ディレクトリで実行する内部ヘルパー"""
    cdk_path = _find_cli("cdk")
    if not cdk_path:
        return {
            "returncode": -2,
            "stdout": "",
            "stderr": "CDK CLIが見つかりません",
            "timed_out": False,
        }

    tmp_dir = _make_temp_dir()
    try:
        # app.py と cdk.json を書き込む
        with open(os.path.join(tmp_dir, "app.py"), "w", encoding="utf-8") as f:
            f.write(app_code)
        with open(os.path.join(tmp_dir, "cdk.json"), "w", encoding="utf-8") as f:
            f.write(_CDK_JSON_TEMPLATE)

        env = os.environ.copy()
        env["CDK_DEFAULT_REGION"] = region
        env["AWS_DEFAULT_REGION"] = region

        result = _run_subprocess(
            [cdk_path] + cdk_args,
            cwd=tmp_dir,
            timeout=timeout,
            env=env,
        )
        return result
    finally:
        _cleanup_temp_dir(tmp_dir)


@mcp.tool()
def cdk_synth(
    app_code: str,
    stack_name: str = "MyCdkStack",
    region: str = DEFAULT_REGION,
    timeout: int = 300,
) -> dict:
    """
    AWS CDK の Python コードからCloudFormationテンプレートを生成（synth）します。
    生成されたテンプレートは deploy_stack でデプロイ可能です。

    注意: このツールはユーザー提供のコードをサブプロセスで実行します。
    信頼できる環境でのみ使用してください。

    前提条件:
        - npm install -g aws-cdk （CDK CLI）
        - pip install aws-cdk-lib constructs （現在のPython環境）

    Args:
        app_code:   AWS CDK の Python アプリコード文字列（app.py の内容）
        stack_name: 生成するスタック名
        region:     対象リージョン
        timeout:    タイムアウト秒数（デフォルト: 300秒）

    Returns:
        cloudformation_template（JSON文字列）を含む dict
    """
    cdk_path = _find_cli("cdk")
    if not cdk_path:
        return {
            "status": "error",
            "error_type": "cli_not_found",
            "guidance": "CDK CLIをインストールしてください: npm install -g aws-cdk",
            "context": "cdk_synth",
        }

    result = _run_cdk_command(app_code, ["synth", "--json", "--quiet"], region, timeout)

    if result["timed_out"]:
        return {"status": "error", "error_type": "timeout", "guidance": f"CDK synth が {timeout}秒でタイムアウトしました。", "stdout": result["stdout"], "stderr": result["stderr"]}
    if result["returncode"] != 0:
        return {"status": "error", "error_type": "cdk_error", "returncode": result["returncode"], "stdout": result["stdout"], "stderr": result["stderr"], "guidance": "CDK コードのエラーを確認してください。stderr を参照してください。"}

    return {
        "status": "ok",
        "stack_name": stack_name,
        "cloudformation_template": result["stdout"],
        "message": f"CDK synth が成功しました。deploy_stack でデプロイできます。",
    }


@mcp.tool()
def cdk_deploy(
    app_code: str,
    stack_name: str = "MyCdkStack",
    region: str = DEFAULT_REGION,
    timeout: int = 600,
    context: dict = None,
) -> dict:
    """
    AWS CDK の Python コードからスタックをデプロイします。

    注意: このツールはユーザー提供のコードをサブプロセスで実行します。
    信頼できる環境でのみ使用してください。

    前提条件:
        - npm install -g aws-cdk （CDK CLI）
        - pip install aws-cdk-lib constructs （現在のPython環境）

    Args:
        app_code:   AWS CDK の Python アプリコード文字列
        stack_name: デプロイするスタック名
        region:     デプロイ先リージョン
        timeout:    タイムアウト秒数（デフォルト: 600秒）
        context:    CDKコンテキスト値 {"key": "value"} 形式

    Returns:
        stdout, stderr を含む dict
    """
    cdk_path = _find_cli("cdk")
    if not cdk_path:
        return {"status": "error", "error_type": "cli_not_found", "guidance": "CDK CLIをインストールしてください: npm install -g aws-cdk", "context": "cdk_deploy"}

    args = ["deploy", "--require-approval", "never"]
    for k, v in (context or {}).items():
        args += ["--context", f"{k}={v}"]

    result = _run_cdk_command(app_code, args, region, timeout)

    if result["timed_out"]:
        return {"status": "error", "error_type": "timeout", "guidance": f"CDK deploy が {timeout}秒でタイムアウトしました。", "stdout": result["stdout"], "stderr": result["stderr"]}
    if result["returncode"] != 0:
        return {"status": "error", "error_type": "cdk_error", "returncode": result["returncode"], "stdout": result["stdout"], "stderr": result["stderr"], "guidance": "デプロイに失敗しました。stderr を参照してください。"}

    return {
        "status": "ok",
        "stack_name": stack_name,
        "stdout": result["stdout"],
        "message": f"CDK deploy が成功しました。get_stack_status でリソースを確認してください。",
    }


@mcp.tool()
def cdk_destroy(
    app_code: str,
    stack_name: str = "MyCdkStack",
    region: str = DEFAULT_REGION,
    timeout: int = 300,
) -> dict:
    """
    AWS CDK スタックを削除します。削除すると元に戻せません。実行前にユーザーに確認を求めてください。

    注意: このツールはユーザー提供のコードをサブプロセスで実行します。
    信頼できる環境でのみ使用してください。

    前提条件:
        - npm install -g aws-cdk （CDK CLI）
        - pip install aws-cdk-lib constructs （現在のPython環境）

    Args:
        app_code:   AWS CDK の Python アプリコード文字列
        stack_name: 削除するスタック名
        region:     リージョン
        timeout:    タイムアウト秒数（デフォルト: 300秒）

    Returns:
        stdout, stderr を含む dict
    """
    cdk_path = _find_cli("cdk")
    if not cdk_path:
        return {"status": "error", "error_type": "cli_not_found", "guidance": "CDK CLIをインストールしてください: npm install -g aws-cdk", "context": "cdk_destroy"}

    result = _run_cdk_command(app_code, ["destroy", "--force"], region, timeout)

    if result["timed_out"]:
        return {"status": "error", "error_type": "timeout", "guidance": f"CDK destroy が {timeout}秒でタイムアウトしました。", "stdout": result["stdout"], "stderr": result["stderr"]}
    if result["returncode"] != 0:
        return {"status": "error", "error_type": "cdk_error", "returncode": result["returncode"], "stdout": result["stdout"], "stderr": result["stderr"], "guidance": "削除に失敗しました。stderr を参照してください。"}

    return {
        "status": "ok",
        "stack_name": stack_name,
        "stdout": result["stdout"],
        "message": f"CDK destroy が成功しました。",
    }


# ─────────────────────────────────────────
# カテゴリ9: Terraform サポート
# ─────────────────────────────────────────

def _run_terraform_command(
    tf_content: str,
    command: str,
    extra_args: list,
    variables: dict,
    region: str,
    timeout: int,
    state_dir: str = None,
) -> dict:
    """Terraformコマンドを一時ディレクトリで実行する内部ヘルパー"""
    tf_path = _find_cli("terraform")
    if not tf_path:
        return {"returncode": -2, "stdout": "", "stderr": "Terraformが見つかりません", "timed_out": False}

    tmp_dir = _make_temp_dir()
    try:
        # main.tf を書き込む
        with open(os.path.join(tmp_dir, "main.tf"), "w", encoding="utf-8") as f:
            f.write(tf_content)

        # state ファイルがあれば一時ディレクトリにコピー
        if state_dir and os.path.isfile(os.path.join(state_dir, "terraform.tfstate")):
            shutil.copy2(
                os.path.join(state_dir, "terraform.tfstate"),
                os.path.join(tmp_dir, "terraform.tfstate"),
            )

        env = os.environ.copy()
        env["AWS_DEFAULT_REGION"] = region
        env["TF_IN_AUTOMATION"] = "1"

        # terraform init
        init_result = _run_subprocess(
            [tf_path, "init", "-no-color", "-input=false"],
            cwd=tmp_dir,
            timeout=120,
            env=env,
        )
        if init_result["returncode"] != 0:
            return init_result

        # 変数フラグを組み立て
        var_args = []
        for k, v in (variables or {}).items():
            var_args += ["-var", f"{k}={v}"]

        cmd_args = [tf_path, command] + extra_args + var_args
        result = _run_subprocess(cmd_args, cwd=tmp_dir, timeout=timeout, env=env)

        # apply/destroy 後に state ファイルを保存
        if state_dir and command in ("apply", "destroy"):
            state_src = os.path.join(tmp_dir, "terraform.tfstate")
            if os.path.isfile(state_src):
                os.makedirs(state_dir, exist_ok=True)
                shutil.copy2(state_src, os.path.join(state_dir, "terraform.tfstate"))

        return result
    finally:
        _cleanup_temp_dir(tmp_dir)


@mcp.tool()
def terraform_plan(
    tf_content: str,
    variables: dict = None,
    region: str = DEFAULT_REGION,
    timeout: int = 300,
) -> dict:
    """
    Terraform 設定の変更プランを表示します（実際の変更は行いません）。

    注意: このツールはユーザー提供のコードをサブプロセスで実行します。
    信頼できる環境でのみ使用してください。

    前提条件: Terraform CLI がインストールされていること
    （https://developer.hashicorp.com/terraform/install）

    Args:
        tf_content: Terraform 設定ファイル（main.tf）の内容文字列
        variables:  {"var_name": "value"} 形式の変数
        region:     対象AWSリージョン
        timeout:    タイムアウト秒数（デフォルト: 300秒）

    Returns:
        plan_output, has_changes を含む dict
    """
    tf_path = _find_cli("terraform")
    if not tf_path:
        return {"status": "error", "error_type": "cli_not_found", "guidance": "Terraformをインストールしてください: https://developer.hashicorp.com/terraform/install", "context": "terraform_plan"}

    result = _run_terraform_command(tf_content, "plan", ["-no-color", "-input=false"], variables, region, timeout)

    if result["timed_out"]:
        return {"status": "error", "error_type": "timeout", "guidance": f"terraform plan が {timeout}秒でタイムアウトしました。", "stdout": result["stdout"], "stderr": result["stderr"]}
    if result["returncode"] == -2:
        return {"status": "error", "error_type": "cli_not_found", "guidance": "Terraformが見つかりません。インストールを確認してください。"}
    if result["returncode"] != 0:
        return {"status": "error", "error_type": "terraform_error", "returncode": result["returncode"], "stdout": result["stdout"], "stderr": result["stderr"], "guidance": "Terraform設定のエラーを確認してください。"}

    has_changes = "No changes." not in result["stdout"]
    return {
        "status": "ok",
        "plan_output": result["stdout"],
        "has_changes": has_changes,
        "message": "変更があります。terraform_apply で適用できます。" if has_changes else "変更はありません。",
    }


@mcp.tool()
def terraform_apply(
    tf_content: str,
    variables: dict = None,
    region: str = DEFAULT_REGION,
    timeout: int = 600,
    state_dir: str = None,
) -> dict:
    """
    Terraform 設定を適用してAWSリソースを作成・更新します。

    注意1: このツールはユーザー提供のコードをサブプロセスで実行します。
    信頼できる環境でのみ使用してください。
    注意2: -auto-approve で自動承認されます。実行前に terraform_plan で確認してください。

    前提条件: Terraform CLI がインストールされていること

    Args:
        tf_content: Terraform 設定ファイルの内容文字列
        variables:  {"var_name": "value"} 形式の変数
        region:     対象AWSリージョン
        timeout:    タイムアウト秒数（デフォルト: 600秒）
        state_dir:  tfstate を永続保存するディレクトリパス（省略時は都度破棄）
                    terraform_destroy で同じパスを指定すると削除できます

    Returns:
        apply_output を含む dict
    """
    tf_path = _find_cli("terraform")
    if not tf_path:
        return {"status": "error", "error_type": "cli_not_found", "guidance": "Terraformをインストールしてください: https://developer.hashicorp.com/terraform/install", "context": "terraform_apply"}

    result = _run_terraform_command(tf_content, "apply", ["-auto-approve", "-no-color", "-input=false"], variables, region, timeout, state_dir)

    if result["timed_out"]:
        return {"status": "error", "error_type": "timeout", "guidance": f"terraform apply が {timeout}秒でタイムアウトしました。", "stdout": result["stdout"], "stderr": result["stderr"]}
    if result["returncode"] == -2:
        return {"status": "error", "error_type": "cli_not_found", "guidance": "Terraformが見つかりません。"}
    if result["returncode"] != 0:
        return {"status": "error", "error_type": "terraform_error", "returncode": result["returncode"], "stdout": result["stdout"], "stderr": result["stderr"], "guidance": "applyに失敗しました。stderr を確認してください。"}

    state_msg = f" tfstate は {state_dir} に保存されました。" if state_dir else " state_dir を指定していないため、tfstateは保持されません。"
    return {
        "status": "ok",
        "apply_output": result["stdout"],
        "state_dir": state_dir,
        "message": f"terraform apply が成功しました。{state_msg}",
    }


@mcp.tool()
def terraform_destroy(
    tf_content: str,
    variables: dict = None,
    region: str = DEFAULT_REGION,
    timeout: int = 300,
    state_dir: str = None,
) -> dict:
    """
    Terraform で作成したAWSリソースを削除します。
    削除すると元に戻せません。実行前にユーザーに確認を求めてください。

    注意: このツールはユーザー提供のコードをサブプロセスで実行します。
    信頼できる環境でのみ使用してください。

    前提条件: Terraform CLI がインストールされていること

    Args:
        tf_content: Terraform 設定ファイルの内容文字列
        variables:  {"var_name": "value"} 形式の変数
        region:     対象AWSリージョン
        timeout:    タイムアウト秒数（デフォルト: 300秒）
        state_dir:  terraform_apply で指定したのと同じ state_dir を指定してください

    Returns:
        destroy_output を含む dict
    """
    tf_path = _find_cli("terraform")
    if not tf_path:
        return {"status": "error", "error_type": "cli_not_found", "guidance": "Terraformをインストールしてください: https://developer.hashicorp.com/terraform/install", "context": "terraform_destroy"}

    result = _run_terraform_command(tf_content, "destroy", ["-auto-approve", "-no-color", "-input=false"], variables, region, timeout, state_dir)

    if result["timed_out"]:
        return {"status": "error", "error_type": "timeout", "guidance": f"terraform destroy が {timeout}秒でタイムアウトしました。", "stdout": result["stdout"], "stderr": result["stderr"]}
    if result["returncode"] == -2:
        return {"status": "error", "error_type": "cli_not_found", "guidance": "Terraformが見つかりません。"}
    if result["returncode"] != 0:
        return {"status": "error", "error_type": "terraform_error", "returncode": result["returncode"], "stdout": result["stdout"], "stderr": result["stderr"], "guidance": "destroyに失敗しました。stderr を確認してください。"}

    return {
        "status": "ok",
        "destroy_output": result["stdout"],
        "message": "terraform destroy が成功しました。",
    }


# ─────────────────────────────────────────
# カテゴリ10: MCP設定
# ─────────────────────────────────────────

@mcp.tool()
def get_mcp_config() -> dict:
    """
    このMCPサーバーをClaude Desktopに登録するための設定JSONと手順を返します。

    Returns:
        config_json（claude_desktop_config.json に追記する設定）、
        instructions（登録手順）を含む dict
    """
    script_path = os.path.abspath(__file__)
    python_path = sys.executable

    # claude_desktop_config.json のパスを特定
    if sys.platform == "win32":
        config_dir = os.path.join(os.environ.get("APPDATA", ""), "Claude")
    elif sys.platform == "darwin":
        config_dir = os.path.expanduser("~/Library/Application Support/Claude")
    else:
        config_dir = os.path.expanduser("~/.config/claude")

    config_file = os.path.join(config_dir, "claude_desktop_config.json")

    # 既登録確認
    already_registered = False
    try:
        if os.path.isfile(config_file):
            with open(config_file, encoding="utf-8") as f:
                existing = json.load(f)
            if "aws-infra-tools" in existing.get("mcpServers", {}):
                already_registered = True
    except Exception:
        pass

    # 非ASCII文字警告
    path_warnings = []
    try:
        script_path.encode("ascii")
    except UnicodeEncodeError:
        path_warnings.append(
            f"スクリプトパス '{script_path}' に非ASCII文字が含まれています。"
            "Claude Desktop の設定ファイルで文字化けが発生する場合は、"
            "パスにASCII文字のみを使用したディレクトリにコピーして使用してください。"
        )

    config_json = {
        "aws-infra-tools": {
            "command": python_path,
            "args": [script_path],
        }
    }

    instructions = f"""Claude Desktop への MCP サーバー登録手順:

1. Claude Desktop を終了する

2. 以下のファイルを開く（なければ新規作成）:
   {config_file}

3. ファイルの内容を以下のように設定する:
{{
  "mcpServers": {{
    "aws-infra-tools": {{
      "command": "{python_path.replace(chr(92), '/')}",
      "args": ["{script_path.replace(chr(92), '/')}"]
    }}
  }}
}}

4. ファイルを保存して Claude Desktop を再起動する

5. Claude Desktop のツールメニューに "aws-infra-tools" が表示されれば完了です。

必要なPythonパッケージ:
  pip install boto3 pyyaml mcp

CDK を使う場合:
  npm install -g aws-cdk
  pip install aws-cdk-lib constructs

Terraform を使う場合:
  https://developer.hashicorp.com/terraform/install からインストール
"""

    return {
        "status": "ok",
        "server_name": "aws-infra-tools",
        "script_path": script_path,
        "python_path": python_path,
        "config_file_path": config_file,
        "config_json": config_json,
        "already_registered": already_registered,
        "path_warnings": path_warnings,
        "instructions": instructions,
        "message": (
            "このMCPサーバーはすでに Claude Desktop に登録されています。"
            if already_registered
            else "instructions の手順に従って Claude Desktop に登録してください。"
        ),
    }


# ─────────────────────────────────────────
# カテゴリ11: EC2インスタンス管理
# ─────────────────────────────────────────

@mcp.tool()
def list_ec2_instances(region: str = DEFAULT_REGION, filters: dict = None) -> dict:
    """
    EC2インスタンスの一覧と状態を返します。

    Args:
        region:  AWSリージョン（デフォルト: ap-northeast-1）
        filters: フィルタ条件 {"Name": "...", "Values": [...]} のリスト形式も可

    Returns:
        instances リストを含む dict
    """
    try:
        import boto3
        ec2 = boto3.client("ec2", region_name=region)
        kwargs = {}
        if filters:
            if isinstance(filters, dict):
                kwargs["Filters"] = [{"Name": k, "Values": v if isinstance(v, list) else [v]} for k, v in filters.items()]
            elif isinstance(filters, list):
                kwargs["Filters"] = filters
        response = ec2.describe_instances(**kwargs)
        instances = []
        for reservation in response["Reservations"]:
            for inst in reservation["Instances"]:
                name = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), "")
                instances.append({
                    "instance_id": inst["InstanceId"],
                    "name": name,
                    "state": inst["State"]["Name"],
                    "instance_type": inst.get("InstanceType", ""),
                    "public_ip": inst.get("PublicIpAddress", ""),
                    "private_ip": inst.get("PrivateIpAddress", ""),
                    "launch_time": str(inst.get("LaunchTime", "")),
                })
        return {"status": "ok", "instances": instances, "total": len(instances), "region": region}
    except Exception as e:
        return _handle_aws_error(e, "list_ec2_instances")


@mcp.tool()
def start_ec2_instances(instance_ids: list, region: str = DEFAULT_REGION) -> dict:
    """
    EC2インスタンスを起動します。

    Args:
        instance_ids: 起動するインスタンスIDのリスト（例: ["i-0123456789abcdef0"]）
        region:       AWSリージョン

    Returns:
        starting_instances リストを含む dict
    """
    try:
        import boto3
        ec2 = boto3.client("ec2", region_name=region)
        response = ec2.start_instances(InstanceIds=instance_ids)
        result = [
            {"instance_id": i["InstanceId"], "previous_state": i["PreviousState"]["Name"], "current_state": i["CurrentState"]["Name"]}
            for i in response["StartingInstances"]
        ]
        return {"status": "ok", "starting_instances": result, "region": region}
    except Exception as e:
        return _handle_aws_error(e, "start_ec2_instances")


@mcp.tool()
def stop_ec2_instances(instance_ids: list, region: str = DEFAULT_REGION, force: bool = False) -> dict:
    """
    EC2インスタンスを停止します。

    Args:
        instance_ids: 停止するインスタンスIDのリスト
        region:       AWSリージョン
        force:        強制停止する場合は True（デフォルト: False）

    Returns:
        stopping_instances リストを含む dict
    """
    try:
        import boto3
        ec2 = boto3.client("ec2", region_name=region)
        response = ec2.stop_instances(InstanceIds=instance_ids, Force=force)
        result = [
            {"instance_id": i["InstanceId"], "previous_state": i["PreviousState"]["Name"], "current_state": i["CurrentState"]["Name"]}
            for i in response["StoppingInstances"]
        ]
        return {"status": "ok", "stopping_instances": result, "region": region}
    except Exception as e:
        return _handle_aws_error(e, "stop_ec2_instances")


@mcp.tool()
def reboot_ec2_instances(instance_ids: list, region: str = DEFAULT_REGION) -> dict:
    """
    EC2インスタンスを再起動します。

    Args:
        instance_ids: 再起動するインスタンスIDのリスト
        region:       AWSリージョン

    Returns:
        status と対象インスタンスIDを含む dict
    """
    try:
        import boto3
        ec2 = boto3.client("ec2", region_name=region)
        ec2.reboot_instances(InstanceIds=instance_ids)
        return {"status": "ok", "rebooted_instance_ids": instance_ids, "region": region, "message": "再起動リクエストを送信しました。"}
    except Exception as e:
        return _handle_aws_error(e, "reboot_ec2_instances")


# ─────────────────────────────────────────
# カテゴリ12: RDSインスタンス管理
# ─────────────────────────────────────────

@mcp.tool()
def list_rds_instances(region: str = DEFAULT_REGION) -> dict:
    """
    RDS DBインスタンスの一覧と状態を返します。

    Args:
        region: AWSリージョン

    Returns:
        instances リストを含む dict
    """
    try:
        import boto3
        rds = boto3.client("rds", region_name=region)
        response = rds.describe_db_instances()
        instances = [
            {
                "db_identifier": db["DBInstanceIdentifier"],
                "status": db["DBInstanceStatus"],
                "engine": db["Engine"],
                "engine_version": db["EngineVersion"],
                "instance_class": db["DBInstanceClass"],
                "endpoint": db.get("Endpoint", {}).get("Address", ""),
                "port": db.get("Endpoint", {}).get("Port", ""),
                "multi_az": db.get("MultiAZ", False),
            }
            for db in response["DBInstances"]
        ]
        return {"status": "ok", "instances": instances, "total": len(instances), "region": region}
    except Exception as e:
        return _handle_aws_error(e, "list_rds_instances")


@mcp.tool()
def start_rds_instance(db_identifier: str, region: str = DEFAULT_REGION) -> dict:
    """
    RDS DBインスタンスを起動します。

    Args:
        db_identifier: DBインスタンス識別子
        region:        AWSリージョン

    Returns:
        status と DBインスタンス情報を含む dict
    """
    try:
        import boto3
        rds = boto3.client("rds", region_name=region)
        response = rds.start_db_instance(DBInstanceIdentifier=db_identifier)
        db = response["DBInstance"]
        return {"status": "ok", "db_identifier": db["DBInstanceIdentifier"], "db_status": db["DBInstanceStatus"], "region": region}
    except Exception as e:
        return _handle_aws_error(e, "start_rds_instance")


@mcp.tool()
def stop_rds_instance(db_identifier: str, region: str = DEFAULT_REGION) -> dict:
    """
    RDS DBインスタンスを停止します。
    注意: RDSは停止後7日で自動的に再起動されます。

    Args:
        db_identifier: DBインスタンス識別子
        region:        AWSリージョン

    Returns:
        status と DBインスタンス情報を含む dict
    """
    try:
        import boto3
        rds = boto3.client("rds", region_name=region)
        response = rds.stop_db_instance(DBInstanceIdentifier=db_identifier)
        db = response["DBInstance"]
        return {
            "status": "ok",
            "db_identifier": db["DBInstanceIdentifier"],
            "db_status": db["DBInstanceStatus"],
            "region": region,
            "warning": "RDSは停止後7日で自動的に再起動されます。",
        }
    except Exception as e:
        return _handle_aws_error(e, "stop_rds_instance")


# ─────────────────────────────────────────
# カテゴリ13: ECSクラスター・サービス管理
# ─────────────────────────────────────────

@mcp.tool()
def list_ecs_services(region: str = DEFAULT_REGION, cluster: str = None) -> dict:
    """
    ECSクラスターとサービスの一覧を返します。

    Args:
        region:  AWSリージョン
        cluster: クラスター名またはARN（省略時は全クラスター）

    Returns:
        clusters と services を含む dict
    """
    try:
        import boto3
        ecs = boto3.client("ecs", region_name=region)
        cluster_arns = [cluster] if cluster else ecs.list_clusters()["clusterArns"]
        result = []
        for cluster_arn in cluster_arns:
            cluster_name = cluster_arn.split("/")[-1]
            svc_arns = ecs.list_services(cluster=cluster_arn).get("serviceArns", [])
            services = []
            if svc_arns:
                svc_detail = ecs.describe_services(cluster=cluster_arn, services=svc_arns)["services"]
                services = [
                    {
                        "service_name": s["serviceName"],
                        "status": s["status"],
                        "desired_count": s["desiredCount"],
                        "running_count": s["runningCount"],
                        "pending_count": s["pendingCount"],
                        "task_definition": s["taskDefinition"].split("/")[-1],
                        "launch_type": s.get("launchType", ""),
                    }
                    for s in svc_detail
                ]
            result.append({"cluster_name": cluster_name, "cluster_arn": cluster_arn, "services": services})
        return {"status": "ok", "clusters": result, "region": region}
    except Exception as e:
        return _handle_aws_error(e, "list_ecs_services")


@mcp.tool()
def scale_ecs_service(cluster: str, service: str, desired_count: int, region: str = DEFAULT_REGION) -> dict:
    """
    ECSサービスのタスク数を変更します。0にすると停止、1以上で起動します。

    Args:
        cluster:       クラスター名またはARN
        service:       サービス名またはARN
        desired_count: 希望タスク数（0で停止）
        region:        AWSリージョン

    Returns:
        status とサービス情報を含む dict
    """
    try:
        import boto3
        ecs = boto3.client("ecs", region_name=region)
        response = ecs.update_service(cluster=cluster, service=service, desiredCount=desired_count)
        svc = response["service"]
        return {
            "status": "ok",
            "service_name": svc["serviceName"],
            "desired_count": svc["desiredCount"],
            "running_count": svc["runningCount"],
            "region": region,
            "message": f"タスク数を {desired_count} に変更しました。",
        }
    except Exception as e:
        return _handle_aws_error(e, "scale_ecs_service")


# ─────────────────────────────────────────
# カテゴリ14: EventBridge Scheduler（時刻指定リソース操作）
# ─────────────────────────────────────────

_SCHEDULER_ROLE_NAME = "MCPAwsInfraSchedulerRole"


def _get_or_create_scheduler_role() -> str:
    """EventBridge Scheduler 用 IAM ロールを取得または作成し、ARN を返す"""
    import boto3, json as _json
    iam = boto3.client("iam")
    try:
        return iam.get_role(RoleName=_SCHEDULER_ROLE_NAME)["Role"]["Arn"]
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "scheduler.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=_SCHEDULER_ROLE_NAME, AssumeRolePolicyDocument=_json.dumps(trust))["Role"]
    iam.attach_role_policy(RoleName=_SCHEDULER_ROLE_NAME, PolicyArn="arn:aws:iam::aws:policy/AmazonEC2FullAccess")
    iam.attach_role_policy(RoleName=_SCHEDULER_ROLE_NAME, PolicyArn="arn:aws:iam::aws:policy/AmazonRDSFullAccess")
    iam.attach_role_policy(RoleName=_SCHEDULER_ROLE_NAME, PolicyArn="arn:aws:iam::aws:policy/AmazonECS_FullAccess")
    return role["Arn"]


def _parse_schedule_expression(schedule_type: str, schedule_expression: str) -> str:
    """スケジュール式を EventBridge Scheduler 形式に変換する"""
    if schedule_type == "one_time":
        try:
            from datetime import datetime
            dt = datetime.fromisoformat(schedule_expression.replace("Z", "+00:00"))
            return f"at({dt.strftime('%Y-%m-%dT%H:%M:%S')})"
        except Exception:
            return f"at({schedule_expression})"
    elif schedule_type == "rate":
        return f"rate({schedule_expression})"
    elif schedule_type == "cron":
        return f"cron({schedule_expression})"
    return schedule_expression


def _build_scheduler_target(action: str, resource_ids: list, action_params: dict, role_arn: str) -> dict:
    """EventBridge Scheduler のターゲット設定を構築する"""
    import json as _json, boto3
    sts = boto3.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = boto3.session.Session().region_name or DEFAULT_REGION

    action_map = {
        "start_ec2": ("aws-sdk:ec2:startInstances", {"InstanceIds": resource_ids}),
        "stop_ec2":  ("aws-sdk:ec2:stopInstances",  {"InstanceIds": resource_ids}),
        "start_rds": ("aws-sdk:rds:startDBInstance", {"DBInstanceIdentifier": resource_ids[0]}),
        "stop_rds":  ("aws-sdk:rds:stopDBInstance",  {"DBInstanceIdentifier": resource_ids[0]}),
    }
    if action in action_map:
        arn_suffix, input_params = action_map[action]
        input_params.update(action_params or {})
        return {
            "Arn": f"arn:aws:scheduler:::target/{arn_suffix}",
            "RoleArn": role_arn,
            "Input": _json.dumps(input_params),
        }
    if action == "scale_ecs":
        cluster = action_params.get("cluster", "")
        service = action_params.get("service", "")
        desired = action_params.get("desired_count", 0)
        return {
            "Arn": f"arn:aws:ecs:{region}:{account_id}:service/{cluster}/{service}",
            "RoleArn": role_arn,
            "Input": _json.dumps({"desiredCount": desired}),
        }
    raise ValueError(f"不明なアクション: {action}")


@mcp.tool()
def create_resource_schedule(
    name: str,
    action: str,
    resource_ids: list,
    schedule_type: str,
    schedule_expression: str,
    timezone: str = "Asia/Tokyo",
    action_params: dict = None,
    region: str = DEFAULT_REGION,
) -> dict:
    """
    EventBridge Scheduler を使って日時指定でAWSリソースを操作するスケジュールを作成します。

    Args:
        name:                スケジュール名（英数字とハイフンのみ）
        action:              操作種別: "start_ec2" / "stop_ec2" / "start_rds" / "stop_rds" / "scale_ecs"
        resource_ids:        対象リソースIDのリスト（EC2: instance_id、RDS: db_identifier）
        schedule_type:       "one_time"（一回限り）/ "rate"（定期）/ "cron"（cron式）
        schedule_expression: one_time なら "2026-03-10T09:00:00"、rate なら "1 hour"、cron なら "0 9 * * ? *"
        timezone:            タイムゾーン（デフォルト: Asia/Tokyo）
        action_params:       追加パラメータ（scale_ecs の場合: {"cluster": "...", "service": "...", "desired_count": 1}）
        region:              AWSリージョン

    Returns:
        schedule_arn を含む dict
    """
    try:
        import boto3
        role_arn = _get_or_create_scheduler_role()
        target = _build_scheduler_target(action, resource_ids, action_params or {}, role_arn)
        scheduler = boto3.client("scheduler", region_name=region)
        expr = _parse_schedule_expression(schedule_type, schedule_expression)
        kwargs = {
            "Name": name,
            "ScheduleExpression": expr,
            "ScheduleExpressionTimezone": timezone,
            "Target": target,
            "FlexibleTimeWindow": {"Mode": "OFF"},
        }
        if schedule_type == "one_time":
            kwargs["ActionAfterCompletion"] = "DELETE"
        response = scheduler.create_schedule(**kwargs)
        return {
            "status": "ok",
            "schedule_name": name,
            "schedule_arn": response["ScheduleArn"],
            "expression": expr,
            "timezone": timezone,
            "action": action,
            "resource_ids": resource_ids,
            "message": f"スケジュール '{name}' を作成しました。",
        }
    except Exception as e:
        return _handle_aws_error(e, "create_resource_schedule")


@mcp.tool()
def list_resource_schedules(region: str = DEFAULT_REGION) -> dict:
    """
    EventBridge Scheduler に登録されているスケジュール一覧を返します。

    Args:
        region: AWSリージョン

    Returns:
        schedules リストを含む dict
    """
    try:
        import boto3
        scheduler = boto3.client("scheduler", region_name=region)
        response = scheduler.list_schedules()
        schedules = [
            {
                "name": s["Name"],
                "arn": s["Arn"],
                "state": s["State"],
                "expression": s.get("ScheduleExpression", ""),
                "target_arn": s.get("Target", {}).get("Arn", ""),
            }
            for s in response.get("Schedules", [])
        ]
        return {"status": "ok", "schedules": schedules, "total": len(schedules), "region": region}
    except Exception as e:
        return _handle_aws_error(e, "list_resource_schedules")


@mcp.tool()
def delete_resource_schedule(name: str, region: str = DEFAULT_REGION) -> dict:
    """
    EventBridge Scheduler のスケジュールを削除します。

    Args:
        name:   削除するスケジュール名
        region: AWSリージョン

    Returns:
        status を含む dict
    """
    try:
        import boto3
        scheduler = boto3.client("scheduler", region_name=region)
        scheduler.delete_schedule(Name=name)
        return {"status": "ok", "deleted_schedule": name, "region": region, "message": f"スケジュール '{name}' を削除しました。"}
    except Exception as e:
        return _handle_aws_error(e, "delete_resource_schedule")


# ─────────────────────────────────────────
# カテゴリ15: アプリ一括起動・停止（testspp）
# ─────────────────────────────────────────

def _find_testspp_resources(region: str) -> dict:
    """
    Name タグに 'testspp' を含む EC2・RDS・ECS リソースを検索して返す。
    """
    import boto3
    result = {"ec2": [], "rds": [], "ecs": []}

    # EC2: Name タグが testspp を含むインスタンス
    ec2 = boto3.client("ec2", region_name=region)
    reservations = ec2.describe_instances(
        Filters=[{"Name": "tag:Name", "Values": ["*testspp*"]}]
    )["Reservations"]
    for r in reservations:
        for inst in r["Instances"]:
            name = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), "")
            result["ec2"].append({
                "instance_id": inst["InstanceId"],
                "name": name,
                "state": inst["State"]["Name"],
            })

    # RDS: DBInstanceIdentifier に testspp を含む
    rds = boto3.client("rds", region_name=region)
    for db in rds.describe_db_instances()["DBInstances"]:
        if "testspp" in db["DBInstanceIdentifier"].lower():
            result["rds"].append({
                "db_identifier": db["DBInstanceIdentifier"],
                "status": db["DBInstanceStatus"],
            })

    # ECS: サービス名に testspp を含む（全クラスター検索）
    ecs = boto3.client("ecs", region_name=region)
    for cluster_arn in ecs.list_clusters().get("clusterArns", []):
        svc_arns = ecs.list_services(cluster=cluster_arn).get("serviceArns", [])
        if not svc_arns:
            continue
        for svc in ecs.describe_services(cluster=cluster_arn, services=svc_arns)["services"]:
            if "testspp" in svc["serviceName"].lower():
                result["ecs"].append({
                    "cluster": cluster_arn.split("/")[-1],
                    "cluster_arn": cluster_arn,
                    "service_name": svc["serviceName"],
                    "desired_count": svc["desiredCount"],
                    "running_count": svc["runningCount"],
                })

    return result


@mcp.tool()
def start_testspp(region: str = DEFAULT_REGION) -> dict:
    """
    「Start testspp」と入力すると呼び出されます。
    Name タグに 'testspp' を含む EC2・RDS・ECS リソースをすべて起動します。
    - EC2: stopped 状態のインスタンスを起動
    - RDS: stopped 状態の DB を起動
    - ECS: desired_count が 0 のサービスを 1 に変更

    Args:
        region: AWSリージョン（デフォルト: ap-northeast-1）

    Returns:
        起動したリソースの一覧を含む dict
    """
    import boto3
    ec2 = boto3.client("ec2", region_name=region)
    rds = boto3.client("rds", region_name=region)
    ecs = boto3.client("ecs", region_name=region)

    resources = _find_testspp_resources(region)
    started = {"ec2": [], "rds": [], "ecs": [], "skipped": []}

    # EC2 起動
    ec2_to_start = [r["instance_id"] for r in resources["ec2"] if r["state"] == "stopped"]
    if ec2_to_start:
        resp = ec2.start_instances(InstanceIds=ec2_to_start)
        started["ec2"] = [{"instance_id": i["InstanceId"], "state": i["CurrentState"]["Name"]} for i in resp["StartingInstances"]]
    for r in resources["ec2"]:
        if r["state"] != "stopped":
            started["skipped"].append({"type": "ec2", "id": r["instance_id"], "reason": f"state={r['state']}"})

    # RDS 起動
    for r in resources["rds"]:
        if r["status"] == "stopped":
            try:
                resp = rds.start_db_instance(DBInstanceIdentifier=r["db_identifier"])
                started["rds"].append({"db_identifier": r["db_identifier"], "status": resp["DBInstance"]["DBInstanceStatus"]})
            except Exception as e:
                started["skipped"].append({"type": "rds", "id": r["db_identifier"], "reason": str(e)})
        else:
            started["skipped"].append({"type": "rds", "id": r["db_identifier"], "reason": f"status={r['status']}"})

    # ECS 起動（desired_count 0 → 1）
    for r in resources["ecs"]:
        if r["desired_count"] == 0:
            try:
                resp = ecs.update_service(cluster=r["cluster_arn"], service=r["service_name"], desiredCount=1)
                started["ecs"].append({"service_name": r["service_name"], "cluster": r["cluster"], "desired_count": 1})
            except Exception as e:
                started["skipped"].append({"type": "ecs", "id": r["service_name"], "reason": str(e)})
        else:
            started["skipped"].append({"type": "ecs", "id": r["service_name"], "reason": f"desired_count={r['desired_count']}"})

    total = len(started["ec2"]) + len(started["rds"]) + len(started["ecs"])
    return {
        "status": "ok",
        "started": started,
        "total_started": total,
        "region": region,
        "message": f"testspp リソース {total} 件を起動しました。",
    }


@mcp.tool()
def stop_testspp(region: str = DEFAULT_REGION) -> dict:
    """
    「Stop testspp」と入力すると呼び出されます。
    Name タグに 'testspp' を含む EC2・RDS・ECS リソースをすべて停止します。
    - EC2: running 状態のインスタンスを停止
    - RDS: available 状態の DB を停止
    - ECS: desired_count を 0 に変更

    Args:
        region: AWSリージョン（デフォルト: ap-northeast-1）

    Returns:
        停止したリソースの一覧を含む dict
    """
    import boto3
    ec2 = boto3.client("ec2", region_name=region)
    rds = boto3.client("rds", region_name=region)
    ecs = boto3.client("ecs", region_name=region)

    resources = _find_testspp_resources(region)
    stopped = {"ec2": [], "rds": [], "ecs": [], "skipped": []}

    # EC2 停止
    ec2_to_stop = [r["instance_id"] for r in resources["ec2"] if r["state"] == "running"]
    if ec2_to_stop:
        resp = ec2.stop_instances(InstanceIds=ec2_to_stop)
        stopped["ec2"] = [{"instance_id": i["InstanceId"], "state": i["CurrentState"]["Name"]} for i in resp["StoppingInstances"]]
    for r in resources["ec2"]:
        if r["state"] != "running":
            stopped["skipped"].append({"type": "ec2", "id": r["instance_id"], "reason": f"state={r['state']}"})

    # RDS 停止
    for r in resources["rds"]:
        if r["status"] == "available":
            try:
                resp = rds.stop_db_instance(DBInstanceIdentifier=r["db_identifier"])
                stopped["rds"].append({"db_identifier": r["db_identifier"], "status": resp["DBInstance"]["DBInstanceStatus"]})
            except Exception as e:
                stopped["skipped"].append({"type": "rds", "id": r["db_identifier"], "reason": str(e)})
        else:
            stopped["skipped"].append({"type": "rds", "id": r["db_identifier"], "reason": f"status={r['status']}"})

    # ECS 停止（desired_count → 0）
    for r in resources["ecs"]:
        if r["desired_count"] > 0:
            try:
                resp = ecs.update_service(cluster=r["cluster_arn"], service=r["service_name"], desiredCount=0)
                stopped["ecs"].append({"service_name": r["service_name"], "cluster": r["cluster"], "desired_count": 0})
            except Exception as e:
                stopped["skipped"].append({"type": "ecs", "id": r["service_name"], "reason": str(e)})
        else:
            stopped["skipped"].append({"type": "ecs", "id": r["service_name"], "reason": "already stopped (desired_count=0)"})

    total = len(stopped["ec2"]) + len(stopped["rds"]) + len(stopped["ecs"])
    return {
        "status": "ok",
        "stopped": stopped,
        "total_stopped": total,
        "region": region,
        "message": f"testspp リソース {total} 件を停止しました。",
    }


# ─────────────────────────────────────────
# Hotel（Terrace Villa Foresta Asama）起動・停止
# ─────────────────────────────────────────

def _find_hotel_resources(region: str) -> dict:
    """
    Name タグが 'Terrace Villa Foresta Asama' の RDS・ECS リソースを検索して返す。
    """
    import boto3
    TAG_NAME = "Terrace Villa Foresta Asama"
    result = {"rds": [], "ecs": []}

    # RDS: Name タグが一致する DB インスタンス
    rds = boto3.client("rds", region_name=region)
    for db in rds.describe_db_instances()["DBInstances"]:
        tags = {t["Key"]: t["Value"] for t in db.get("TagList", [])}
        if tags.get("Name") == TAG_NAME:
            result["rds"].append({
                "db_identifier": db["DBInstanceIdentifier"],
                "status": db["DBInstanceStatus"],
            })

    # ECS: Name タグが一致するサービス（全クラスター検索）
    ecs = boto3.client("ecs", region_name=region)
    for cluster_arn in ecs.list_clusters().get("clusterArns", []):
        svc_arns = ecs.list_services(cluster=cluster_arn).get("serviceArns", [])
        if not svc_arns:
            continue
        for svc in ecs.describe_services(cluster=cluster_arn, services=svc_arns, include=["TAGS"])["services"]:
            tags = {t["key"]: t["value"] for t in svc.get("tags", [])}
            if tags.get("Name") == TAG_NAME:
                result["ecs"].append({
                    "cluster": cluster_arn.split("/")[-1],
                    "cluster_arn": cluster_arn,
                    "service_name": svc["serviceName"],
                    "desired_count": svc["desiredCount"],
                    "running_count": svc["runningCount"],
                })

    return result


@mcp.tool()
def start_hotel(region: str = DEFAULT_REGION) -> dict:
    """
    「Start Hotel」と入力すると呼び出されます。
    Name タグが 'Terrace Villa Foresta Asama' の RDS・ECS リソースをすべて起動します。
    - RDS: stopped 状態の DB を起動
    - ECS: desired_count が 0 のサービスを 1 に変更

    Args:
        region: AWSリージョン（デフォルト: ap-northeast-1）

    Returns:
        起動したリソースの一覧を含む dict
    """
    import boto3
    rds = boto3.client("rds", region_name=region)
    ecs = boto3.client("ecs", region_name=region)

    resources = _find_hotel_resources(region)
    started = {"rds": [], "ecs": [], "skipped": []}

    # RDS 起動
    for r in resources["rds"]:
        if r["status"] == "stopped":
            try:
                resp = rds.start_db_instance(DBInstanceIdentifier=r["db_identifier"])
                started["rds"].append({"db_identifier": r["db_identifier"], "status": resp["DBInstance"]["DBInstanceStatus"]})
            except Exception as e:
                started["skipped"].append({"type": "rds", "id": r["db_identifier"], "reason": str(e)})
        else:
            started["skipped"].append({"type": "rds", "id": r["db_identifier"], "reason": f"status={r['status']}"})

    # ECS 起動（desired_count 0 → 1）
    for r in resources["ecs"]:
        if r["desired_count"] == 0:
            try:
                ecs.update_service(cluster=r["cluster_arn"], service=r["service_name"], desiredCount=1)
                started["ecs"].append({"service_name": r["service_name"], "cluster": r["cluster"], "desired_count": 1})
            except Exception as e:
                started["skipped"].append({"type": "ecs", "id": r["service_name"], "reason": str(e)})
        else:
            started["skipped"].append({"type": "ecs", "id": r["service_name"], "reason": f"desired_count={r['desired_count']}"})

    total = len(started["rds"]) + len(started["ecs"])
    return {
        "status": "ok",
        "started": started,
        "total_started": total,
        "region": region,
        "message": f"Terrace Villa Foresta Asama リソース {total} 件を起動しました。",
    }


@mcp.tool()
def stop_hotel(region: str = DEFAULT_REGION) -> dict:
    """
    「Stop Hotel」と入力すると呼び出されます。
    Name タグが 'Terrace Villa Foresta Asama' の RDS・ECS リソースをすべて停止します。
    - RDS: available 状態の DB を停止
    - ECS: desired_count を 0 に変更

    Args:
        region: AWSリージョン（デフォルト: ap-northeast-1）

    Returns:
        停止したリソースの一覧を含む dict
    """
    import boto3
    rds = boto3.client("rds", region_name=region)
    ecs = boto3.client("ecs", region_name=region)

    resources = _find_hotel_resources(region)
    stopped = {"rds": [], "ecs": [], "skipped": []}

    # RDS 停止
    for r in resources["rds"]:
        if r["status"] == "available":
            try:
                resp = rds.stop_db_instance(DBInstanceIdentifier=r["db_identifier"])
                stopped["rds"].append({"db_identifier": r["db_identifier"], "status": resp["DBInstance"]["DBInstanceStatus"]})
            except Exception as e:
                stopped["skipped"].append({"type": "rds", "id": r["db_identifier"], "reason": str(e)})
        else:
            stopped["skipped"].append({"type": "rds", "id": r["db_identifier"], "reason": f"status={r['status']}"})

    # ECS 停止（desired_count → 0）
    for r in resources["ecs"]:
        if r["desired_count"] > 0:
            try:
                ecs.update_service(cluster=r["cluster_arn"], service=r["service_name"], desiredCount=0)
                stopped["ecs"].append({"service_name": r["service_name"], "cluster": r["cluster"], "desired_count": 0})
            except Exception as e:
                stopped["skipped"].append({"type": "ecs", "id": r["service_name"], "reason": str(e)})
        else:
            stopped["skipped"].append({"type": "ecs", "id": r["service_name"], "reason": "already stopped (desired_count=0)"})

    total = len(stopped["rds"]) + len(stopped["ecs"])
    return {
        "status": "ok",
        "stopped": stopped,
        "total_stopped": total,
        "region": region,
        "message": f"Terrace Villa Foresta Asama リソース {total} 件を停止しました。",
    }


# ─────────────────────────────────────────
# エントリポイント
# ─────────────────────────────────────────
if __name__ == "__main__":
    transport = os.environ.get("MCP_TRANSPORT", "stdio")
    if transport == "sse":
        # host/port は環境変数 FASTMCP_HOST / FASTMCP_PORT で指定
        os.environ.setdefault("FASTMCP_HOST", os.environ.get("MCP_HOST", "127.0.0.1"))
        os.environ.setdefault("FASTMCP_PORT", os.environ.get("MCP_PORT", "8000"))
        mcp.run(transport="streamable-http")
    else:
        mcp.run(transport="stdio")
