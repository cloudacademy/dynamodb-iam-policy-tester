from flask import Flask
from flask import render_template
from flask import request
import boto3
import botocore
from boto3.dynamodb.conditions import Key, Attr
from boto3.session import Session
import json
import time

app = Flask(__name__)


def get_assume_role_session(role_arn):
    session_name = str(time.time())
    client = boto3.client("sts")
    account_id = client.get_caller_identity()["Account"]
    response = client.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
    session = Session(
        aws_access_key_id=response["Credentials"]["AccessKeyId"],
        aws_secret_access_key=response["Credentials"]["SecretAccessKey"],
        aws_session_token=response["Credentials"]["SessionToken"],
    )

    return session


def get_dynamodb_client(role_arn):
    session = get_assume_role_session(role_arn)
    return session.client("dynamodb")


def attach_role_policy(client, role_name, policy_arn):
    role = client.get_role(RoleName=role_name)
    client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)


def query_dynamodb(client, user_id, attributes):
    if user_id:
        try:
            if not attributes:
                items = client.query(
                    TableName="users",
                    KeyConditionExpression="Id = :user_id",
                    ExpressionAttributeValues={":user_id": {"S": user_id}},
                )
            else:
                items = client.query(
                    TableName="users",
                    KeyConditionExpression="Id = :user_id",
                    ExpressionAttributeValues={":user_id": {"S": user_id}},
                    ProjectionExpression=attributes,
                )
                return json.dumps(items["Items"], indent=2)
        except botocore.exceptions.ClientError as e:
            return json.dumps(str(e), indent=2)

    return None


def get_policy(client, policy_arn):
    policy = client.get_policy(PolicyArn=policy_arn)
    policy_version = client.get_policy_version(
        PolicyArn=policy_arn, VersionId=policy["Policy"]["DefaultVersionId"]
    )
    policy_document = policy_version["PolicyVersion"]["Document"]
    return json.dumps(policy_version["PolicyVersion"]["Document"], indent=2)


@app.route("/")
def home():

    account_id = boto3.client("sts").get_caller_identity().get("Account")
    client = boto3.client("iam")

    role_name = "lab"
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    policy_name = "dynamodb-policy"
    policy_arn = f"arn:aws:iam::{account_id}:policy/{policy_name}"

    attach_role_policy(client, role_name, policy_arn)

    ddb_client = get_dynamodb_client(role_arn)

    user_id = request.args.get("id")
    attributes = request.args.get("attributes")

    result = query_dynamodb(ddb_client, user_id, attributes)

    policy_json = get_policy(client, policy_arn)

    return render_template("home.html", policy=policy_json, result=result)
