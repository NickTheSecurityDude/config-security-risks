##############################################################
#
# iam_stack.py
#
# Resources:
#   Lambda Execution Role
#
# Exports:
#  config_ebs_enc_lambda_role
#
##############################################################

from aws_cdk import (
  aws_iam as iam,
  core
)

class IAMStack(core.Stack):

  def __init__(self, scope: core.Construct, construct_id: str, env, **kwargs) -> None:
    super().__init__(scope, construct_id, **kwargs)

    # get acct id for policies
    # acct_id=env['account']
    region=env['region']

    # create lambda execution role, use same role for both lambdas
    self._config_ebs_enc_lambda_role=iam.Role(self,"EBS Encrypted Lambda Role",
      role_name="Config_ebs_s3_Lambda_Execution_Role-"+region,
      assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
      inline_policies=[iam.PolicyDocument(
        statements=[iam.PolicyStatement(
          actions=["config:PutEvaluations"],
          effect=iam.Effect.ALLOW,
          resources=["*"]
        )]
      )],
      managed_policies=[
        iam.ManagedPolicy.from_aws_managed_policy_name('IAMReadOnlyAccess'),
        iam.ManagedPolicy.from_aws_managed_policy_name('service-role/AWSLambdaBasicExecutionRole')
      ]
    )

  # Exports
  @property
  def config_ebs_enc_lambda_role(self) -> iam.IRole:
    return self._config_ebs_enc_lambda_role

  