##############################################################
#
# lambda_stack.py
#
# Resources:
#  1 lambda function (code in /lambda folder (from_asset))
#
##############################################################

from aws_cdk import (
  aws_iam as iam,
  aws_lambda as lambda_,
  core
)

class LambdaStack(core.Stack):

  def __init__(self, scope: core.Construct, construct_id: str, config_ebs_enc_lambda_role: iam.IRole, **kwargs) -> None:
    super().__init__(scope, construct_id, **kwargs)

    # get acct id for policies
    #acct_id=env['account']

    # create the config S3 Customer KMS checker Lambda function
    self._s3_cust_kms=lambda_.Function(self,"Config S3 Cust KMS Lambda Func",
      code=lambda_.Code.from_asset("lambda/s3_cust_kms.zip"),
      handler="s3_cust_kms.lambda_handler",
      runtime=lambda_.Runtime.PYTHON_3_8,
      role=config_ebs_enc_lambda_role,
      timeout=core.Duration.seconds(60)
    )    

    # create the config ebs encrypted volume checker Lambda function
    self._ebs_encrypted_volumes=lambda_.Function(self,"Config KMS IAM Lambda Func",
      code=lambda_.Code.from_asset("lambda/ebs_encrypted_volumes.zip"),
      handler="ebs_encrypted_volumes.lambda_handler",
      runtime=lambda_.Runtime.PYTHON_3_8,
      role=config_ebs_enc_lambda_role,
      timeout=core.Duration.seconds(60)
    )

  # Exports
  @property
  def s3_cust_kms_function(self) -> lambda_.IFunction:
    return self._s3_cust_kms

  @property
  def ebs_encrypted_volumes_function(self) -> lambda_.IFunction:
    return self._ebs_encrypted_volumes




