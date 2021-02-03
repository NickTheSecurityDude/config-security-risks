# Using Config to Identify AWS Top Security Risks

## Searches for the following:
- EBS volumes without Encryption
- EBS encryption off by default
- S3 buckets not using **customer** KMS Encryption

Howto Install:  
If needed, export your AWS profile:  
`export AWS_PROFILE=profile_name`

Create a virtual environment and launch the stacks:  
```
python3 -m venv .venv  
source .venv/bin/activate   
python3 -m pip install -r requirements.txt  
cdk bootstrap aws://<account-id>/<region>  
cdk synth   
cdk deploy --all --require-approval never
```
