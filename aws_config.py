import boto3
import os
from botocore.exceptions import ClientError

class AWSConfig:
    def __init__(self):
        self.aws_access_key_id = os.environ.get('AWS_ACCESS_KEY_ID')
        self.aws_secret_access_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
        self.region_name = os.environ.get('AWS_REGION', 'ap-south-1')
        self.bucket_name = os.environ.get('S3_BUCKET_NAME', 'vitlearnary-files-daksh')
        self.s3_enabled = bool(self.aws_access_key_id and self.aws_secret_access_key)
        
    def get_s3_client(self):
        if not self.s3_enabled:
            print("⚠️  S3 disabled - no AWS credentials provided")
            return None
            
        try:
            return boto3.client(
                's3',
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                region_name=self.region_name
            )
        except Exception as e:
            print(f"❌ S3 client creation failed: {e}")
            return None

aws_config = AWSConfig()