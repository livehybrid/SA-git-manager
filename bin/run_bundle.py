import sys
import os
import subprocess, shlex
import itertools
import re
import boto3
import base64
import logging
from botocore.exceptions import ClientError

from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators

@Configuration(streaming=False, local=True, type='reporting')
class runBundle(GeneratingCommand):
    target = Option(require=True)
    splunk_exe = os.path.join(os.environ['SPLUNK_HOME'], 'bin', 'splunk')

    def get_secret(secret_name):
    #    print "Finding secret={}".format(secret_name)
        region_name = "eu-west-2"

        session = boto3.session.Session()
        client = session.client(
            service_name='secretsmanager',
            region_name=region_name
        )

        try:
            get_secret_value_response = client.get_secret_value(
                SecretId=secret_name
            )
        except ClientError as e:
            if e.response['Error']['Code'] == 'DecryptionFailureException':
                # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
                # Deal with the exception here, and/or rethrow at your discretion.
                raise e
            elif e.response['Error']['Code'] == 'InternalServiceErrorException':
                # An error occurred on the server side.
                # Deal with the exception here, and/or rethrow at your discretion.
                raise e
            elif e.response['Error']['Code'] == 'InvalidParameterException':
                # You provided an invalid value for a parameter.
                # Deal with the exception here, and/or rethrow at your discretion.
                raise e
            elif e.response['Error']['Code'] == 'InvalidRequestException':
                # You provided a parameter value that is not valid for the current state of the resource.
                # Deal with the exception here, and/or rethrow at your discretion.
                raise e
            elif e.response['Error']['Code'] == 'ResourceNotFoundException':
                # We can't find the resource that you asked for.
                # Deal with the exception here, and/or rethrow at your discretion.
                print("secret={} not found in secretsmanager".format(secret_name))
                return ""
        else:
            # Decrypts secret using the associated KMS CMK.
            # Depending on whether the secret is a string or binary, one of these fields will be populated.
            if 'SecretString' in get_secret_value_response:
                return get_secret_value_response['SecretString']
            else:
                return base64.b64decode(get_secret_value_response['SecretBinary'])

    def replace_secret(value):
    #    pprint.pprint(value.groups())
        print("Replacing secret={}".format(value.group(2)))
        secret = get_secret(value.group(2))
        return "{}{}{}".format(value.group(1),secret,value.group(3))

    def generate(self):

        try:
            secret_files = os.popen("grep -Rl splunksecret /opt/splunk/etc/shcluster /opt/splunk/etc/master-apps /opt/splunk/etc/deployment-apps").read()
            secret_value = "NOT CONFIGURED"
            for secret_file in iter(secret_files.splitlines()):
                logging.error("Secrets found in file={}".format(secret_file))
                with open(secret_file) as f:
                    buffer=f.read()
            	secret_value=re.sub(r"(.*)#splunksecret\:([^#]+)#(.*)", self.replace_secret, buffer)
                logging.error("secret_value={}".format(secret_value))

            if secret_value == "NOT CONFIGURED":
                yield {'output':'Secret Value Not Obtained'}
            else:
                runOutput = subprocess.check_output([self.splunk_exe, 'apply', 'shcluster-bundle', '--answer-yes','-target', self.target, '-auth', 'admin:'])
                yield {'output':runOutput}

        except Exception as e:
            error = repr(e)
            yield {"error":error}

dispatch(runBundle, sys.argv, sys.stdin, sys.stdout, __name__)
