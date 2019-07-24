import re
import os
import fileinput
import boto3
import base64
from botocore.exceptions import ClientError
import subprocess, shlex


def runGitCommand(command,output=True):
    kwargs = {}
    kwargs['stdout'] = subprocess.PIPE
    kwargs['stderr'] = subprocess.PIPE
    kwargs['cwd']  = '/opt/splunk/etc'
    proc = subprocess.Popen(shlex.split("git {}".format(command)), **kwargs)
    (stdout_str, stderr_str) = proc.communicate()
    return_code = proc.wait()
    #Git output
    if output:
        if stdout_str:
            print stdout_str
        if stderr_str:
            print stderr_str

print "type,tag,date"
runGitCommand("fetch --all",False)
#runGitCommand("tag -l --format=\"%(refname:short),%(creatordate)\"")
runGitCommand("for-each-ref --sort=committerdate refs/tags/ --format='Tag,%(refname:short),%(contents:subject) - %(authorname) (%(committerdate:relative))'")
runGitCommand("for-each-ref --sort=committerdate refs/remotes/origin/ --format='Branch,%(refname:strip=3),%(contents:subject) - %(authorname) (%(committerdate:relative))'")