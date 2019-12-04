import sys
sys.dont_write_bytecode = True
import os
import json
import time
import cobra.mit.access
import cobra.mit.request
import cobra.mit.session
import ssl
import requests
import yaml
from getpass import getpass
from os.path import expanduser, dirname, realpath, isfile

requests.packages.urllib3.disable_warnings()
ssl._create_default_https_context = ssl._create_unverified_context

homeDir = expanduser("~")

# Config file
lib_path = dirname(__file__)
credentials = lib_path + '/config.yaml'

if not isfile(credentials):
    sys.exit("Configuration file not found: '%s'" % credentials)

class Session():
    def __init__(self, environment, debug_flag=False, dry_run=False, delete=False, force=False, verbose_flag=None, file_logger=None, init_user=None):
        self.env = environment
        self.sessionCookie = homeDir + "/.ACI_" + environment

        # debug flag <True / False>
        self.debug_flag = debug_flag

        # delete flag <True / False>. Mark objects for deletion instead of creation.
        self.delete = delete

        # dry_run flag <True / False>. When <True>, enable debug and do not commit the changes.
        self.dry_run = dry_run

        self.verbose_flag = verbose_flag

        # force flag <True / False>. When <True>, disable the confirmation questions
        self.force = force

        # logging object and the username who launched the script
        self.file_logger = file_logger
        self.init_user = {'user': init_user}

    def checkToken(self):
        # Login if Cookie file "sessionCookie" was not found
        if not isfile(self.sessionCookie):
            self.login()
        else:
            with open(self.sessionCookie, 'r') as f:
                s = f.read()
            s = json.loads(s)

            self.ls.cookie = s['cookie']
            if s['refreshTime']:
                # Re-login if the Cookie expires in less than 5 minutes
                if s['refreshTime'] - int(time.time()) < 300:
                    self.login()
            else:
                self.login()

    def login(self):
        try:
            self.md.login()
        except Exception as e:
            sys.exit('! ERROR: {}'.format(e))
        # Store the login parameters: 'cookie', 'refreshTime', 'refreshTimeoutSeconds' to file in JSON format
        # This is used later to re-use cookie and calculate the cookie expiration time
        s = {'cookie': self.ls.cookie, 'refreshTime': self.ls.refreshTime, 'refreshTimeoutSeconds':  self.ls.refreshTimeoutSeconds}
        f = open(self.sessionCookie, 'w')
        try:
            f.write(json.dumps(s))
        finally:
            f.close()

    def logIntoEnvironment(self):
        # Load credentials
        with open(credentials, 'r') as cred:
            cfg = yaml.safe_load(cred)
        try:
            apic = cfg['aci'][self.env]['apic']

            # Disable proxy settings for connection to this APIC
            os.environ['NO_PROXY'] = apic

            username = cfg['aci'][self.env].get('username')
            if not username:
                username = raw_input('Username: ')
            password = cfg['aci'][self.env].get('password')
            if not password:
                password = getpass()
        except Exception as e:
            sys.exit('! ERROR: Problem reading the credential configuration: {}'.format(e))

        self.ls = cobra.mit.session.LoginSession('https://' + apic, username, password)
        self.md = cobra.mit.access.MoDirectory(self.ls)
        self.checkToken()
        self.c = cobra.mit.request.ConfigRequest()

    def commit(self):
        if not self.dry_run:
            try:
                self.md.commit(self.c)
            except cobra.mit.request.CommitError as e:
                print ('! Error: {}'.format(e))
                raise
