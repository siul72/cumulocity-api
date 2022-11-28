import json
import os
import logging
import sys
import requests
from requests_toolbelt import MultipartEncoder, MultipartEncoderMonitor
from c8yrc.rest_client.c8y_enterprise import C8yQueries, BlobRepository
from c8yrc.rest_client.c8y_exception import C8yException


class CumulocityClient:

    def __init__(self, hostname: str, tenant: str, user: str, password: str, tfacode: str = '',
                 ignore_ssl_validate: bool = False):
        self.hostname = hostname
        self.tenant = tenant
        self.user = user
        self.password = password
        self.tfacode = tfacode
        self.session = requests.Session()
        self.token = None
        if hostname.startswith('http'):
            self.url = hostname
        else:
            self.url = f'https://{hostname}'
        if ignore_ssl_validate:
            self.session.verify = False

    @staticmethod
    def _progress_bar(monitor):
        progress = int(monitor.bytes_read/monitor.len*20)
        sys.stdout.write("\r[{}/{}] bytes |".format(monitor.bytes_read, monitor.len))
        sys.stdout.write("{}>".format("=" * progress))
        sys.stdout.write("{}|".format(" " * (20-progress)))
        sys.stdout.flush()

    def _post_data(self, query, files):
        req_url = f'{self.url}{query}'

        if self.token:
            headers = {'Authorization': 'Bearer ' + self.token}
        else:
            headers = {'X-XSRF-TOKEN': self.session.cookies.get_dict()['XSRF-TOKEN']}

        try:
            encoder = MultipartEncoder(files)
            monitor = MultipartEncoderMonitor(encoder, callback=self._progress_bar)
            headers['Content-Type'] = monitor.content_type
            # response = self.session.post(url=req_url, headers=headers, files=files, verify=False)
            response = self.session.post(url=req_url, data=monitor, headers=headers, verify=False)
        except requests.exceptions.InvalidURL as e:
            raise C8yException(f'wrong url {req_url}',  e)

        if response.status_code == 200:
            logging.debug('200 Ok response')
        elif response.status_code == 401:
            logging.error('Not authorized')
        elif response.status_code == 202:
            logging.error('202 Accepted')
        else:
            logging.error(f'Server Error received, Status Code: {response.status_code}')
        return response

    def _get_data(self):
        pass

    def validate_tenant_id(self):
        tenant_id = None
        current_user_url = self.url + C8yQueries.GET_LOGIN_OPTIONS
        headers = {}
        response = self.session.get(current_user_url, headers=headers)
        logging.debug(f'Response received: {response}')
        if response.status_code == 200:
            login_options_body = json.loads(response.content.decode('utf-8'))
            login_options = login_options_body['loginOptions']
            for option in login_options:
                if 'initRequest' in option:
                    tenant_id = option['initRequest'].split('=')[1]
                    if self.tenant != tenant_id:
                        logging.debug(f'Wrong Tenant ID {self.tenant}, Correct Tenant ID: {tenant_id}')
                        self.tenant = tenant_id
                    else:
                        tenant_id = None
                    break
        else:
            logging.error(f'Error validating Tenant ID!')
        return tenant_id

    def validate_remote_access_role(self):
        is_valid = False
        current_user_url = self.url + f'/user/currentUser'
        if self.token:
            headers = {'Content-Type': 'application/json',
                       'Authorization': 'Bearer ' +self.token}
        else:
            headers = {'Content-Type': 'application/json',
                        'X-XSRF-TOKEN': self.session.cookies.get_dict()['XSRF-TOKEN'] }
        response = self.session.get(current_user_url, headers=headers)
        logging.debug(f'Response received: {response}')
        if response.status_code == 200:
            user = json.loads(response.content.decode('utf-8'))
            effective_roles = user['effectiveRoles']
            for role in effective_roles:
                if 'ROLE_REMOTE_ACCESS_ADMIN' == role['id']:
                    logging.debug(f'Remote Access Role assigned to User {self.user}!')
                    is_valid = True
                    break
        else:
            logging.error(f'Error retrieving User Data!')
            is_valid = False
        return is_valid

    def validate_token(self):
        is_valid = False
        current_user_url = self.url + f'/user/currentUser'
        headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + self.token}
        response = self.session.get(current_user_url, headers=headers)
        logging.debug(f'Response received: {response}')
        if response.status_code == 200:
            is_valid = True
        else:
            logging.error(f'Error validating Token {response.status_code}. Please provide Tenant User and Password!')
            del os.environ['C8Y_TOKEN']
            is_valid = False
            sys.exit(1)
        return is_valid

    def retrieve_token(self):
        oauth_url = self.url + f'/tenant/oauth?tenant_id={self.tenant}'
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        body = {
            'grant_type': 'PASSWORD',
            'username': self.user,
            'password': self.password,
            'tfa_code': self.tfacode
        }
        logging.debug(f'Sending requests to {oauth_url}')
        response = self.session.post(oauth_url, headers=headers, data=body)
        if response.status_code == 200:
            logging.debug(f'Authentication successful. Tokens have been updated {self.session.cookies.get_dict()}!')
            os.environ['C8Y_TOKEN'] = self.session.cookies.get_dict()['authorization']
        elif response.status_code == 401:
            logging.error(f'User {self.user} is not authorized to access Tenant {self.tenant} or TFA-Code is invalid.')
            sys.exit(1)
        else:
            logging.error(f'Server Error received for User {self.user} and Tenant {self.tenant}. Status Code: {response.status_code}')
            sys.exit(1)
        return self.session

    def read_ext_Id(self, device, extype):
        identiy_url = self.url + f'/identity/externalIds/{extype}/{device}'
        #auth_string = f'{self.tenant}/{self.user}:{self.password}'
        #encoded_auth_string = b64encode(
        #    bytes(auth_string, 'utf-8')).decode('ascii')
        if self.token:
            headers = {'Content-Type': 'application/json',
                       'Authorization': 'Bearer ' +self.token}
        else:
            headers = {'Content-Type': 'application/json',
                    'X-XSRF-TOKEN': self.session.cookies.get_dict()['XSRF-TOKEN']
                   #'Authorization': 'Basic ' + encoded_auth_string
                    }
        logging.debug(f'Sending requests to {identiy_url}')
        response = self.session.get(identiy_url, headers=headers)
        logging.debug(f'Response received: {response}')
        ext_id = None
        if response.status_code == 200:
            ext_id = json.loads(response.content.decode('utf-8'))
        elif response.status_code == 401:
            logging.error(f'User {self.user} is not authorized to read Device Data of Device {device}')
            sys.exit(1)
        elif response.status_code == 404:
            logging.error(f'Device {device} not found!')
            # print(f'Device {device} not found!')
            sys.exit(1)
        else:
            logging.error(f'Error on retrieving device. Status Code {response.status_code}')
            # print(f'Error on retrieving device. Status Code {response.status_code}')
            sys.exit(1)
        return ext_id

    def read_mo(self, device, extype):
        ext_id = self.read_ext_Id(device, extype)
        mor_id = None
        mor = None
        if ext_id['managedObject']['id']:
            mor_id = ext_id['managedObject']['id']
        if mor_id:
            managed_object_url = self.url + f'/inventory/managedObjects/{mor_id}'
            if self.token:
                headers = {'Content-Type': 'application/json',
                       'Authorization': 'Bearer ' +self.token}
            else:
                headers = {'Content-Type': 'application/json',
                    'X-XSRF-TOKEN': self.session.cookies.get_dict()['XSRF-TOKEN']
                   #'Authorization': 'Basic ' + encoded_auth_string
                    }
            #auth_string = f'{self.tenant}/{self.user}:{self.password}'
            #encoded_auth_string = b64encode(
            #    bytes(auth_string, 'utf-8')).decode('ascii')
            logging.debug(f'Sending requests to {managed_object_url}')
            response = self.session.get(managed_object_url, headers=headers)
            logging.debug(f'Response received: {response}')
            if response.status_code == 200:
                mor = json.loads(response.content.decode('utf-8'))

            elif response.status_code == 401:
                logging.error(f'User {self.user} is not authorized to read Device Data of Device {device}')

            elif response.status_code == 404:
                logging.error(f'Device {device} not found!')

            else:
                logging.error(f'Error on retrieving device. Status Code {response.status_code}')

            return mor

    def get_config_id(self, mor, config):
        access_list = mor['c8y_RemoteAccessList']
        device = mor['name']
        config_id = None
        for remote_access in access_list:
            if not remote_access['protocol'] == 'PASSTHROUGH':
                continue
            if config and remote_access['name'] == config:
                config_id = remote_access['id']
                logging.info(f'Using Configuration with Name "{config}" and Remote Port {remote_access["port"]}')
                break
            if not config:
                config_id = remote_access['id']
                logging.info(f'Using Configuration with Name "{config}" and Remote Port {remote_access["port"]}')
                break
        if not config_id:
            if config:
                logging.error(
                    f'Provided config name "{config}" for "{device}" was not found or not of type "PASSTHROUGH"')
                sys.exit(1)
            else:
                logging.error(f'No config of Type "PASSTHROUGH" has been found for device "{device}"')
                sys.exit(1)
        return config_id

    def get_device_id(self, mor):
        return mor['id']

    def get_firmware_info(self, device, extype):
        #identiy_url = self.url + f'/identity/externalIds/{extype}/{device}'
        identiy_url = self.url + f'/devicemanagement/device/{device}'
        #auth_string = f'{self.tenant}/{self.user}:{self.password}'
        #encoded_auth_string = b64encode(
        #    bytes(auth_string, 'utf-8')).decode('ascii')
        if self.token:
            headers = {'Content-Type': 'application/json',
                       'Authorization': 'Bearer ' +self.token}
        else:
            headers = {'Content-Type': 'application/json',
                       'X-XSRF-TOKEN': self.session.cookies.get_dict()['XSRF-TOKEN']
                       #'Authorization': 'Basic ' + encoded_auth_string
                       }
        logging.debug(f'Sending requests to {identiy_url}')
        response = self.session.get(identiy_url, headers=headers)
        logging.debug(f'Response received: {response}')
        ext_id = None
        if response.status_code == 200:
            ext_id = json.loads(response.content.decode('utf-8'))
        elif response.status_code == 401:
            logging.error(f'User {self.user} is not authorized to read Device Data of Device {device}')

        elif response.status_code == 404:
            logging.error(f'Device {device} not found!')

        else:
            logging.error(f'Error on retrieving device. Status Code {response.status_code}')
        return ext_id

    def upload_firmware(self, artifact_file_location, metadata_file_location):
        _payload = {
            "repository": BlobRepository.AZURE,
            "description": "Uploaded by Jenkins",
            "cabTicket": "Jenkins advice not to use Cab Advisory Boards",
            "approvedBy": "jenkins@schindler.com",
            "canary": False,
            "restrictedToCPG": False,
            "restrictedToCCC": False,
        }
        try:
            artifact_file_name = os.path.basename(artifact_file_location)
            metadata_file_name = os.path.basename(metadata_file_location)
            multiple_files = [('file', (artifact_file_name, open(artifact_file_location, 'rb'), 'application/octet-stream')),
             ('metadata', (metadata_file_name, open(metadata_file_location, 'rb'), 'application/octet-stream')),
             ('requestDto', ('requestDto_name', json.dumps(_payload).encode('utf-8'), 'application/json'))]
        except FileNotFoundError as e:
            msg = 'artifact or metadata files not found'
            logging.error(msg)
            raise C8yException(msg, e)
        response = self._post_data(query=C8yQueries.POST_BLOB_UPLOAD, files=multiple_files)
        logging.debug(f'Response received: {response}')
        if response.status_code == 200:
            logging.info('firmware uploaded')
        elif response.status_code == 202:
            logging.info('firmware upload accepted')
        else:
            msg = f'unable to upload the image artifact: {response.content}'
            raise C8yException(msg, None)






