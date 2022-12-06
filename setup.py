#  Copyright (c) 2021 Software AG, Darmstadt, Germany and/or its licensors
#
#  SPDX-License-Identifier: Apache-2.0
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#


from setuptools import setup

setup(name='c8yrc',
      version='0.0.14',
      description='Cumulocity Rest Client',

      license='Apache v2',
      packages=['c8yrc',
                'c8yrc.tcp_socket',
                'c8yrc.websocket_client',
                'c8yrc.rest_client'],
      entry_points={
        'console_scripts': [
              'c8yrc=c8yrc.main:start'
            ],
      },
      install_requires=[
        'requests>=2.26.0',
        'websocket_client>=1.2.1',
        'requests_toolbelt>=0.9.1'
      ],
      zip_safe=False)

