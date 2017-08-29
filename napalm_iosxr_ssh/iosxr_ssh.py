# -*- coding: utf-8 -*-
# Copyright 2017 Napalm Automation. All rights reserved.
#
# The contents of this file are licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

from __future__ import absolute_import
from __future__ import unicode_literals

# import stdlib
import re
import difflib
import logging

# import third party lib
import sisqo

# import NAPALM base
import napalm_base.helpers
import napalm_iosxr.constants as C
from napalm_base.base import NetworkDriver
from napalm_base.utils import py23_compat
from napalm_base.exceptions import ConnectionException
from napalm_base.exceptions import LockError
from napalm_base.exceptions import MergeConfigException
from napalm_base.exceptions import ReplaceConfigException
from napalm_base.exceptions import CommandTimeoutException
from napalm_base.utils.py23_compat import text_type

logging.basicConfig(filename='iosxr.log', level=logging.DEBUG)
log = logging.getLogger(__file__)

class IOSXRDriver(NetworkDriver):

    """IOS-XR driver class: inherits NetworkDriver from napalm_base."""

    def __init__(self, hostname, username, password, timeout=10, optional_args=None):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.pending_changes = False
        self.replace = False
        if optional_args is None:
            self.optional_args = {}
        self.port = self.optional_args.get('port', 22)
        self.lock_on_connect = self.optional_args.get('config_lock', False)

        self.device = sisqo.SSH(host=self.hostname,
                            username=self.username,
                            port = self.port,
                            sshOptions=self.optional_args.get('ssh_options', None),
                            timeout=self.timeout,
                            logger=log)
        self._in_config_mode = False
        log.debug('Creating a new instance of the NAPALM IOS-XR SSH driver')
        log.debug('Connecting to %s:%d as %s', self.hostname, self.port, self.username)
        log.debug('Optional args:')
        log.debug(self.optional_args)


    def open(self):
        try:
            self.device.authenticate(password=self.password)
            if self.lock_on_connect:
                self.lock()
        except (sisqo.ssh.NotAuthenticatedError, sisqo.ssh.NotConnectedError) as err:
            raise ConnectionException(err.args[0])


    def close(self):
            self.device.disconnect()


    def _send_command(self, command, configuration=False, timeout=None):
        '''
        Helper to send the command and get the output.
        '''
        if self._in_config_mode and not configuration:
            # When the driver is in config mode,
            #   you can still execute arbitrary commands, not configuration-related.
            command = 'do {base_cmd}'.format(base_cmd=command)
        log.debug('Sending command: %s', command)
        if not self.is_alive()['is_alive']:
            return
        if timeout:
            self.device.write(command, timeout=timeout)
        else:
            self.device.write(command)
        output = self.device.read()
        log.debug('Received the output:')
        log.debug(output)
        # The output has a line with the timestamp.
        # e.g.:
        # Tue Jul 18 11:53:32.372 UTC
        # For this reason, we need to strip the first line
        return '\n'.join(output.splitlines()[1:])

    def lock(self):
        '''
        Lock the configuration DB.
        '''
        if self._in_config_mode:
            log.info('Already in configuration mode')
            return
        log.debug('Trying to lock the config DB')
        cfg_lock_out = self._send_command('configure exclusive')
        # Current Configuration Session  Line       User      Date                     Lock
        # 00000011-000a7139-0000008c     /dev/vty0  username  Tue Jul 18 11:02:16 2017 *
        #
        # Can not enter exclusive mode. The Configuration Namespace is locked by another agent.
        cfg_lock_lines = cfg_lock_out.splitlines()
        if not cfg_lock_lines:
            # Nothing back, means everything was fine, config lock succeeded.
            self._in_config_mode = True
            return
        else:
            rgx = '([0-9a-z-]+)\s+([a-z0-9\/]+)\s+(\w+)\s+(.*)\s+(.?)'  # a beautiful regex
            # to extract the timestamp and the username locking the config database
            lock_user = 'unknown'
            lock_ts = 'unknown'
            for line in cfg_lock_lines:
                rgx_res = re.search(rgx, line, re.I)
                if not rgx_res:
                    continue
                if rgx_res.group(5) != '*':
                    continue
                lock_user = rgx_res.group(3)
                lock_ts = rgx_res.group(4)
            lock_msg = 'Can\'t lock db because {usr} has been in config' \
                       ' mode since {ts}'.format(usr=lock_user, ts=lock_ts)
            log.error(lock_msg)
            raise LockError(lock_msg)
        self._in_config_mode = True

    def _load_config(self, filename=None, config=None, replace=False):
        self.replace = replace
        err_class = ReplaceConfigException if replace else MergeConfigException
        if not self._in_config_mode:
            # Enter in config mode and lock the DB.
            self.lock()
        if filename:
            log.debug('Reading configuration from %s', filename)
            with open(filename, 'r') as cfg_file:
                config = cfg_file.read()
        log.debug('Loading configuration')
        log.debug(config)
        if not config:
            raise err_class('Please provide a valid config to load.')
        self.pending_changes = True
        for line in config.splitlines():
            out = self._send_command(line, configuration=True)
            if '''Invalid input detected at '^' marker''' in out:
                log.error('Invalid configuration %s', line)
                log.error(out)
                log.error('Discarding the candidate configuration')
                self.discard_config()  # rollback on error.
                raise err_class('Invalid configuration: {}'.format(line))

    def load_merge_candidate(self, filename=None, config=None):
        '''
        Load the configuration changes in the candidate configuration and merge.
        '''
        return self._load_config(filename=filename, config=config)

    def load_replace_candidate(self, filename=None, config=None):
        '''
        Load the configuration changes in the candidate configuration and replace.
        '''
        return self._load_config(filename=filename, config=config, replace=True)

    def compare_config(self):
        '''
        Compare the candidate with the running configuration.
        '''
        if self._in_config_mode and self.pending_changes and not self.replace:
            show_candidate = self._send_command('show configuration merge', configuration=True)
            show_running = self._send_command('show running-config', configuration=True)
            diff = difflib.unified_diff(show_running.splitlines(1)[2:-2],
                                        show_candidate.splitlines(1)[2:-2])
            return ''.join([line.replace('\r', '') for line in diff])
        elif self._in_config_mode and self.pending_changes and self.replace:
            diff = self._send_command('show configuration changes diff', configuration=True)
            return diff
        return ''

    def discard_config(self):
        '''
        Discard the configuration changes made in the candidate.
        '''
        log.debug('Discarding the candidate config')
        if self._in_config_mode:
            discarding = self._send_command('abort', configuration=True)
            # When executing abort, it also quits the configuration mode.
            self._in_config_mode = False

    def commit_config(self):
        '''
        Commit the configuration changes.
        '''
        log.debug('Committing')
        if self._in_config_mode and self.pending_changes:
            commit_cmd = 'commit {replace} save-running filename disk0:rollback-0'.format(
                replace='replace' if self.replace else '')
            committing = self._send_command(commit_cmd, configuration=True, timeout=5)
            if 'This commit will replace' in committing:
                log.debug('Confirming commit replace')
                confirming = self._send_command('yes', configuration=True)
            elif 'This could be a few minutes if your config is large. Confirm?' in committing:
                log.debug('Confirming file copy')
                confirming = self._send_command('', configuration=True)
            log.debug('Exiting config mode')
            self.unlock()

    def unlock(self):
        '''
        Unlock the configuration DB by exiting config mode.
        '''
        log.debug('Unlocking the config DB')
        self.pending_changes = False
        self.replace = False
        if self.lock_on_connect or not self._in_config_mode:
            return
        else:
            self._send_command('abort', configuration=True)
            self._in_config_mode = False

    def is_alive(self):
        null = chr(0)
        try:
            # Try sending ASCII null byte to maintain
            #   the connection alive
            self._send_command(null)
        except (sisqo.ssh.NotConnectedError, sisqo.ssh.NotAuthenticatedError):
            # If unable to send, we can tell for sure
            #   that the connection is unusable,
            #   hence return False.
            return {
                'is_alive': False
            }
        return {
            'is_alive': True
        }

    def cli(self, commands):
        '''
        Execute raw CLI commands and return the output,
        as provided by the device.
        '''
        if not isinstance(commands, (list, tuple)):
            raise TypeError('Please enter a valid list of commands!')
        cli_output = {}
        for command in commands:
            response = self._send_command(command)
            cli_output[command] = response
        return cli_output


    def get_facts(self):

        facts = {
            'vendor': u'Cisco',
            'os_version': u'',
            'hostname': u'',
            'uptime': -1,
            'serial_number': u'',
            'fqdn': u'',
            'model': u'',
            'interface_list': []
        }

        uptime = self._send_command('show operational SystemTime uptime')
        version = self._send_command('show version')
        sn_model = self._send_command('show inventory rack')
        fqdn = self._send_command('show configuration running-config domain name')
        ifaces = self._send_command('show interfaces')
        parsed_ifaces = napalm_base.helpers.textfsm_extractor(self, 'show_interfaces', ifaces)
        for iface in parsed_ifaces:
            facts['interface_list'].append(iface['interface'])
        facts['uptime'] = int(uptime.split()[-1])
        for line in uptime.splitlines():
            if line.lower().startswith('hostname:'):
                hostname = line.split()[-1]
                break
        for line in version.splitlines():
            if line.lower().startswith('cisco ios xr software'):
                facts['os_version'] = line.split('Version ')[-1]
                break
        if 'invalid input' in sn_model.lower():
            facts['serial_number'] = None
            facts['model'] = u'xrv'
        else:
            facts['serial_number'] = sn_model.splitlines()[-1].split()[-1]
            facts['model'] = sn_model.splitlines()[-1].split()[-2]
        facts['hostname'] = hostname
        if 'no such configuration' in fqdn.lower():
            facts['fqdn'] = hostname
        else:
            facts['fqdn'] = hostname + '.' + fqdn.split()[-1]
        return facts
