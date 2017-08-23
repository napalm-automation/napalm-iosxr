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

from __future__ import unicode_literals

# import stdlib
import re
import socket
import difflib
import logging

# import third party lib
from netmiko import ConnectHandler
from netmiko import __version__ as netmiko_version
from netmiko.ssh_exception import NetMikoTimeoutException
from netmiko.ssh_exception import NetMikoAuthenticationException

# import NAPALM base
import napalm_base.helpers
import napalm_iosxr.constants as C
from napalm_base.base import NetworkDriver
from napalm_base.utils import py23_compat
from napalm_base.exceptions import ConnectionException
from napalm_base.exceptions import MergeConfigException
from napalm_base.exceptions import ReplaceConfigException
from napalm_base.exceptions import CommandTimeoutException
from napalm_base.exceptions import LockError
from napalm_base.exceptions import UnlockError
from napalm_base.utils.py23_compat import text_type

logging.basicConfig(filename='iosxr.log', level=logging.DEBUG)
log = logging.getLogger(__file__)


class IOSXRSSHDriver(NetworkDriver):
    '''
    SSH-based driver for IOS-XR.
    '''

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.pending_changes = False
        self.replace = False
        if optional_args is None:
            optional_args = {}
        self.port = optional_args.get('port', 22)
        self.lock_on_connect = optional_args.get('config_lock', False)
        # Netmiko possible arguments
        netmiko_argument_map = {
            'keepalive': 30,
            'verbose': False,
            'global_delay_factor': 1,
            'use_keys': False,
            'key_file': None,
            'ssh_strict': False,
            'system_host_keys': False,
            'alt_host_keys': False,
            'alt_key_file': '',
            'ssh_config_file': None
        }
        fields = netmiko_version.split('.')
        fields = [int(x) for x in fields]
        maj_ver, min_ver, bug_fix = fields
        if maj_ver >= 2:
            netmiko_argument_map['allow_agent'] = False
        elif maj_ver == 1 and min_ver >= 1:
            netmiko_argument_map['allow_agent'] = False
        # Build dict of any optional Netmiko args
        self.netmiko_optional_args = {}
        for k, v in netmiko_argument_map.items():
            try:
                self.netmiko_optional_args[k] = optional_args[k]
            except KeyError:
                self.netmiko_optional_args[k] = v
        log.debug('Creating a new instance of the NAPALM IOS-XR SSH driver')
        log.debug('Connecting to %s:%d as %s', self.hostname, self.port, self.username)
        log.debug('Optional args:')
        log.debug(self.netmiko_optional_args)
        self._in_config_mode = False

    def _send_command(self, command, configuration=False):
        '''
        Helper to send the command and get the output.
        '''
        if self._in_config_mode and not configuration:
            # When the driver is in config mode,
            #   you can still execute arbitrary commands, not configuration-related.
            command = 'do {base_cmd}'.format(base_cmd=command)
        log.debug('Sending command: %s', command)
        output = self.device.send_command_timing(command,
                 delay_factor=self.netmiko_optional_args['global_delay_factor'],
                 max_loops=self.timeout/self.netmiko_optional_args['global_delay_factor'])
        log.debug('Received the output:')
        log.debug(output)
        # The output has a newline after the command prompt
        #   and another line with the timestamp.
        # e.g.:
        #
        # Tue Jul 18 11:53:32.372 UTC
        # For this reason, we need to strip the first two lines
        #   and return only what comes after.
        return '\n'.join(output.splitlines()[2:])

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
        # Can not enter exclusive mode. The Configuration Namespace is locked by another agent.
        cfg_lock_lines = cfg_lock_out.splitlines()
        if not cfg_lock_lines:
            # Nothing back, means everything was fine, config lock succeeded.
            self._in_config_mode = True
            return
        if 'Can not enter exclusive mode' in cfg_lock_lines[-1] or\
           'Cannot enter exclusive mode' in cfg_lock_lines[-1]:  # on the bloody IOS-XR >= 6.x
            rgx = '([0-9a-z-]+)\s+([a-z0-9\/]+)\s+(\w+)\s+(.*)\s+(.?)'   # a beautiful regex
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
            lock_msg = 'Configuration DB locked by {usr} since {ts}'.format(usr=lock_user,
                                                                            ts=lock_ts)
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
        if self._in_config_mode and self.pending_changes:
            show_candidate = self._send_command('show configuration merge', configuration=True)
            show_running = self._send_command('show running-config', configuration=True)
            diff = difflib.unified_diff(show_running.splitlines(1)[2:-2],
                                        show_candidate.splitlines(1)[2:-2])
            return ''.join([line.replace('\r', '') for line in diff])
        return ''

    def discard_config(self):
        '''
        Discard the configuration changes made in the candidate.
        '''
        log.debug('Discarding the candidate config')
        if self._in_config_mode:
            discarding = self._send_command('abort', configuration=True)
            # When executing abort, it also quites the configuration mode.
            self.unlock()

    def commit_config(self):
        '''
        Commit the configuration changes.
        '''
        log.debug('Committing')
        if self._in_config_mode and self.pending_changes:
            commit_cmd = 'commit {replace} save-running filename disk0:rollback-0'.format(
                         replace='replace' if self.replace else '')
            committing = self._send_command(commit_cmd, configuration=True)
            if 'This could be a few minutes if your config is large. Confirm?' in committing:
                log.debug('Confirming file copy')
                confirming = self._send_command('\n', configuration=True)
            log.debug('Exiting config mode')
            exiting = self._send_command('exit', configuration=True)
            self.unlock()

    def unlock(self):
        '''
        Unlock the configuration DB.
        '''
        log.debug('Unlocking the config DB')
        self.pending_changes = False
        self.replace = False
        if not self.lock_on_connect:
            self._in_config_mode = False

    def open(self):
        '''
        Open the connection with the device.
        '''
        try:
            self.device = ConnectHandler(device_type='cisco_xr',
                                         ip=self.hostname,
                                         port=self.port,
                                         username=self.username,
                                         password=self.password,
                                         **self.netmiko_optional_args)
            self.device.timeout = self.timeout
            if self.lock_on_connect:
                self.lock()
        except NetMikoTimeoutException as t_err:
            raise ConnectionException(t_err.args[0])
        except NetMikoAuthenticationException as au_err:
            raise ConnectionException(au_err.args[0])

    def close(self):
        if hasattr(self.device, 'remote_conn'):
            self.device.remote_conn.close()

    def is_alive(self):
        null = chr(0)
        try:
            # Try sending ASCII null byte to maintain
            #   the connection alive
            self.device.send_command(null)
        except (socket.error, EOFError):
            # If unable to send, we can tell for sure
            #   that the connection is unusable,
            #   hence return False.
            return {
                'is_alive': False
            }
        return {
            'is_alive': self.device.remote_conn.transport.is_active()
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

    def get_interfaces(self):

        interfaces = {}

        INTERFACE_DEFAULTS = {
            'is_enabled': False,
            'is_up': False,
            'mac_address': u'',
            'description': u'',
            'speed': -1,
            'last_flapped': -1.0
        }

        interfaces_command = 'show interfaces'

        interfaces_ssh_reply = self._send_command(interfaces_command)

        t = napalm_base.helpers.textfsm_extractor(self, "cisco_xr_show_interfaces", interfaces_ssh_reply)
        t = napalm_base.helpers.textfsm_extractor(self, "cisco_xr_show_interfaces_admin", interfaces_ssh_reply)

        return interfaces
