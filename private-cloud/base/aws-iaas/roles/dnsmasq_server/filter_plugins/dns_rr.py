#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2023 Cloudera, Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = '''
    name: combine_onto
    author: Webster Mudge (@wmudge) <wmudge@cloudera.com>
    short_description: combine two dictionaries
    description:
        - Create a dictionary (hash/associative array) as a result of merging existing dictionaries.
        - This is the reverse of the C(ansible.builtin.combine) filter.
    positional: _input, _dicts
    options:
        _input:
            description:
                - First dictionary to combine.
            type: dict
            required: True
        _dicts:
            description:
                - The list of dictionaries to combine
            type: list
            elements: dict
            required: True
        recursive:
            description:
                - If V(True), merge elements recursively.
            type: boolean
            default: False
        list_merge:
            description: Behavior when encountering list elements.
            type: str
            default: replace
            choices:
                replace: overwrite older entries with newer ones
                keep: discard newer entries
                append: append newer entries to the older ones
                prepend: insert newer entries in front of the older ones
                append_rp: append newer entries to the older ones, overwrite duplicates
                prepend_rp: insert newer entries in front of the older ones, discard duplicates
'''

EXAMPLES = '''
    # ab => {'a':1, 'b':2, 'c': 4}
    ab: {{ {'a':1, 'b':2} | cloudera.exe.combine_onto({'b':3, 'c':4}) }}

    many: "{{ dict1 | cloudera.exe.combine_onto(dict2, dict3, dict4) }}"
    
    # defaults => {'a':{'b':3, 'c':4}, 'd': 5}
    # customization => {'a':{'c':20}}
    # final => {'a':{'b':3, 'c':20}, 'd': 5}
    final: "{{ customization | cloudera.exe.combine_onto(defaults, recursive=true) }}"
'''

RETURN = '''
    _value:
        description: Resulting merge of supplied dictionaries.
        type: dict
'''

import binascii
import struct

from ansible.errors import AnsibleFilterError
from ansible.module_utils.common.text.converters import to_bytes, to_native, to_text


# See https://sigmaris.info/blog/2018/04/encoding-dns-uri-records-for-dnsmasq/
def to_dns_value(a, *args, **kw):
    '''Produce hexadecimal representation of DNS binary values suitable for dns-rr records in dnsmasq'''
    priority = kw.pop('priority', 10)
    weight = kw.pop('weight', 1)
    
    try:
        transformed = binascii.hexlify(struct.pack('!HH', priority, weight)) + binascii.hexlify(to_bytes(a))
    except Exception as e:
        raise AnsibleFilterError("to_dns_value - %s" % to_native(e), orig_exc=e)
      
    return to_text(transformed)

class FilterModule(object):
    '''Custom and derivative filters'''

    def filters(self):
        return {
            'to_dns_value': to_dns_value
        }
