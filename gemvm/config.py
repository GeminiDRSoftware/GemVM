#!/usr/bin/env python3
#
# Copyright(c) 2022 Association of Universities for Research in Astronomy, Inc.

"""
A script for maintaining a simple GemVM configuration file, so that users can
conveniently specify one or more disk images and the associated configuration
via a short name label. The motivation is partly to avoid routine manipulation
of the paths to disk images that must be protected from inadvertent deletion.

Much of the logic lives in gemvm.py, allowing the latter also to function as a
stand-alone script outside the package (eg. using the OS python), if convenient.
"""

import argparse
import json
import os
import sys

from .gemvm import config_file, get_config, invocation_err
from .gemvm import standardize_paths, check_file_access
from .gemvm import _add_main_args, _merge_args

indent = 4


def confirm(prompt):

    while True:

        try:
            answer = input(f'{prompt} (y/[n]): ').lower()
        except (EOFError, KeyboardInterrupt):
            answer = ''
            print()

        if answer in ('y', 'yes'):
            return True
        elif answer in ('n', 'no', ''):
            return False


def list_entries(section):

    padding = indent * ' '

    for name, params in section.items():

        if not isinstance(params, dict):
            sys.stderr.write(f"WARNING: invalid entry '{name}'\n\n")
            continue

        print(f'{name}')

        for kw, val in params.items():
            if isinstance(val, list):
                print(f'{padding}{kw}')
                for item in val:
                    print(f'{2*padding}{item}')
            else:
                print(f'{padding}{kw} {val}')

        print()


def write_config(config, filename):

    with open(filename, mode='w') as config_fd:
        config_fd.write(json.dumps(config, indent=indent))


def main():

    script_name = os.path.basename(sys.argv[0])

    parser = argparse.ArgumentParser(
        description='A script for maintaining the gemvm configuration file'
    )
    subparsers = parser.add_subparsers(dest='cmd', required=True,
                                       help='operation to perform')

    name_args = {'dest' : 'name', 'type' : str,
                 'help' : 'name assigned to the VM definition / disk image(s)'}

    parser_add = subparsers.add_parser('add',
                                       help='add/update a VM configuration')
    parser_add.add_argument(**name_args)
    _add_main_args(parser_add, lookup=False)

    parser_del = subparsers.add_parser('del',
                                       help='delete VM configuration(s)')
    parser_del.add_argument(**name_args, nargs='?')

    parser_list = subparsers.add_parser('list',
                                        help='list VM configuration(s)')
    parser_list.add_argument(**name_args, nargs='?')

    args = parser.parse_args()

    # Read any existing config, defaulting to an empty one:
    config, conf_errs = get_config(config_file)

    if args.name is None:
        section = config['names']
    else:
        if args.name in config['names']:
            section = {args.name : config['names'][args.name]}
        elif args.cmd in ('del', 'list'):
            # Error if user tries to list or delete a non-existent entry:
            invocation_err(f"entry '{args.name}' not found")

    # Add/update an entry:
    if args.cmd == 'add':

        if conf_errs:
            invocation_err("can't update corrupt config; delete it (or fix "
                           "manually) first")

        vm_args = _merge_args(args)

        # Must convert any relative paths, in order to find the VM image when
        # working in another directory. Also require existence & rw perms, to
        # help catch mistakes immediately, but there is no file type check,
        # since the user *could* provide a raw disk image.
        vm_args['disk_images'] = standardize_paths(vm_args['disk_images'])
        try:
            check_file_access(vm_args['disk_images'])
        except FileNotFoundError as e:
            invocation_err(e)

        modified = True
        if args.name in config['names']:
            list_entries(section)
            if not confirm(f'Replace existing entry {args.name}?'):
                modified = False
                print('Aborted')

        if modified:
            config['names'][args.name] = vm_args

    # Delete one or all entries:
    elif args.cmd == 'del':

        if args.name:
            list_entries(section)
            modified = confirm(f'Delete entry {args.name}?')
        else:
            modified = confirm('Delete ALL config entries?')

        if modified:
            if args.name is None:
                config['names'] = {}
            else:
                del config['names'][args.name]
        else:
            print('Aborted')

    # List existing entries (creating an empty config if there is none):
    elif args.cmd == 'list':

        modified = False

        list_entries(section)

    # Save updated config, if applicable:
    if modified:
        write_config(config, config_file)


if __name__ == '__main__':
    main()
