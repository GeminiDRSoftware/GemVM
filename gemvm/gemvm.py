#!/usr/bin/env python3
#
# Copyright(c) 2022 Association of Universities for Research in Astronomy, Inc.

"""
A simple, self-contained script that makes it easier for users to run a VM
image with QEMU on their local machine.
"""

import argparse
import asyncio
import contextlib
import curses
import functools
import json
import os
import shlex
import signal
import subprocess
import sys
import time
import traceback

# Default values:
ssh_port = 2222
mem_GB = 3.0
use_virtio = True
show_console = False

config_file = os.path.expanduser(
    os.path.join('~', '.gemvm', 'config.json')
)


def standardize_paths(filenames):
    """Guarantee a list of canonical paths with duplicates removed"""
    return list(dict.fromkeys([os.path.realpath(os.path.expanduser(filename))
                               for filename in filenames]))

def check_file_access(filenames):
    mode = os.R_OK | os.W_OK  # need +w unless "-drive media=cdrom"
    for filename in filenames:
        if not (os.path.isfile(filename) and os.access(filename, mode)):
            raise FileNotFoundError(f'cannot read/write {filename}')


# Only one instance of this can be called from a given Python process without a
# QMP socket conflict. It blocks execution anyway but wouldn't be thread safe.

class VMControl:

    states = ('off', 'booting', 'running', 'shutting_down')

    def __init__(self, disk_images, cmd='qemu-system-x86_64', title=None,
                 mem=mem_GB, port=ssh_port, virtio=use_virtio,
                 boot_timeout=300, shutdown_timeout=60, console=show_console,
                 flush_log=False):

        if isinstance(disk_images, str):
            disk_images = [disk_images]
        self.disk_images = standardize_paths(disk_images)
        self.cmd = cmd
        if title is not None:
            self.title = title
        else:
            self.title, _ = os.path.splitext(
                os.path.basename(
                    self.disk_images[0] if self.disk_images else ''
                )
            )
        self.mem = mem
        self.port = port
        self.virtio = virtio
        self.boot_timeout = boot_timeout
        self.shutdown_timeout = shutdown_timeout
        self.console = console
        self.flush_log = flush_log

        self.log_file = f'gemvm_{self.title}.log'
        self.qmp_sock = os.path.join(os.sep, 'tmp', f'.gemvm_qmp_{os.getpid()}')

        self._state = 'off'
        self._qmp_established = False
        self._tasks = {}
        self._log_fd = None
        self._shutdown_msg = 'Shutdown requested'
        self._info = (
            f'Once booted, log in with:\n'
            f'  ssh -Y -p {self.port} <username>@localhost\n\n'
            f'Press Ctrl-C to shut down\n'
        )
        self._scrn_attrs = {}

        self.pid = None
        self.exit_status = None
        self.mem_err = False
        self.timed_out = False

    @property
    def state(self):
        return self._state

    @state.setter
    def state(self, state):
        if state in self.states:
            self._state = state
        else:
            raise ValueError(f'Invalid VM state: {state}')

    @property
    def qmp_established(self):
        return self._qmp_established

    @property
    def cmd_args(self):

        if self.virtio:
            disk_type = 'virtio'
            net_type = 'virtio-net-pci'
        else:
            disk_type = 'ide'
            net_type = 'e1000e'

        args = [
            f'-drive file={disk_image},index={n},if={disk_type},cache=off'
            for n, disk_image in enumerate(self.disk_images)
        ]
        args.extend((
            f'-m {self.mem}G',
            f'-name "{self.title}"',
            f'-machine type=q35,accel=hvf:kvm:tcg',
            f'-smp 2',
            f'-boot menu=off',
            f'-qmp unix:{self.qmp_sock},server,nowait',
            f'-device {net_type},netdev=net0',
            f'-netdev user,id=net0,hostfwd=tcp:127.0.0.1:{self.port}-:22',
        ))
        if self.console is False:
            args.extend((
                f'-vga none',
                f'-nographic',
            ))
        return args

    def log_context(self):
        if self._log_fd and not self._log_fd.closed:
            # If the log's already/still open, re-use file handle:
            return contextlib.nullcontext(self._log_fd)
        else:
            # Hold log file open for duration of outermost context manager
            # (just a single write if that's the context in self.log):
            self._log_fd = open(self.log_file, 'a+',
                                encoding='utf-8', errors='surrogateescape')
            return self._log_fd

    def log(self, msg, time_stamp=True):
        with self.log_context() as log_fd:
            if time_stamp:
                ts = time.strftime("%H:%M:%S", time.localtime())
                log_fd.write(f'{ts}  {msg}\n')
            else:
                log_fd.write(f'{msg}\n')
            if self.flush_log:
                log_fd.flush()

    def __call__(self):
        # Raise an explicit error if the user gives a bad file path, rather
        # than having to search the log. We could also check things like ssh
        # port availability, but in general it's more reliable to apply EAFP
        # than anticipate every problem (especially memory errors).
        check_file_access(self.disk_images)

        # Run the main event loop, with curses status display:
        curses.wrapper(lambda stdscr : asyncio.run(self._run(stdscr)))
        return self.exit_status

    def __repr__(self):
        return(f"<{self.__class__.__name__}(title='{self.title}', "
               f"disk_images={self.disk_images}, mem={self.mem}, "
               f"port={self.port}, virtio={self.virtio}, pid={self.pid}, "
               f"state='{self.state}', qmp_established={self.qmp_established}, "
               f"timed_out={self.timed_out}, exit_status={self.exit_status})>")

    def _keyboard_interrupt(self, events):
        events['shutdown_request'].set()
        self.log(self._shutdown_msg)

    async def _run_vm(self, events):

        # Open log separately for subprocess, which needs to use binary mode
        # (the process will get its own copy of the file handle in any case):
        with open(self.log_file, 'a+b') as log_fd:

            try:
                # Run VM in background session so it doesn't die on ctrl-c,
                # capturing all output to the log:
                proc = await asyncio.create_subprocess_exec(
                       self.cmd,
                       *shlex.split(' '.join(self.cmd_args)), # split opts+args
                       stdin=subprocess.PIPE,
                       stdout=log_fd,
                       stderr=subprocess.STDOUT,
                       start_new_session=True,
                )
                self.pid = proc.pid

                # This must not fail, which would confuse the exit state:
                try:
                    self.log(f'Subprocess Id {self.pid}')
                except:
                    pass

                # Yield control while waiting for process to complete, then
                # save its exit code when it does:
                self.exit_status = await proc.wait()

            # Preserve VM state when timing out:
            except asyncio.CancelledError:
                self.log('Wait for subprocess cancelled')
                raise

            # Set state to 'off' in case of exception running subprocess:
            except:
                self.state = 'off'
                raise

            # Set state to 'off' if process completed (with or without errors):
            else:
                self.state = 'off'

            finally:
                # Cancel any tasks that may still be running if the VM didn't
                # start & stop normally, so the script doesn't hang or produce
                # unexpected errors:
                self._cancel_tasks('_shut_down', '_wait_until_booted',
                                   '_shutdown_timer', '_boot_timer')

            # If the process ran but produced exit status 1, scrape the log for
            # a for a memory allocation error (which qemu's exit code doesn't
            # distinguish from other errors), so we can advise the user on what
            # to do. This message appears not to change with the user's locale.
            if self.exit_status == 1:
                log_fd.seek(0, 0)
                for line in log_fd:
                    if b'cannot set up guest memory' in line:
                        self.mem_err = True
                        break
                log_fd.seek(0, 2)  # return to end


    async def _wait_until_booted(self, events):

        while self.state == 'booting':
            self.log('Attempt ssh connection')
            try:
                await self._check_ssh()
            except ConnectionError:
                await asyncio.sleep(1)  # retry port after 1s
            else:
                self.state = 'running'
                self._cancel_tasks('_boot_timer')  # unblock event loop exit
                break

        # This coroutine should get cancelled before this ever happens. Don't
        # raise an exception, which would block any coroutines waiting on this.
        if self.state != 'running':
            self.log(f'State changed before successful connection to '
                     f'localhost:{self.port}\n')

    async def _check_ssh(self):

        # This usually gives ConnectionRefusedError just on the first try:
        reader, writer = await asyncio.open_connection(
            host='127.0.0.1', port=self.port
        )
        # This occasionally gets EOF instead of the expected reply (presumably
        # because of some time-out or the server not being ready yet, as when
        # the ssh client briefly produces "read: Connection reset by peer"):
        try:
            reply = await reader.readline()
        finally:
            writer.close()

        self.log(f'Reply {reply} from guest ssh service')

        if not reply.startswith(b'SSH-2.0-'):
            raise ConnectionError(
                f'Bad reply "{reply}" from guest ssh service.'
            )

    def _initscr(self, stdscr):

        curses.use_default_colors()  # keep existing background
        curses.init_pair(1, curses.COLOR_RED, -1)
        curses.init_pair(2, curses.COLOR_GREEN, -1)
        curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLUE)
        curses.curs_set(0)  # don't show cursor
        self._scrn_attrs = {
            'default' : curses.color_pair(0),
            'booting' : curses.color_pair(1) | curses.A_BOLD,
            'running' : curses.color_pair(2) | curses.A_BOLD,
            'shutting_down' : curses.color_pair(1) | curses.A_BOLD,
            'title' : curses.color_pair(3) | curses.A_BOLD,
            'heartbeat' : curses.color_pair(1) | curses.A_BOLD,
        }
        self._show_title(stdscr)
        stdscr.addstr(4, 0, self._info, self._scrn_attrs['default'])

    def _show_title(self, stdscr):
        title = f'GemVM: {self.title}'.center(curses.COLS)
        stdscr.addstr(0, 0, title, self._scrn_attrs['title'])

    async def _progress(self, events, stdscr):

        state = None
        while self.state != 'off':

            curses.update_lines_cols()  # detect re-sizing
            self._show_title(stdscr)

            if self.state != state:
                state = self.state
                t_start = time.time()  # just for an indicative count
                msg = state.capitalize().replace('_', ' ')
                if state == 'running':
                    beat_text = '\u2665'
                    beat_attr = self._scrn_attrs['heartbeat']
                else:
                    beat_attr = self._scrn_attrs[state]

            if state == 'running':
                beat_attr ^= curses.A_INVIS  # toggle heartbeat visibility
            else:
                beat_text = f'{int(time.time()-t_start):3d}'

            stdscr.addstr(2, 0, msg.ljust(curses.COLS), self._scrn_attrs[state])
            stdscr.addstr(2, len(msg)+1, beat_text, beat_attr)

            if events['shutdown_request'].is_set():
                stdscr.addstr(2, curses.COLS - len(self._shutdown_msg) - 1,
                              self._shutdown_msg, curses.color_pair(0))

            stdscr.refresh()

            await asyncio.sleep(1)

        # If anything has gone wrong (eg. QMP), add a warning to the status?

    async def _boot_timer(self, events):

        # Impose a general boot timeout, to avoid hanging indefinitely if the
        # VM itself hangs (but leave long enough for a "normal" fsck before
        # ceding manual control to the user).
        try:
            await asyncio.sleep(self.boot_timeout)
        except asyncio.CancelledError:
            return
        if self.state == 'booting':
            self.timed_out = True
            self.log('Boot timed out')
            self._cancel_tasks()  # May leave QEMU running in the background

    async def _shut_down(self, events):

        # Can't shut down reliably until finished booting (already scheduled):
        await asyncio.wait_for(self._tasks['_wait_until_booted'], timeout=None)

        # If any of the following fails, just log the exception and time out in
        # a separate co-routine, rather than catching the error.

        # Open the QMP socket for communicating with QEMU.
        # Here we'll get a ConnectionRefusedError if the socket can't be opened
        # (eg. because overwritten) or FileNotFoundError if it doesn't exist.
        reader, writer = await asyncio.open_unix_connection(self.qmp_sock)

        try:
            self.log(f'Opened socket {self.qmp_sock}')

            # Negotiate capabilities and enter "command mode", as per the QMP
            # documentation. We might get a JSONDecodeError if the reply is
            # malformed, but I haven't seen that happen.
            reply = await reader.readline()  # returns version & "capabilities"
            writer.write(b'{"execute": "qmp_capabilities"}\r\n')
            reply = json.loads(await reader.readline())
            if 'return' in reply and reply['return'] == {}: # standard response
                self._qmp_established = True
                self.log('Established QMP connection')
            else:
                # Should we re-try here? Don't guess at failure modes not seen.
                raise ConnectionError(
                    f'Failed to establish QMP connection at {self.qmp_sock}'
                )

            # Now we're ready to shut down as soon as the signal arrives:
            await events['shutdown_request'].wait()
            writer.write(b'{"execute": "system_powerdown"}\r\n')
            self.state = 'shutting_down'  # wait for {'event' : 'POWERDOWN'} ?
            self.log('Sent system_powerdown command')
            while self.state != 'off':
                reply = json.loads(await reader.readline())
                if 'event' in reply and reply['event'] == 'SHUTDOWN':
                    # The VM has shut down, but self.state gets set to 'off'
                    # by _run_vm, when the process exits a couple of sec later.
                    # Log this confirmation (& POWERDOWN) in a later version.
                    break

        finally:
            writer.close()

        # The shutdown timer gets cancelled by _run_vm if QEMU now exits as
        # expected, otherwise it keeps running so the user will get control
        # back and an exit status report.

    async def _shutdown_timer(self, events):

        # Can't shut down until we're asked to *and* the VM has booted:
        await asyncio.wait_for(self._tasks['_wait_until_booted'], timeout=None)

        await events['shutdown_request'].wait()

        # Shutdown normally takes about 2-6s with a minimal OS install
        await asyncio.sleep(self.shutdown_timeout)
        self.timed_out = True
        self.log('Shutdown timed out')
        self._cancel_tasks()

    async def _run(self, stdscr):

        # Finish initializing appearance with curses:
        self._initscr(stdscr)

        # Instead of overwriting the log file, delete & (re)create it in
        # append mode, which should guarantee (per POSIX) that QEMU & logging
        # elsewhere in this script won't overwrite each other:
        try:
            os.remove(self.log_file)
        except OSError:
            pass

        # Hold log file open during execution of the main routine:
        with self.log_context() as log_fd:

            loop = asyncio.get_running_loop()
            events = {
                'shutdown_request' : asyncio.Event(),
            }
            loop.add_signal_handler(
                signal.SIGINT,
                functools.partial(self._keyboard_interrupt, events)
            )

            self.state = 'booting'

            self._tasks = {
                name : asyncio.create_task(getattr(self, name)(events)) for
                  name in (
                      '_run_vm',
                      '_wait_until_booted',
                      '_boot_timer',
                      '_shut_down',
                      '_shutdown_timer',
                  )
            }
            self._tasks['_progress'] = asyncio.create_task(
                self._progress(events, stdscr)  # this one has an extra arg
            )

            self.log('', time_stamp=False)
            self.log('Starting event loop')

            # Main event loop (saving any exceptions for later):
            retvals = await asyncio.gather(*self._tasks.values(),
                                           return_exceptions=True)

            self.log(f'{self}')

            # Append any internal exceptions to the log:
            errors = []
            for retval in retvals:
                if isinstance(retval, Exception) and not \
                   isinstance(retval, asyncio.CancelledError):
                    errors.append('\n')
                    errors.extend(
                        traceback.format_exception(type(retval), retval,
                                                   retval.__traceback__)
                    )
            if errors:
                self.log(
                    '-'*78 + '\n'
                    'Errors were produced while running the control script:\n' +
                    ''.join(errors),
                    time_stamp=False
                )

    def _cancel_tasks(self, *names):
        if not names:
            names = self._tasks.keys()
        for name in names:
            self._tasks[name].cancel()


def get_config(filename=None):

    default = {'version' : 1, 'names' : {}}

    err = False

    if not filename:
        return default, err

    try:
        with open(filename) as config_fd:  # user's default encoding
            config = json.loads(config_fd.read())
    except json.JSONDecodeError:
        err = True
    except OSError:
        config = default
    else:
        try:
            assert isinstance(config['names'], dict)
        except (TypeError, KeyError, AssertionError):
            err = True

    # Should this get logged (would have to move log deletion to main script)?
    if err:
        config = default
        sys.stderr.write(f'Ignoring corrupt config (try re-creating it):\n'
                         f'  {filename}\n')

    return config, err


def _add_main_args(parser, lookup=True):

    # Define main VM config arguments for this script & the config script

    parser.add_argument('-m', '--mem', type=float,
                        help='memory in GB to allocate for guest VM (>=0.25)')
    parser.add_argument('-p', '--port', type=int,
                        help='host port number for guest ssh service to '
                             'listen on')
    parser.add_argument('--virtio', action='store_true',
                        help='use paravirtualized disk & network devices')
    parser.add_argument('--no-virtio', action='store_false', dest='virtio',
                        help='emulate disk & network hardware instead of '
                             'requiring paravirtualized drivers in the '
                             'guest kernel')
    parser.add_argument('--console', action='store_true',
                        help='enable console window / VNC server (whatever '
                             'default the installed QEMU has available on '
                             'your desktop) for troubleshooting?')
    if lookup:
        help_str = ('path or user-defined name of a VM disk image file; if '
                    'a value has no directory prefixed and matches a name '
                    'defined in the configuration file, it gets mapped to the '
                    'corresponding path(s), otherwise it is treated as a path '
                    'directly')
    else:
        help_str = 'path of a VM disk image file'

    parser.add_argument('disk_images', nargs='+', type=str,
                        metavar='disk_image', help=help_str)

    parser.set_defaults(virtio=None, console=None)


def _merge_args(args, config=None):

    # Two modes of usage:
    # - Generate merged args for VMControl by combining user args with an
    #   existing config (with >=0 entries) & defaults (config=<path>).
    # - Generate a new config from user args & defaults (config=None).

    # Main set of args to pass through (besides mandatory "disk_images"):
    defaults = {'mem': mem_GB, 'port': ssh_port, 'virtio': use_virtio,
                'console': show_console}

    # Copy applicable user args into a dict containing a new disk_images list,
    # adding a title parameter with the name if generating VM args:
    args_dict = vars(args)
    merged_args = {'disk_images': []}
    for kw in defaults:
        merged_args[kw] = args_dict.get(kw)
    if config:
        merged_args['title'] = ''

    # Fill in anything not specified on the command line from config file:
    for name in args.disk_images:
        if config and not os.path.dirname(name) and name in config['names']:
            entry = config['names'][name]
            try:
                assert isinstance(entry['disk_images'], list)
            except (TypeError, KeyError, AssertionError):
                raise ValueError(f"Corrupt entry '{name}' in config file")
            merged_args['disk_images'].extend(entry['disk_images'])
            if merged_args['title'] == '':
                merged_args['title'] = name
            for kw in defaults:
                if merged_args[kw] is None:
                    merged_args[kw] = entry.get(kw)
        else:
            merged_args['disk_images'].append(name)
            if config and merged_args['title'] == '':
                merged_args['title'] = None

    # Fall back to global defaults for parameters not specified anywhere:
    for kw in defaults:
        if merged_args[kw] is None:
            merged_args[kw] = defaults[kw]

    return merged_args


def invocation_err(msg):
    script_name = os.path.basename(sys.argv[0])
    sys.stderr.write(f'{script_name}: {msg}\n')
    sys.exit(1)


def main():

    parser = argparse.ArgumentParser(
        description='A simple control script for using QEMU to run a VM image '
                    'that accepts login via ssh'
    )
    _add_main_args(parser)

    # Combine user args & optional config file to construct VM args:
    args = parser.parse_args()
    config, conf_errs = get_config(config_file)
    try:
        vm_args = _merge_args(args, config)
    except ValueError as e:
        invocation_err(e)

    # Instantiate & run the VM:
    vm = VMControl(**vm_args)
    try:
        exit_status = vm()
    except (FileNotFoundError, PermissionError) as e:
        invocation_err(e)

    # Report outcome to the user:
    if exit_status == 0:
        msg = '\nVM process completed successfully'
        print(msg + '\n')
        vm.log(msg, time_stamp=False)

    else:
        if vm.timed_out:
            msg = f'\nTimed out while {vm.state.replace("_", " ")}.'
            sys.stderr.write(msg + '\n')
            vm.log(msg, time_stamp=False)

        end = f'see {vm.log_file}\n'
        if exit_status is None:
            if vm.pid is None:
                msg = f'\nFailed to start VM process: {end}'
            else:
                try:
                    os.kill(vm.pid, 0)  # no-op checks if it's still running
                except ProcessLookupError:
                    # This will probably never happen, because process should
                    # remain as a zombie until the parent gets its exit status:
                    msg = f'\nVM process died uncleanly: {end}'
                else:
                    msg = (f'\nApparently failed to shut down VM process: {end}'
                           f'\nTry logging in with ssh and issuing "sudo '
                           f'shutdown now" manually; otherwise\nkill process '
                           f'{vm.pid} if it\'s unresponsive.\n')
        else:
            if exit_status < 0:
                msg = f'\nVM process killed with signal {-exit_status}: {end}'
            else:
                msg = (f'\nVM process completed with error status '
                       f'{exit_status}: {end}')

        sys.stderr.write(msg + '\n')
        vm.log(msg, time_stamp=False)

        if vm.mem_err:
            msg = (f'It looks like QEMU failed to allocate {vm.mem}GB of '
                   f'contiguous memory to run the VM.\n\n'
                   f'Try restarting large programs such as your Web browser, '
                   f'to reduce memory\nfragmentation (or closing them '
                   f'entirely if that doesn\'t solve it). If the\nproblem '
                   f'persists, try reducing the "mem" parameter value '
                   f'(without going below\n0.25 to 0.5GB for tolerable '
                   f'performance with a minimal OS installation).\n')
            sys.stderr.write(msg + '\n')
            vm.log(msg, time_stamp=False)

    sys.exit(1 if exit_status is None else exit_status)


if __name__ == '__main__':
    main()
