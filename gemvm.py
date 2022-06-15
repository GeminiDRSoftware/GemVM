#!/usr/bin/env python3
#
# Copyright(c) 2022 Association of Universities for Research in Astronomy, Inc.

import asyncio
import functools
import json
import os
import shlex
import signal
import socket
import subprocess
import sys
import time
import traceback

ssh_port = 2222
mem_GB = 3

debug = False


class VMControl:

    states = ('off', 'booting', 'running', 'shutting_down')

    def __init__(self, disk_image, cmd='qemu-system-x86_64', mem=3, port=2222,
                 debug=False):

        self.disk_image = disk_image
        self.cmd = cmd
        self.mem = mem
        self.port = port
        self.debug = debug

        self.title, _ = os.path.splitext(os.path.basename(self.disk_image))
        self.log_file = f'gemvm_{self.title}.log'
        self.qmp_sock = os.path.join(os.sep, 'tmp', f'.gemvm_qmp_{os.getpid()}')

        self._state = 'off'
        self._qmp_established = False
        self._tasks = {}

        self.pid = None
        self.exit_status = None
        self.mem_err = False

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

        return (
            f'-m {self.mem}G',
            f'-hda {self.disk_image}',
            # f'-drive file={self.disk_image},if=virtio,cache=off',
            f'-name "{self.title}"',
            f'-machine q35',
            f'-smp 2',
            f'-vga none',
            f'-nographic',
            f'-boot menu=off',
            f'-qmp unix:{self.qmp_sock},server,nowait',
            f'-device e1000,netdev=net0',
            # f'-device virtio-net-pci,netdev=net0',
            f'-netdev user,id=net0,hostfwd=tcp:127.0.0.1:{self.port}-:22',
        )

    # Only one instance can be called from a given Python process without a QMP
    # socket conflict. This call blocks execution anyway but isn't thread safe.
    def __call__(self):
        asyncio.run(self._run())
        return self.exit_status

    def __repr__(self):
        return(f"<{self.__class__.__name__}('{self.disk_image}', "
               f"mem={self.mem}, port={self.port}, pid={self.pid}, "
               f"state='{self.state}', qmp_established={self.qmp_established}, "
               f"exit_status={self.exit_status})>")

    def _keyboard_interrupt(self, events):
        events['shutdown_request'].set()

    async def _run_vm(self, events):

        # Instead of overwriting the log file, delete & (re)create it in
        # append mode, which should guarantee (per POSIX) that QEMU won't
        # overwrite any text that gets appended elsewhere in this script, if
        # the subprocess is still running at exit due to a time-out.
        try:
            os.remove(self.log_file)
        except OSError:
            pass

        with open(self.log_file, 'a+b') as log:

            try:
                # Run VM in background session so it doesn't die on ctrl-c,
                # capturing all output to the log:
                proc = await asyncio.create_subprocess_exec(
                       self.cmd,
                       *shlex.split(' '.join(self.cmd_args)), # split opts+args
                       stdin=subprocess.PIPE,
                       stdout=log,
                       stderr=subprocess.STDOUT,
                       start_new_session=True,
                )
                self.pid = proc.pid

                if self.debug:
                    print(f'\nPID {self.pid}')

                # Yield control while waiting for process to complete, then
                # save its exit code when it does:
                self.exit_status = await proc.wait()

                # In the event of failure, scrape the log for a memory
                # allocation error (which qemu's exit code doesn't distinguish
                # from other errors), so we can advise the user on what to do.
                # This message appears not to change with the locale setting.
                if self.exit_status == 1:
                    log.seek(0, 0)
                    for line in log:
                        if b'cannot set up guest memory' in line:
                            self.mem_err = True
                            break
                    log.seek(0, 2)  # return to end

            finally:
                # Cancel any tasks that may still be running if the VM didn't
                # start & stop normally, so the script doesn't hang or produce
                # unexpected errors, and set the final machine state:
                self._cancel_tasks('_shut_down', '_wait_until_booted',
                                   '_shutdown_timeout', '_boot_timeout')
                self.state = 'off'

    async def _wait_until_booted(self, events):

        while self.state == 'booting':
            if self.debug:
                print('\nAttempt ssh connection')
            try:
                await self._check_ssh()
            except ConnectionError:
                await asyncio.sleep(1)  # retry port after 1s
            else:
                self.state = 'running'
                self._cancel_tasks('_boot_timeout')  # unblock event loop exit
                break

        # This coroutine should get cancelled before this ever happens. Don't
        # raise an exception, which would block any coroutines waiting on this.
        if self.state != 'running':
            sys.stderr.write(f'State changed before successful connection '
                             f'to localhost:{self.port}\n')

    async def _check_ssh(self):

        # This usually gives ConnectionRefusedError just on the first try:
        reader, writer = await asyncio.open_connection(
            host=socket.gethostbyname('localhost'), port=self.port
        )
        # This occasionally gets EOF instead of the expected reply (presumably
        # because of some time-out or the server not being ready yet, as when
        # the ssh client briefly produces "read: Connection reset by peer"):
        try:
            reply = await reader.readline()
        finally:
            writer.close()

        if self.debug:
            print(f'\nReply {reply} from guest ssh service')

        if not reply.startswith(b'SSH-2.0-'):
            raise ConnectionError(
                f'Bad reply "{reply}" from guest ssh service.'
            )

    async def _progress(self, events):

        shutdown_req_msg = False
        while self.state != 'off':
            char = self.state[0]
            print(char, end='', flush=True)
            if not shutdown_req_msg and events['shutdown_request'].is_set():
                shutdown_req_msg = True
                print('\nShutdown requested')
            await asyncio.sleep(1)
        # If anything has gone wrong (eg. QMP), add a warning to the status?

    async def _boot_timeout(self, events):

        # Impose a general boot timeout, to avoid hanging indefinitely if the
        # VM itself hangs (but leave long enough for a "normal" fsck before
        # ceding manual control to the user).
        try:
            await asyncio.sleep(300)
        except asyncio.CancelledError:
            return
        if self.state == 'booting':
            sys.stderr.write('\nTimed out.\n')
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
            # Negotiate capabilities and enter "command mode", as per the QMP
            # documentation. We might get a JSONDecodeError if the reply is
            # malformed, but I haven't seen that happen.
            reply = await reader.readline()  # returns version & "capabilities"
            writer.write(b'{"execute": "qmp_capabilities"}\r\n')
            reply = json.loads(await reader.readline())
            if 'return' in reply and reply['return'] == {}: # standard response
                self._qmp_established = True
            else:
                # Should we re-try here? Don't guess at failure modes not seen.
                raise ConnectionError(
                    f'Failed to establish QMP connection at {self.qmp_sock}'
                )

            # Now we're ready to shut down as soon as the signal arrives:
            await events['shutdown_request'].wait()
            writer.write(b'{"execute": "system_powerdown"}\r\n')
            self.state = 'shutting_down'  # wait for {'event' : 'POWERDOWN'} ?
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

    async def _shutdown_timeout(self, events):

        # Can't shut down until we're asked to *and* the VM has booted:
        await asyncio.wait_for(self._tasks['_wait_until_booted'], timeout=None)

        await events['shutdown_request'].wait()

        await asyncio.sleep(60)  # shut down normally takes a couple of sec.
        sys.stderr.write('\nShut down timed out.\n')
        self._cancel_tasks()

    async def _run(self):

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
                  '_progress',
                  '_boot_timeout',
                  '_shut_down',
                  '_shutdown_timeout',
              )
        }

        # Main event loop (saving any exceptions for later):
        retvals = await asyncio.gather(*self._tasks.values(),
                                       return_exceptions=True)

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
            with open(self.log_file, 'a+', encoding='utf-8',
                      errors='surrogateescape') as log:
                log.write('-'*78+'\n')
                log.write('Errors were produced while running the control '
                          'script:\n')
                log.writelines(errors)

    def _cancel_tasks(self, *names):
        if not names:
            names = self._tasks.keys()
        for name in names:
            self._tasks[name].cancel()


if __name__ == '__main__':

    t = time.time()

    vm = VMControl('qemuiraf.qcow2', mem=mem_GB, port=ssh_port, debug=debug)

    exit_status = vm()

    if debug:
        print(f'\nAfter execution: {vm}')

    if exit_status == 0:
        print('\nVM process completed successfully\n')
    else:
        end = f'see {vm.log_file}\n\n'
        if exit_status is None:
            if vm.pid is None:
                err = f'\nFailed to start VM process: {end}'
            else:
                try:
                    os.kill(vm.pid, 0)  # no-op checks if it's still running
                except ProcessLookupError:
                    # This will probably never happen, because process should
                    # remain as a zombie until the parent gets its exit status:
                    err = f'\nVM process died uncleanly: {end}'
                else:
                    err = (f'\nApparently failed to shut down VM process: {end}'
                           f'Try logging in with ssh and issuing "sudo '
                           f'shutdown now" manually; otherwise\nkill process '
                           f'{vm.pid} if it\'s unresponsive.\n\n')
        else:
            if exit_status < 0:
                err = f'\nVM process killed with signal {-exit_status}: {end}'
            else:
                err = (f'\nVM process completed with error status '
                       f'{exit_status}: {end}')
        sys.stderr.write(err)

        if vm.mem_err:
            sys.stderr.write(f'It looks like QEMU failed to allocate {mem_GB}'
                             f'GB of contiguous memory to run the VM.\n\n'
                             f'Try restarting large programs such as your Web '
                             f'browser, to reduce memory\nfragmentation (or '
                             f'closing them entirely if that doesn\'t solve '
                             f'it). If the\nproblem persists, try reducing '
                             f'"mem_GB" in the configuration, but note that\n'
                             f'the VM is unlikely to work well with much less '
                             f'than 1GB (untested).\n\n')

    print('T', time.time() - t)

    sys.exit(1 if exit_status is None else exit_status)