# Copyright (c) 2005-2006 LOGILAB S.A. (Paris, FRANCE).
# Copyright (c) 2005-2006 CEA Grenoble
# http://www.logilab.fr/ -- mailto:contact@logilab.fr
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the CECILL license, available at
# http://www.inria.fr/valorisation/logiciels/Licence.CeCILL-V2.pdf
#
"""Pseudo Terminal Device

    Pseudo terminals are a unique feature of UNIX, and always come in form of
    pairs of devices (/dev/ptyXX and /dev/ttyXX), which are connected to each
    other by the operating system. One may think of them as two serial devices
    linked by a null-modem cable. Being based on devices the number of
    simultanous instances of this class is (globally) limited by the number of
    those device pairs, which is 256.

    Another technic are UNIX 98 PTY's. These are supported also, and prefered
    over the (obsolete) predecessor.

    There's a sinister ioctl(2), signal(2) and job control stuff
    nessesary to make everything work as it should.

    Much of the stuff can be simplified by using openpty from glibc2.
    Compatibility issues with obsolete installations and other unixes
    may prevent this.

Based on the konsole code from Lars Doelle.


@author: Lars Doelle
@author: Sylvain Thenault
@copyright: 2003, 2005, 2006
@organization: CEA-Grenoble
@organization: Logilab
@license: CECILL
"""

__revision__ = '$Id: pty_.py,v 1.23 2006-02-15 10:24:01 alf Exp $'

import os
import errno
import select
import signal
import stat
import sys
from pty import openpty
from struct import pack
from fcntl import ioctl, fcntl, F_SETFL
from resource import getrlimit, RLIMIT_NOFILE
from termios import tcgetattr, tcsetattr, VINTR, VQUIT, VERASE, \
     TIOCSPGRP, TCSANOW, TIOCSWINSZ, TIOCSCTTY

import qt
import shell.core.signalable as signalable
from shell.core.common import CTRL
import shell.controller.qt3.procctrl as procctrl


class Job:
    def __init__(self, string):
        self.start = 0
        self.string = string
        self.length = len(string)

    def finished(self):
        return self.start == len(self.string)


class PtyProcess(signalable.Signalable, qt.QObject):
    """fork a process using a controlling terminal

    Ptys provide a pseudo terminal connection to a program, with child process
    invocation, monitoring and control.

    Although closely related to pipes, these pseudo terminal connections have
    some ability, that makes it nessesary to uses them. Most importent, they
    know about changing screen sizes and UNIX job control.

    Within the terminal emulation framework, this class represents the
    host side of the terminal together with the connecting serial line.

    One can create many instances of this class within a program.
    As a side effect of using this class, a signal(2) handler is
    installed on SIGCHLD.
    """

    def __init__(self):
        super(PtyProcess, self).__init__()
        # the process id of the process.
        # If it is called after the process has exited, it returns the process
        # id of the last child process that was created by this instance of
        # Process.
        # Calling it before any child process has been started by this
        # Process instance causes pid to be 0.
        self.pid = None
        # The process' exit status as returned by "waitpid".
        self.status = None
        # True if the process is currently running.
        self.running = False
        # the stdout socket descriptors
        self.out = [-1, -1]
        # the socket notifiers for the above socket descriptors
        self._outnot = None
        procctrl.theProcessController.addProcess(self)
        self.wsize = (0, 0)
        self.addutmp = False
        self.term = None
        self.openPty()
        self._pending_send_jobs = []
        self._pending_send_job_timer = None
        self.myconnect('receivedStdout', self.dataReceived)
        self.myconnect('processExited',  self.donePty)

    def XXX__del__(self):
        # destroying the Process instance sends a SIGKILL to the
        # child process (if it is running) after removing it from the
        # list of valid processes
        procctrl.theProcessController.removeProcess(self)
        # this must happen before we kill the child
        # TODO: block the signal while removing the current process from the
        # process list
        if self.running:
            self.kill(signal.SIGKILL)
        # Clean up open fd's and socket notifiers.
        self.closeStdout()
        # TODO: restore SIGCHLD and SIGPIPE handler if this is the last Process

    def run(self, pgm, args, term, addutmp):
        """start the client program

        having a `run' separate from the constructor allows to make
        the necessary connections to the signals and slots of the
        instance before starting the execution of the client
        """
        self.term = term
        self.addutmp = addutmp
        self.start([pgm] + args)
        self.resume()

    def openPty(self):
        """"""
        self.master_fd, self.slave_fd = openpty()
        #print os.ttyname(self.master_fd)
        #print os.ttyname(self.slave_fd)
        fcntl(self.master_fd, F_SETFL, os.O_NDELAY)
        return self.master_fd

    def setWriteable(self, writeable):
        """set the slave pty writable"""
        ttyname = os.ttyname(self.slave_fd)
        mode = os.stat(ttyname).st_mode
        if writeable:
            mode |= stat.S_IWGRP
        else:
            mode &= ~(stat.S_IWGRP|stat.S_IWOTH)
        os.chmod(ttyname, mode)

    def setSize(self, lines, columns):
        """Informs the client program about the actual size of the window."""
        #print 'PTY set size', lines, columns
        self.wsize = (lines, columns)
        if self.master_fd is None:
            return
        #print 'PTY propagate size'
        ioctl(self.master_fd, TIOCSWINSZ, pack('4H', lines, columns, 0, 0))

    def setupCommunication(self):
        """overriden from Process"""
        self.out[0] = self.master_fd
        self.out[1] = os.dup(2) # Dummy

    def sendBytes(self, string):
        """sends len bytes through the line"""
        #XXX: print "INPUT (sendByte): ", string
        if self._pending_send_jobs:
            self.appendSendJob(string)
        else:
            written = 0
            while written < len(string):
                try:
                    written += os.write(self.master_fd, string[written:])
                except OSError, ex:
                    if ex.errno in (errno.EAGAIN, errno.EINTR):
                        self.appendSendJob(string)
                    return

    def appendSendJob(self, string):
        """"""
        self._pending_send_jobs.append(Job(string))
        if not self._pending_send_job_timer:
            self._pending_send_job_timer = qt.QTimer()
            self._pending_send_job_timer.connect(self._pending_send_job_timer,
                                                 qt.SIGNAL('timeout()'),
                                                 self.doSendJobs)
        self._pending_send_job_timer.start(0)

    def doSendJobs(self):
        """qt slot"""
        while self._pending_send_jobs:
            job = self._pending_send_jobs[0]
            job.start += os.write(self.master_fd, job.string[job.start:])
            #if ( errno!=EAGAIN and errno!=EINTR )
            #   self._pending_send_jobs.remove(self._pending_send_jobs.begin())
            #   return
            if job.finished():
                self._pending_send_jobs.remove(job)
        if self._pending_send_job_timer:
            self._pending_send_job_timer.stop()

    def dataReceived(self, fd, lenlist):
        """qt slot: indicates that a block of data is received """
        try:
            buf = os.read(fd, 4096)
        except OSError:
            import traceback
            traceback.print_exc()
            return
        lenlist[0] = len(buf)
        if not buf:
            return

        #XXX: these two signals are the same and we could have used the same one
        # but it is just to order code
        
        #TODO: consider the option of not sending the block_in signal here
        # and avoid showing things on the terminal and wait until plugin processed
        # the output to see if a different thing has to be shown
        self.myemit('block_in', (buf,)) # signal to show it on screen
        self.myemit('processOutput', (buf,)) # signal to pass it to plugins

    def donePty(self):
        """qt slot"""
##         if HAVE_UTEMPTER and self.addutmp:
##             utmp = UtmpProcess(self.master_fd, '-d',
##                                os.ttyname(self.slave_fd))
##             utmp.start(RUN_BLOCK)
        # this is called when the shell process exits
        self.myemit('done', (self.exitStatus(),))

    def detach(self):
        """Detaches Process from child process. All communication is closed.

        No exit notification is emitted any more for the child process.
        Deleting the Process will no longer kill the child process.
        Note that the current process remains the parent process of the child
        process.
        """
        procctrl.theProcessController.removeProcess(self)
        self.running = False
        self.pid = 0
        # clean up open fd's and socket notifiers.
        self.closeStdout()

    def closeStdout(self):
        """This causes the stdout file descriptor of the child process to be
        closed.

        return False if no communication to the process's stdout
        had been specified in the call to start().
        """
        self.suspend(delete=True)
        self._outnot = None
        os.close(self.out[0])

    def normalExit(self):
        """return True if the process has already finished and has exited
        "voluntarily", ie: it has not been killed by a signal.

        Note that you should check exitStatus() to determine
        whether the process completed its task successful or not.
        """
        return self.pid and not self.running and os.WIFEXITED(self.status)

    def exitStatus(self):
        """Returns the exit status of the process.

        Please use normalExit() to check whether the process has
        exited cleanly (i.e., normalExit() returns True)
        before calling this function because if the process did not exit
        normally, it does not have a valid exit status.
        """
        return os.WEXITSTATUS(self.status)

    def processHasExited(self, state):
        """Immediately called after a process has exited. This function normally
        calls commClose to close all open communication channels to this
        process and emits the "processExited" signal.
        """
        if self.running:
            self.running = False
            self.status = state
        self.commClose()
        # also emit a signal if the process was run Blocking
        self.myemit('processExited')

    def childOutput(self, fdno):
        """Called by "slotChildOutput" this function copies data arriving from
        the child process's stdout to the respective buffer and emits the
        signal "receivedStdout".
        """
        len_ = -1
        # NB <alf>:the slot is supposed to change the value of
        # len_ at least, dataReceived does it in the c++
        # version. I emulate this by passing a list
        lenlist = [len_]
        self.myemit("receivedStdout", (fdno, lenlist))
        len_ = lenlist[0]
        return len_

    def _parentSetupCommunication(self):
        """Called right after a (successful) fork on the parent side. This
        function will do some communications cleanup, like closing
        the reading end of the "stdin" communication channel.

        Furthermore, it must also create the "outnot" QSocketNotifiers
        and connect its Qt slots to the respective member functions.
        """
        os.close(self.out[1])
        # fcntl(out[0], F_SETFL, O_NONBLOCK))
        self._outnot = qt.QSocketNotifier(self.out[0],
                                          qt.QSocketNotifier.Read, self)
        self.connect(self._outnot, qt.SIGNAL('activated(int)'),
                     self.slotChildOutput)
        self.suspend()

    def commClose(self):
        """Should clean up the communication links to the child after it has
        exited. Should be called from "processHasExited".
        """
        # If both channels are being read we need to make sure that one socket
        # buffer doesn't fill up whilst we are waiting for data on the other
        # (causing a deadlock). Hence we need to use select.
        # Once one or other of the channels has reached EOF (or given an error)
        # go back to the usual mechanism.
        fcntl(self.out[0], F_SETFL, os.O_NONBLOCK)
        self.suspend(delete=True)
        self._outnot = None
        while True:
            # * If the process is still running we block until we
            # receive data. (p_timeout = 0, no timeout)
            # * If the process has already exited, we only check
            # the available data, we don't wait for more.
            # (p_timeout = &timeout, timeout immediately)
            if self.running:
                timeout = None
            else:
                timeout = 0
            rfds = [self.out[0]]
            rlist = select.select(rfds, [], [], timeout)[0]
            if not rlist:
                break
            ret = 1
            while ret > 0:
                ret = self.childOutput(self.out[0])
            if ret == 0:
                break
        os.close(self.out[0])

    def start(self, arguments):
        """Starts the process.

        For a detailed description of the various run modes and communication
        semantics, have a look at the general description of the Process class.

        The following problems could cause this function to raise an exception:

        * The process is already running.
        * The command line argument list is empty.
        * The starting of the process failed (could not fork).
        * The executable was not found.

        param comm  Specifies which communication links should be
        established to the child process (stdin/stdout/stderr). By default,
        no communication takes place and the respective communication
        signals will never get emitted.

        return True on success, False on error
        (see above for error conditions)
        """
        uid, gid = self._startInit(arguments)
        fd = os.pipe()
        # note that we use fork() and not vfork() because vfork() has unclear
        # semantics and is not standardized.
        self.pid = os.fork()
        #print 'pid', self.pid
        if 0 == self.pid:
            self._childStart(uid, gid, fd, arguments)
        else:
            self._parentStart(fd)

    def _startInit(self, arguments):
        """initialisation part of the start method"""
        if self.running:
            raise Exception('cannot start a process that is already running')
        if not arguments:
            raise Exception('no executable has been assigned')
        self.status = 0
        self.setupCommunication()
        # We do this in the parent because if we do it in the child process
        # gdb gets confused when the application runs from gdb.
        uid = os.getuid()
        gid = os.getgid()
        self.running = True
        return uid, gid

    def _childStart(self, uid, gid, fd, arguments):
        """parent process part of the start method"""
        if fd[0]:
            os.close(fd[0])
        # drop privileges
        os.setgid(gid)
        os.setuid(uid)
        tt = self.slave_fd
        # reset signal handlers for child process
        for i in range(1, signal.NSIG):
            try:
                signal.signal(i, signal.SIG_DFL)
            except RuntimeError, ex:
                #print 'error resetting signal handler for sig %d: %s' % (i, ex)
                continue
        # Don't know why, but his is vital for SIGHUP to find the child.
        # Could be, we get rid of the controling terminal by this.
        soft = getrlimit(RLIMIT_NOFILE)[0]
        # We need to close all remaining fd's.
        # Especially the one used by Process.start to see if we are running ok.
        for i in range(soft):
            # FIXME: (result of merge) Check if (not) closing fd is OK)
            if i != tt:# and i != self.master_fd):
                try:
                    os.close(i)
                except OSError:
                    continue
        os.dup2(tt, sys.stdin.fileno())
        os.dup2(tt, sys.stdout.fileno())
        os.dup2(tt, sys.stderr.fileno())
        if tt > 2:
            os.close(tt)
        # Setup job control
        # This is pretty obscure stuff which makes the session
        # to be the controlling terminal of a process group.
        os.setsid()
        ioctl(0, TIOCSCTTY, '')
        # This sequence is necessary for event propagation. Omitting this
        # is not noticeable with all clients (bash,vi). Because bash
        # heals this, use '-e' to test it.
        pgrp = os.getpid()
        ioctl(0, TIOCSPGRP, pack('i', pgrp))

        # XXX FIXME: the following crashes
#        os.setpgid(0, 0)
#        os.close(os.open(os.ttyname(tt), os.O_WRONLY))
#        os.setpgid(0, 0)

        tty_attrs = tcgetattr(0)
        tty_attrs[-1][VINTR] = CTRL('C')
        tty_attrs[-1][VQUIT] = CTRL('\\')
        tty_attrs[-1][VERASE] = 0177
        tcsetattr(0, TCSANOW, tty_attrs);

        #os.close(self.master_fd)
        # propagate emulation
        if self.term:
            os.environ['TERM'] = self.term
        ioctl(0, TIOCSWINSZ, pack('4H', self.wsize[0], self.wsize[1], 0, 0))
        # finally, pass to the new program
        os.execvp(arguments[0], arguments)
        sys.exit(1) # control should never come here.

    def _parentStart(self, fd):
        """parent process part of the start method"""
        if fd[1]:
            os.close(fd[1])
        # Check whether client could be started.
        if fd[0]:
            while True:
                bytes = os.read(fd[0], 1)
                if not bytes:
                    break # success
                if ord(bytes) == 1:
                    # Error
                    self.running = False
                    os.close(fd[0])
                    self.pid = 0
                    return False
                break # success
        if fd[0]:
            os.close(fd[0])
        self._parentSetupCommunication()

    def kill(self, signo):
        """Stop the process (by sending it a signal).

        param signo	The signal to send. The default is SIGTERM.
        return True if the signal was delivered successfully.
        """
        os.kill(self.pid, signo)

    def suspend(self, delete=False):
        """Suspend processing of data from stdout of the child process.
        """
        if self._outnot:
            self._outnot.setEnabled(False)
            if delete:
                self._outnot.deleteLater()

    def resume(self):
        """Resume processing of data from stdout of the child process.
        """
        if self._outnot:
            self._outnot.setEnabled(True)

    def slotChildOutput(self, fdno):
        """This slot gets activated when data from the child's stdout arrives.
        It usually calls "childOutput"
        """
        if not self.childOutput(fdno):
            self.closeStdout()
