"""
Profiling hooks

This module contains a couple of decorators (`profile` and `coverage`) that
can be used to wrap functions and/or methods to produce profiles and line
coverage reports.  There's a third convenient decorator (`timecall`) that
measures the duration of function execution without the extra profiling
overhead.

Usage example (Python 2.4 or newer)::

    from profilehooks import profile, coverage

    @profile    # or @coverage
    def fn(n):
        if n < 2: return 1
        else: return n * fn(n-1)

    print fn(42)

Usage example (Python 2.3 or older)::

    from profilehooks import profile, coverage

    def fn(n):
        if n < 2: return 1
        else: return n * fn(n-1)

    # Now wrap that function in a decorator
    fn = profile(fn) # or coverage(fn)

    print fn(42)

Reports for all thusly decorated functions will be printed to sys.stdout
on program termination.  You can alternatively request for immediate
reports for each call by passing immediate=True to the profile decorator.

There's also a @timecall decorator for printing the time to sys.stderr
every time a function is called, when you just want to get a rough measure
instead of a detailed (but costly) profile.

Caveats

  A thread on python-dev convinced me that hotshot produces bogus numbers.
  See http://mail.python.org/pipermail/python-dev/2005-November/058264.html

  I don't know what will happen if a decorated function will try to call
  another decorated function.  All decorators probably need to explicitly
  support nested profiling (currently TraceFuncCoverage is the only one
  that supports this, while HotShotFuncProfile has support for recursive
  functions.)

  Profiling with hotshot creates temporary files (*.prof for profiling,
  *.cprof for coverage) in the current directory.  These files are not
  cleaned up.  Exception: when you specify a filename to the profile
  decorator (to store the pstats.Stats object for later inspection),
  the temporary file will be the filename you specified with '.raw'
  appended at the end.

  Coverage analysis with hotshot seems to miss some executions resulting
  in lower line counts and some lines errorneously marked as never
  executed.  For this reason coverage analysis now uses trace.py which is
  slower, but more accurate.

Copyright (c) 2004--2008 Marius Gedminas <marius@pov.lt>
Copyright (c) 2007 Hanno Schlichting
Copyright (c) 2008 Florian Schulze

Released under the MIT licence since December 2006:

    Permission is hereby granted, free of charge, to any person obtaining a
    copy of this software and associated documentation files (the "Software"),
    to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom the
    Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.

(Previously it was distributed under the GNU General Public Licence.)
"""
      

__author__ = "Marius Gedminas (marius@gedmin.as)"
__copyright__ = "Copyright 2004-2009 Marius Gedminas"
__license__ = "MIT"
__version__ = "1.4"
__date__ = "2009-03-31"


import atexit
import inspect
import sys
import re

               
from profile import Profile
import pstats

                                     
try:
    import hotshot
    import hotshot.stats
except ImportError:
    hotshot = None

                       
import trace

                                                                         
if hotshot is not None:
    import _hotshot
    import hotshot.log

                               
try:
    import cProfile
except ImportError:
    cProfile = None

              
import time


                                 
AVAILABLE_PROFILERS = {}


def profile(fn=None, skip=0, filename=None, immediate=False, dirs=False,
            sort=None, entries=40,
            profiler=('cProfile', 'profile', 'hotshot')):
    """Mark `fn` for profiling.

    If `skip` is > 0, first `skip` calls to `fn` will not be profiled.

    If `immediate` is False, profiling results will be printed to
    sys.stdout on program termination.  Otherwise results will be printed
    after each call.

    If `dirs` is False only the name of the file will be printed.
    Otherwise the full path is used.

    `sort` can be a list of sort keys (defaulting to ['cumulative',
    'time', 'calls']).  The following ones are recognized::

        'calls'      -- call count
        'cumulative' -- cumulative time
        'file'       -- file name
        'line'       -- line number
        'module'     -- file name
        'name'       -- function name
        'nfl'        -- name/file/line
        'pcalls'     -- call count
        'stdname'    -- standard name
        'time'       -- internal time

    `entries` limits the output to the first N entries.

    `profiler` can be used to select the preferred profiler, or specify a
    sequence of them, in order of preference.  The default is ('cProfile'.
    'profile', 'hotshot').

    If `filename` is specified, the profile stats will be stored in the
    named file.  You can load them pstats.Stats(filename).

    Usage::

        def fn(...):
            ...
        fn = profile(fn, skip=1)

    If you are using Python 2.4, you should be able to use the decorator
    syntax::

        @profile(skip=3)
        def fn(...):
            ...

    or just ::

        @profile
        def fn(...):
            ...

    """
    if fn is None:                                                
        def decorator(fn):
            return profile(fn, skip=skip, filename=filename,
                           immediate=immediate, dirs=dirs,
                           sort=sort, entries=entries,
                           profiler=profiler)
        return decorator
                                            
    if isinstance(profiler, str):
        profiler = [profiler]
    for p in profiler:
        if p in AVAILABLE_PROFILERS:
            profiler_class = AVAILABLE_PROFILERS[p]
            break
    else:
        raise ValueError('only these profilers are available: %s'
                             % ', '.join(AVAILABLE_PROFILERS))
    fp = profiler_class(fn, skip=skip, filename=filename,
                        immediate=immediate, dirs=dirs,
                        sort=sort, entries=entries)
                                                                    
                                
                                                                            
                                                              
    def new_fn(*args, **kw):
        return fp(*args, **kw)
    new_fn.__doc__ = fn.__doc__
    new_fn.__name__ = fn.__name__
    new_fn.__dict__ = fn.__dict__
    new_fn.__module__ = fn.__module__
    return new_fn


def coverage(fn):
    """Mark `fn` for line coverage analysis.

    Results will be printed to sys.stdout on program termination.

    Usage::

        def fn(...):
            ...
        fn = coverage(fn)

    If you are using Python 2.4, you should be able to use the decorator
    syntax::

        @coverage
        def fn(...):
            ...

    """
    fp = TraceFuncCoverage(fn)                         
                                                                            
                                                              
    def new_fn(*args, **kw):
        return fp(*args, **kw)
    new_fn.__doc__ = fn.__doc__
    new_fn.__name__ = fn.__name__
    new_fn.__dict__ = fn.__dict__
    new_fn.__module__ = fn.__module__
    return new_fn


def coverage_with_hotshot(fn):
    """Mark `fn` for line coverage analysis.

    Uses the 'hotshot' module for fast coverage analysis.

    BUG: Produces inaccurate results.

    See the docstring of `coverage` for usage examples.
    """
    fp = HotShotFuncCoverage(fn)
                                                                            
                                                              
    def new_fn(*args, **kw):
        return fp(*args, **kw)
    new_fn.__doc__ = fn.__doc__
    new_fn.__name__ = fn.__name__
    new_fn.__dict__ = fn.__dict__
    new_fn.__module__ = fn.__module__
    return new_fn


class FuncProfile(object):
    """Profiler for a function (uses profile)."""

                                               
    in_profiler = False

    Profile = Profile

    def __init__(self, fn, skip=0, filename=None, immediate=False, dirs=False,
                 sort=None, entries=40):
        """Creates a profiler for a function.

        Every profiler has its own log file (the name of which is derived
        from the function name).

        FuncProfile registers an atexit handler that prints profiling
        information to sys.stderr when the program terminates.
        """
        self.fn = fn
        self.skip = skip
        self.filename = filename
        self.immediate = immediate
        self.dirs = dirs
        self.sort = sort or ('cumulative', 'time', 'calls')
        if isinstance(self.sort, str):
            self.sort = (self.sort, )
        self.entries = entries
        self.reset_stats()
        atexit.register(self.atexit)

    def __call__(self, *args, **kw):
        """Profile a singe call to the function."""
        self.ncalls += 1
        if self.skip > 0:
            self.skip -= 1
            self.skipped += 1
            return self.fn(*args, **kw)
        if FuncProfile.in_profiler:
                                    
            return self.fn(*args, **kw)
                                                                          
                              
        profiler = self.Profile()
        try:
            FuncProfile.in_profiler = True
            return profiler.runcall(self.fn, *args, **kw)
        finally:
            FuncProfile.in_profiler = False
            self.stats.add(profiler)
            if self.immediate:
                self.print_stats()
                self.reset_stats()

    def print_stats(self):
        """Print profile information to sys.stdout."""
        funcname = self.fn.__name__
        filename = self.fn.func_code.co_filename
        lineno = self.fn.func_code.co_firstlineno
        print
        print "*** PROFILER RESULTS ***"
        print "%s (%s:%s)" % (funcname, filename, lineno)
        print "function called %d times" % self.ncalls,
        if self.skipped:
            print "(%d calls not profiled)" % self.skipped
        else:
            print
        print
        stats = self.stats
        if self.filename:
            stats.dump_stats(self.filename)
        if not self.dirs:
            stats.strip_dirs()
        stats.sort_stats(*self.sort)
        stats.print_stats(self.entries)

    def reset_stats(self):
        """Reset accumulated profiler statistics."""
                                                                       
        self.stats = pstats.Stats(Profile())
        self.ncalls = 0
        self.skipped = 0

    def atexit(self):
        """Stop profiling and print profile information to sys.stdout.

        This function is registered as an atexit hook.
        """
        if not self.immediate:
            self.print_stats()


AVAILABLE_PROFILERS['profile'] = FuncProfile


if cProfile is not None:

    class CProfileFuncProfile(FuncProfile):
        """Profiler for a function (uses cProfile)."""

        Profile = cProfile.Profile

    AVAILABLE_PROFILERS['cProfile'] = CProfileFuncProfile


if hotshot is not None:

    class HotShotFuncProfile(object):
        """Profiler for a function (uses hotshot)."""

                                                   
        in_profiler = False

        def __init__(self, fn, skip=0, filename=None):
            """Creates a profiler for a function.

            Every profiler has its own log file (the name of which is derived
            from the function name).

            HotShotFuncProfile registers an atexit handler that prints
            profiling information to sys.stderr when the program terminates.

            The log file is not removed and remains there to clutter the
            current working directory.
            """
            self.fn = fn
            self.filename = filename
            if self.filename:
                self.logfilename = filename + ".raw"
            else:
                self.logfilename = fn.__name__ + ".prof"
            self.profiler = hotshot.Profile(self.logfilename)
            self.ncalls = 0
            self.skip = skip
            self.skipped = 0
            atexit.register(self.atexit)

        def __call__(self, *args, **kw):
            """Profile a singe call to the function."""
            self.ncalls += 1
            if self.skip > 0:
                self.skip -= 1
                self.skipped += 1
                return self.fn(*args, **kw)
            if HotShotFuncProfile.in_profiler:
                                        
                return self.fn(*args, **kw)
            try:
                HotShotFuncProfile.in_profiler = True
                return self.profiler.runcall(self.fn, *args, **kw)
            finally:
                HotShotFuncProfile.in_profiler = False

        def atexit(self):
            """Stop profiling and print profile information to sys.stderr.

            This function is registered as an atexit hook.
            """
            self.profiler.close()
            funcname = self.fn.__name__
            filename = self.fn.func_code.co_filename
            lineno = self.fn.func_code.co_firstlineno
            print
            print "*** PROFILER RESULTS ***"
            print "%s (%s:%s)" % (funcname, filename, lineno)
            print "function called %d times" % self.ncalls,
            if self.skipped:
                print "(%d calls not profiled)" % self.skipped
            else:
                print
            print
            stats = hotshot.stats.load(self.logfilename)
                                                                                   
                                                    
            if self.filename:
                stats.dump_stats(self.filename)
                                                  
            stats.strip_dirs()
            stats.sort_stats('cumulative', 'time', 'calls')
            stats.print_stats(40)

    AVAILABLE_PROFILERS['hotshot'] = HotShotFuncProfile


    class HotShotFuncCoverage:
        """Coverage analysis for a function (uses _hotshot).

        HotShot coverage is reportedly faster than trace.py, but it appears to
        have problems with exceptions; also line counts in coverage reports
        are generally lower from line counts produced by TraceFuncCoverage.
        Is this my bug, or is it a problem with _hotshot?
        """

        def __init__(self, fn):
            """Creates a profiler for a function.

            Every profiler has its own log file (the name of which is derived
            from the function name).

            HotShotFuncCoverage registers an atexit handler that prints
            profiling information to sys.stderr when the program terminates.

            The log file is not removed and remains there to clutter the
            current working directory.
            """
            self.fn = fn
            self.logfilename = fn.__name__ + ".cprof"
            self.profiler = _hotshot.coverage(self.logfilename)
            self.ncalls = 0
            atexit.register(self.atexit)

        def __call__(self, *args, **kw):
            """Profile a singe call to the function."""
            self.ncalls += 1
            return self.profiler.runcall(self.fn, args, kw)

        def atexit(self):
            """Stop profiling and print profile information to sys.stderr.

            This function is registered as an atexit hook.
            """
            self.profiler.close()
            funcname = self.fn.__name__
            filename = self.fn.func_code.co_filename
            lineno = self.fn.func_code.co_firstlineno
            print
            print "*** COVERAGE RESULTS ***"
            print "%s (%s:%s)" % (funcname, filename, lineno)
            print "function called %d times" % self.ncalls
            print
            fs = FuncSource(self.fn)
            reader = hotshot.log.LogReader(self.logfilename)
            for what, (filename, lineno, funcname), tdelta in reader:
                if filename != fs.filename:
                    continue
                if what == hotshot.log.LINE:
                    fs.mark(lineno)
                if what == hotshot.log.ENTER:
                                                                                 
                                                                                
                                                                                 
                                                                 
                    if lineno == fs.firstlineno:
                        lineno = fs.firstcodelineno
                    fs.mark(lineno)
            reader.close()
            print fs


class TraceFuncCoverage:
    """Coverage analysis for a function (uses trace module).

    HotShot coverage analysis is reportedly faster, but it appears to have
    problems with exceptions.
    """

                                                            
    tracer = trace.Trace(count=True, trace=False,
                         ignoredirs=[sys.prefix, sys.exec_prefix])

                                                    
    tracing = False

    def __init__(self, fn):
        """Creates a profiler for a function.

        Every profiler has its own log file (the name of which is derived
        from the function name).

        TraceFuncCoverage registers an atexit handler that prints
        profiling information to sys.stderr when the program terminates.

        The log file is not removed and remains there to clutter the
        current working directory.
        """
        self.fn = fn
        self.logfilename = fn.__name__ + ".cprof"
        self.ncalls = 0
        atexit.register(self.atexit)

    def __call__(self, *args, **kw):
        """Profile a singe call to the function."""
        self.ncalls += 1
        if TraceFuncCoverage.tracing:
            return self.fn(*args, **kw)
        try:
            TraceFuncCoverage.tracing = True
            return self.tracer.runfunc(self.fn, *args, **kw)
        finally:
            TraceFuncCoverage.tracing = False

    def atexit(self):
        """Stop profiling and print profile information to sys.stderr.

        This function is registered as an atexit hook.
        """
        funcname = self.fn.__name__
        filename = self.fn.func_code.co_filename
        lineno = self.fn.func_code.co_firstlineno
        print
        print "*** COVERAGE RESULTS ***"
        print "%s (%s:%s)" % (funcname, filename, lineno)
        print "function called %d times" % self.ncalls
        print
        fs = FuncSource(self.fn)
        for (filename, lineno), count in self.tracer.counts.items():
            if filename != fs.filename:
                continue
            fs.mark(lineno, count)
        print fs
        never_executed = fs.count_never_executed()
        if never_executed:
            print "%d lines were not executed." % never_executed


class FuncSource:
    """Source code annotator for a function."""

    blank_rx = re.compile(r"^\s*finally:\s*(#.*)?$")

    def __init__(self, fn):
        self.fn = fn
        self.filename = inspect.getsourcefile(fn)
        self.source, self.firstlineno = inspect.getsourcelines(fn)
        self.sourcelines = {}
        self.firstcodelineno = self.firstlineno
        self.find_source_lines()

    def find_source_lines(self):
        """Mark all executable source lines in fn as executed 0 times."""
        strs = trace.find_strings(self.filename)
        lines = trace.find_lines_from_code(self.fn.func_code, strs)
        self.firstcodelineno = sys.maxint
        for lineno in lines:
            self.firstcodelineno = min(self.firstcodelineno, lineno)
            self.sourcelines.setdefault(lineno, 0)
        if self.firstcodelineno == sys.maxint:
            self.firstcodelineno = self.firstlineno

    def mark(self, lineno, count=1):
        """Mark a given source line as executed count times.

        Multiple calls to mark for the same lineno add up.
        """
        self.sourcelines[lineno] = self.sourcelines.get(lineno, 0) + count

    def count_never_executed(self):
        """Count statements that were never executed."""
        lineno = self.firstlineno
        counter = 0
        for line in self.source:
            if self.sourcelines.get(lineno) == 0:
                if not self.blank_rx.match(line):
                    counter += 1
            lineno += 1
        return counter

    def __str__(self):
        """Return annotated source code for the function."""
        lines = []
        lineno = self.firstlineno
        for line in self.source:
            counter = self.sourcelines.get(lineno)
            if counter is None:
                prefix = ' ' * 7
            elif counter == 0:
                if self.blank_rx.match(line):
                    prefix = ' ' * 7
                else:
                    prefix = '>' * 6 + ' '
            else:
                prefix = '%5d: ' % counter
            lines.append(prefix + line)
            lineno += 1
        return ''.join(lines)


def timecall(fn=None, immediate=True):
    """Wrap `fn` and print its execution time.

    Example::

        @timecall
        def somefunc(x, y):
            time.sleep(x * y)

        somefunc(2, 3)

    will print the time taken by somefunc on every call.  If you want just
    a summary at program termination, use

        @timecall(immediate=False)

    """
    if fn is None:                                                 
        def decorator(fn):
            return timecall(fn, immediate=immediate)
        return decorator
                                             
    fp = FuncTimer(fn, immediate=immediate)
                                                                            
                                                              
    def new_fn(*args, **kw):
        return fp(*args, **kw)
    new_fn.__doc__ = fn.__doc__
    new_fn.__name__ = fn.__name__
    new_fn.__dict__ = fn.__dict__
    new_fn.__module__ = fn.__module__
    return new_fn


class FuncTimer(object):

    def __init__(self, fn, immediate):
        self.fn = fn
        self.ncalls = 0
        self.totaltime = 0
        self.immediate = immediate
        if not immediate:
            atexit.register(self.atexit)

    def __call__(self, *args, **kw):
        """Profile a singe call to the function."""
        fn = self.fn
        self.ncalls += 1
        try:
            start = time.time()
            return fn(*args, **kw)
        finally:
            duration = time.time() - start
            self.totaltime += duration
            if self.immediate:
                funcname = fn.__name__
                filename = fn.func_code.co_filename
                lineno = fn.func_code.co_firstlineno
                print >> sys.stderr, "\n  %s (%s:%s):\n    %.3f seconds\n" % (
                                        funcname, filename, lineno, duration)
    def atexit(self):
        if not self.ncalls:
            return
        funcname = self.fn.__name__
        filename = self.fn.func_code.co_filename
        lineno = self.fn.func_code.co_firstlineno
        print ("\n  %s (%s:%s):\n"
               "    %d calls, %.3f seconds (%.3f seconds per call)\n" % (
                                funcname, filename, lineno, self.ncalls,
                                self.totaltime, self.totaltime / self.ncalls))

