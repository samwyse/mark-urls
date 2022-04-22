#! /usr/bin/env python

"""Scan text looking for URLs and retreive page titles.

If the URL is on a line by itself then inserts a line with the title above the line with the URL.  Otherwise, replace the URL with a Markdown
in-line style link showing the title.  For example, this:

    Refer to http://example.com/foobar for additional info.

becomes this:

    Refer to [Example Domain](http://example.com/foobar) for additional info.
    
"""

# Insure maximum compatibility between Python 2 and 3
from __future__ import absolute_import, division, print_function

try:
    basestring
except NameError:
    basestring = str

# Metadate...
__author__ = "Samuel T. Denton, III <sam.denton@dell.com>"
__contributors__ = []
__copyright__ = "Copyright 2022 Samuel T. Denton, III"
__version__ = '0.9'

# Declutter our namespace
##__all__ = []

# Python standard libraries
import logging

logger = logging.getLogger(__name__)

import argparse, os, sys
import re
import ssl
try:
    from urllib.request import Request, urlopen
    import http
    from http.cookies import SimpleCookie
    from html import unescape
except ImportError:
    from urllib2 import Request, urlopen
    import httplib
    from Cookie import SimpleCookie

def main_init(parser=None):
    """Parse command line options."""
    if parser is None:
        parser = argparse.ArgumentParser(description=__doc__,
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument("--doctest", action='store_true',
            help=argparse.SUPPRESS)
        parser.add_argument("--verbose", "-v", action="count", default=0,
            help="better explain what's being done")
    parser.add_argument("--output", "-o",
        type=argparse.FileType('w'), default=sys.stdout,
        metavar="FILE",
        help="Write output to <file> instead of stdout")
    parser.add_argument("inputs", nargs="*", metavar='FILE',
        type=argparse.FileType('r'), default=sys.stdin,
        help="input file name")

    return parser

def get_title(url,
              headers={'User-Agent': "Mozilla/5.0 (X11; U; Linux i686) Gecko/20071127 Firefox/2.0.0.11"},
              title_re=re.compile(b'\<title\>([^<]*)\<\/title\>', re.IGNORECASE),
              ):
    req = Request(url, headers=headers)
    f = urlopen(req)
    buffer = f.read()
    match = title_re.search(buffer)
    if match:
        title = unescape(match.group(1).decode()).strip()
    else:
        title = 'UNTITLED'
    return title

def main_call(args):
    """Process options and arguments."""
    # Delay importing non-standard libraries until after
    # argparse has had a chance to provide help, etc.
    ##import ...

    url_re = re.compile('(https?://\S+)')
    for input in args.inputs:
        for line in input:
            pieces = url_re.split(line)
            if len(pieces) == 3 and pieces[0].isspace() and pieces[2].isspace():
                new = (pieces[0], '*', get_title(pieces[1]), '*', pieces[2], line)
            else:
                new = []
                args = [iter(pieces)] * 2
                for text, url in zip(*args):
                    new.extend((text, '[', get_title(url), '](', url, ')'))
                new.append(pieces[-1])
            print(''.join(new), end='')
    return

    cj = cookielib.MozillaCookieJar()
    if args.cookie:
        if '=' in args.cookie:
            cj.set_cookie(SimpleCookie(args.cookie))
        else:
            # argument is a filename
            cj.load(args.cookie)
    if args.junk_session_cookies:
        cj.clear_session_cookies()

    opener = build_opener(HTTPCookieProcessor(cj))
    if "user_agent" in kwargs:
        opener.addheaders = [('User-agent', kwargs.pop("user_agent"))]
    install_opener(opener)

    output = kwargs.pop("output", sys.stdout)

    request = Request(args.url, data=args.data)
    if args.request:
        request.method = args.request
    if args.referer:
        request.add_header("Referer", args.referer)
    if args.user:
        base64string = base64.b64encode(args.user)
        request.add_header("Authorization", "Basic %s" % base64string)
    if args.user_agent:
        request.add_header("User-Agent", args.user_agent)
    context = ssl._create_unverified_context() if args.insecure else None
    try:
        result = urlopen(request, context=context)
    except Exception as err:
        print(err, file=sys.stderr)
        sys.exit(1)
    else:
        if args.cookie_jar:
            cj.save(args.cookie_jar, ignore_discard=True)
        if output:
            CHUNK = 16*1024
            for chunk in iter(lambda: result.read(CHUNK), ''):
                output.write(chunk)

def main(argv=None):
    """Execute as a script."""

    argv = [r'C:\Users\nx733e\Documents\Zoom\2022-04-21 17.26.12 Virtual happy hour\meeting_saved_chat.txt']

    # Cribbed from [Python main() functions](https://www.artima.com/weblogs/viewpost.jsp?thread=4829)
    if argv is None:
        argv = sys.argv[1:]
    elif isinstance(argv, basestring):
        # When run from an interactive Python interpreter, this allows us
        # to say "main('-foo bar')" instead of "main(['-foo', 'bar'])".
        import shlex  # only import when needed...
        argv = shlex.split(argv)  # split using shell-like syntax
    else:
        pass
    parser = main_init()
    args = parser.parse_args(argv)

    if args.doctest:
        import doctest
        doctest.testmod()
        try:
            doctest.testfile(os.path.splitext(__file__)[0] + '.rst')
        except IOError:
            pass
        return

    if args.verbose:
        logger.setLevel(logging.INFO if args.verbose == 1 else logging.DEBUG)
        from pprint import pformat
        logger.debug(pformat(vars(args)))

    try:
        return main_call(args)
    except:
        etype, value, tb = sys.exc_info()
        if issubclass(etype, SystemExit):
            raise
        import pdb, traceback
        traceback.print_exception(etype, value, tb)
        print(file=sys.stderr)
        pdb.post_mortem()

if __name__ == '__main__':
    logging.basicConfig()
    sys.exit(main())
