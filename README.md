# mark-urls
Scan text looking for URLs and retreive the page title

If the URL is on a line by itself then insert a line with the title above the line with the URL.  Otherwise, replace the URL with a Markdown
in-line style link showing the title.  For example, this:

    Refer to http://example.com/foobar for additional info.

becomes this:

    Refer to [Example Domain](http://example.com/foobar) for additional info.
