# Memcached

## CoSMIX changes
To add SUVM mstore support, we annotated a single LOC of slab.c:414, with the SUVM mstore annotation.
To compile Memcached with SUVM support, use the Cosmix.mk Makefile.
Please note, since CoSMIX currently relies on function signatures as source for annotations, Memcached cannot be built natively for this source code. Instead, you must link with an empty
function, such as provided by temp.c file. See the example to build natively with the Makefile CoSMIX.mk.

## Dependencies

* libevent, http://www.monkey.org/~provos/libevent/ (libevent-dev)

## Environment

### Linux

If using Linux, you need a kernel with epoll.  Sure, libevent will
work with normal select, but it sucks.

epoll isn't in Linux 2.4, but there's a backport at:

    http://www.xmailserver.org/linux-patches/nio-improve.html

You want the epoll-lt patch (level-triggered).

### Mac OS X

If you're using MacOS, you'll want libevent 1.1 or higher to deal with
a kqueue bug.

Also, be warned that the -k (mlockall) option to memcached might be
dangerous when using a large cache.  Just make sure the memcached machines
don't swap.  memcached does non-blocking network I/O, but not disk.  (it
should never go to disk, or you've lost the whole point of it)

## Website

* http://www.memcached.org

## Contributing

Want to contribute?  Up-to-date pointers should be at:

* http://contributing.appspot.com/memcached
