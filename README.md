Add openqa-scan script for your openQA needs:

- Scan traces & coredumps.
- List jobs.
- Cancel, comment, delete, prioritize and restart jobs.
- Accepts almost any kind of openQA URL that shows jobs.

NOTES
- To avoid its usage as a weapon of mass deletion, the script limits itself to 99 jobs.
- Actions that require an API key assume a working `$HOME/.netrc` supported by default by Python Requests without the need for special authentication code. The format is:
 `machine openqa.suse.de login $USER password $APIKEY:$APISECRET`
- The only dependencies are Python 3.11+ & Python Requests.

Example usage:

```
# List Tumbleweed x86_64 jobs
$ openqa-scan -b latest https://openqa.opensuse.org/group_overview/1

# Scan Tumbleweed x86_64 for coredumps & traces:
$ openqa-scan -x all https://openqa.opensuse.org/group_overview/1

# Scan SLE aggregates
$ openqa-scan -x all -d sle -v 15-SP6 -v 15-SP7 -b yesterday https://openqa.suse.de
$ openqa-scan -x all -d sle -v 15-SP4 -v 15-SP5 -b yesterday https://openqa.suse.de
```

```
usage: openqa-scan [-h] [-A {cancel,delete,restart}] [-a {aarch64,i586,ppc64le,riscv64,s390x,x86_64}] [-b BUILD] [-c COMMENT] [-d DISTRI] [-f FLAVOR] [-g GROUPID] [-p PRIORITY]
                   [-r {aborted,complete,failed,incomplete,none,not_complete,not_ok,obsoleted,ok,parallel_failed,parallel_restarted,passed,skipped,softfailed,timeout_exceeded,user_cancelled,user_restarted}]
                   [-s {assigned,cancelled,done,execution,final,pre_execution,running,scheduled,setup,uploading}] [-v VERSION] [-V] [-x {all,coredumps,traces}]
                   url [url ...]

positional arguments:
  url                   openQA url

options:
  -h, --help            show this help message and exit
  -A, --action {cancel,delete,restart}
  -a, --arch {aarch64,i586,ppc64le,riscv64,s390x,x86_64}
  -b, --build BUILD     build or YYYYMMDD date, today, yesterday or latest
  -c, --comment COMMENT
                        add comment
  -d, --distri DISTRI
  -f, --flavor FLAVOR
  -g, --groupid GROUPID
  -p, --priority PRIORITY
                        set priority
  -r, --result {aborted,complete,failed,incomplete,none,not_complete,not_ok,obsoleted,ok,parallel_failed,parallel_restarted,passed,skipped,softfailed,timeout_exceeded,user_cancelled,user_restarted}
  -s, --state {assigned,cancelled,done,execution,final,pre_execution,running,scheduled,setup,uploading}
  -v, --version VERSION
                        product version
  -V, --verbose         show comments and first line of traces
  -x, --extract {all,coredumps,traces}
```

