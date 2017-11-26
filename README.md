# SSHB

#### Disclaimer: I'm not responsible for any illegal use of this tool. Usage of sshb to get unauthorized access to targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. I assume no liability and I'm not responsible for any misuse or damage caused by this tool. Use it at YOUR OWN RISK.

#### NOTE: Code written in 2009


It was created for **educational** purposes (and fun), use it only for **ethical hacking**.

### Usage

```
    .:: SSH Brute Forcer ::.

 Compilation time: Nov 26 2017 ^ 17:05:51
 ASCII chars support only.
 SSHB Version: 0.2 testing (linux)
 Use This At Your Own Risk!!

 Options:
   --forks <n>       Forks number [default 10]
   --fake  <n>       Process fake name
   --iplist <n>      IP list file
   --threads <n>     Threads number
   --passwd <n>      Users-Passwd file [default login.list]
   --timeout <n>     Time out in seconds [default 15]

 Usage:
   ./sshb [options] [target_ip:port || --iplist <nnn>]
   ./sshb [options] 127.0.0.1:24 72.43.180.251
   ./sshb [options] --iplist scan.log
```
