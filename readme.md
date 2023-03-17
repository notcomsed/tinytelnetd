# tinytelnetd
tiny telnet server for windows. support win7 win 8.1,win10. multi-user, not need privilege .stand alone binary, not have relylibrary.

### How to use
#### start
```bash
telnetd.exe -l 127.0.0.1 -p 23 -k 123456789
```

It will listen 127.0.0.1:23, and password "123456789"

#### use simple
```bash
telnetd.exe -k 123456789
```

It will default listen 0.0.0.0:23

#### logged

```bash
telnetd.exe -k 123456789 >> C:\logs\telnetd.log
```

use `-h` to get help

#### source code
source code limit 4 user, if you want support more user, modify source code.
