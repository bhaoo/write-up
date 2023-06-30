# GDOUCTF 2023

## Web

### 泄露的伪装

通过 dirsearch 可以发现 `/test.txt` 、 `/www.rar` 为可访问文件， `/test.txt` 文件内容即为开屏显示内容， `/www.rar` 为一个空的压缩包

通过 010Editor 可以发现 `www.rar` 的文件头为 504B0304，说明此文件原先为 ZIP 压缩包，修改文件名为 `www.zip` 并打开压缩包可以获得 `gift（2）.txt` 文件，使用文本打开可以得到下一关 `/orzorz.php` ，跳转到 `/orzorz.php` 可以得到一下 PHP 代码。

```php
<?php
error_reporting(0);
if(isset($_GET['cxk'])){
    $cxk=$_GET['cxk'];
    if(file_get_contents($cxk)=="ctrl"){
        echo $flag;
    }else{
        echo "洗洗睡吧";
    }
}else{
    echo "nononoononoonono";
}
?>
```

file\_get\_contents() 函数可以通过 php://input 或者 data:// 伪协议进行绕过，例如 `data://text/plain;base64,<base64 data>` 或者 `php://input` 并且在 body 属性中加入所需 input 的值

通过构造 payload `[params]cxk=php://input [body]ctrl` 即可获得 flag

### 反方向的钟

通过 Network 可知当前系统的 PHP 版本为 7.3.11，排除 \_\_wakeup() 绕过这一方法。

通过逐步分析类可以构造出以下示例

```php
$a = new school(new classroom("one class", new teacher("ing", "department")), "ong");
$str = base64_encode(serialize($a));
echo $str;
// Tzo2OiJzY2hvb2wiOjI6e3M6MTA6ImRlcGFydG1lbnQiO086OToiY2xhc3Nyb29tIjoyOntzOjQ6Im5hbWUiO3M6OToib25lIGNsYXNzIjtzOjY6ImxlYWRlciI7Tzo3OiJ0ZWFjaGVyIjozOntzOjQ6Im5hbWUiO3M6MzoiaW5nIjtzOjQ6InJhbmsiO3M6MTA6ImRlcGFydG1lbnQiO3M6MTU6IgB0ZWFjaGVyAHNhbGFyeSI7aToxMDAwMDt9fXM6MTA6ImhlYWRtYXN0ZXIiO3M6Mzoib25nIjt9 
```

通过构造 payload 可以回显 Pretty Good ! Ctfer! 说明执行成功，就到了下一步，即使用 SplFileObject 类进行读写文件，搭配 php:// 伪协议即可获取 flag.php 的内容

通过构造 payload `a=SplFileObject&b=php://filter/read=convert.base64-encode/resource=flag.php` 回显得到 PD9waHANCiRmbGFnID0gIk5TU0NURnszOWIxYWE4NS1mNTEyLTQwYTEtOTI4NS0wNmIyYmZmMjY5ZmJ9IjsNCj8+DQo=，解密即可得到 flag

### 受不了一点

第一关为 md5 的强比较绕过，通过构造数组 `ctf[]=1&gdou[]=2` 绕过即可。

第二关为 cookie，直接设置 cookie 为 `j0k3r` 即可。

第三关为类型弱比较，通过在传参时添加字母即 `aaa=114514&bbb=114514a` 就可以绕过。

第四关为引用变量，通过代码可以进行构造

```php
$1 = $flag;
$flag = $1 = $flag;
```

即 payload(params) `1=flag&flag=1` 就可以获得 flag 了。

### EZ WEB

通过查看源代码可以获得 Hint "/src"，通过访问后便可以得到 `app.py` 。

通过查看 `app.py` 可以看到这题需要使用 Flask 模板注入，并且还提供了一个入口 `/super-secret-route-nobody-will-guess` 并且支持 PUT 方式发送请求，因此发送 PUT 请求即可得到 flag 了。

### hate eat snake

可以发现蛇的速度可以通过 Snake 类的 speed 属性进行设置，因此通过 setInterval() 函数让蛇速度一直为 0 即可获得 flag

```js
let snake = new Snake('eatSnake', 0, false);
setInterval(() => { snake.speed = 0 }, 1);
```

## MISC

### misc\_or\_crypto?

> bmp图片隐写

下载附件后获得 `flag.bmp` 文件，通过在 Linux 终端中输入

```sh
$ string flag.bmp
```

即可以获得一串 RSA 密钥以及一串密文，通过将密文解密即可获得 flag，但是存在一个坑，即 **flag 以 NSSCTF{} 形式提交**。

### Matryoshka

> 压缩包套娃

通过下载附件可以得到压缩包 `Matryoshka.zip` ，解压后可以得到加密的压缩包 `Matryoshka1000.zip`

以及密码文本 `password1000.txt` 。通过分析需要替换才能获得真正的密码，替换如下

```python
passwd = open('./task/password1000.txt').read()

passwd = passwd.replace('one', '1')
passwd = passwd.replace('two', '2')
passwd = passwd.replace('three', '3')
passwd = passwd.replace('four', '4')
passwd = passwd.replace('five', '5')
passwd = passwd.replace('six', '6')
passwd = passwd.replace('seven', '7')
passwd = passwd.replace('eight', '8')
passwd = passwd.replace('nine', '9')
passwd = passwd.replace('zero', '0')
passwd = passwd.replace('plus', '+')
passwd = passwd.replace('times', '*')

print(passwd)
# 8509527+170747742+410330*351657887+51791538
```

通过 eval 函数执行可以得出计算结果为 `144296011821517` ，验证结果密码错误，尝试从左到右进行计算。

```python
print((8509527+170747742+410330)*351657887+51791538)
# 63181528278494851
```

以上密码经过验证密码正确，因此通过循环解开所有套娃的压缩包即可。在解开所有压缩包之前还需要获得剩下两个运算符的替换。通过上面类似代码可以得出

```python
passwd = passwd.replace('minus', '-')
passwd = passwd.replace('mod', '%')
```

当循环代码执行到 996 时报错【解压密码错误】，通过查看密码可以发现密码为 `-29041679` 是负数，需要转换为正数才可以，因此需要使用 abs 函数，具体代码如下

```python
import zipfile
import re
import os

def password(_path):
    pwd = open(_path)
    
    passwd = pwd.read()
    passwd = passwd.replace('one', '1')
    passwd = passwd.replace('two', '2')
    passwd = passwd.replace('three', '3')
    passwd = passwd.replace('four', '4')
    passwd = passwd.replace('five', '5')
    passwd = passwd.replace('six', '6')
    passwd = passwd.replace('seven', '7')
    passwd = passwd.replace('eight', '8')
    passwd = passwd.replace('nine', '9')
    passwd = passwd.replace('zero', '0')
    passwd = passwd.replace('plus', '+')
    passwd = passwd.replace('times', '*')
    passwd = passwd.replace('minus', '-')
    passwd = passwd.replace('mod', '%')

    number = re.findall(r'\d+', passwd)
    symbol = re.findall(r'\D+', passwd)

    result = ''

    for i in range(len(symbol)):
        if i == 0:
            result = str(eval(str(int(number[i])) + symbol[i] + str(int(number[i + 1]))))
        else:
            result = str(eval(result + symbol[i] + str(int(number[i + 1]))))

    pwd.close()
    return str(abs(int(result)))


path = './Matryoshka.zip'
zip_src = zipfile.ZipFile(path, 'r')
zip_src.extractall('./task')
zip_src.close()

for i in range(1000, -1, -1):
    zip_path = "./task/Matryoshka{}.zip".format(i)
    password_path = "./task/password{}.txt".format(i)

    print(i, password(password_path).encode())
    zip_src = zipfile.ZipFile(zip_path)
    zip_src.extractall('./task', pwd=password(password_path).encode())

    zip_src.close()
    os.remove(zip_path)
    os.remove(password_path)
```

运行结束后获得 `flag.txt` 文件，内容即为 flag

### pixelart

> 参考WP https://www.nssctf.cn/note/set/1790 感谢 hehanzzz 师傅

下载附件通过 010Editor 可以在尾部发现提示 `320*180` 的提示，而源图片分辨率为 `3840*2160` ，说明按照等比例缩小了 12 倍，因此需要编写代码将图片缩小 12 倍

```python
from PIL import Image

original_image = Image.open('arcaea.png')

new_width = original_image.width // 12
new_height = original_image.height // 12

new_image = Image.new("RGB",(new_width,new_height))

for x in range(new_width):
    for y in range(new_height):
        pixel = original_image.getpixel((x *12,y*12))
        new_image.putpixel((x,y),pixel)

new_image.save("flag.png")
```

之后通过 `zsteg flag.png` 即可获得 flag
