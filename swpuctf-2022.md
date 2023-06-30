# SWPUCTF 2022

## Web

### numgame

进入页面后是个文字游戏，题目为 `10+10=?` ，但是无论如何加减都不能改到 `20` 。

<figure><img src=".gitbook/assets/numgame-1.png" alt=""><figcaption></figcaption></figure>

因此开始尝试 `F12` 打开开发者工具，但是不起作用，发现右键也被禁用了。下一步直接一把梭把 JavaScript 禁用了，禁用之后打开开发者工具，可以发现 `/js/1.js` ，其内容如下

```js
var input = $('input'),
    input_val = parseInt(input.val()),
    btn_add = $('.add'),
    btn_remove = $('.remove');

input.keyup(function() {
    input_val = parseInt(input.val())
});

btn_add.click(function(e) {
    input_val++;
    input.val(input_val);
    console.log(input_val);
    if(input_val==18){
        input_val=-20;
        input.val(-20);

    }
});

btn_remove.click(function(e) {
    input_val--;
    input.val(input_val);
});
// NSSCTF{TnNTY1RmLnBocA==}
```

对 `TnNTY1RmLnBocA==` 进行 Base64 解码可以得到 `NsScTf.php` ，访问 `NsScTf.php` 可以得到以下内容

```php
<?php
error_reporting(0);
//hint: 与get相似的另一种请求协议是什么呢
include("flag.php");
class nss{
    static function ctf(){
        include("./hint2.php");
    }
}
if(isset($_GET['p'])){
    if (preg_match("/n|c/m",$_GET['p'], $matches))
        die("no");
    call_user_func($_GET['p']);
}else{
    highlight_file(__FILE__);
}
```

通过提示可得知应该使用 `POST` 请求协议，由于 nss 类内函数 ctf 为静态函数，可以直接通过 `nss::ctf` 来调用。通过访问 `/hint2.php` 可以得知类名为 `nss2` ，因此通过构造 payload `p=nss2::ctf` 就可以得到 flag 了。
