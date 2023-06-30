# MRCTF 2020

## Web

### Ez\_bypass

#### **题目**

```php
<?php
include 'flag.php';
$flag = 'MRCTF{xxxxxxxxxxxxxxxxxxxxxxxxx}';
if (isset($_GET['gg']) && isset($_GET['id'])) {
  $id = $_GET['id'];
  $gg = $_GET['gg'];
  if (md5($id) === md5($gg) && $id !== $gg) {
    echo 'You got the first step';
    if (isset($_POST['passwd'])) {
      $passwd = $_POST['passwd'];
      if (!is_numeric($passwd)) {
        if ($passwd == 1234567) {
          echo 'Good Job!';
          highlight_file('flag.php');
          die('By Retr_0');
        } else {
          echo "can you think twice??";
        }
      } else {
        echo 'You can not get it !';
      }

    } else {
      die('only one way to get the flag');
    }
  } else {
    echo "You are not a real hacker!";
  }
} else {
  die('Please input first');
}
```

#### **MD5 绕过**

构造 payload `gg[]=1&&id[]=2` 进行绕过即可

#### **is\_numeric() 函数绕过**

构造 payload `passwd=1234567a` 进行绕过即可获得到 flag
