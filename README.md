# Software Security - Debugger Dyanmic Analysis

## XDebug Output Analyzer 
Project consists in a Java Program to Parse and Analyze Code that should match patterns such as SQL Injection Protection, XSS Protection, Code Injection Protection and so on...

The patterns are composed by the entry points, the sensitive functions and the sinks that should be present within those functions.

Example of a Pattern:
```
SQL Injection
$_GET,$_POST,$_COOKIE,$_REQUEST,HTTP_GET_VARS,HTTP_POST_VARS,HTTP_COOKIE_VARS,HTTP_REQUEST_VARS
mysql_escape_string,mysql_real_escape_string
mysql_query,mysql_unbuffered_query,mysql_db_query
```


Read over project specification and guidelines to run the code
![alt tag](https://github.com/carloscorreia94/SoftwareSecurityProject/blob/master/ssoft_a13.pdf)