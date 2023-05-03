---
title: 通过 Cloudflare 和 acme.sh 开源脚本，实现申请 ssl 证书加免费续期
date: 2023-03-20
categories: [工具]
tags: [ssl]
---
## 使用的开源项目

acme 仓库地址：[acmesh-official/acme.sh: A pure Unix shell script implementing ACME client protocol (github.com)](https://github.com/acmesh-official/acme.sh)

其中关于 DNS 解析申请的相关说明：https://github.com/acmesh-official/acme.sh/wiki/dnsapi

## 写一个脚本来使用 acme 工具申请域名
手写了一个 shell 脚本，通过 acme 提供的开源脚本，在 cloudflare 申请脚本：

apply_ssl.sh
```bash
#!/bin/bash
echo "请输入邮箱:";
read your_email;
#echo ${your_email};
echo "请输入CF_Key"
read cf_key;
#echo ${cf_key}
echo "请输入域名:"
read domain;

echo "开始执行: ";
curl https://get.acme.sh | sh -s email=$your_email
export CF_Key=$cf_key
export CF_Email=$your_email
/root/.acme.sh/acme.sh --issue --dns dns_cf -d $domain
```
使用前提：

（1）**域名已经被托管在 Cloudflare，域名仅用 DNS 解析**。结果大概是这样：

![](https://s2.loli.net/2023/03/29/b4vXfjLQw2zFCU6.png)

（2）**要给脚本加执行权限**：
```
[root@racknerd-1f76df ~]# chmod +x apply.sh
```
（3）最后一行，要使用 acme 脚本安装的全路径，否则会无法执行，查找 acme 的全路径的命令是：
```
[root@racknerd-1f76df ~]# type -a acme.sh
acme.sh is aliased to `/root/.acme.sh/acme.sh'
```
我安装后的全路径就是` /root/.acme.sh/acme.sh`，如果脚本最后一行没执行成功，出现这个报错：
````
apply.sh: line 16: acme.sh: command not found

```
是因为全路径和我的不太一样，查找后手动修改一下，重新执行即可。

## nginx 配置证书

证书申请成功后，找到证书，在 /ect/nginx/conf.d 下创建文件，一般来说会命名为：域名.conf。

输入内容：

```bash
 server{
        listen 443 ssl;
        root 打开这个域名会访问到的地址;
        server_name 域名;  
        client_max_body_size 40m;  

        ssl_certificate "x.cer"; 
        ssl_certificate_key "x.key"; 
        ssl_protocols TLSv1.1 TLSv1.2;
        ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:HIGH:!aNULL:!MD5:!RC4:!DHE;
        ssl_prefer_server_ciphers on;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 10m;
        error_page   404    /404.html;
        error_page   500 502 503 504     /50x.html;
    }
```
需要修改的内容：
```
root：访问这个域名，会访问到哪里，一般是网站的首页地址
server_name：域名（比如 blog.nan.directory）
ssl_certificate：刚才申请的证书目录下，后缀为 cer 的文件所在的全路径
ssl_certificate_key：刚才申请的证书目录下，后缀为 key 的文件所在的全路径
```

重启 nginx 服务：

```bash
systemctl restart nginx
```

不报错就是重启成功。如果有报错排查对应的报错即可。

## 访问你的域名
前面都没问题，访问浏览器查看效果：
```
https://域名
```