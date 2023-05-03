---
title: MySQL 在 centos 上备份
date: 2023-03-20
categories: [shell脚本]
tags: [MySQL备份,shell 脚本]
---
## MySQL 在 centos 上备份
写一个脚本，需求是，备份最近 7 天 MySQL 的数据，过期删除：

backup_mysql_exam.sh
```shell
#!/bin/bash

# MySQL 用户名
USER="root"
# MySQL 密码
PASSWORD="123456"
# 要备份的数据库
DATABASE="exam"
# 备份的数据
BACKUP_DIR="/data/mysqlbackup"
DATE=$(date +"%Y-%m-%d")
# MySQL TCP 端口
PORT=8889


mkdir -p ${BACKUP_DIR}


mysqldump -u${USER} -p${PASSWORD} -hlocalhost --port=${PORT} ${DATABASE} > ${BACKUP_DIR}/${DATABASE}_${DATE}.sql


find ${BACKUP_DIR} -type f -name "${DATABASE}_*.sql" -mtime +7 -exec rm {} \;

```
给脚本增加执行权限：
```
chmod +x 文件全路径
```
定义定时任务，每天凌晨执行脚本：

```
crontab -e
```

增加定义任务 cron 表达式：
```
0 0 * * * 脚本全路径
```
