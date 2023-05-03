---

title: SpringBoot 快速集成 Shiro

date: 2023-05-03

author: liyanan

categories: [SpringBoot,Shiro]

tags: [SpringBoot,Shiro]

---
## Shiro 简介
### 定义
Apache Shiro 是一个 Java 安全框架，可以进行身份验证、授权、加密和会话管理。并且有易于理解的 API。
### Shiro 的理念
Shiro 想为开发者提供简单的 API 来实现一些安全性的需求，它常用来做：
* 身份验证与授权
* 访问控制（给用户分配特定角色）
* 单点登录（SSO）

![rpWZxDBuMs6IbNlKLE6emisgD2vZgDKQHnff-sjN_RE.png](https://s2.loli.net/2023/05/03/ierjsDWkaBFchYQ.png)

**Authentication（身份验证）：可以简单理解为登陆。**

**Authorization：授权，访问控制的过程，即确定“谁”可以访问什么。**

**Session Management（会话管理）：（HTTP 是无状态了，为了知道这个客户端曾经访问过，我们通过传递唯一的 会话 ID（Session ID） 来识别哪个客户端曾经访问过）。**

**Cryptography（加密）：使用密码算法确保数据安全，同时仍然易于使用。**

### Shiro 的主要架构

![_mmEn5rCOSO7GKdPhh3HG8Hm8-bzZxX1TVgBKETvG8Q.png](https://s2.loli.net/2023/05/03/3iLKBwrCQe8F26d.png)

Shiro 的主要架构有 3 个：
* **Subject**：当前用户（这里可以简单认为是一个用户，也可以是第三方服务等等）
* **SecurityManager**：Shiro 的核心，用来协调安全组件。但是一般来说，开发人员只需要关注 Subject API 即可，SecurityManager 一般不需要过多的定义。
* **Realms**：可以理解为特殊的 DAO，它封装了数据源的细节，使 Shiro 可以根据需求来关联数据。SecurityManager 至少要绑定一个 Realms（当然可以绑定多个）。

## SpringBoot 集成 Shiro
本次示例代码使用最基础的模式，没有使用常用的和 jwt 结合的方式，在查询用户时，也没有连接数据库，这样可以更清晰的掌握 Shiro 的使用逻辑。
### 项目环境
Java: 8
SpringBoot: 2.7.11
Maven: 3.9.0
Shiro SpringBoot Starter: 1.11.0
### 引入依赖
本次使用 Maven 构建工程，在 pom.xml 增加如下依赖：
```
	<dependencies>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-web</artifactId>
		</dependency>
		<dependency>
			<groupId>org.apache.shiro</groupId>
			<artifactId>shiro-spring-boot-web-starter</artifactId>
			<version>1.11.0</version>
		</dependency>
	</dependencies>
```
### 配置 Shiro
#### 定义 Realm
UserRealm.java
```java
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import nan.directory.shirodemo.entity.SysUser;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


public class UserRealm extends AuthorizingRealm {

    private static final List<SysUser> sysUserList = Arrays.asList(new SysUser("zhangsan", "123456"),
            new SysUser("lisi", "654321"));

    private static final Map<String, SysUser> userMap = sysUserList.stream().collect(Collectors.toMap(SysUser::getUsername, sysUser -> sysUser));

    private SysUser findByUsername(String userName) {
        return userMap.get(userName);
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        // 暂时不做角色设置
        return new SimpleAuthorizationInfo();
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        // 获取用户输入的账号和密码
        UsernamePasswordToken userToken = (UsernamePasswordToken) token;
        String username = userToken.getUsername();
        String password = String.valueOf(userToken.getPassword());

        // 查询内存中是否存在该用户
        SysUser user = findByUsername(username);
        if (user == null) {
            throw new UnknownAccountException("用户名或密码错误！");
        }

        // 判断密码是否正确
        if (!password.equals(user.getPassword())) {
            throw new IncorrectCredentialsException("用户名或密码错误！");
        }

        // 认证成功，返回一个认证信息对象
        return new SimpleAuthenticationInfo(user, password, getName());
    }
}

```
定义 UserRealm 继承 org.apache.shiro.realm 包 下的 AuthorizingRealm，通过集成该类，可以自定义用户授权的逻辑。

继承该类必须实现两个方法：doGetAuthorizationInfo 与 doGetAuthenticationInfo。
doGetAuthorizationInfo：角色权限检查逻辑。
doGetAuthenticationInfo：身份认证检查逻辑。

在代码中，我在内存中定义了 Map 存储用户信息，来当作数据源。（此处可以通过连接数据库来获得用户相关信息）

重新实现 doGetAuthenticationInfo 方法，判断当前用户是否已经进行认证。
#### 定义 Shiro 配置
通过配置类 ShiroConfig，将自定义的 UserRealm 告知 Shiro 框架。并且配置 Shiro 的路由放行规则。
```java
import org.apache.shiro.realm.Realm;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.LinkedHashMap;
import java.util.Map;

@Configuration
public class ShiroConfig {
    @Bean
    public Realm userRealm() {
        return new UserRealm();
    }

    @Bean
    public DefaultWebSecurityManager securityManager() {
        DefaultWebSecurityManager manager = new DefaultWebSecurityManager();
        manager.setRealm(userRealm());
        return manager;
    }

    /**
     * 创建ShiroFilterFactoryBean
     */
    @Bean("shiroFilterFactoryBean")
    public ShiroFilterFactoryBean shiroFilterFactoryBean() {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        shiroFilterFactoryBean.setSecurityManager(securityManager());
        shiroFilterFactoryBean.setLoginUrl("/api/login");
        shiroFilterFactoryBean.setSuccessUrl("/api/succ");
        Map<String, String> filterMap = new LinkedHashMap<>();
        filterMap.put("/login", "anon");
        filterMap.put("/logout", "anon");
        filterMap.put("/**", "authc"); // 验证

        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterMap);
        return shiroFilterFactoryBean;
    }
}
```
使用 `@Configuration` 告知 SpringBoot 这是一个配置类。上面分别注入三个 bean：
UserRealm：自定义的 Realm，自定义身份认证逻辑。

securityManager：将自定义的 Realm 绑定 DefaultWebSecurityManager。

ShiroFilterFactoryBean：在这里设置刚才注入的 securityManager。并且重新配置 loginUrl、successUrl，这两个配置分别表示未登录跳转路由、登录成功跳转路由。此处如果不进行自定义则会走默认的 login.jsp。配置放行路由（anon）。anon 需要放在配置路由的最前。此处使用 LinkedHashMap 保证自定义路由规则的顺序。最后使用 authc，保证除 anon 之外的访问全部要进行授权判断。

#### 定义 Controller
LoginController.java
```java
package nan.directory.shirodemo.controller;

import nan.directory.shirodemo.dto.UserLoginDTO;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

    @PostMapping("/login")
    public String login(UserLoginDTO userLoginDTO) {
        Subject subject = SecurityUtils.getSubject();
        if (subject.isAuthenticated()) {
            return "login succ";
        }
        String username = userLoginDTO.getUsername();
        String password = userLoginDTO.getPassword();
        UsernamePasswordToken token = new UsernamePasswordToken(username, password);
        subject.login(token);
        return "login succ";
    }

    @PostMapping("/logout")
    public String logOut() {
        Subject subject = SecurityUtils.getSubject();
        if (subject.isAuthenticated()) {
            // 退出登录
            subject.logout();
        }
        return "logout succ";
    }

    @RequestMapping("/api/login")
    public String loginMsg() {
        return "please login";
    }

    @GetMapping("/api/succ")
    public String loginSucc() {
        return "login succ";
    }
}
```
/login：登录。通过 SecurityUtils.getSubject() 获取当前 Subject，使用 UsernamePasswordToken 对象并传入用户名密码。并且使用 subject.login 登录。如果登录失败则会跳转到 loginUrl（目前是/api/login ），登陆成功则跳转到 successUrl（目前是/api/succ ）。

/logout：登出。通过 SecurityUtils.getSubject() 获取当前 Subject，如果当前用户已登录则退出登录。

/api/login：未登录跳转路由（ShiroFilterFactoryBean 中的配置）

/api/succ：登录成功跳转路由（ShiroFilterFactoryBean 中的配置）
## 总结
本次使用 Shiro 与 SpringBoot 结合的方式来实现一个简单的登录和登出功能。它本身与 SpringBoot 的结合没有那么的流畅，但是它简单、轻量。可以就实现一个基于 session 的授权认证。加密。还可以通过与 jwt 结合来实现单点登录，还可以通过自定义 filter，组成 filter 链来实现一些接口安全的判断等等。