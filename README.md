# API AuthCI

A lightweight authorization framework based on HTTP method and API path (e.g., GET:/user/list) for Spring Boot applications.

## 特性 Features

- **基于请求路径的权限控制**：通过 HTTP 方法和 API 路径进行细粒度的权限验证
- **多种 Token 生成方式**：支持 UUID 和 JWT 两种 Token 生成方式
- **多设备登录管理**：支持设置最大登录设备数和每设备类型的登录数限制
- **分布式锁支持**：使用 Redisson 实现分布式锁，确保并发操作的安全性
- **设备类型识别**：自动识别请求设备类型，支持按设备类型管理登录
- **灵活的配置选项**：提供丰富的配置选项，满足不同场景的需求

## 快速开始 Quick Start

### 1. 添加依赖

```xml
<dependency>
    <groupId>io.github.gtbnh</groupId>
    <artifactId>api_authci</artifactId>
    <version>1.0.0</version>
</dependency>
```

### 2. 配置 application.yaml

```yaml
# API 鉴权配置
# API Authentication Configuration
api-authci:
  # 是否启用鉴权功能
  # Whether to enable authentication functionality
  enabled: true
  
  # 请求头配置
  # Request header configuration
  headers:
    # token在请求头中的名字
    # Token name in request header
    token: 'token'
  
  # Token类型，可选值：uuid, jwt
  # Token type, optional values: uuid, jwt
  token-type: uuid
  
  # token 过期时间字符串，格式如 1ms 1s 1m 1h 1d 1M 1y
  # Token expiration time string, format like 1ms 1s 1m 1h 1d 1M 1y
  expirationStr: '7d'
  
  # 公共资源，不需要鉴权的路径
  # Public resources, paths that don't need authentication
  public-resource:
    - '/login'
  
  # JWT密钥（使用JWT token时必须配置）
  # JWT secret key (must be configured when using JWT token)
  secret-key: your-secret-key
  
  # 最大允许登录设备数
  # Maximum allowed login devices
  max-allow-login-devices: 1
  
  # 每种设备类型允许的登录数
  # Allowed login count per device type
  per-device-type-allow-login-count: 99
```

### 3. 实现权限获取接口

```java
import com.ci2.api_authci.intf.ApiAuthciIntf;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class CustomApiAuthciImpl implements ApiAuthciIntf {
    @Override
    public List<String> getPermissions(Object loginId, String loginType) {
        // 根据登录ID和登录类型获取用户权限列表
        // 示例：返回用户拥有的API权限
        return List.of("GET:/user/list", "POST:/user/add");
    }
}
```

### 4. 生成 Token

```java
import com.ci2.api_authci.util.AAUtil;

// 生成Token
String token = AAUtil.getToken(loginId);

// 生成带自定义载荷的Token
Map<String, Object> payload = new HashMap<>();
payload.put("role", "admin");
String tokenWithPayload = AAUtil.getToken(loginId, payload);
```

### 5. 权限验证

框架会自动拦截请求并验证权限，无需手动调用。

## 核心功能 Core Features

### Token 管理

- **生成 Token**：支持 UUID 和 JWT 两种方式
- **验证 Token**：自动验证 Token 的有效性
- **Token 过期**：支持设置 Token 过期时间
- **多设备登录**：支持管理用户的多设备登录

### 权限验证

- **基于路径的权限控制**：通过 HTTP 方法和 API 路径进行权限验证
- **公共资源配置**：支持配置不需要鉴权的公共资源路径
- **自定义权限验证**：通过实现 `PermValidator` 接口自定义权限验证逻辑

### 多设备管理

- **设备类型识别**：自动识别请求设备类型
- **登录限制**：支持设置最大登录设备数和每设备类型的登录数限制
- **用户踢出**：支持踢出用户的所有登录或指定 Token 的登录

### 分布式锁

- **并发安全**：使用 Redisson 实现分布式锁，确保并发操作的安全性
- **原子操作**：确保多设备登录管理的原子性

## 配置选项 Configuration Options

| 配置项 | 说明 | 默认值 |
|-------|------|-------|
| `api-authci.enabled` | 是否启用鉴权功能 | `true` |
| `api-authci.headers.token` | Token 在请求头中的名字 | `token` |
| `api-authci.token-type` | Token 类型，可选值：`uuid`, `jwt` | `uuid` |
| `api-authci.expirationStr` | Token 过期时间字符串，格式如 `1ms 1s 1m 1h 1d 1M 1y` | `7d` |
| `api-authci.public-resource` | 公共资源，不需要鉴权的路径 | `['/login']` |
| `api-authci.secret-key` | JWT 密钥（使用 JWT token 时必须配置） | - |
| `api-authci.max-allow-login-devices` | 最大允许登录设备数 | `1` |
| `api-authci.per-device-type-allow-login-count` | 每种设备类型允许的登录数 | `99` |

## 工具类 API

### AAUtil

- **getToken(Object loginId)**：生成 Token
- **getToken(Object loginId, Map<String, Object> payload)**：生成带自定义载荷的 Token
- **getLoginId()**：获取当前登录 ID
- **getLoginType()**：获取当前登录类型
- **getPayload()**：获取 Token 中的载荷数据
- **kickout(Object loginId)**：踢出用户的所有登录
- **kickoutByToken(String token)**：踢出指定 Token 的登录
- **logout()**：当前用户登出
- **getAllLoginInfo(Object loginId)**：获取用户的所有登录信息
- **getAllApiPerms()**：获取所有 API 权限

### 异常类

- **NotLoginException**：未登录异常
- **PermDeniedException**：权限拒绝异常

## 工作原理 Working Principle

1. **请求拦截**：通过 `ApiAuthciInterceptor` 拦截 HTTP 请求
2. **Token 验证**：验证请求中的 Token 是否有效
3. **权限验证**：根据 HTTP 方法和 API 路径验证用户是否拥有相应权限
4. **设备管理**：管理用户的多设备登录，确保登录数不超过限制
5. **分布式锁**：使用 Redisson 实现分布式锁，确保并发操作的安全性

## 依赖 Dependencies

- Spring Boot 3.5.11+
- Redis
- Hutool JWT 5.8.42+
- Redisson 3.52.0+
- UserAgentUtils 1.21+
- Fastjson2 2.0.60+

## 许可证 License

Apache-2.0

## 贡献 Contributing

欢迎提交 Issue 和 Pull Request！

## 联系 Contact

- GitHub: [https://github.com/gtbnh/api_authci](https://github.com/gtbnh/api_authci)
- Email: xyxx12684@gmail.com
