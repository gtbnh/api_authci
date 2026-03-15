package com.ci2.api_authci.property;

import cn.hutool.crypto.digest.HmacAlgorithm;
import cn.hutool.jwt.JWT;
import cn.hutool.jwt.JWTUtil;
import cn.hutool.jwt.signers.JWTSigner;
import cn.hutool.jwt.signers.JWTSignerUtil;
import com.ci2.api_authci.util.MUtils;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;

/**
 * API 鉴权配置属性
 * API Authentication Configuration Properties
 * 
 * 该类用于定义API鉴权的配置属性
 * This class is used to define configuration properties for API authentication
 */
@ConfigurationProperties(prefix = "api-authci")
@Data
@Configuration
public class ApiAuthciProperty {

    /**
     * 是否启用鉴权功能
     * Whether to enable authentication functionality
     */
    private boolean enabled = true;
    
    /**
     * 请求头配置
     * Request header configuration
     */
    private Headers headers;
    
    /**
     * Token类型，默认为UUID
     * Token type, default is UUID
     */
    private TokenType tokenType = TokenType.uuid;
    
    /**
     * 公共资源，不需要鉴权的路径
     * Public resources, paths that don't need authentication
     */
    private List<String> publicResource = new ArrayList<>();
    
    /**
     * JWT密钥
     * JWT secret key
     */
    private String secretKey;

    private String algorithmId;

    /**
     * token 过期时间字符串，expiration 属性不存在时使用此属性
     * Token expiration time string, used when expiration property is not present
     */
    private String expirationStr = "7d";
    
    /**
     * token 过期时间，单位ms，-1代表不过期
     * Token expiration time, in milliseconds, -1 mean not expired
     */
    private Long expiration;

    /**
     * 是否允许多设备登录
     * Whether to allow multi-device login
     */
//    private boolean allowMultiDeviceLogin = false;

    private int maxAllowLoginDevices = 1;

    private int perDeviceTypeAllowLoginCount = 99;
    /**
     * 获取token过期时间
     * Get token expiration time
     * 
     * @return 过期时间，单位ms
     * @return expiration time, in milliseconds
     */
    public long getExpiration() {
        if (expiration == null) {
            long parsed = MUtils.parseTimeToMs(expirationStr);
            expiration = parsed;
            return parsed;
        }

        return expiration;
    }

    /**
     * 请求头配置类
     * Request header configuration class
     */
    @Data
    public static class Headers {
        /**
         * token在请求头中的名字
         * Token name in request header
         */
        private String token = "Authorization";

    }

    /**
     * Token类型枚举
     * Token type enum
     */
    public enum TokenType {
        /**
         * UUID类型token
         * UUID type token
         */
        uuid,
        /**
         * JWT类型token
         * JWT type token
         */
        jwt;
    }

}
