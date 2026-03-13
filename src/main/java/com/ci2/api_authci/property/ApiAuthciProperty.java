package com.ci2.api_authci.property;

import com.ci2.api_authci.util.MUtils;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties(prefix = "api-authci")
@Data
@Configuration
public class ApiAuthciProperty {

    private boolean enabled = true;
    private Headers headers;
    private TokenType tokenType = TokenType.uuid;
    private List<String> publicResource = new ArrayList<>();
    private String secretKey;
    //token 过期时间字符串 expiration 属性不存在时使用此属性
    private String expirationStr = "7d";
    //token 过期时间 单位ms
    private Long expiration;

    private boolean allowMultiDeviceLogin=false;


    public long getExpiration() {

        if (expiration == null) {
            long parsed = MUtils.parseTimeToMs(expirationStr);
            expiration = parsed;
            return parsed;
        }
        return expiration;
    }

    @Data
    public static class Headers {
        //token在请求头中的名字
        private String token = "Authorization";

    }

    public enum TokenType {
        uuid(),
        jwt();
    }


}
