package com.ci2.api_authci.exception;

public class NotRedisException extends RuntimeException {
    public NotRedisException() {
        super("use the token type of uuid must have a redis");
    }

    public NotRedisException( Throwable cause) {
        super("use the token type of uuid must have a redis",cause);
    }
}
