package com.ci2.api_authci.exception;

/**
 * 未登录异常
 * Not Login Exception
 * 
 * 当用户未登录或登录已过期时抛出此异常
 * This exception is thrown when the user is not logged in or the login has expired
 */
public class NotLoginException extends RuntimeException {
    /**
     * 构造函数
     * Constructor
     */
    public NotLoginException() {
        super("Not logged in");
    }

    public NotLoginException(String message) {
        super(message);
    }
}
