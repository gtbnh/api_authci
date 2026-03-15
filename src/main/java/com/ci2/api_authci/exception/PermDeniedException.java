package com.ci2.api_authci.exception;

/**
 * 权限拒绝异常
 * Permission Denied Exception
 * 
 * 当用户没有权限访问某个资源时抛出此异常
 * This exception is thrown when the user does not have permission to access a resource
 */
public class PermDeniedException extends RuntimeException {
    /**
     * 构造函数
     * Constructor
     */
    public PermDeniedException() {
        super("Permission denied by api auth ci interceptor");
    }

    /**
     * 构造函数
     * Constructor
     * 
     * @param message 异常消息 exception message     */
    public PermDeniedException(String message) {
        super(message);
    }
}
