package com.ci2.api_authci.exception;

public class PermDeniedException extends RuntimeException {
    public PermDeniedException() {
        super("Permission denied by api auth ci interceptor");
    }

    public PermDeniedException(String message) {
        super(message);
    }
}
