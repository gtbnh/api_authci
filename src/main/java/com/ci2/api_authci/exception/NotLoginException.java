package com.ci2.api_authci.exception;

public class NotLoginException extends RuntimeException {
    public NotLoginException() {
        super("Not logged in");
    }
}
