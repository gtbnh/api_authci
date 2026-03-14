package com.ci2.api_authci;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * API 鉴权应用启动类
 * API Authentication Application Startup Class
 * 
 * 该类是应用的入口点，用于启动 Spring Boot 应用
 * This class is the entry point of the application, used to start the Spring Boot application
 */
@SpringBootApplication
public class ApiAuthciApplication {

    /**
     * 主方法
     * Main method
     * 
     * @param args 命令行参数
     * @param args command line arguments
     */
    public static void main(String[] args) {
        SpringApplication.run(ApiAuthciApplication.class, args);
    }

}
