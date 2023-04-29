package com.hh.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author huihui
 * @date 2023/4/29 14:58
 * @description AuthorizationController
 */
@RestController
@Slf4j
public class AuthorizationController {

    @GetMapping("/test01")
    public String test01() {
        return "成功test01";
    }

}
