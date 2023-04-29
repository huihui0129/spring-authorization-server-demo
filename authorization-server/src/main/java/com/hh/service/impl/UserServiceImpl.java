//package com.hh.service.impl;
//
//import lombok.RequiredArgsConstructor;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.security.core.userdetails.User;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.core.userdetails.UsernameNotFoundException;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.stereotype.Service;
//
///**
// * @author huihui
// * @date 2023/4/29 15:16
// * @description UserServiceImpl
// */
//@Service
//@RequiredArgsConstructor
//@Slf4j
//public class UserServiceImpl implements UserDetailsService {
//
//    private final PasswordEncoder passwordEncoder;
//
//    @Override
//    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//        log.info("加载用户：{}", username);
//        return User.builder().username("admin").password(passwordEncoder.encode("123456")).authorities("admin:list").build();
//    }
//
//}
