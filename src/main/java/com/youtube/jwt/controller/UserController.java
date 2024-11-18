package com.youtube.jwt.controller;

import com.youtube.jwt.entity.User;
import com.youtube.jwt.service.UserService;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {

        @Autowired
        private UserService userService;

        @PostConstruct
        public void initRolesAndUsers(){
                userService.initRolesAndUsers();
        }

        @PostMapping({"/registerNewUser"})
        public User registerNewUser(@RequestBody User user){
               return userService.registerNewUser(user);
        }

        @GetMapping({"/forAdmin"})
        @PreAuthorize("hasRole('Admin')")
        public String forAdmin(){
                return "This URL is only accessible to admin";
        }


        @GetMapping({"/forUser"})
        @PreAuthorize("hasRole('User')")
        public String forUser(){
                return "This URL is only accessible to the user";
        }

}
