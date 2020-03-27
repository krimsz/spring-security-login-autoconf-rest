package com.example.demosecurity;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SampleController {

    @GetMapping(value = "hello")
    public String publicEndpoint(){
        return "Hello Public";
    }

    @GetMapping(value = "secured/hello")
    public String privateEndpoint(){
        return "Hello Secured";
    }

}
