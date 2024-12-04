package com.example.Controller;

import org.springframework.web.bind.annotation.RestController;
import com.example.Dto.OrderDto;
import java.util.List;
import java.util.UUID;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@RestController
public class OrderController {

    @GetMapping("/order-status")
    @PreAuthorize("hasAuthority('SCOPE_openid')")
    public String orderStatus(){
        return "Its Working..";
    }
    
    @GetMapping("/orders")
    @PreAuthorize("hasAnyRole('VIEWER', 'ADMIN')")
    public List<OrderDto> getOrders(){
        return List.of(
            new OrderDto(
                  UUID.randomUUID(),
                     "Laptop"
            )
        );
    }

    @PostMapping("/orders")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public UUID createOrder(@RequestBody String orderType) {
        return UUID.randomUUID();
    }
}
