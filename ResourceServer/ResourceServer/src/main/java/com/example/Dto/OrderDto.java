package com.example.Dto;

import java.util.UUID;

public record OrderDto(
    UUID orderId,
    String orderType
) {

}
