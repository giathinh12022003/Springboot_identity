package com.microservices.identity_service.dto.request;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserCreationRequest {
    String userName;
    String passWord;
    String name;
    String phoneNumber;
    String email;
}
