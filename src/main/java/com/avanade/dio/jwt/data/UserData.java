package com.avanade.dio.jwt.data;

import lombok.*;

import java.io.Serializable;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class UserData implements Serializable {

    private String username;
    private String password;
}
