package com.avanade.dio.jwt.service;

import com.avanade.dio.jwt.data.UserData;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

// Posso importar de forma estática e chamar somente o método || Como no caso do método emptyList()
import java.util.ArrayList;
import java.util.List;

import static java.util.Collections.*;

@Service
public class UserDetailServiceImpl  implements UserDetailsService {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public UserDetailServiceImpl(BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserData user = findUser(username);
        if(user == null)
            throw new UsernameNotFoundException(username);

        return new User(user.getUsername(), user.getPassword(), emptyList());
    }

    private UserData findUser(String username) {
        return new UserData("admin", bCryptPasswordEncoder.encode("12345"));
    }

    public List<UserData> listUsers() {
        ArrayList<UserData> users = new ArrayList<UserData>();
        users.add(findUser("admin"));
        return users;
    }
}
