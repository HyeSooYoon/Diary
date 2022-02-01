package com.diary.em.Service;

import java.util.ArrayList;
import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

public class CustomUserDetails extends User implements UserDetails {
    
    private User user;

public User getUser() {
    return user;
}

public void setUser(User user) {
    this.user = user;
}

private static final long serialVersionUID = 2020921373107176828L;

public CustomUserDetails () {}

public CustomUserDetails (User user) {
    super(user);
}

@Override
public Set<Authorities> getAuthorities() {
    return super.getAuthorities();
}
@Override
public boolean isAccountNonExpired() {
    return true;
}
@Override
public boolean isAccountNonLocked() {
    return true;
}
@Override
public boolean isCredentialsNonExpired() {
    return true;
}
@Override
public boolean isEnabled() {
    return true;
}
 
}

