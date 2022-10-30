package com.example.corespringsecurity.sevice.Impl;

import com.example.corespringsecurity.domain.Account;
import com.example.corespringsecurity.repository.UserRepository;
import com.example.corespringsecurity.sevice.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service("userService")
public class UserServiceImpl implements UserService
{
    @Autowired
    private UserRepository userRepository;

    @Transactional
    @Override
    public void createUser(Account account)
    {
        userRepository.save(account);
    }
}
