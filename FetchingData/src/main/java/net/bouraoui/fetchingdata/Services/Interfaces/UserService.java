package net.bouraoui.fetchingdata.Services.Interfaces;

import net.bouraoui.fetchingdata.Entities.User;

import java.util.List;
import java.util.Optional;

public interface UserService {

    List<User> getAllUsers();

    Optional<User> getUserById(String id);

    User createUser(User user) ;

    void deleteUserById(String id);
    void updateUser(User user);

    User getUserByEmail(String email);
}
