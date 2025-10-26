package net.bouraoui.fetchingdata.Controllers;

import net.bouraoui.fetchingdata.Entities.Satellite;
import net.bouraoui.fetchingdata.Entities.User;
import net.bouraoui.fetchingdata.Services.Interfaces.SatelliteService;
import net.bouraoui.fetchingdata.Services.Interfaces.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/v1/users/")
public class UserController {

    private final UserService userService;
    private final SatelliteService satelliteService;

    public UserController(UserService userService, SatelliteService satelliteService) {
        this.userService = userService;
        this.satelliteService = satelliteService;
    }


    // Create a new user
    @PostMapping("/createUser")
    public ResponseEntity<?> createUser(@RequestBody User user) {
        User existingUser = userService.getUserByEmail(user.getEmail());

        if (existingUser != null) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body("A user with this email already exists.");
        }

        User createdUser = userService.createUser(user);
        return ResponseEntity.status(HttpStatus.CREATED).body(createdUser);
    }


    // Add satellites to an existing user
    @PostMapping("/addSatellite")
    public ResponseEntity<String> addSatellites(@RequestBody AddSatelliteRequest request) {
        User user = userService.getUserByEmail(request.email());
        if (user!=null) {
            //User user = userOptional.get();
            List<Integer> satelliteIds = request.satellites().stream()
                    .map(Satellite::getNorad_id)
                    .toList();

            // Update user's satellite list (merge with existing if needed)
            List<Integer> updatedSatelliteIds = new ArrayList<>(user.getNoradIDs());
            updatedSatelliteIds.addAll(satelliteIds);
            user.setNoradIDs(updatedSatelliteIds);

            userService.updateUser(user);
            return ResponseEntity.ok("Satellites successfully added to user.");
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found.");
        }
    }


    @GetMapping("/getUser/{id}")
    public ResponseEntity<User> getUserById(@PathVariable("id") String id) {
        Optional<User> userOptional = userService.getUserById(id);
        return userOptional.map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND).body(null));
    }


    @GetMapping("/stallitesTrackeByUser/{email}")
    public ResponseEntity<List<Satellite>> getSatellitesByUser(@PathVariable("email") String email) {
        User user = userService.getUserByEmail(email);
        if (user != null) {
            List<Integer> satelliteIds = user.getNoradIDs();
            List<Satellite> satellites = satelliteService.findAllByNoradID(satelliteIds);

            return ResponseEntity.ok(satellites);
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
        }
    }



}