package net.bouraoui.fetchingdata.Controllers;

import lombok.AllArgsConstructor;
import net.bouraoui.fetchingdata.Entities.Satellite;
import net.bouraoui.fetchingdata.Entities.User;
import net.bouraoui.fetchingdata.Services.Interfaces.SatelliteService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/v1/satellites")
@AllArgsConstructor
public class SatelliteController {

    private final SatelliteService satelliteService;

    @GetMapping("/getSatellites")
    public ResponseEntity<List<Satellite>> getAllSatellites() {
        List<Satellite> satelliteList = satelliteService.getTop30SatellitesPrioritized();
        return ResponseEntity.ok(satelliteList);
    }
}