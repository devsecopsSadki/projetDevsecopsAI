package net.bouraoui.fetchingdata.Controllers;

import net.bouraoui.fetchingdata.Entities.Satellite;

import java.util.List;

public record AddSatelliteRequest(
        String id,
        String email,
        List<Satellite> satellites
) {
}
