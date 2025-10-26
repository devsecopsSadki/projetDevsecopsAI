package net.bouraoui.fetchingdata.Services.Interfaces;

import net.bouraoui.fetchingdata.Entities.Satellite;
import org.springframework.data.mongodb.core.aggregation.ArithmeticOperators;

import java.util.List;

public interface SatelliteService {
    List<Satellite> getTop30SatellitesPrioritized();

    List<Satellite> findAllById(List<String> ids);

    List<Satellite> findAllByNoradID(List<Integer> noradIDs);
}
