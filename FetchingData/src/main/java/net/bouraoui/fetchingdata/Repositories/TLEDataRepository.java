package net.bouraoui.fetchingdata.Repositories;

import net.bouraoui.fetchingdata.Entities.TLEData;
import net.bouraoui.fetchingdata.Entities.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

public interface TLEDataRepository extends MongoRepository<TLEData, String> {
    Optional<TLEData> findBySatelliteName(String satelliteName);


}
