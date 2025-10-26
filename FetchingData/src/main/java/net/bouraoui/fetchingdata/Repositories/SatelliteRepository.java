package net.bouraoui.fetchingdata.Repositories;

import net.bouraoui.fetchingdata.Entities.Satellite;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface SatelliteRepository extends MongoRepository<Satellite,String> {

    @Query(value = "{ popular: 'yes' }", sort = "{ popular : -1 }")
    List<Satellite> findTop30ByPopularYes(org.springframework.data.domain.Pageable pageable);

    @Query("{ 'norad_id': { $in: ?0 } }")
    List<Satellite> findSatellitesByNoradIds(List<Integer> noradIds);

}
