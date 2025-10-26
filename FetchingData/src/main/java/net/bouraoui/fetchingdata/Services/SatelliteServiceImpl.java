package net.bouraoui.fetchingdata.Services;

import lombok.AllArgsConstructor;
import net.bouraoui.fetchingdata.Entities.Satellite;
import net.bouraoui.fetchingdata.Repositories.SatelliteRepository;
import net.bouraoui.fetchingdata.Services.Interfaces.SatelliteService;

import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;

import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.stereotype.Service;

import java.util.List;

@Service
@AllArgsConstructor
public class SatelliteServiceImpl implements SatelliteService {
    @Autowired
    private SatelliteRepository satelliteRepository;

    @Override
    public List<Satellite> getTop30SatellitesPrioritized() {
        Pageable limit = PageRequest.of(0, 30);
        return satelliteRepository.findTop30ByPopularYes(limit);
    }

    @Override
    public List<Satellite> findAllById(List<String> ids){
        return satelliteRepository.findAllById(ids);
    }

    @Override
    public List<Satellite> findAllByNoradID(List<Integer> noradIDs) {
        return satelliteRepository.findSatellitesByNoradIds(noradIDs);
    }

}
