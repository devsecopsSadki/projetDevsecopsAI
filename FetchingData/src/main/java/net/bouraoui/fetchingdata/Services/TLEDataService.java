package net.bouraoui.fetchingdata.Services;


import net.bouraoui.fetchingdata.Entities.TLEData;
import net.bouraoui.fetchingdata.Repositories.TLEDataRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import org.json.JSONObject;

import java.util.Optional;

@Service

public class TLEDataService {

    private static final String API_URL = "https://api.n2yo.com/rest/v1/satellite/tle/{satelliteId}&apiKey=ST8DZ8-AAVC2J-8QR7CC-5H4M";

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private TLEDataRepository repository;

    public String fetchAndSaveTLEData(Integer satelliteId) {
        try {
            String response = restTemplate.getForObject(API_URL, String.class, satelliteId);
            System.out.println("response: "+response);

            if (response != null) {
                JSONObject jsonResponse = new JSONObject(response);
                if (!jsonResponse.has("tle") || jsonResponse.getString("tle").isEmpty()) {
                    System.err.println("Invalid or missing 'tle' field in API response for satellite ID: " + satelliteId);
                    return null; // Skip this entry if TLE is invalid or empty
                }
                String satelliteName = jsonResponse.getJSONObject("info").optString("satname", "Unknown Satellite");
                String[] tleLines = jsonResponse.getString("tle").split("\n");
                String tleLine1 = tleLines[0];
                String tleLine2 = tleLines[1];
                if (tleLines.length < 2) {
                    System.err.println("Invalid TLE format in response for satellite ID: " + satelliteId);
                    return null;
                }

                /*Optional<TLEData> existingTLE = repository.findBySatelliteName(satelliteName);

               if (existingTLE.isPresent()) {
                    TLEData tleData = existingTLE.get();
                    if (!tleData.getTleLine1().equals(tleLine1) || !tleData.getTleLine2().equals(tleLine2)) {
                        tleData.updateTLEData(tleLine1, tleLine2);
                        repository.save(tleData);
                        return formatTLEData(satelliteId, satelliteName, tleLine1, tleLine2);
                    }
                } else {
                    TLEData newTLEData = new TLEData(satelliteId, satelliteName, tleLine1, tleLine2);
                    repository.save(newTLEData);
                    return formatTLEData(satelliteId, satelliteName, tleLine1, tleLine2);
                }*/
                return formatTLEData(satelliteId, satelliteName, tleLine1, tleLine2);

            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    private String formatTLEData(Integer satelliteId, String satelliteName, String tleLine1, String tleLine2) {
        return String.format(
                "Satellite ID: %d\nSatellite Name: %s\nTLE Line 1: %s\nTLE Line 2: %s",
                satelliteId, satelliteName, tleLine1, tleLine2
        );
    }
}

