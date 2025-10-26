package net.bouraoui.fetchingdata.Entities;

import lombok.Getter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.LocalDateTime;

@Document(collection = "tle_data")
@Getter
public class TLEData {

    @Id
    private String id;

    private Integer satelliteId;
    private String satelliteName;
    private String tleLine1;
    private String tleLine2;
    private LocalDateTime lastUpdated;

    public TLEData() {

    }

    public TLEData(Integer satelliteId, String satelliteName, String tleLine1, String tleLine2) {
        this.satelliteId = satelliteId;
        this.satelliteName = satelliteName;
        this.tleLine1 = tleLine1;
        this.tleLine2 = tleLine2;
        this.lastUpdated = LocalDateTime.now();
    }



    public void updateTLEData(String tleLine1, String tleLine2) {
        this.tleLine1 = tleLine1;
        this.tleLine2 = tleLine2;
        this.lastUpdated = LocalDateTime.now();
    }

    public String getTleLine1() {
        return tleLine1;
    }

    public String getTleLine2() {
        return tleLine2;
    }
}