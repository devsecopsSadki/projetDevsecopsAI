package net.bouraoui.fetchingdata.Entities;


import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Document(collection = "satellites")
@Getter@Setter@AllArgsConstructor@NoArgsConstructor@Builder
public class Satellite {

    @Id
    private String id;
    private String name;
    private int norad_id;
    private String Owner;
    private String launchDate;
    private String launchSite;
    private String popular;

}
