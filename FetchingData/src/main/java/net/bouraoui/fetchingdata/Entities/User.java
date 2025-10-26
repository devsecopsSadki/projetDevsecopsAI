package net.bouraoui.fetchingdata.Entities;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.List;

@Document(collection = "sattelitesbyuser")
@AllArgsConstructor@Builder@NoArgsConstructor
public class User {

    @Id
    private String id;
    private String name;
    private String email;
    private List<Integer> noradIDs;//norad_ids




    // Getters and Setters
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public List<Integer> getNoradIDs() {
        return noradIDs;
    }

    public void setNoradIDs(List<Integer> noradIDs) {
        this.noradIDs = noradIDs;
    }
}