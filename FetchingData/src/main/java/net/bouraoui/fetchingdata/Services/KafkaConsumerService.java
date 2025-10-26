package net.bouraoui.fetchingdata.Services;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.logging.Logger;

@Component
public class KafkaConsumerService {

    private static final double MU_EARTH = 398600.4418; // Earth's gravitational parameter, km^3/s^2
    private static final double EARTH_RADIUS = 6378.1;
    private static final String KAFKA_TOPIC = "processedDataTopic";
    private static final String TOPIC_HEALTH = "health";
    private static final String TOPIC_ENDOFLIFE = "endoflife";
    private static final String TOPIC_COLLISION = "collision";
    private static final Logger logger = Logger.getLogger(KafkaConsumerService.class.getName());

    @Autowired
    private KafkaTemplate<String, String> kafkaTemplate;

    public KafkaConsumerService() {
        System.out.println("✅ KafkaConsumerService loaded by Spring");
    }

    @KafkaListener(topics = "processedDataTopic", groupId = "tle_data_group", autoStartup = "true",properties = {
            "max.poll.interval.ms=300000",  // 5 minutes
            "session.timeout.ms=10000",     // 10 seconds
            "heartbeat.interval.ms=3000",   // 3 seconds
            "enable.auto.commit=false"
    })
    public void receiveData(String message) {
        try {


            ObjectMapper objectMapper = new ObjectMapper();
            Map<String, Object> receivedData = objectMapper.readValue(message, Map.class);
            System.out.println("Received synthetic data from Kafka:");
            for (Map.Entry<String, Object> entry : receivedData.entrySet()) {
                System.out.println(entry.getKey() + " => " + entry.getValue());
            }

            Integer satelliteId = (Integer) receivedData.get("satellite_id");



            String satelliteName = (String) receivedData.get("satellite_name");
            String tleLine1 = (String) receivedData.get("tle_line1");

            String tleLine2 = (String) receivedData.get("tle_line2");
            Integer timeSinceLaunch = (Integer) receivedData.get("time_since_launch");
            System.out.println("time snce lanch: "+timeSinceLaunch);

            Double orbitalAltitudeDouble = (Double) receivedData.get("orbital_altitude");
            Integer orbital_altitude = orbitalAltitudeDouble != null ? orbitalAltitudeDouble.intValue() : null;

            Double batteryVoltageDouble = (Double) receivedData.get("battery_voltage");
            Float batteryVoltage = batteryVoltageDouble != null ? batteryVoltageDouble.floatValue() : null;
            Double solarPanelTempDouble = (Double) receivedData.get("solar_panel_temperature");
            Float solarPanelTemperature = solarPanelTempDouble != null ? solarPanelTempDouble.floatValue() : null;

            Double attitudeErrorDouble = (Double) receivedData.get("attitude_control_error");
            Float attitudeControlError = attitudeErrorDouble != null ? attitudeErrorDouble.floatValue() : null;

            Double dataRateDouble = (Double) receivedData.get("data_transmission_rate");
            Float dataTransmissionRate = dataRateDouble != null ? dataRateDouble.floatValue() : null;

            Integer thermalControlStatus = (Integer) receivedData.get("thermal_control_status");
            double line1_epoch = Double.parseDouble(tleLine1.substring(18, 32).trim());
            double inclination = Double.parseDouble(tleLine2.substring(8, 16).trim());
            double raan = Double.parseDouble(tleLine2.substring(17, 25).trim());
            double eccentricity = Double.parseDouble("0." + tleLine2.substring(26, 33).trim());
            double mean_motion = Double.parseDouble(tleLine2.substring(52, 63).trim());

            double orbitalPeriod = 86400 / mean_motion;
            /*double r = EARTH_RADIUS + orbital_altitude;
            double orbital_velocity_approx = Math.sqrt(MU_EARTH / r);
*/

            double orbital_velocity_approx = 5000 / orbital_altitude;
            double motion_launch_interaction = mean_motion * timeSinceLaunch;

            double inclinationNorm = inclination / 180.0;
            double altitudeNorm = (orbital_altitude - 160) / (2000 - 160);
            double meanMotionNorm = (mean_motion - 11) / (16 - 11);
            altitudeNorm = Math.max(0, Math.min(1, altitudeNorm));
            meanMotionNorm = Math.max(0, Math.min(1, meanMotionNorm));

            double collisionRisk = (inclinationNorm * 0.3) +
                    (eccentricity * 0.3) +
                    ((1 - altitudeNorm) * 0.2) +
                    (meanMotionNorm * 0.2);

            int collisionWarning = (collisionRisk > 0.6) ? 1 : 0;
            System.out.println("timeSinceLaunch: " + timeSinceLaunch);
            System.out.println("orbital_altitude: " + orbital_altitude);

            System.out.println("Processing Satellite Data - ID: " + satelliteId + ", Name: " + satelliteName);

            // Send data to respective topics
            sendToHealthTopic(satelliteId, satelliteName, timeSinceLaunch, orbital_altitude, batteryVoltage,
                    solarPanelTemperature, attitudeControlError, dataTransmissionRate, thermalControlStatus);

            sendToEndOfLifeTopic(satelliteId, satelliteName, orbital_altitude,
                    orbital_velocity_approx, collisionWarning, eccentricity, mean_motion,
                    motion_launch_interaction, raan, line1_epoch);

            sendToCollisionTopic(satelliteId, satelliteName, tleLine1, tleLine2);

        } catch (Exception e) {
            System.err.println("Error processing received Kafka message: " + e.getMessage());
        }
    }

    private void sendToHealthTopic(Integer satelliteId, String satelliteName, Integer timeSinceLaunch,
                                   Integer orbitalAltitude, Float batteryVoltage, Float solarPanelTemperature,
                                   Float attitudeControlError, Float dataTransmissionRate, Integer thermalControlStatus) {
        try {
            Map<String, Object> healthData = Map.of(
                    "satellite_id", satelliteId,
                    "satellite_name", satelliteName,
                    "time_since_launch", timeSinceLaunch,
                    "orbital_altitude", orbitalAltitude,
                    "battery_voltage", batteryVoltage,
                    "solar_panel_temperature", solarPanelTemperature,
                    "attitude_control_error", attitudeControlError,
                    "data_transmission_rate", dataTransmissionRate,
                    "thermal_control_status", thermalControlStatus
            );
            String message = new ObjectMapper().writeValueAsString(healthData);
            kafkaTemplate.send(TOPIC_HEALTH, message);
            System.out.println("Health data sent to topic: " + TOPIC_HEALTH);
        } catch (Exception e) {
            System.err.println("Error sending to Health Topic: " + e.getMessage());
        }
    }

    private void sendToEndOfLifeTopic(Integer satelliteId, String satelliteName, Integer orbital_altitude,
                                      Double orbital_velocity_approx, Integer collisionWarning, Double eccentricity,
                                      Double mean_motion, Double motion_launch_interaction, Double raan, Double line1_epoch) {
        try {
            Map<String, Object> endOfLifeData = new java.util.HashMap<>();
            endOfLifeData.put("satellite_id", satelliteId);
            endOfLifeData.put("satellite_name", satelliteName);

            endOfLifeData.put("orbital_altitude", orbital_altitude);
            endOfLifeData.put("orbital_velocity_approx", orbital_velocity_approx);
            endOfLifeData.put("collision_warning", collisionWarning);
            endOfLifeData.put("eccentricity", eccentricity);
            endOfLifeData.put("mean_motion", mean_motion);
            endOfLifeData.put("motion_launch_interaction", motion_launch_interaction);
            endOfLifeData.put("raan", raan);
            endOfLifeData.put("line1_epoch", line1_epoch);

            String message = new ObjectMapper().writeValueAsString(endOfLifeData);
            kafkaTemplate.send(TOPIC_ENDOFLIFE, message);
            System.out.println("End-of-life data sent to topic: " + TOPIC_ENDOFLIFE);
        } catch (Exception e) {
            System.err.println("Error sending to End-of-life Topic: " + e.getMessage());
        }
    }

    private void sendToCollisionTopic(Integer satelliteId, String satelliteName, String tleLine1, String tleLine2) {
        try {
            Map<String, Object> collisionData = Map.of(
                    "satellite_id", satelliteId,
                    "satellite_name", satelliteName,
                    "tle_line1", tleLine1,
                    "tle_line2", tleLine2
            );
            String message = new ObjectMapper().writeValueAsString(collisionData);
            kafkaTemplate.send(TOPIC_COLLISION, message);
            System.out.println("Collision data sent to topic: " + TOPIC_COLLISION);
        } catch (Exception e) {
            System.err.println("Error sending to Collision Topic: " + e.getMessage());
        }
    }

    public Integer calculateTimeSinceLaunch(String tleLine1) {
        try {
            System.out.println("🔍 Raw TLE Line 1: " + tleLine1);

            String epochStr = tleLine1.substring(18, 32).trim();
            System.out.println("🔍 Extracted epoch string: " + epochStr);

            // Extract year
            String yearStr = epochStr.substring(0, 2);
            int year = Integer.parseInt(yearStr) + 2000;
            System.out.println("🔍 Parsed year: " + year);

            // Extract day of year
            double dayOfYear = Double.parseDouble(epochStr.substring(2));
            System.out.println("🔍 Parsed day of year (fractional): " + dayOfYear);

            // Convert to launch date
            LocalDate launchDate = LocalDate.of(year, 1, 1).plusDays((long) (dayOfYear - 1));
            System.out.println("📅 Launch date calculated: " + launchDate);

            // Current date
            LocalDate currentDate = LocalDate.now();
            System.out.println("📅 Current date: " + currentDate);

            long daysSinceLaunch = ChronoUnit.DAYS.between(launchDate, currentDate);
            System.out.println("🧮 Days since launch: " + daysSinceLaunch);

            return (int) daysSinceLaunch;

        } catch (Exception e) {
            System.err.println("❌ Error calculating time since launch: " + e.getMessage());
            return 0;
        }
    }


}
