package ca.sheridancollege.koonerga.service;

import java.util.List;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.beans.factory.annotation.Value;

import ca.sheridancollege.koonerga.domain.Alert;
import ca.sheridancollege.koonerga.domain.ScanResult;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;



@Service

public class FlaskApiService {
	
  
    private final RestTemplate restTemplate;
    private final String flaskApiBaseUrl;

    // Constructor with RestTemplate injection
    public FlaskApiService(RestTemplate restTemplate, 
                         @Value("${flask.api.base-url}") String flaskApiBaseUrl) {
        this.restTemplate = restTemplate;
        this.flaskApiBaseUrl = flaskApiBaseUrl;
    }

  
    public List<ScanResult> getRecentScans() {
        String url = flaskApiBaseUrl + "/scans";
        ResponseEntity<List<ScanResult>> response = restTemplate.exchange(
                url,
                HttpMethod.GET,
                null,
                new ParameterizedTypeReference<List<ScanResult>>() {});
        System.out.println("Scan"+ response);
        return response.getBody();
    }

    public List<Alert> getRecentAlerts() {
        String url = flaskApiBaseUrl + "/alerts";
        ResponseEntity<List<Alert>> response = restTemplate.exchange(
                url,
                HttpMethod.GET,
                null,
                new ParameterizedTypeReference<List<Alert>>() {});
        System.out.println("Scan"+ response);
        return response.getBody();
    }

}
