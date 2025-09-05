package ca.sheridancollege.koonerga.web.rest;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import ca.sheridancollege.koonerga.domain.Alert;
import ca.sheridancollege.koonerga.domain.ScanResult;
import ca.sheridancollege.koonerga.service.FlaskApiService;
import lombok.AllArgsConstructor;

@RestController
@RequestMapping("/api/access")
public class HomeController {
	 private final FlaskApiService flaskApiService;
	 
	 public HomeController(FlaskApiService flaskApiService) {
	        this.flaskApiService = flaskApiService;
	    }
	 
	 @GetMapping("/scans")
	    public ResponseEntity<List<ScanResult>> getRecentScans() {
	        return ResponseEntity.ok(flaskApiService.getRecentScans());
	    }

	    @GetMapping("/alerts")
	    public ResponseEntity<List<Alert>> getRecentAlerts() {
	        return ResponseEntity.ok(flaskApiService.getRecentAlerts());
	    }
}
