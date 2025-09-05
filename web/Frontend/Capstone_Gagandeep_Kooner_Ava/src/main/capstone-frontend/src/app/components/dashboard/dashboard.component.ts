import { Component } from '@angular/core';
import { CapstoneService } from '../../services/capstone.service';
import { MatCardModule } from '@angular/material/card';
import { MatTableModule } from '@angular/material/table';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [  MatCardModule,
      MatTableModule,
      MatIconModule,
      MatButtonModule],
  templateUrl: './dashboard.component.html',
  styleUrl: './dashboard.component.css'
})
export class DashboardComponent {
	scanCount = 0;
	  alertCount = 0;
	  recentScans: any[] = [];
	  recentAlerts: any[] = [];
	  constructor(private capstoneService: CapstoneService){}
     
	  ngOnInit(): void {
	     this.loadData();
		 this.loadAlertData();
	   }

	   loadData(): void {
	     this.capstoneService.getRecentScans().subscribe(scans => {
	       this.scanCount = scans.length;
	       this.recentScans = scans.slice(0, 5);
	     });
}
    loadAlertData(): void {
     this.capstoneService.getRecentAlerts().subscribe(alerts => {
       this.alertCount = alerts.length;
       this.recentAlerts = alerts.slice(0, 5);
     });
	 }
}