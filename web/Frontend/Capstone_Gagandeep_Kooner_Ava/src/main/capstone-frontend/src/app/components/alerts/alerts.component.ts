import { Component } from '@angular/core';
import { CapstoneService } from '../../services/capstone.service';
import { MatCardModule } from '@angular/material/card';
import { MatTableModule } from '@angular/material/table';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { DatePipe } from '@angular/common';



@Component({
  selector: 'app-alerts',
  standalone: true,
  imports: [  MatCardModule,
      MatTableModule,
      MatIconModule,
      MatButtonModule,
	DatePipe],
  templateUrl: './alerts.component.html',
  styleUrl: './alerts.component.css'
})

export class AlertsComponent {
	dataSource: any[] = [];
	
	displayedColumns: string[] = ['essid', 'bssid', 'type', 'channel', 'power', 'time'];
	  constructor(private capstoneService: CapstoneService) { }

	  ngOnInit(): void {
	    this.capstoneService.getRecentAlerts().subscribe(alerts => {
	      this.dataSource = alerts;
	    });
	  }
}
