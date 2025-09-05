import { Component } from '@angular/core';
import { CapstoneService } from '../../services/capstone.service';
import { MatCardModule } from '@angular/material/card';
import { MatTableModule } from '@angular/material/table';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { CommonModule, DatePipe } from '@angular/common';
@Component({
  selector: 'app-scan-results',
  standalone: true,
  imports: [  MatCardModule,
      MatTableModule,
      MatIconModule,
      MatButtonModule,
	  DatePipe,
  CommonModule],
  templateUrl: './scan-results.component.html',
  styleUrl: './scan-results.component.css'
})
export class ScanResultsComponent {
	displayedColumns: string[] = ['essid', 'bssid', 'channel', 'power', 'auth', 'enc', 'time'];
	  dataSource: any[] = [];

	  constructor(private capstoneService: CapstoneService) { }

	  ngOnInit(): void {
	    this.capstoneService.getRecentScans().subscribe(scans => {
	      this.dataSource = scans;
	    });

}
}
