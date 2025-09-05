import { TestBed } from '@angular/core/testing';

import { CapstoneService } from './capstone.service';

describe('CapstoneService', () => {
  let service: CapstoneService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(CapstoneService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
